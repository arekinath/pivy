/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <strings.h>
#include <limits.h>

#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <wintypes.h>
#include <winscard.h>
#endif

#include <sys/types.h>
#include <sys/errno.h>
#if defined(__sun)
#include <sys/fork.h>
#endif
#include <sys/wait.h>

#include "libssh/sshkey.h"
#include "libssh/sshbuf.h"
#include "libssh/digest.h"

#include "sss/hazmat.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if defined(__sun)
#include <libtecla.h>
#else
#include <editline/readline.h>
#endif

#include <libzfs.h>
#include <libzfs_core.h>
#include <libnvpair.h>

#define USING_SPL
#include "tlv.h"
#include "piv.h"
#include "bunyan.h"
#include "json.h"
#include "debug.h"

#include "words.h"

static struct piv_token *ks = NULL;
static struct piv_token *selk = NULL;
static int min_retries = 1;

static libzfs_handle_t *zfshdl = NULL;

static SCARDCONTEXT ctx;

const char *optstring = "d";

extern char *buf_to_hex(const uint8_t *buf, size_t len, boolean_t spaces);

#if defined(__sun)
static GetLine *sungl = NULL;

static char *
readline(const char *prompt)
{
	char *line;
	line = gl_get_line(sungl, prompt, NULL, -1);
	if (line != NULL)
		line = strdup(line);
	return (line);
}
#endif

static uint8_t *
parse_hex(const char *str, uint *outlen)
{
	const uint len = strlen(str);
	uint8_t *data = calloc(1, len / 2 + 1);
	uint idx = 0;
	uint shift = 4;
	uint i;
	for (i = 0; i < len; ++i) {
		const char c = str[i];
		boolean_t skip = B_FALSE;
		if (c >= '0' && c <= '9') {
			data[idx] |= (c - '0') << shift;
		} else if (c >= 'a' && c <= 'f') {
			data[idx] |= (c - 'a' + 0xa) << shift;
		} else if (c >= 'A' && c <= 'F') {
			data[idx] |= (c - 'A' + 0xA) << shift;
		} else if (c == ':' || c == ' ' || c == '\t' ||
		    c == '\n' || c == '\r') {
			skip = B_TRUE;
		} else {
			fprintf(stderr, "error: invalid hex digit: '%c'\n", c);
			return (NULL);
		}
		if (skip == B_FALSE) {
			if (shift == 4) {
				shift = 0;
			} else if (shift == 0) {
				++idx;
				shift = 4;
			}
		}
	}
	if (shift == 0) {
		fprintf(stderr, "error: odd number of hex digits "
		    "(incomplete)\n");
		return (NULL);
	}
	*outlen = idx;
	return (data);
}

static void
assert_pin(struct piv_token *pk)
{
	int rv;
	uint retries = min_retries;
	char prompt[64];
	char *guid;
	char *pin = NULL;
	guid = buf_to_hex(pk->pt_guid, 4, B_FALSE);
	snprintf(prompt, 64, "Enter PIV PIN for token %s: ", guid);
	do {
		pin = getpass(prompt);
	} while (pin == NULL && errno == EINTR);
	if ((pin == NULL && errno == ENXIO) ||
	    (pin != NULL && strlen(pin) == 0)) {
		piv_txn_end(pk);
		fprintf(stderr, "error: a PIN code is required to "
		    "unlock token %s\n", guid);
		exit(4);
	} else if (pin == NULL) {
		piv_txn_end(pk);
		perror("getpass");
		exit(3);
	}
	pin = strdup(pin);
	free(guid);

	rv = piv_verify_pin(pk, pin, &retries, B_FALSE);
	if (rv == EACCES) {
		piv_txn_end(pk);
		if (retries == 0) {
			fprintf(stderr, "error: token is locked due to too "
			    "many invalid PIN code entries\n");
			exit(10);
		}
		fprintf(stderr, "error: invalid PIN code (%d attempts "
		    "remaining)\n", retries);
		exit(4);
	} else if (rv == EAGAIN) {
		piv_txn_end(pk);
		fprintf(stderr, "error: insufficient retries remaining "
		    "(%d left)\n", retries);
		exit(4);
	} else if (rv != 0) {
		piv_txn_end(pk);
		fprintf(stderr, "error: failed to verify PIN\n");
		exit(4);
	}
}

const char *
_umem_debug_init()
{
	return ("guards");
}

enum chaltype {
	CHAL_RECOVERY = 1,
	CHAL_VERIFY_AUDIT = 2,
};

enum chaltag {
	CTAG_HOSTNAME = 1,
	CTAG_CTIME = 2,
	CTAG_DESCRIPTION = 3,
	CTAG_WORDS = 4,
};

struct challenge {
	uint8_t c_version;
	enum chaltype c_type;
	uint8_t c_id;
	char *c_description;
	char *c_hostname;
	uint64_t c_ctime;
	uint8_t c_words[4];
	struct sshkey *c_destkey;
	struct piv_ecdh_box *c_keybox;
};

enum intent {
	INTENT_UNUSED,
	INTENT_CHALRESP,
	INTENT_DIRECT
};

struct partstate {
	struct partstate *ps_next;
	uint8_t ps_id;
	char *ps_name;
	char *ps_shortid;
	uint8_t *ps_guid;
	struct piv_ecdh_box *ps_box;
	struct piv_ecdh_box *ps_respbox;
	struct challenge *ps_challenge;
	enum intent ps_intent;
	uint8_t *ps_share;
	size_t ps_len;
};

static void
free_challenge(struct challenge *chal)
{
	if (chal->c_keybox != NULL)
		piv_box_free(chal->c_keybox);
	if (chal->c_description)
		free(chal->c_description);
	if (chal->c_hostname)
		free(chal->c_hostname);
	if (chal->c_destkey)
		sshkey_free(chal->c_destkey);
	free(chal);
}

static int
chalbox_make(struct challenge *chal, struct piv_ecdh_box **outbox)
{
	struct piv_ecdh_box *box = NULL;
	struct sshbuf *buf;
	uint8_t *data = NULL;
	struct piv_ecdh_box *kb = chal->c_keybox;
	struct apdubuf *iv = &kb->pdb_iv;
	struct apdubuf *enc = &kb->pdb_enc;
	int rc;

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	box = piv_box_new();
	VERIFY(box != NULL);

	if ((rc = sshbuf_put_u8(buf, chal->c_version)) ||
	    (rc = sshbuf_put_u8(buf, chal->c_type)) ||
	    (rc = sshbuf_put_u8(buf, chal->c_id)))
		goto out;
	if ((rc = sshbuf_put_eckey8(buf, chal->c_destkey->ecdsa)))
		goto out;
	if ((rc = sshbuf_put_eckey8(buf, kb->pdb_ephem_pub->ecdsa)) ||
	    (rc = sshbuf_put_string8(buf, iv->b_data, iv->b_len)) ||
	    (rc = sshbuf_put_string8(buf, enc->b_data, enc->b_len)))
		goto out;
	if ((rc = sshbuf_put_u8(buf, CTAG_HOSTNAME)) ||
	    (rc = sshbuf_put_cstring8(buf, chal->c_hostname)) ||
	    (rc = sshbuf_put_u8(buf, CTAG_CTIME)) ||
	    (rc = sshbuf_put_u8(buf, 8)) ||
	    (rc = sshbuf_put_u64(buf, chal->c_ctime)) ||
	    (rc = sshbuf_put_u8(buf, CTAG_DESCRIPTION)) ||
	    (rc = sshbuf_put_cstring8(buf, chal->c_description)) ||
	    (rc = sshbuf_put_u8(buf, CTAG_WORDS)) ||
	    (rc = sshbuf_put_u8(buf, 4)) ||
	    (rc = sshbuf_put_u8(buf, chal->c_words[0])) ||
	    (rc = sshbuf_put_u8(buf, chal->c_words[1])) ||
	    (rc = sshbuf_put_u8(buf, chal->c_words[2])) ||
	    (rc = sshbuf_put_u8(buf, chal->c_words[3])))
		goto out;

	box->pdb_cipher = strdup(kb->pdb_cipher);
	box->pdb_kdf = strdup(kb->pdb_kdf);
	bcopy(kb->pdb_guid, box->pdb_guid, sizeof (box->pdb_guid));
	box->pdb_slot = kb->pdb_slot;
	box->pdb_guidslot_valid = kb->pdb_guidslot_valid;
	if ((rc = piv_box_set_data(box, sshbuf_ptr(buf), sshbuf_len(buf))))
		goto out;
	if ((rc = piv_box_seal_offline(kb->pdb_pub, box)))
		goto out;

	*outbox = box;
	box = NULL;

out:
	if (box != NULL)
		piv_box_free(box);
	sshbuf_free(buf);
	free(data);
	return (rc);
}

static int
sshbuf_put_challenge(struct sshbuf *buf, struct challenge *chal)
{
	struct piv_ecdh_box *box;
	int rc;

	if ((rc = chalbox_make(chal, &box)))
		return (rc);
	rc = sshbuf_put_piv_box(buf, box);
	return (rc);
}

static int
chalbox_get_challenge(struct piv_ecdh_box *box, struct challenge **outchal)
{
	struct challenge *chal;
	struct sshbuf *buf, *kbuf;
	uint8_t *data;
	size_t len;
	uint8_t type;
	struct sshkey *k;
	int rc;

	VERIFY0(piv_box_take_data(box, &data, &len));

	chal = calloc(1, sizeof (struct challenge));
	VERIFY(chal != NULL);

	buf = sshbuf_from(data, len);
	VERIFY(buf != NULL);

	if ((rc = sshbuf_get_u8(buf, &chal->c_version)))
		goto out;
	if (chal->c_version != 1) {
		fprintf(stderr, "error: invalid challenge version: v%d "
		    "(only v1 is supported)\n", (int)chal->c_version);
		rc = ENOTSUP;
		goto out;
	}

	if ((rc = sshbuf_get_u8(buf, &type)))
		goto out;
	chal->c_type = (enum chaltype)type;

	if ((rc = sshbuf_get_u8(buf, &chal->c_id)))
		goto out;

	chal->c_destkey = (k = sshkey_new(KEY_ECDSA));
	k->ecdsa_nid = box->pdb_pub->ecdsa_nid;
	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY(k->ecdsa != NULL);
	if ((rc = sshbuf_get_eckey8(buf, k->ecdsa)) ||
	    (rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa))))
		goto out;

	chal->c_keybox = piv_box_new();
	VERIFY(chal->c_keybox != NULL);

	chal->c_keybox->pdb_cipher = strdup(box->pdb_cipher);
	chal->c_keybox->pdb_kdf = strdup(box->pdb_kdf);
	chal->c_keybox->pdb_free_str = B_TRUE;

	VERIFY0(sshkey_demote(box->pdb_pub, &chal->c_keybox->pdb_pub));

	chal->c_keybox->pdb_ephem_pub = (k = sshkey_new(KEY_ECDSA));
	k->ecdsa_nid = box->pdb_pub->ecdsa_nid;
	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY(k->ecdsa != NULL);
	if ((rc = sshbuf_get_eckey8(buf, k->ecdsa)) ||
	    (rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa))))
		goto out;

	if ((rc = sshbuf_get_string8(buf, &chal->c_keybox->pdb_iv.b_data,
	    &chal->c_keybox->pdb_iv.b_size)))
		goto out;
	chal->c_keybox->pdb_iv.b_len = chal->c_keybox->pdb_iv.b_size;
	if ((rc = sshbuf_get_string8(buf, &chal->c_keybox->pdb_enc.b_data,
	    &chal->c_keybox->pdb_enc.b_size)))
		goto out;
	chal->c_keybox->pdb_enc.b_len = chal->c_keybox->pdb_enc.b_size;

	kbuf = sshbuf_new();
	VERIFY(kbuf != NULL);

	while (sshbuf_len(buf) > 0) {
		uint8_t tag;
		sshbuf_reset(kbuf);
		if ((rc = sshbuf_get_u8(buf, &tag)) ||
		    (rc = sshbuf_get_stringb8(buf, kbuf)))
			goto out;
		len = sshbuf_len(kbuf);
		switch (tag) {
		case CTAG_HOSTNAME:
			chal->c_hostname = sshbuf_dup_string(kbuf);
			VERIFY(chal->c_hostname != NULL);
			break;
		case CTAG_CTIME:
			if ((rc = sshbuf_get_u64(kbuf, &chal->c_ctime)))
				goto out;
			break;
		case CTAG_DESCRIPTION:
			chal->c_description = sshbuf_dup_string(kbuf);
			VERIFY(chal->c_description != NULL);
			break;
		case CTAG_WORDS:
			if ((rc = sshbuf_get_u8(kbuf, &chal->c_words[0])) ||
			    (rc = sshbuf_get_u8(kbuf, &chal->c_words[1])) ||
			    (rc = sshbuf_get_u8(kbuf, &chal->c_words[2])) ||
			    (rc = sshbuf_get_u8(kbuf, &chal->c_words[3])))
				goto out;
			break;
		default:
			/* do nothing */
			break;
		}
	}

	*outchal = chal;
	chal = NULL;

out:
	sshbuf_free(buf);
	free(data);
	if (chal != NULL)
		free_challenge(chal);
	return (rc);
}

static void
intent_prompt(int n, struct partstate *pstates)
{
	struct partstate *pstate;
	char *line;
	uint set = 0;

prompt:
	fprintf(stderr, "Parts:\n");
	set = 0;
	for (pstate = pstates; pstate != NULL; pstate = pstate->ps_next) {
		const char *intent;
		switch (pstate->ps_intent) {
		case INTENT_UNUSED:
			intent = "do not use";
			break;
		case INTENT_DIRECT:
			++set;
			intent = "insert directly";
			break;
		case INTENT_CHALRESP:
			++set;
			intent = "challenge-response";
			break;
		}
		fprintf(stderr, "  [%d] %s (%s): %s\n", pstate->ps_id,
		    pstate->ps_name, pstate->ps_shortid, intent);
	}
	if (set < n) {
		fprintf(stderr, "\nChosen: %d out of %d required\n", set, n);
		fprintf(stderr, "Commands:\n  +1 -- set [1] to insert "
		    "directly\n  =2 -- set [2] to challenge-response\n"
		    "  -3 -- do not use [3]\n  q -- cancel and quit\n");
		line = readline("> ");
	} else {
		fprintf(stderr, "\nReady to execute.\n"
		    "Press return to begin.\n");
		line = readline("");
	}

	if (line == NULL)
		exit(1);
	if (set >= n && strlen(line) == 0) {
		free(line);
		return;
	}
	if (strcmp("q", line) == 0)
		exit(1);
	if (strlen(line) < 2)
		goto prompt;
	int sel = atoi(&line[1]);
	for (pstate = pstates; pstate != NULL; pstate = pstate->ps_next) {
		if (sel == pstate->ps_id)
			break;
	}
	if (pstate == NULL || sel != pstate->ps_id) {
		fprintf(stderr, "Invalid command: '%s'\n", line);
		goto prompt;
	}
	switch (line[0]) {
	case '+':
		pstate->ps_intent = INTENT_DIRECT;
		break;
	case '=':
		pstate->ps_intent = INTENT_CHALRESP;
		break;
	case '-':
		pstate->ps_intent = INTENT_UNUSED;
		break;
	default:
		fprintf(stderr, "Unknown command: '%s'\n", line);
	}

	goto prompt;
}

static void
open_box_with_cak(const char *name, const char *guidhex,
    struct sshkey *cak, struct piv_ecdh_box *box)
{
	struct piv_slot *slot;
	int rc;

	VERIFY0(piv_txn_begin(selk));
	VERIFY0(piv_select(selk));

	VERIFY0(piv_read_cert(selk, PIV_SLOT_CARD_AUTH));
	slot = piv_get_slot(selk, PIV_SLOT_CARD_AUTH);
	VERIFY(slot != NULL);

	if (piv_auth_key(selk, slot, cak) != 0) {
		piv_txn_end(selk);
		fprintf(stderr, "error: found a token with "
		    "GUID match for %s (%s), but CAK auth "
		    "failed!\n", name, guidhex);
		exit(3);
	}
	fprintf(stderr, "Using '%s' (%s)\n", name, guidhex);

	VERIFY0(piv_read_cert(selk, PIV_SLOT_KEY_MGMT));
	slot = piv_get_slot(selk, PIV_SLOT_KEY_MGMT);
	VERIFY(slot != NULL);

again:
	rc = piv_box_open(selk, slot, box);
	if (rc == EPERM) {
		assert_pin(selk);
		goto again;
	} else if (rc != 0) {
		fprintf(stderr, "error: failed to open "
		    "PIV box: %d (%s)\n", rc, strerror(rc));
		piv_txn_end(selk);
		exit(3);
	}

	piv_txn_end(selk);
}

static void
printwrap(const char *data, size_t col)
{
	size_t offset = 0;
	size_t len = strlen(data);
	char *buf = malloc(col + 1);

	while (offset < len) {
		size_t rem = len - offset;
		if (rem > col)
			rem = col;
		bcopy(&data[offset], buf, rem);
		buf[rem] = 0;
		printf("%s\n", buf);
		offset += rem;
	}
}

static void
read_b64_minibox(struct piv_ecdh_box **outbox)
{
	char *linebuf, *p;
	size_t len = 1024, pos = 0;
	struct piv_ecdh_box *box = NULL;
	struct sshbuf *buf;

	linebuf = malloc(len);
	buf = sshbuf_new();
	VERIFY(linebuf != NULL);
	VERIFY(buf != NULL);

	do {
		if (len - pos < 128) {
			len *= 2;
			p = malloc(len);
			VERIFY(p != NULL);
			bcopy(linebuf, p, pos + 1);
			free(linebuf);
			linebuf = p;
		}
		p = fgets(&linebuf[pos], len - pos, stdin);
		if (p == NULL)
			exit(1);
		if (sshbuf_b64tod(buf, linebuf) == 0) {
			struct sshbuf *pbuf = sshbuf_fromb(buf);
			pos = 0;
			linebuf[0] = 0;
			if (sshbuf_get_piv_box(pbuf, &box) == 0)
				sshbuf_free(buf);
			sshbuf_free(pbuf);
		} else {
			pos += strlen(&linebuf[pos]);
		}
	} while (box == NULL);

	*outbox = box;
}

static int
ynprompt(const char *prompt)
{
	char *p = NULL, *pr;
	int rc;

	pr = malloc(strlen(prompt) + 2);
	VERIFY(pr != NULL);
	pr[0] = 0;
	strcat(pr, prompt);
	strcat(pr, " ");
again:
	free(p);
	p = readline(pr);
	if (p == NULL)
		exit(1);
	if (strlen(p) == 0) {
		rc = 0;
		goto out;
	}
	if (strcmp(p, "y") == 0 || strcmp(p, "Y") == 0) {
		rc = 1;
		goto out;
	}
	if (strcmp(p, "n") == 0 || strcmp(p, "N") == 0) {
		rc = -1;
		goto out;
	}
	goto again;
out:
	free(p);
	free(pr);
	return (rc);
}

static void
config_convert_arrays(nvlist_t *json, nvlist_t **out)
{
	nvlist_t *config;
	nvlist_t *oldopt, *opt;
	nvlist_t *part;

	nvlist_t *oldopts, *oldparts;
	uint32_t noldopts, noldparts;

	nvlist_t **opts, **parts;
	size_t nopts, nparts;
	nvpair_t *pair;

	char nbuf[8];
	int32_t i, j;

	VERIFY0(nvlist_lookup_nvlist(json, "o", &oldopts));
	VERIFY0(nvlist_lookup_uint32(oldopts, "length", &noldopts));
	VERIFY3U(noldopts, >=, 1);

	opts = calloc(sizeof (nvlist_t *), noldopts + 1);
	nopts = 0;

	for (i = 0; i < noldopts; ++i) {
		snprintf(nbuf, sizeof (nbuf), "%d", i);
		VERIFY0(nvlist_lookup_nvlist(oldopts, nbuf, &oldopt));

		VERIFY0(nvlist_alloc(&opt, NV_UNIQUE_NAME, 0));

		pair = nvlist_next_nvpair(oldopt, NULL);
		for (; pair != NULL; pair = nvlist_next_nvpair(oldopt, pair)) {
			if (strcmp("p", nvpair_name(pair)) == 0)
				continue;
			VERIFY0(nvlist_add_nvpair(opt, pair));
		}

		VERIFY0(nvlist_lookup_nvlist(oldopt, "p", &oldparts));
		VERIFY0(nvlist_lookup_uint32(oldparts, "length", &noldparts));

		parts = calloc(sizeof (nvlist_t *), noldparts);
		nparts = 0;

		for (j = 0; j < noldparts; ++j) {
			snprintf(nbuf, sizeof (nbuf), "%d", j);
			VERIFY0(nvlist_lookup_nvlist(oldparts, nbuf, &part));
			parts[nparts++] = part;
		}

		VERIFY0(nvlist_add_nvlist_array(opt, "p", parts, nparts));
		free(parts);

		opts[nopts++] = opt;
	}

	VERIFY0(nvlist_alloc(&config, NV_UNIQUE_NAME, 0));

	pair = nvlist_next_nvpair(json, NULL);
	for (; pair != NULL; pair = nvlist_next_nvpair(json, pair)) {
		if (strcmp("o", nvpair_name(pair)) == 0)
			continue;
		VERIFY0(nvlist_add_nvpair(config, pair));
	}

	VERIFY0(nvlist_add_nvlist_array(config, "o", opts, nopts));
	free(opts);

	*out = config;
}

static void
config_replace_primary(nvlist_t *json, nvlist_t *nprim, nvlist_t **out)
{
	nvlist_t *config;
	nvlist_t *oldopt, *opt;
	nvlist_t *part;

	nvlist_t *oldopts, *oldparts;
	uint32_t noldopts, noldparts;

	nvlist_t **opts, **parts;
	size_t nopts, nparts;
	nvpair_t *pair;

	char nbuf[8];
	int32_t i, j, n, m;

	VERIFY0(nvlist_lookup_nvlist(json, "o", &oldopts));
	VERIFY0(nvlist_lookup_uint32(oldopts, "length", &noldopts));
	VERIFY3U(noldopts, >=, 1);

	opts = calloc(sizeof (nvlist_t *), noldopts + 1);
	nopts = 0;

	opts[nopts++] = nprim;

	for (i = 0; i < noldopts; ++i) {
		snprintf(nbuf, sizeof (nbuf), "%d", i);
		VERIFY0(nvlist_lookup_nvlist(oldopts, nbuf, &oldopt));

		VERIFY0(nvlist_lookup_int32(oldopt, "n", &n));
		VERIFY0(nvlist_lookup_int32(oldopt, "m", &m));

		if (n == 1 && m == 1)
			continue;

		VERIFY0(nvlist_alloc(&opt, NV_UNIQUE_NAME, 0));

		pair = nvlist_next_nvpair(oldopt, NULL);
		for (; pair != NULL; pair = nvlist_next_nvpair(oldopt, pair)) {
			if (strcmp("p", nvpair_name(pair)) == 0)
				continue;
			VERIFY0(nvlist_add_nvpair(opt, pair));
		}

		VERIFY0(nvlist_lookup_nvlist(oldopt, "p", &oldparts));
		VERIFY0(nvlist_lookup_uint32(oldparts, "length", &noldparts));

		parts = calloc(sizeof (nvlist_t *), noldparts);
		nparts = 0;

		for (j = 0; j < noldparts; ++j) {
			snprintf(nbuf, sizeof (nbuf), "%d", j);
			VERIFY0(nvlist_lookup_nvlist(oldparts, nbuf, &part));
			parts[nparts++] = part;
		}

		VERIFY0(nvlist_add_nvlist_array(opt, "p", parts, nparts));
		free(parts);

		opts[nopts++] = opt;
	}

	VERIFY0(nvlist_alloc(&config, NV_UNIQUE_NAME, 0));

	pair = nvlist_next_nvpair(json, NULL);
	for (; pair != NULL; pair = nvlist_next_nvpair(json, pair)) {
		if (strcmp("o", nvpair_name(pair)) == 0)
			continue;
		VERIFY0(nvlist_add_nvpair(config, pair));
	}

	VERIFY0(nvlist_add_nvlist_array(config, "o", opts, nopts));
	free(opts);

	*out = config;
}

static void
make_primary_config(struct piv_token *t, const char *name, const uint8_t *key,
    size_t keylen, nvlist_t **out)
{
	struct piv_slot *slot;
	struct sshbuf *buf;
	nvlist_t *config;
	nvlist_t *part;
	char *guidhex, *b64;
	char tmpbuf[1024];
	struct piv_ecdh_box *box;

	VERIFY0(nvlist_alloc(&config, NV_UNIQUE_NAME, 0));
	VERIFY0(nvlist_alloc(&part, NV_UNIQUE_NAME, 0));

	VERIFY0(nvlist_add_int32(config, "n", 1));
	VERIFY0(nvlist_add_int32(config, "m", 1));

	buf = sshbuf_new();
	VERIFY(buf != NULL);
	VERIFY0(sshbuf_put(buf, t->pt_guid, sizeof (t->pt_guid)));
	guidhex = sshbuf_dtob16(buf);
	sshbuf_reset(buf);

	VERIFY0(nvlist_add_string(part, "n", name));
	VERIFY0(nvlist_add_string(part, "g", guidhex));
	free(guidhex);

	VERIFY0(piv_txn_begin(t));
	VERIFY0(piv_select(t));

	VERIFY0(piv_read_cert(t, PIV_SLOT_CARD_AUTH));
	slot = piv_get_slot(t, PIV_SLOT_CARD_AUTH);

	VERIFY0(piv_auth_key(t, slot, slot->ps_pubkey));
	VERIFY0(sshkey_to_base64(slot->ps_pubkey, &b64));
	snprintf(tmpbuf, sizeof (tmpbuf), "%s %s",
	    sshkey_ssh_name(slot->ps_pubkey), b64);
	VERIFY0(nvlist_add_string(part, "p", tmpbuf));
	free(b64);

	VERIFY0(piv_read_cert(t, PIV_SLOT_KEY_MGMT));
	slot = piv_get_slot(t, PIV_SLOT_KEY_MGMT);

	box = piv_box_new();
	VERIFY(box != NULL);
	VERIFY0(piv_box_set_data(box, key, keylen));
	VERIFY0(piv_box_seal(t, slot, box));

	piv_txn_end(t);

	VERIFY0(sshbuf_put_piv_box(buf, box));
	b64 = sshbuf_dtob64(buf);
	VERIFY0(nvlist_add_string(part, "b", b64));
	free(b64);

	sshbuf_free(buf);
	piv_box_free(box);

	VERIFY0(nvlist_add_nvlist_array(config, "p", &part, 1));

	*out = config;
}

struct part {
	struct part *p_next;
	const char *p_name;
	char p_guid[16];
	struct sshkey *p_pubkey;
};

static void
make_backup_config(const struct part *ps, size_t n, const uint8_t *key,
    size_t keylen, nvlist_t **out)
{
	size_t m = 0, i = 0;
	const struct part *p;
	struct sshbuf *buf;
	nvlist_t *config;
	nvlist_t *part;
	nvlist_t **parts;
	char *guidhex = NULL, *b64;
	struct piv_ecdh_box *box;
	sss_Keyshare *share, *shares;

	VERIFY3U(keylen, ==, 32);

	for (p = ps; p != NULL; p = p->p_next)
		++m;
	VERIFY3U(m, >, 1);
	VERIFY3U(n, <=, m);
	VERIFY3U(n, >, 0);

	shares = calloc(sizeof (sss_Keyshare), m);
	VERIFY(shares != NULL);
	sss_create_keyshares(shares, key, m, n);

	parts = calloc(sizeof (nvlist_t *), m);
	VERIFY(parts != NULL);

	VERIFY0(nvlist_alloc(&config, NV_UNIQUE_NAME, 0));

	VERIFY0(nvlist_add_int32(config, "n", n));
	VERIFY0(nvlist_add_int32(config, "m", m));

	for (p = ps; p != NULL; p = p->p_next) {
		VERIFY0(nvlist_alloc(&part, NV_UNIQUE_NAME, 0));
		share = &shares[i];
		parts[i++] = part;

		VERIFY0(nvlist_add_string(part, "n", p->p_name));

		buf = sshbuf_new();
		VERIFY(buf != NULL);
		VERIFY0(sshbuf_put(buf, p->p_guid, sizeof (p->p_guid)));
		guidhex = sshbuf_dtob16(buf);
		sshbuf_reset(buf);

		VERIFY0(nvlist_add_string(part, "g", guidhex));
		free(guidhex);

		box = piv_box_new();
		VERIFY(box != NULL);
		bcopy(p->p_guid, box->pdb_guid, sizeof (box->pdb_guid));
		box->pdb_slot = PIV_SLOT_KEY_MGMT;
		box->pdb_guidslot_valid = B_TRUE;
		VERIFY0(piv_box_set_data(box, (uint8_t *)share,
		    sizeof (sss_Keyshare)));
		explicit_bzero(share, sizeof (sss_Keyshare));
		VERIFY0(piv_box_seal_offline(p->p_pubkey, box));

		VERIFY0(sshbuf_put_piv_box(buf, box));
		b64 = sshbuf_dtob64(buf);
		VERIFY0(nvlist_add_string(part, "b", b64));
		free(b64);

		sshbuf_reset(buf);
		piv_box_free(box);
	}

	free(shares);

	VERIFY0(nvlist_add_nvlist_array(config, "p", parts, i));
	free(parts);

	*out = config;
}

static nvlist_t *
prompt_new_backup(const uint8_t *key, size_t keylen)
{
	char *line = NULL, *p;
	nvlist_t *bk;
	struct sshbuf *buf;
	char *guidhex;
	uint8_t *guid;
	int rc;
	uint i, n, m, glen;
	struct part *part = NULL, *parts = NULL, *lastpart = NULL;

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	n = 0;
	m = 0;

backup:
	fprintf(stderr, "Backup configuration:\n");
	fprintf(stderr, "  %d out of %d from:\n", n, m);
	for (i = 1, part = parts; part != NULL; part = part->p_next, ++i) {
		VERIFY0(sshbuf_put(buf, part->p_guid, 4));
		guidhex = sshbuf_dtob16(buf);
		sshbuf_reset(buf);
		fprintf(stderr, "  * [%d] %s (%s)\n", i, part->p_name, guidhex);
		free(guidhex);
	}
	if (parts == NULL)
		fprintf(stderr, "  * No tokens configured yet\n");

	fprintf(stderr, "\nCommands:\n  +\tadd new key\n  =N\tset N value\n"
	    "  .\tfinish configuration\n");
	free(line);
	line = readline("> ");
	if (line == NULL)
		exit(1);

	if (strcmp("+", line) == 0) {
		part = calloc(1, sizeof (struct part));
		VERIFY(part != NULL);
readguid:
		free(line);
		line = readline("Token GUID (hex): ");
		if (line == NULL)
			exit(1);
		guid = parse_hex(line, &glen);
		if (guid == NULL || glen != sizeof (part->p_guid)) {
			free(guid);
			goto readguid;
		}
		bcopy(guid, part->p_guid, glen);
		free(guid);

		free(line);
		line = readline("Friendly name for this token: ");
		if (line == NULL)
			exit(1);
		part->p_name = line;
		line = NULL;
		VERIFY(part->p_name != NULL);

readpubkey:
		free(line);
		line = readline("Public key: ");
		if (line == NULL)
			exit(1);
		p = line;
		part->p_pubkey = sshkey_new(KEY_ECDSA);
		VERIFY(part->p_pubkey != NULL);
		rc = sshkey_read(part->p_pubkey, &p);
		if (rc != 0) {
			fprintf(stderr, "Bad public key\n");
			sshkey_free(part->p_pubkey);
			goto readpubkey;
		}

		if (lastpart == NULL) {
			lastpart = part;
			parts = part;
		} else {
			lastpart->p_next = part;
			lastpart = part;
		}
		++m;
		goto backup;
	} else if (line[0] == '=') {
		n = atoi(&line[1]);
		if (n < 1 || n > m) {
			n = 0;
			fprintf(stderr, "Invalid N value\n");
		}
		goto backup;
	} else if (strcmp(".", line) == 0) {
		if (n < 1 || n > m) {
			fprintf(stderr, "Invalid N value, please set it\n");
			goto backup;
		}
		/* FALLTHROUGH */
	} else {
		fprintf(stderr, "Invalid command\n");
		goto backup;
	}

	make_backup_config(parts, n, key, keylen, &bk);
	free(line);

	return (bk);
}

static nvlist_t *
prompt_new_primary(const uint8_t *key, size_t keylen)
{
	char *line = NULL;
	nvlist_t *prim;
	struct piv_token *token;
	struct piv_slot *slot;
	struct sshbuf *buf;
	char *guidhex;
	uint i, sel;

	buf = sshbuf_new();
	VERIFY(buf != NULL);

primary:
	fprintf(stderr, "Available PIV tokens:\n");
	piv_release(ks);
	ks = piv_enumerate(ctx);
	for (i = 1, token = ks; token != NULL; token = token->pt_next, ++i) {
		VERIFY0(piv_txn_begin(token));
		VERIFY0(piv_select(token));
		(void) piv_read_all_certs(token);

		VERIFY0(sshbuf_put(buf, token->pt_guid, 4));
		guidhex = sshbuf_dtob16(buf);
		sshbuf_reset(buf);

		fprintf(stderr, " * [%d] %s (%s)\n", i, guidhex,
		    token->pt_rdrname);
		free(guidhex);

		piv_txn_end(token);
	}
	fprintf(stderr, "\n");
	free(line);
	line = readline("Use which token? ");
	if (line == NULL)
		exit(1);
	if (strcmp("q", line) == 0)
		exit(1);
	if (strlen(line) < 1)
		goto primary;
	sel = atoi(line);
	for (i = 1, token = ks; token != NULL; token = token->pt_next, ++i) {
		if (i == sel)
			break;
	}
	if (token == NULL) {
		fprintf(stderr, "Unknown token %d\n", sel);
		goto primary;
	}

	if (token->pt_nochuid) {
		fprintf(stderr, "error: this token has no CHUID file. "
		    "Please generate one with `piv-tool init'.\n");
		exit(1);
	}
	slot = piv_get_slot(token, PIV_SLOT_CARD_AUTH);
	if (slot == NULL || !slot->ps_pubkey) {
		fprintf(stderr, "error: this token does not have a CARD_AUTH "
		    "key generated. Please generate one with "
		    "`piv-tool generate 9a'.\n");
		exit(1);
	}
	slot = piv_get_slot(token, PIV_SLOT_KEY_MGMT);
	if (slot == NULL || !slot->ps_pubkey) {
		fprintf(stderr, "error: this token does not have a KEY_MGMT "
		    "key generated. Please generate one with "
		    "`piv-tool -a eccp256 generate 9d'.\n");
		exit(1);
	}
	if (slot->ps_pubkey->type != KEY_ECDSA) {
		fprintf(stderr, "error: this token does not have an EC key "
		    "in the KEY_MGMT slot\n");
		exit(2);
	}

	free(line);
	line = readline("Enter a friendly name for this token: ");
	if (line == NULL)
		exit(1);

	make_primary_config(token, line, key, keylen, &prim);

	free(line);
	sshbuf_free(buf);

	return (prim);
}

struct zfs_unlock_state {
	const char *zus_fsname;
	nvlist_t *zus_config;
	zfs_handle_t *zus_zfs_handle;
};

static void unlock_recovery(nvlist_t *, const char *, void (*)(const uint8_t *,
    size_t, boolean_t, void *), void *cookie);

static void
unlock_generic(nvlist_t *config, const char *thing,
    void (*usekey)(const uint8_t *, size_t, boolean_t, void *), void *cookie)
{
	nvlist_t *opts, *opt;
	uint32_t nopts;
	int32_t ver, i;
	int rc;
	char nbuf[8];
	int32_t n, m;
	nvlist_t *parts, *part;
	uint32_t nparts;

	struct piv_token *t;
	struct piv_ecdh_box *box;
	struct sshbuf *buf;

	char *guidhex, *name, *cakenc, *boxenc;
	uint8_t *guid;
	uint guidlen;
	struct sshkey *cak;

	VERIFY0(nvlist_lookup_int32(config, "v", &ver));
	if (ver != 1) {
		fprintf(stderr, "error: unsupported config version: "
		    "v%d found (v1 supported)", (int)ver);
		exit(2);
	}

	VERIFY0(nvlist_lookup_nvlist(config, "o", &opts));
	VERIFY0(nvlist_lookup_uint32(opts, "length", &nopts));
	if (nopts < 1) {
		fprintf(stderr, "error: config needs at least one "
		    "valid option\n");
		exit(2);
	}

pass1:
	/* First pass: try all n=m=1 options. */
	for (i = 0; i < nopts; ++i) {
		char *ptr;

		snprintf(nbuf, sizeof (nbuf), "%d", i);
		VERIFY0(nvlist_lookup_nvlist(opts, nbuf, &opt));

		VERIFY0(nvlist_lookup_int32(opt, "n", &n));
		VERIFY0(nvlist_lookup_int32(opt, "m", &m));

		if (n != 1 || m != 1)
			continue;

		VERIFY0(nvlist_lookup_nvlist(opt, "p", &parts));
		VERIFY0(nvlist_lookup_uint32(parts, "length", &nparts));
		VERIFY3U(nparts, ==, 1);

		VERIFY0(nvlist_lookup_nvlist(parts, "0", &part));
		VERIFY0(nvlist_lookup_string(part, "n", &name));
		VERIFY0(nvlist_lookup_string(part, "g", &guidhex));

		guid = parse_hex(guidhex, &guidlen);
		VERIFY(guid != NULL);
		VERIFY3U(guidlen, ==, 16);

		for (t = ks; t != NULL; t = t->pt_next) {
			if (bcmp(t->pt_guid, guid, guidlen) == 0) {
				selk = t;
				break;
			}
		}
		free(guid);
		if (selk == NULL)
			continue;

		VERIFY0(nvlist_lookup_string(part, "p", &cakenc));

		cak = sshkey_new(KEY_UNSPEC);
		VERIFY(cak != NULL);
		ptr = cakenc;
		VERIFY0(sshkey_read(cak, &ptr));

		VERIFY0(nvlist_lookup_string(part, "b", &boxenc));
		buf = sshbuf_new();
		VERIFY(buf != NULL);
		VERIFY0(sshbuf_b64tod(buf, boxenc));
		VERIFY0(piv_box_from_binary(sshbuf_ptr(buf),
		    sshbuf_len(buf), &box));

		open_box_with_cak(name, guidhex, cak, box);

		uint8_t *key;
		size_t keylen;
		VERIFY0(piv_box_take_data(box, &key, &keylen));

		usekey(key, keylen, B_FALSE, cookie);
		return;
	}

	fprintf(stderr, "No PIV tokens on the system matched a primary "
	    "configuration.\n");
	rc = ynprompt("Re-scan and try again? [Y/n]");
	if (rc == 1 || rc == 0) {
		piv_release(ks);
		ks = piv_enumerate(ctx);
		goto pass1;
	}

	unlock_recovery(config, thing, usekey, cookie);
}

static void
unlock_recovery(nvlist_t *config, const char *thing,
    void (*usekey)(const uint8_t *, size_t, boolean_t, void *), void *cookie)
{
	nvlist_t *opts, *opt;
	uint32_t nopts;
	int32_t ver, i, j;
	int rc;
	char nbuf[8];
	int32_t n, m;
	nvlist_t *parts, *part;
	uint32_t nparts;

	struct piv_token *t;
	struct piv_slot *slot;
	struct piv_ecdh_box *box;
	struct sshbuf *buf;

	char *guidhex, *name, *boxenc;
	uint8_t *guid;
	uint guidlen;
	char *line = NULL;
	uint sel;

	struct sshkey *ephem = NULL, *ephempub = NULL;

	struct partstate *pstates = NULL, *lpstate = NULL;
	struct partstate *pstate;

	fprintf(stderr, "\nEntering recovery mode.\n");

	VERIFY0(nvlist_lookup_int32(config, "v", &ver));
	if (ver != 1) {
		fprintf(stderr, "error: unsupported config version: "
		    "v%d found (v1 supported)", (int)ver);
		exit(2);
	}

	VERIFY0(nvlist_lookup_nvlist(config, "o", &opts));
	VERIFY0(nvlist_lookup_uint32(opts, "length", &nopts));
	if (nopts < 2) {
		fprintf(stderr, "error: config needs at least two "
		    "valid options to use recovery mode\n");
		exit(2);
	}

	/*
	 * To prepare for recovery, generate an in-memory EC key. We will
	 * use this as the recipient of challenge-response boxes.
	 */
	VERIFY0(sshkey_generate(KEY_ECDSA, 256, &ephem));
	VERIFY0(sshkey_demote(ephem, &ephempub));

config_again:
	fprintf(stderr, "The following configurations are available:\n");

	for (i = 0; i < nopts; ++i) {
		snprintf(nbuf, sizeof (nbuf), "%d", i);
		VERIFY0(nvlist_lookup_nvlist(opts, nbuf, &opt));

		VERIFY0(nvlist_lookup_int32(opt, "n", &n));
		VERIFY0(nvlist_lookup_int32(opt, "m", &m));

		VERIFY0(nvlist_lookup_nvlist(opt, "p", &parts));
		VERIFY0(nvlist_lookup_uint32(parts, "length", &nparts));

		if (n == 1 && m == 1) {
			fprintf(stderr, "  [%d] ", i + 1);
		} else {
			fprintf(stderr, "  [%d] %d out of %d from: ",
			    i + 1, n, m);
		}

		for (j = 0; j < nparts; ++j) {
			snprintf(nbuf, sizeof (nbuf), "%d", j);
			VERIFY0(nvlist_lookup_nvlist(parts, nbuf, &part));

			VERIFY0(nvlist_lookup_string(part, "n", &name));
			VERIFY0(nvlist_lookup_string(part, "g", &guidhex));
			guidhex = strdup(guidhex);
			guidhex[8] = 0;

			if (j > 0)
				fprintf(stderr, ", ");
			fprintf(stderr, "%s (%s)", name, guidhex);
		}
		fprintf(stderr, "\n");
	}

	fprintf(stderr, "\n");
	free(line);
	line = readline("Use which configuration? (or q to exit) ");
	if (line == NULL)
		exit(1);
	if (strcmp("", line) == 0)
		goto config_again;
	if (strcmp("q", line) == 0)
		exit(1);

	sel = atoi(line) - 1;
	if (sel >= nopts)
		goto config_again;
	snprintf(nbuf, sizeof (nbuf), "%d", sel);
	if (nvlist_lookup_nvlist(opts, nbuf, &opt))
		goto config_again;

	VERIFY0(nvlist_lookup_int32(opt, "n", &n));
	VERIFY0(nvlist_lookup_int32(opt, "m", &m));

	VERIFY0(nvlist_lookup_nvlist(opt, "p", &parts));
	VERIFY0(nvlist_lookup_uint32(parts, "length", &nparts));

	for (j = 0; j < nparts; ++j) {
		snprintf(nbuf, sizeof (nbuf), "%d", j);
		VERIFY0(nvlist_lookup_nvlist(parts, nbuf, &part));

		pstate = calloc(1, sizeof (struct partstate));
		if (lpstate == NULL) {
			pstates = pstate;
			lpstate = pstate;
		} else {
			lpstate->ps_next = pstate;
			lpstate = pstate;
		}
		pstate->ps_id = j + 1;

		VERIFY0(nvlist_lookup_string(part, "n", &name));
		pstate->ps_name = name;
		VERIFY0(nvlist_lookup_string(part, "g", &guidhex));
		guid = parse_hex(guidhex, &guidlen);
		VERIFY(guid != NULL);
		VERIFY3U(guidlen, ==, 16);
		pstate->ps_guid = guid;
		pstate->ps_shortid = strdup(guidhex);
		pstate->ps_shortid[8] = 0;

		VERIFY0(nvlist_lookup_string(part, "b", &boxenc));
		buf = sshbuf_new();
		VERIFY(buf != NULL);
		VERIFY0(sshbuf_b64tod(buf, boxenc));
		VERIFY0(piv_box_from_binary(sshbuf_ptr(buf),
		    sshbuf_len(buf), &box));
		pstate->ps_box = box;

		pstate->ps_intent = INTENT_UNUSED;
	}

	fprintf(stderr, "\nBelow is a list of all the available parts for "
	    "this configuration. You need to\nacquire %d parts to recover the "
	    "key, which can either be using a token\ninserted directly into "
	    "this system, or acquired through a challenge-response\nprocess "
	    "with a remote system.\n\n", n);

	intent_prompt(n, pstates);

	sss_Keyshare *shares;
	uint8_t *share;
	size_t slen;
	shares = calloc(n, sizeof (sss_Keyshare));
	int nshare = 0;

	for (pstate = pstates; pstate != NULL; pstate = pstate->ps_next) {
		char tbuf[128];
		struct sshbuf *cbuf;
		uint8_t id;
		struct challenge *chal;
		struct piv_ecdh_box *respbox = NULL;
redo_ps:
		switch (pstate->ps_intent) {
		case INTENT_CHALRESP:
			fprintf(stderr, "Challenging token '%s' (%s)...\n",
			    pstate->ps_name, pstate->ps_shortid);

			pstate->ps_challenge = (chal = calloc(1,
			    sizeof (struct challenge)));
			chal->c_version = 1;
			chal->c_type = CHAL_RECOVERY;
			chal->c_id = pstate->ps_id;
			chal->c_description = strdup(thing);
			VERIFY0(gethostname(tbuf, sizeof (tbuf)));
			chal->c_hostname = strdup(tbuf);
			chal->c_ctime = time(NULL);
			arc4random_buf(&chal->c_words, sizeof (chal->c_words));
			chal->c_destkey = ephempub;
			chal->c_keybox = pstate->ps_box;

			cbuf = sshbuf_new();
			VERIFY(cbuf != NULL);

			sshbuf_put_challenge(cbuf, chal);

			fprintf(stderr, "CHALLENGE\n--\n");
			printwrap(sshbuf_dtob64(cbuf), 65);
			sshbuf_free(cbuf);

			fprintf(stderr, "\n%-20s   %s %s %s %s\n\n",
			    "VERIFICATION WORDS",
			    wordlist[chal->c_words[0]],
			    wordlist[chal->c_words[1]],
			    wordlist[chal->c_words[2]],
			    wordlist[chal->c_words[3]]);

			fprintf(stderr, "Please transport the verification "
			    "words by a separate\ncommunication channel to "
			    "the challenge and response.\n");

			fprintf(stderr, "\n[enter response followed "
			    "by newline]\n");
			read_b64_minibox(&respbox);

			rc = piv_box_open_offline(ephem, respbox);
			if (rc != 0) {
				fprintf(stderr, "Response invalid.\n");
				rc = ynprompt("Retry? [Y/n]");
				if (rc == 1 || rc == 0)
					goto redo_ps;
				exit(1);
			}

			VERIFY0(piv_box_take_data(respbox, &share, &slen));
			cbuf = sshbuf_from(share, slen);
			VERIFY0(sshbuf_get_u8(cbuf, &id));
			VERIFY0(sshbuf_get_string8(cbuf, &share, &slen));

			if (m > 1) {
				VERIFY3U(slen, ==, sizeof (sss_Keyshare));
				bcopy(share, shares[nshare++], slen);
				free(share);
				share = NULL;
			}
			break;
		case INTENT_DIRECT:
			fprintf(stderr, "Using token '%s' (%s) directly...\n",
			    pstate->ps_name, pstate->ps_shortid);
			piv_release(ks);
			ks = piv_enumerate(ctx);

			if ((rc = piv_box_find_token(ks, pstate->ps_box,
			    &t, &slot))) {
				fprintf(stderr, "Failed to find token %s\n",
				    pstate->ps_shortid);
				rc = ynprompt("Retry? [Y/n]");
				if (rc == 1 || rc == 0)
					goto redo_ps;
				exit(1);
			}

			VERIFY0(piv_txn_begin(t));
			VERIFY0(piv_select(t));
redo_ps_open:
			rc = piv_box_open(t, slot, pstate->ps_box);
			if (rc == EPERM) {
				assert_pin(t);
				goto redo_ps_open;
			} else if (rc != 0) {
				fprintf(stderr, "error: failed to open "
				    "PIV box: %d (%s)\n", rc, strerror(rc));
				piv_txn_end(t);
				exit(3);
			}
			piv_txn_end(t);

			VERIFY0(piv_box_take_data(pstate->ps_box,
			    &share, &slen));
			if (m > 1) {
				VERIFY3U(slen, ==, sizeof (sss_Keyshare));
				bcopy(share, shares[nshare++], slen);
				free(share);
				share = NULL;
			}
			break;
		default:
			break;
		}
	}

	if (n == 1 && m == 1) {
		usekey(share, slen, B_TRUE, cookie);
		return;
	}

	VERIFY3U(nshare, ==, n);

	uint8_t *key = calloc(1, 32);
	sss_combine_keyshares(key, (const sss_Keyshare *)shares, n);
	usekey(key, 32, B_TRUE, cookie);
}

static void
do_zfs_rekey(const uint8_t *key, size_t keylen, boolean_t recov, void *cookie)
{
	int rc;
	struct zfs_unlock_state *state;
	nvlist_t *config;
	nvlist_t **opts, *opt;
	nvlist_t **parts, *part;
	nvlist_t **nvarr;
	uint nopts, nparts;
#if !defined(__sun)
	FILE *file;
#endif
	char *json;
	size_t jsonlen;
	char *line;
	char *guidhex, *name;
	int32_t n, m;
	uint sel, i, j;
	boolean_t changed = B_FALSE;

	state = (struct zfs_unlock_state *)cookie;

	config_convert_arrays(state->zus_config, &config);

config_again:
	fprintf(stderr, "The following configurations are available:\n");

	VERIFY0(nvlist_lookup_nvlist_array(config, "o", &opts, &nopts));
	for (i = 1; i <= nopts; ++i) {
		opt = opts[i - 1];

		VERIFY0(nvlist_lookup_int32(opt, "n", &n));
		VERIFY0(nvlist_lookup_int32(opt, "m", &m));

		VERIFY0(nvlist_lookup_nvlist_array(opt, "p", &parts, &nparts));

		if (n == 1 && m == 1) {
			fprintf(stderr, "  [%d] ", i);
		} else {
			fprintf(stderr, "  [%d] %d out of %d from: ", i, n, m);
		}

		for (j = 0; j < nparts; ++j) {
			part = parts[j];

			VERIFY0(nvlist_lookup_string(part, "n", &name));
			VERIFY0(nvlist_lookup_string(part, "g", &guidhex));
			guidhex = strdup(guidhex);
			guidhex[8] = 0;

			if (j > 0)
				fprintf(stderr, ", ");
			fprintf(stderr, "%s (%s)", name, guidhex);
		}
		fprintf(stderr, "\n");
	}
	fprintf(stderr, "  [%d] + new backup configuration\n", i);

	fprintf(stderr, "\n");
	line = readline("Replace which configuration? (or q to finish) ");
	if (line == NULL)
		exit(1);
	if (strcmp("", line) == 0) {
		free(line);
		goto config_again;
	}
	if (strcmp("q", line) == 0) {
		free(line);
		goto save;
	}
	sel = atoi(line) - 1;
	free(line);
	if (sel > nopts)
		goto config_again;

	if (sel < nopts) {
		opt = opts[sel];
		VERIFY0(nvlist_lookup_int32(opt, "n", &n));
		VERIFY0(nvlist_lookup_int32(opt, "m", &m));
		nvarr = malloc(sizeof (nvlist_t *) * nopts);
		bcopy(opts, nvarr, sizeof (nvlist_t *) * nopts);
	} else {
		n = 0;
		nvarr = malloc(sizeof (nvlist_t *) * (nopts + 1));
		bcopy(opts, nvarr, sizeof (nvlist_t *) * nopts);
		++nopts;
	}

	if (n == 1 && m == 1) {
		fprintf(stderr, "Please select a new primary PIV token to use "
		    "for unlocking this filesystem\nin the future.\n\n");
		nvarr[sel] = prompt_new_primary(key, keylen);
	} else {
		fprintf(stderr, "Please add tokens to construct a new backup "
		    "configuration. At least 2 tokens\nmust be used, in an "
		    "N-out-of-M scheme for recovery.\n\nEach token's full GUID "
		    "and Key Management public key is required (these can\nbe "
		    "obtained from the output of `piv-tool list' and `piv-tool "
		    "pubkey 9d').\n\n");
		nvarr[sel] = prompt_new_backup(key, keylen);
	}
	VERIFY0(nvlist_add_nvlist_array(config, "o", nvarr, nopts));
	changed = B_TRUE;
	goto config_again;

save:
	if (!changed)
		exit(0);

#if defined(__sun)
	VERIFY0(nvlist_dump_json(config, &json));
	jsonlen = strlen(json);
#else
	jsonlen = 4096;
	json = malloc(jsonlen);
	VERIFY(json != NULL);
	json[0] = 0;

	file = fmemopen(json, jsonlen, "w");
	VERIFY0(nvlist_print_json(file, config));
	fclose(file);
#endif

	rc = zfs_prop_set(state->zus_zfs_handle, "rfd77:config", json);
	if (rc != 0) {
		fprintf(stderr, "error: failed to set ZFS property "
		    "for new configuration: %d (%s)\n",
		    rc, strerror(rc));
		exit(4);
	}

	free(json);
	nvlist_free(config);
}

static void
do_zfs_unlock(const uint8_t *key, size_t keylen, boolean_t recov, void *cookie)
{
	int rc;
	struct zfs_unlock_state *state;
	state = (struct zfs_unlock_state *)cookie;

#if !defined(ZFS_KEYSTATUS_AVAILABLE)
	fprintf(stderr, "error: this ZFS implementation does not support "
	    "ZFS encryption\n");
	exit(4);
#else
	rc = lzc_load_key(state->zus_fsname, B_FALSE, (uint8_t *)key, keylen);
	if (rc != 0) {
		fprintf(stderr, "error: failed to load key "
		    "material into ZFS: %d (%s)\n",
		    rc, strerror(rc));
		exit(4);
	}
#endif

	if (recov) {
		nvlist_t *config, *nprim;
#if !defined(__sun)
		FILE *file;
#endif
		char *json;
		size_t jsonlen;

		fprintf(stderr, "Please select a new primary PIV token to use "
		    "for unlocking this filesystem\nin the future.\n\n");
		nprim = prompt_new_primary(key, keylen);
		config_replace_primary(state->zus_config, nprim, &config);

#if defined(__sun)
		VERIFY0(nvlist_dump_json(config, &json));
		jsonlen = strlen(json);
#else
		jsonlen = 4096;
		json = malloc(jsonlen);
		VERIFY(json != NULL);
		json[0] = 0;

		file = fmemopen(json, jsonlen, "w");
		VERIFY0(nvlist_print_json(file, config));
		fclose(file);
#endif

		rc = zfs_prop_set(state->zus_zfs_handle, "rfd77:config", json);
		if (rc != 0) {
			fprintf(stderr, "error: failed to set ZFS property "
			    "for new configuration: %d (%s)\n",
			    rc, strerror(rc));
			exit(4);
		}

		free(json);
		nvlist_free(nprim);
		nvlist_free(config);
	}

	zfs_close(state->zus_zfs_handle);

	exit(0);
}

static void
cmd_genopt(const char *cmd, const char *subcmd, const char *opt,
    const char *argv[], int argc)
{
	nvlist_t *config;
	nvlist_t **options;
	char *json;
	uint8_t *key;
	size_t keylen, jsonlen;
	uint i;
	int rc;
	const char **newargv;
	size_t newargc, maxargc;
#if defined(__sun)
	char *jsonp;
#else
	FILE *file;
#endif
	pid_t kid, rkid;
	int inpipe[2];
	ssize_t done;

	key = calloc(1, 32);
	keylen = 32;
	arc4random_buf(key, keylen);

	maxargc = argc + 10;
	newargv = calloc(maxargc, sizeof (char *));
	newargc = 0;

	newargv[newargc++] = cmd;
	newargv[newargc++] = subcmd;

	newargv[newargc++] = opt;
	newargv[newargc++] = "encryption=on";
	newargv[newargc++] = opt;
	newargv[newargc++] = "keyformat=raw";

	VERIFY0(nvlist_alloc(&config, NV_UNIQUE_NAME, 0));
	VERIFY0(nvlist_add_int32(config, "v", 1));

	options = calloc(2, sizeof (nvlist_t *));

	fprintf(stderr, "Beginning interactive setup\n\n");

	fprintf(stderr, "Please select a primary PIV token to use for "
	    "unlocking in the normal\n");
	fprintf(stderr, "(non-recovery) case.\n\n");

	options[0] = prompt_new_primary(key, keylen);

	fprintf(stderr, "\nIf the primary token has been destroyed or is no "
	    "longer available, then a\nbackup configuration will be needed.\n"
	    "\nA backup configuration is composed of an N-out-of-M scheme, "
	    "where there are\nM registered tokens and N of them are required "
	    "to perform the recovery.\n\nThe backup tokens do not need to be "
	    "physically present on this machine,\neither during this setup "
	    "process or during recovery. Only the Key Management\npublic keys "
	    "from each token and that token's GUID are required now (these\n"
	    "can be obtained from the output of `piv-tool list' and "
	    "`piv-tool pubkey 9d')\n\n");

	options[1] = prompt_new_backup(key, keylen);

	VERIFY0(nvlist_add_nvlist_array(config, "o", options, 2));

#if defined(__sun)
	VERIFY0(nvlist_dump_json(config, &jsonp));
	jsonlen = strlen(jsonp);
	json = malloc(jsonlen + 32);
	json[0] = 0;
	strcat(json, "rfd77:config=");
	strcat(json, jsonp);
	jsonlen = strlen(json);
#else
	jsonlen = 4096;
	json = malloc(jsonlen);
	VERIFY(json != NULL);
	json[0] = 0;

	file = fmemopen(json, jsonlen, "w");
	fprintf(file, "rfd77:config=");
	VERIFY0(nvlist_print_json(file, config));
	fclose(file);
#endif

	newargv[newargc++] = opt;
	newargv[newargc++] = json;

	for (i = 0; i < argc; ++i)
		newargv[newargc++] = argv[i];

	newargv[newargc++] = 0;

	fprintf(stderr, "Executing \"%s %s\"...\n", cmd, subcmd);

	VERIFY0(pipe(inpipe));

	kid = fork();
	if (kid == -1) {
		perror("fork");
		exit(1);
	} else if (kid == 0) {
		VERIFY0(close(inpipe[1]));
		VERIFY0(dup2(inpipe[0], STDIN_FILENO));
		VERIFY0(close(inpipe[0]));
		VERIFY0(execvp(cmd, (char * const *)newargv));
	} else {
		VERIFY0(close(inpipe[0]));
		done = write(inpipe[1], key, keylen);
		VERIFY3S(done, ==, keylen);
		VERIFY0(close(inpipe[1]));

		rkid = waitpid(kid, &rc, 0);
		VERIFY3S(rkid, ==, kid);
		if (!WIFEXITED(rc)) {
			fprintf(stderr, "error: child did not exit\n");
			exit(1);
		}
		exit(WEXITSTATUS(rc));
	}
}

static void
cmd_rekey(const char *fsname)
{
	zfs_handle_t *ds;
	nvlist_t *props, *prop, *config;
	char *json;
	char *thing;
	size_t tlen;
	struct zfs_unlock_state state;

	tlen = strlen(fsname) + 128;
	thing = calloc(1, tlen);
	snprintf(thing, tlen, "Unlock ZFS filesystem %s", fsname);

	ds = zfs_open(zfshdl, fsname, ZFS_TYPE_DATASET);
	if (ds == NULL) {
		fprintf(stderr, "error: failed to open dataset %s\n",
		    fsname);
		exit(1);
	}

	props = zfs_get_user_props(ds);
	VERIFY(props != NULL);

	if (nvlist_lookup_nvlist(props, "rfd77:config", &prop)) {
		fprintf(stderr, "error: no rfd77:config property "
		    "could be read on dataset %s\n", fsname);
		exit(1);
	}

	VERIFY0(nvlist_lookup_string(prop, "value", &json));

	if (nvlist_parse_json(json, strlen(json), &config,
	    NVJSON_FORCE_INTEGER | NVJSON_ERRORS_TO_STDERR, NULL)) {
		fprintf(stderr, "error: failed to parse rfd77:config "
		    "property on dataset %s\n", fsname);
		exit(2);
	}

	VERIFY(config != NULL);

	bzero(&state, sizeof (state));
	state.zus_fsname = fsname;
	state.zus_config = config;
	state.zus_zfs_handle = ds;

	fprintf(stderr, "Attempting to unlock ZFS '%s'...\n", fsname);
	unlock_generic(config, thing, do_zfs_rekey, (void *)&state);

	zfs_close(ds);
}

static void
cmd_unlock(const char *fsname)
{
	zfs_handle_t *ds;
	nvlist_t *props, *prop, *config;
#if defined(ZFS_KEYSTATUS_AVAILABLE)
	uint64_t kstatus;
#endif
	char *json;
	char *thing;
	size_t tlen;
	struct zfs_unlock_state state;

	tlen = strlen(fsname) + 128;
	thing = calloc(1, tlen);
	snprintf(thing, tlen, "Unlock ZFS filesystem %s", fsname);

	ds = zfs_open(zfshdl, fsname, ZFS_TYPE_DATASET);
	if (ds == NULL) {
		fprintf(stderr, "error: failed to open dataset %s\n",
		    fsname);
		exit(1);
	}

#if defined(ZFS_KEYSTATUS_AVAILABLE)
	props = zfs_get_all_props(ds);
	VERIFY(props != NULL);

	if (nvlist_lookup_nvlist(props, "keystatus", &prop)) {
		fprintf(stderr, "error: no keystatus property "
		    "could be read on dataset %s\n", fsname);
		exit(1);
	}
	VERIFY0(nvlist_lookup_uint64(prop, "value", &kstatus));

	if (kstatus == ZFS_KEYSTATUS_AVAILABLE) {
		fprintf(stderr, "error: key already loaded for %s\n",
		    fsname);
		exit(1);
	}
#else
	props = zfs_get_user_props(ds);
	VERIFY(props != NULL);
#endif

	if (nvlist_lookup_nvlist(props, "rfd77:config", &prop)) {
		fprintf(stderr, "error: no rfd77:config property "
		    "could be read on dataset %s\n", fsname);
		exit(1);
	}

	VERIFY0(nvlist_lookup_string(prop, "value", &json));

	if (nvlist_parse_json(json, strlen(json), &config,
	    NVJSON_FORCE_INTEGER | NVJSON_ERRORS_TO_STDERR, NULL)) {
		fprintf(stderr, "error: failed to parse rfd77:config "
		    "property on dataset %s\n", fsname);
		exit(2);
	}

	VERIFY(config != NULL);

	bzero(&state, sizeof (state));
	state.zus_fsname = fsname;
	state.zus_config = config;
	state.zus_zfs_handle = ds;

	fprintf(stderr, "Attempting to unlock ZFS '%s'...\n", fsname);
	unlock_generic(config, thing, do_zfs_unlock, (void *)&state);

	zfs_close(ds);
}

static void
cmd_respond(void)
{
	struct piv_ecdh_box *chalbox;
	struct challenge *chal;
	struct piv_token *t;
	struct piv_slot *slot;
	char *line;
	int rc;

	fprintf(stderr, "[enter challenge followed by newline]\n");
	read_b64_minibox(&chalbox);

	if ((rc = piv_box_find_token(ks, chalbox, &t, &slot))) {
		fprintf(stderr, "error: failed to find token to match "
		    "challenge\n");
		exit(1);
	}

	fprintf(stderr, "Decrypting challenge...\n");
	VERIFY0(piv_txn_begin(t));
	VERIFY0(piv_select(t));
again:
	rc = piv_box_open(t, slot, chalbox);
	if (rc == EPERM) {
		assert_pin(t);
		goto again;
	} else if (rc != 0) {
		fprintf(stderr, "error: failed to open "
		    "PIV box: %d (%s)\n", rc, strerror(rc));
		piv_txn_end(t);
		exit(3);
	}
	piv_txn_end(t);

	if (chalbox_get_challenge(chalbox, &chal)) {
		fprintf(stderr, "error: failed to parse infobox\n");
		exit(3);
	}
	piv_box_free(chalbox);

	fprintf(stderr, "\nCHALLENGE\n---\n");
	const char *purpose;
	switch (chal->c_type) {
	case CHAL_RECOVERY:
		purpose = "recovery of at-rest encryption keys";
		break;
	case CHAL_VERIFY_AUDIT:
		purpose = "verification of hash-chain audit trail";
		break;
	default:
		exit(1);
	}
	fprintf(stderr, "%-20s   %s\n", "Purpose", purpose);
	fprintf(stderr, "%-20s   %s\n", "Description", chal->c_description);
	fprintf(stderr, "%-20s   %s\n", "Hostname", chal->c_hostname);

	struct tm tmctime;
	time_t ctime;
	char tbuf[128];

	bzero(&tmctime, sizeof (tmctime));
	ctime = (time_t)chal->c_ctime;
	localtime_r(&ctime, &tmctime);
	strftime(tbuf, sizeof (tbuf), "%Y-%m-%d %H:%M:%S", &tmctime);
	fprintf(stderr, "%-20s   %s (local time)\n", "Generated at", tbuf);

	fprintf(stderr, "\n%-20s   %s %s %s %s\n\n", "VERIFICATION WORDS",
	    wordlist[chal->c_words[0]], wordlist[chal->c_words[1]],
	    wordlist[chal->c_words[2]], wordlist[chal->c_words[3]]);
	fprintf(stderr, "Please check that these verification words match the "
	    "original source via a\nseparate communications channel to the "
	    "one used to transport the challenge\nitself.\n\n");

	line = readline("If these details are correct and you wish to "
	    "respond, type 'YES': ");
	if (line == NULL)
		exit(1);
	if (strcmp(line, "YES") != 0)
		exit(1);
	free(line);

	fprintf(stderr, "Decrypting payload...\n");
	VERIFY0(piv_txn_begin(t));
	VERIFY0(piv_select(t));
again2:
	rc = piv_box_open(t, slot, chal->c_keybox);
	if (rc == EPERM) {
		assert_pin(t);
		goto again2;
	} else if (rc != 0) {
		fprintf(stderr, "error: failed to open "
		    "PIV box: %d (%s)\n", rc, strerror(rc));
		piv_txn_end(t);
		exit(3);
	}
	piv_txn_end(t);

	struct piv_ecdh_box *respbox;
	struct sshbuf *resp;
	uint8_t *kdata;
	size_t klen;

	VERIFY0(piv_box_take_data(chal->c_keybox, &kdata, &klen));

	resp = sshbuf_new();
	VERIFY(resp != NULL);
	VERIFY0(sshbuf_put_u8(resp, chal->c_id));
	VERIFY0(sshbuf_put_string8(resp, kdata, klen));
	free(kdata);
	kdata = NULL;

	respbox = piv_box_new();
	VERIFY(respbox != NULL);

	VERIFY0(piv_box_set_data(respbox, sshbuf_ptr(resp), sshbuf_len(resp)));
	VERIFY0(piv_box_seal_offline(chal->c_destkey, respbox));

	sshbuf_reset(resp);
	VERIFY0(sshbuf_put_piv_box(resp, respbox));

	fprintf(stderr, "\nRESPONSE\n---\n");
	printwrap(sshbuf_dtob64(resp), 65);
	sshbuf_free(resp);
	piv_box_free(respbox);

	free_challenge(chal);

	exit(0);
}

void
usage(void)
{
	fprintf(stderr,
	    "usage: piv-zfs [options] operation\n"
	    "Available operations:\n"
	    "  unlock <zfs>            Unlock an encrypted ZFS filesystem\n"
	    "  zfs-create -- <args>    Run 'zfs create' with arguments and\n"
	    "                          input transformed to provide keys for\n"
	    "                          encryption.\n"
	    "  zpool-create -- <args>  Like zfs-create but used to create a\n"
	    "                          new pool\n"
	    "  respond                 Respond to a recovery challenge using a\n"
	    "                          locally inserted PIV token/card\n"
	    "  rekey <zfs>             Change key configuration for an already\n"
	    "                          created ZFS filesystem\n");
	exit(3);
}

int
main(int argc, char *argv[])
{
	LONG rv;
	extern char *optarg;
	extern int optind;
	int c;

	bunyan_init();
	bunyan_set_name("piv-zfs");

#if defined(__sun)
	sungl = new_GetLine(4096, 4096);
	VERIFY(sungl != NULL);
#endif

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'd':
			bunyan_set_level(TRACE);
			break;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "error: operation required\n");
		usage();
	}

	const char *op = argv[optind++];

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardEstablishContext failed: %s\n",
		    pcsc_stringify_error(rv));
		return (1);
	}

	ks = piv_enumerate(ctx);

	zfshdl = libzfs_init();

	if (strcmp(op, "unlock") == 0) {
		const char *fsname;

		if (optind >= argc) {
			fprintf(stderr, "error: target zfs required\n");
			usage();
		}
		fsname = argv[optind++];

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		cmd_unlock(fsname);

	} else if (strcmp(op, "rekey") == 0) {
		const char *fsname;

		if (optind >= argc) {
			fprintf(stderr, "error: target zfs required\n");
			usage();
		}
		fsname = argv[optind++];

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		cmd_rekey(fsname);

	} else if (strcmp(op, "respond") == 0) {

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		cmd_respond();

	} else if (strcmp(op, "zfs-create") == 0) {
		if (optind >= argc) {
			fprintf(stderr, "error: zfs create args required\n");
			usage();
		}
		cmd_genopt("zfs", "create", "-o",
		    (const char **)&argv[optind], argc - optind);

	} else if (strcmp(op, "zpool-create") == 0) {
		if (optind >= argc) {
			fprintf(stderr, "error: zpool create args required\n");
			usage();
		}
		cmd_genopt("zpool", "create", "-O",
		    (const char **)&argv[optind], argc - optind);

	} else {
		fprintf(stderr, "error: invalid operation '%s'\n", op);
		usage();
	}

	libzfs_fini(zfshdl);

	return (0);
}
