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
			exit(1);
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
		exit(1);
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

	rv = piv_verify_pin(pk, pin, &retries);
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
sshbuf_put_minibox(struct sshbuf *buf, struct piv_ecdh_box *box)
{
	int rc;
	const char *tname;

	if ((rc = sshbuf_put_u8(buf, 0xF0)))
		return (rc);
	rc = sshbuf_put_string8(buf, box->pdb_guid, sizeof (box->pdb_guid));
	if (rc)
		return (rc);
	if ((rc = sshbuf_put_u8(buf, box->pdb_slot)) ||
	    (rc = sshbuf_put_cstring8(buf, box->pdb_cipher)) ||
	    (rc = sshbuf_put_cstring8(buf, box->pdb_kdf)))
		return (rc);

	if (box->pdb_pub->ecdsa_nid != box->pdb_ephem_pub->ecdsa_nid)
		return (EINVAL);

	tname = sshkey_curve_nid_to_name(box->pdb_pub->ecdsa_nid);
	VERIFY(tname != NULL);
	if ((rc = sshbuf_put_cstring8(buf, tname)) ||
	    (rc = sshbuf_put_eckey(buf, box->pdb_pub->ecdsa)) ||
	    (rc = sshbuf_put_eckey(buf, box->pdb_ephem_pub->ecdsa)))
		return (rc);

	if ((rc = sshbuf_put_string8(buf, box->pdb_iv.b_data,
	    box->pdb_iv.b_len)))
		return (rc);

	if ((rc = sshbuf_put_string(buf, box->pdb_enc.b_data,
	    box->pdb_enc.b_len)))
		return (rc);

	return (0);
}

static int
sshbuf_get_minibox(struct sshbuf *buf, struct piv_ecdh_box **outbox)
{
	struct piv_ecdh_box *box = NULL;
	uint8_t ver;
	int rc;
	uint8_t *tmpbuf = NULL;
	struct sshkey *k = NULL;
	size_t len;
	uint8_t temp;
	char *tname = NULL;

	box = piv_box_new();
	VERIFY(box != NULL);

	if ((rc = sshbuf_get_u8(buf, &ver)))
		goto out;
	if (ver != 0xF0) {
		fprintf(stderr, "error: invalid minibox version: v%d "
		    "(only v1 is supported)\n", (int)ver);
		rc = ENOTSUP;
		goto out;
	}

	if ((rc = sshbuf_get_string8(buf, &tmpbuf, &len)))
		goto out;
	if (len != sizeof (box->pdb_guid)) {
		rc = EINVAL;
		goto out;
	}
	bcopy(tmpbuf, box->pdb_guid, len);
	free(tmpbuf);
	tmpbuf = NULL;
	if ((rc = sshbuf_get_u8(buf, &temp)))
		goto out;
	box->pdb_slot = temp;

	box->pdb_free_str = B_TRUE;
	if ((rc = sshbuf_get_cstring8(buf, (char **)&box->pdb_cipher, NULL)) ||
	    (rc = sshbuf_get_cstring8(buf, (char **)&box->pdb_kdf, NULL)))
		goto out;

	if ((rc = sshbuf_get_cstring8(buf, &tname, NULL)))
		goto out;
	k = sshkey_new(KEY_ECDSA);
	k->ecdsa_nid = sshkey_curve_name_to_nid(tname);
	VERIFY(k->ecdsa_nid != -1);

	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY(k->ecdsa != NULL);

	if ((rc = sshbuf_get_eckey(buf, k->ecdsa)) ||
	    (rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa))))
		goto out;
	box->pdb_pub = k;
	k = NULL;

	k = sshkey_new(KEY_ECDSA);
	k->ecdsa_nid = box->pdb_pub->ecdsa_nid;

	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY(k->ecdsa != NULL);

	if ((rc = sshbuf_get_eckey(buf, k->ecdsa)) ||
	    (rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa))))
		goto out;
	box->pdb_ephem_pub = k;
	k = NULL;

	if ((rc = sshbuf_get_string8(buf, &box->pdb_iv.b_data,
	    &box->pdb_iv.b_size)))
		goto out;
	box->pdb_iv.b_len = box->pdb_iv.b_size;
	if ((rc = sshbuf_get_string(buf, &box->pdb_enc.b_data,
	    &box->pdb_enc.b_size)))
		goto out;
	box->pdb_enc.b_len = box->pdb_enc.b_size;

	*outbox = box;
	box = NULL;

out:
	if (box != NULL)
		piv_box_free(box);
	if (k != NULL)
		sshkey_free(k);
	free(tname);
	free(tmpbuf);
	return (rc);
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
	    (rc = sshbuf_put_u8(buf, chal->c_id)) ||
	    (rc = sshbuf_put_cstring8(buf, chal->c_hostname)) ||
	    (rc = sshbuf_put_u64(buf, chal->c_ctime)) ||
	    (rc = sshbuf_put_cstring8(buf, chal->c_description)) ||
	    (rc = sshbuf_put_u8(buf, chal->c_words[0])) ||
	    (rc = sshbuf_put_u8(buf, chal->c_words[1])) ||
	    (rc = sshbuf_put_u8(buf, chal->c_words[2])) ||
	    (rc = sshbuf_put_u8(buf, chal->c_words[3])))
		goto out;
	if ((rc = sshbuf_put_eckey(buf, chal->c_destkey->ecdsa)))
		goto out;

	if ((rc = sshbuf_put_eckey(buf, kb->pdb_ephem_pub->ecdsa)) ||
	    (rc = sshbuf_put_string8(buf, iv->b_data, iv->b_len)) ||
	    (rc = sshbuf_put_string8(buf, enc->b_data, enc->b_len)))
		goto out;

	box->pdb_cipher = strdup(kb->pdb_cipher);
	box->pdb_kdf = strdup(kb->pdb_kdf);
	bcopy(kb->pdb_guid, box->pdb_guid, sizeof (box->pdb_guid));
	box->pdb_slot = kb->pdb_slot;
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
	rc = sshbuf_put_minibox(buf, box);
	return (rc);
}

static int
chalbox_get_challenge(struct piv_ecdh_box *box, struct challenge **outchal)
{
	struct challenge *chal;
	struct sshbuf *buf;
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

	if ((rc = sshbuf_get_u8(buf, &chal->c_id)) ||
	    (rc = sshbuf_get_cstring8(buf, &chal->c_hostname, NULL)) ||
	    (rc = sshbuf_get_u64(buf, &chal->c_ctime)) ||
	    (rc = sshbuf_get_cstring8(buf, &chal->c_description, NULL)) ||
	    (rc = sshbuf_get_u8(buf, &chal->c_words[0])) ||
	    (rc = sshbuf_get_u8(buf, &chal->c_words[1])) ||
	    (rc = sshbuf_get_u8(buf, &chal->c_words[2])) ||
	    (rc = sshbuf_get_u8(buf, &chal->c_words[3])))
		goto out;

	chal->c_destkey = (k = sshkey_new(KEY_ECDSA));
	k->ecdsa_nid = box->pdb_pub->ecdsa_nid;
	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY(k->ecdsa != NULL);
	if ((rc = sshbuf_get_eckey(buf, k->ecdsa)) ||
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
	if ((rc = sshbuf_get_eckey(buf, k->ecdsa)) ||
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
	char *p;
	char *linebuf;
	size_t len = 1024, pos = 0;
	uint8_t set = 0;

	linebuf = malloc(len);

prompt:
	fprintf(stderr, "Parts:\n");
	for (pstate = pstates; pstate != NULL; pstate = pstate->ps_next) {
		const char *intent;
		set = 0;
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
		fprintf(stderr, "Commands:\n  +0 -- set [0] to insert "
		    "directly\n  =1 -- set [1] to challenge-response\n"
		    "  -2 -- do not use [2]\n  q -- cancel and quit\n");
		fprintf(stderr, "> ");
	} else {
		fprintf(stderr, "\nReady to execute.\n"
		    "Press return to begin.\n");
	}

	p = fgets(&linebuf[pos], len - pos, stdin);
	if (p == NULL || strlen(linebuf) == 0)
		exit(1);
	if (set >= n && linebuf[0] == '\n' && linebuf[1] == 0) {
		free(linebuf);
		return;
	}
	linebuf[strlen(linebuf) - 1] = 0;
	if (strcmp("q", linebuf) == 0)
		exit(1);
	if (strlen(linebuf) < 2)
		goto prompt;
	int sel = atoi(&linebuf[1]);
	for (pstate = pstates; pstate != NULL; pstate = pstate->ps_next) {
		if (sel == pstate->ps_id)
			break;
	}
	if (pstate == NULL || sel != pstate->ps_id) {
		fprintf(stderr, "Invalid command: '%s'\n", linebuf);
		goto prompt;
	}
	switch (linebuf[0]) {
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
		fprintf(stderr, "Unknown command: '%s'\n", linebuf);
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
			if (sshbuf_get_minibox(pbuf, &box) == 0)
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
	char buf[16];
	char *p;
again:
	fprintf(stderr, "%s ", prompt);
	p = fgets(buf, sizeof (buf), stdin);
	if (p == NULL || strlen(buf) == 0)
		exit(1);
	if (strcmp(buf, "\n") == 0)
		return (0);
	if (strcmp(buf, "y\n") == 0 ||
	    strcmp(buf, "Y\n") == 0)
		return (1);
	if (strcmp(buf, "n\n") == 0 ||
	    strcmp(buf, "N\n") == 0)
		return (-1);
	goto again;
}

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

	char *linebuf, *p;
	size_t len = 1024, pos = 0;

	struct sshkey *ephem = NULL, *ephempub = NULL;

	struct partstate *pstates = NULL;
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

	linebuf = malloc(len);

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
			fprintf(stderr, "  [%d] ", i);
		} else {
			fprintf(stderr, "  [%d] %d out of %d from: ", i, n, m);
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

	fprintf(stderr, "\nUse which configuration? (or q to exit) ");
	p = fgets(&linebuf[pos], len - pos, stdin);
	if (p == NULL || linebuf[strlen(linebuf) - 1] != '\n')
		exit(1);
	if (strcmp("\n", p) == 0)
		goto config_again;
	if (strcmp("q\n", p) == 0)
		exit(1);
	linebuf[strlen(linebuf) - 1] = 0;

	if (nvlist_lookup_nvlist(opts, linebuf, &opt))
		goto config_again;

	VERIFY0(nvlist_lookup_int32(opt, "n", &n));
	VERIFY0(nvlist_lookup_int32(opt, "m", &m));

	VERIFY0(nvlist_lookup_nvlist(opt, "p", &parts));
	VERIFY0(nvlist_lookup_uint32(parts, "length", &nparts));

	for (j = 0; j < nparts; ++j) {
		snprintf(nbuf, sizeof (nbuf), "%d", j);
		VERIFY0(nvlist_lookup_nvlist(parts, nbuf, &part));

		pstate = calloc(1, sizeof (struct partstate));
		pstate->ps_next = pstates;
		pstates = pstate;
		pstate->ps_id = j;

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
	sss_combine_keyshares(key, shares, n);
	usekey(key, 32, B_TRUE, cookie);
}

static void
do_zfs_unlock(const uint8_t *key, size_t keylen, boolean_t recov, void *cookie)
{
	int rc;
	const char *fsname = (const char *)cookie;

	rc = lzc_load_key(fsname, B_FALSE, (uint8_t *)key, keylen);
	if (rc != 0) {
		fprintf(stderr, "error: failed to load key "
		    "material into ZFS: %d (%s)\n",
		    rc, strerror(rc));
		exit(4);
	}

	if (recov) {

	}

	exit(0);
}

#if 0
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

	char nbuf[8];
	int32_t i, j, n, m;

	VERIFY0(nvlist_lookup_nvlist(config, "o", &oldopts));
	VERIFY0(nvlist_lookup_uint32(oldopts, "length", &noldopts));
	VERIFY3U(noldopts, >=, 1);

	opts = calloc(sizeof (nvlist_t *), noldopts + 1);
	nopts = 0;

	for (i = 0; i < noldopts; ++i) {
		snprintf(nbuf, sizeof (nbuf), "%d", i);
		VERIFY0(nvlist_lookup_nvlist(oldopts, nbuf, &oldopt));

		VERIFY0(nvlist_lookup_int32(opt, "n", &n));
		VERIFY0(nvlist_lookup_int32(opt, "m", &m));

		if (n == 1 && m == 1)
			continue;

		VERIFY0(nvlist_lookup_nvlist(oldopt, "p", &oldparts));
		VERIFY0(nvlist_lookup_uint32(oldparts, "length", &noldparts));

		
	}

	VERIFY0(nvlist_alloc(&config, NV_UNIQUE_NAME, 0));
}
#endif

static void
cmd_unlock(const char *fsname)
{
	zfs_handle_t *ds;
	nvlist_t *props, *prop, *config;
	uint64_t kstatus;
	char *json;
	char *thing;
	size_t tlen;

	tlen = strlen(fsname) + 128;
	thing = calloc(1, tlen);
	snprintf(thing, tlen, "Unlock ZFS filesystem %s", fsname);

	ds = zfs_open(zfshdl, fsname, ZFS_TYPE_DATASET);
	if (ds == NULL) {
		fprintf(stderr, "error: failed to open dataset %s\n",
		    fsname);
		exit(1);
	}

	props = zfs_get_all_props(ds);
	VERIFY(props != NULL);

	if (nvlist_lookup_nvlist(props, "keystatus", &prop)) {
		fprintf(stderr, "error: no keystatus property "
		    "could be read on dataset %s\n", fsname);
		exit(1);
	}
	VERIFY0(nvlist_lookup_uint64(prop, "value", &kstatus));

	/*if (kstatus == ZFS_KEYSTATUS_AVAILABLE) {
		fprintf(stderr, "error: key already loaded for %s\n",
		    fsname);
		exit(1);
	}*/

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

	fprintf(stderr, "Attempting to unlock ZFS '%s'...\n", fsname);
	unlock_generic(config, thing, do_zfs_unlock, (void *)fsname);
}

static void
cmd_respond(void)
{
	struct piv_ecdh_box *chalbox;
	struct challenge *chal;
	struct piv_token *t;
	struct piv_slot *slot;
	char *p;
	char linebuf[128];
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

	fprintf(stderr, "If these details are correct and you wish to "
	    "respond, type 'YES': ");
	p = fgets(linebuf, sizeof (linebuf), stdin);
	if (p == NULL)
		exit(1);
	if (strcmp(linebuf, "YES\n") != 0)
		exit(1);

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
	VERIFY0(sshbuf_put_minibox(resp, respbox));

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
	    "usage: piv-zfs [options] operation\n");
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

	} else if (strcmp(op, "respond") == 0) {

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		cmd_respond();

	} else {
		fprintf(stderr, "error: invalid operation '%s'\n", op);
		usage();
	}

	libzfs_fini(zfshdl);

	return (0);
}
