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
#include <err.h>

#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <wintypes.h>
#include <winscard.h>
#endif

#include <sys/types.h>
#include <sys/errno.h>
#include "debug.h"
#if defined(__sun)
#include <sys/fork.h>
#endif
#include <sys/wait.h>
#include <sys/stat.h>

#include "libssh/sshkey.h"
#include "libssh/sshbuf.h"
#include "libssh/digest.h"
#include "libssh/ssherr.h"
#include "libssh/authfd.h"

#include "sss/hazmat.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if defined(__sun)
#include <libtecla.h>
#else
#include <editline/readline.h>
#endif

#include "tlv.h"
#include "errf.h"
#include "ebox.h"
#include "piv.h"
#include "bunyan.h"

static int ebox_authfd;
static SCARDCONTEXT ebox_ctx;
static boolean_t ebox_ctx_init = B_FALSE;
static const char *ebox_pin;
static uint ebox_min_retries = 1;

enum ebox_exit_status {
	EXIT_OK = 0,
	EXIT_USAGE = 1,
	EXIT_ERROR = 2,
	EXIT_INTERACTIVE = 3,
	EXIT_PIN = 4,
	EXIT_PIN_LOCKED = 5,
};

static boolean_t ebox_batch = B_FALSE;
static boolean_t ebox_raw_in = B_FALSE;
static boolean_t ebox_raw_out = B_FALSE;
static struct ebox_tpl *ebox_tpl;

#define	TPL_DEFAULT_PATH	"%s/.ebox/tpl/%s"
#define	TPL_MAX_SIZE		4096

#ifndef LINT
#define pcscerrf(call, rv)	\
    errf("PCSCError", NULL, call " failed: %d (%s)", \
    rv, pcsc_stringify_error(rv))
#endif

extern char *buf_to_hex(const uint8_t *buf, size_t len, boolean_t spaces);

static char *
piv_token_shortid(struct piv_token *pk)
{
	char *guid;
	guid = strdup(piv_token_guid_hex(pk));
	guid[8] = '\0';
	return (guid);
}

static const char *
pin_type_to_name(enum piv_pin type)
{
	switch (type) {
	case PIV_PIN:
		return ("PIV PIN");
	case PIV_GLOBAL_PIN:
		return ("Global PIN");
	case PIV_PUK:
		return ("PUK");
	default:
		VERIFY(0);
		return (NULL);
	}
}

static void
assert_pin(struct piv_token *pk, boolean_t prompt)
{
	errf_t *er;
	uint retries = ebox_min_retries;
	enum piv_pin auth = piv_token_default_auth(pk);

	if (ebox_pin == NULL && !prompt)
		return;

	if (ebox_pin == NULL && prompt) {
		char prompt[64];
		char *guid = piv_token_shortid(pk);
		snprintf(prompt, 64, "Enter %s for token %s: ",
		    pin_type_to_name(auth), guid);
		do {
			ebox_pin = getpass(prompt);
		} while (ebox_pin == NULL && errno == EINTR);
		if ((ebox_pin == NULL && errno == ENXIO) ||
		    strlen(ebox_pin) < 1) {
			piv_txn_end(pk);
			errx(EXIT_PIN, "a PIN is required to unlock "
			    "token %s", guid);
		} else if (ebox_pin == NULL) {
			piv_txn_end(pk);
			err(EXIT_PIN, "failed to read PIN");
		} else if (strlen(ebox_pin) < 6 || strlen(ebox_pin) > 8) {
			const char *charType = "digits";
			if (piv_token_is_ykpiv(pk))
				charType = "characters";
			errx(EXIT_PIN, "a valid PIN must be 6-8 %s in length",
			    charType);
		}
		ebox_pin = strdup(ebox_pin);
		free(guid);
	}
	er = piv_verify_pin(pk, auth, ebox_pin, &retries, B_FALSE);
	if (errf_caused_by(er, "PermissionError")) {
		piv_txn_end(pk);
		if (retries == 0) {
			errx(EXIT_PIN_LOCKED, "token is locked due to too "
			    "many invalid PIN attempts");
		}
		errx(EXIT_PIN, "invalid PIN (%d attempts remaining)", retries);
	} else if (errf_caused_by(er, "MinRetriesError")) {
		piv_txn_end(pk);
		if (retries == 0) {
			errx(EXIT_PIN_LOCKED, "token is locked due to too "
			    "many invalid PIN attempts");
		}
		errx(EXIT_PIN, "insufficient PIN retries remaining (%d left)",
		    retries);
	} else if (er) {
		piv_txn_end(pk);
		errfx(EXIT_PIN, er, "failed to verify PIN");
	}
}

static errf_t *
local_unlock_agent(struct piv_ecdh_box *box)
{
	struct piv_ecdh_box *rebox = NULL;
	struct sshkey *pubkey, *temp = NULL, *temppub = NULL;
	errf_t *err;
	int rc;
	uint i;
	uint8_t code;
	struct ssh_identitylist *idl = NULL;
	struct sshbuf *req = NULL, *buf = NULL, *boxbuf = NULL, *reply = NULL;
	struct sshbuf *datab = NULL;
	boolean_t found = B_FALSE;

	pubkey = piv_box_pubkey(box);

	rc = ssh_fetch_identitylist(ebox_authfd, &idl);
	if (rc) {
		err = ssherrf("ssh_fetch_identitylist", rc);
		goto out;
	}

	for (i = 0; i < idl->nkeys; ++i) {
		if (sshkey_equal_public(idl->keys[i], pubkey)) {
			found = B_TRUE;
			break;
		}
	}
	if (!found) {
		err = errf("KeyNotFound", NULL, "No matching key found in "
		    "ssh agent");
		goto out;
	}

	rc = sshkey_generate(KEY_ECDSA, sshkey_size(pubkey), &temp);
	if (rc) {
		err = ssherrf("sshkey_generate", rc);
		goto out;
	}
	if ((rc = sshkey_demote(temp, &temppub))) {
		err = ssherrf("sshkey_demote", rc);
		goto out;
	}

	req = sshbuf_new();
	reply = sshbuf_new();
	buf = sshbuf_new();
	boxbuf = sshbuf_new();
	if (req == NULL || reply == NULL || buf == NULL || boxbuf == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	if ((rc = sshbuf_put_u8(req, SSH2_AGENTC_EXTENSION))) {
		err = ssherrf("sshbuf_put_u8", rc);
		goto out;
	}
	if ((rc = sshbuf_put_cstring(req, "ecdh-rebox@joyent.com"))) {
		err = ssherrf("sshbuf_put_cstring", rc);
		goto out;
	}

	if ((err = sshbuf_put_piv_box(boxbuf, box)))
		goto out;
	if ((rc = sshbuf_put_stringb(buf, boxbuf))) {
		err = ssherrf("sshbuf_put_stringb", rc);
		goto out;
	}
	if ((rc = sshbuf_put_u32(buf, 0)) ||
	    (rc = sshbuf_put_u8(buf, 0))) {
		err = ssherrf("sshbuf_put_u32", rc);
		goto out;
	}
	sshbuf_reset(boxbuf);
	if ((rc = sshkey_putb(temppub, boxbuf))) {
		err = ssherrf("sshkey_putb", rc);
		goto out;
	}
	if ((rc = sshbuf_put_stringb(buf, boxbuf))) {
		err = ssherrf("sshbuf_put_stringb", rc);
		goto out;
	}
	if ((rc = sshbuf_put_u32(buf, 0))) {
		err = ssherrf("sshbuf_put_u32", rc);
		goto out;
	}

	if ((rc = sshbuf_put_stringb(req, buf))) {
		err = ssherrf("sshbuf_put_stringb", rc);
		goto out;
	}

	rc = ssh_request_reply(ebox_authfd, req, reply);
	if (rc) {
		err = ssherrf("ssh_request_reply", rc);
		goto out;
	}

	if ((rc = sshbuf_get_u8(reply, &code))) {
		err = ssherrf("sshbuf_get_u8", rc);
		goto out;
	}
	if (code != SSH_AGENT_SUCCESS) {
		err = errf("SSHAgentError", NULL, "SSH agent returned "
		    "message code %d to rebox request", (int)code);
		goto out;
	}
	sshbuf_reset(boxbuf);
	if ((rc = sshbuf_get_stringb(reply, boxbuf))) {
		err = ssherrf("sshbuf_get_stringb", rc);
		goto out;
	}

	if ((err = sshbuf_get_piv_box(boxbuf, &rebox)))
		goto out;

	if ((err = piv_box_open_offline(temp, rebox)))
		goto out;

	if ((err = piv_box_take_datab(rebox, &datab)))
		goto out;

	if ((err = piv_box_set_datab(box, datab)))
		goto out;

	err = ERRF_OK;

out:
	sshbuf_free(req);
	sshbuf_free(reply);
	sshbuf_free(buf);
	sshbuf_free(boxbuf);
	sshbuf_free(datab);

	sshkey_free(temp);
	sshkey_free(temppub);

	ssh_free_identitylist(idl);
	piv_box_free(rebox);
	return (err);
}

static errf_t *
local_unlock(struct piv_ecdh_box *box)
{
	errf_t *err, *agerr = NULL;
	int rc;
	struct piv_slot *slot;
	struct piv_token *tokens = NULL, *token;

	if (ssh_get_authentication_socket(&ebox_authfd) != -1) {
		agerr = local_unlock_agent(box);
		if (agerr == ERRF_OK)
			return (ERRF_OK);
	}

	if (!piv_box_has_guidslot(box)) {
		if (agerr)
			return (agerr);
		return (errf("NoGUIDSlot", NULL, "box does not have GUID "
		    "and slot information, can't unlock with local hardware"));
	}

	if (!ebox_ctx_init) {
		rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
		    &ebox_ctx);
		if (rc != SCARD_S_SUCCESS) {
			errfx(EXIT_ERROR, pcscerrf("SCardEstablishContext", rc),
			    "failed to initialise libpcsc");
		}
	}

	err = piv_find(ebox_ctx, piv_box_guid(box), GUID_LEN, &tokens);
	if (errf_caused_by(err, "NotFoundError")) {
		err = piv_enumerate(ebox_ctx, &tokens);
		if (err && agerr)
			err = agerr;
	}
	if (err)
		goto out;

	err = piv_box_find_token(tokens, box, &token, &slot);
	if (err)
		goto out;

	if ((err = piv_txn_begin(token)))
		goto out;
	if ((err = piv_select(token))) {
		piv_txn_end(token);
		goto out;
	}

	boolean_t prompt = B_FALSE;
pin:
	assert_pin(token, prompt);
	err = piv_box_open(token, slot, box);
	if (errf_caused_by(err, "PermissionError") && !prompt) {
		prompt = B_TRUE;
		goto pin;
	} else if (err) {
		piv_txn_end(token);
		goto out;
	}

	piv_txn_end(token);
	err = ERRF_OK;

out:
	piv_release(tokens);
	return (err);
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
read_b64_box(struct piv_ecdh_box **outbox)
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

static errf_t *
parse_hex(const char *str, uint8_t **out, size_t *outlen)
{
	const size_t len = strlen(str);
	uint8_t *data = calloc(1, len / 2 + 1);
	size_t idx = 0;
	size_t shift = 4;
	size_t i;
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
			free(data);
			return (errf("HexParseError", NULL,
			    "invalid hex digit: '%c'", c));
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
		free(data);
		return (errf("HexParseError", NULL,
		    "odd number of digits (incomplete)"));
	}
	*outlen = idx;
	*out = data;
	return (ERRF_OK);
}

static errf_t *
parse_keywords_part(struct ebox_tpl_config *config, int argc, char *argv[],
    uint *idxp)
{
	uint i = *idxp;
	struct ebox_tpl_part *part = NULL;
	uint8_t *guid = NULL;
	struct sshkey *pubkey = NULL;
	struct sshkey *cak = NULL;
	const char *name = NULL;
	size_t guidlen;
	errf_t *error = NULL;
	int rc;
	char *p;
	struct piv_token *token;
	struct piv_slot *slot;

	for (; i < argc; ++i) {
		if (strcmp(argv[i], "part") == 0 ||
		    strcmp(argv[i], "primary") == 0 ||
		    strcmp(argv[i], "recovery") == 0 ||
		    strcmp(argv[i], "add-primary") == 0 ||
		    strcmp(argv[i], "remove-primary") == 0 ||
		    strcmp(argv[i], "add-recovery") == 0 ||
		    strcmp(argv[i], "remove-recovery") == 0 ||
		    strcmp(argv[i], "require") == 0) {
			--i;
			break;
		}
		if (strcmp(argv[i], "guid") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'guid' keyword requires argument");
				goto out;
			}
			error = parse_hex(argv[i], &guid, &guidlen);
			if (error) {
				error = errf("SyntaxError", error,
				    "error parsing argument to 'guid' keyword");
				goto out;
			}
			if (guidlen != GUID_LEN) {
				error = errf("SyntaxError", errf("LengthError",
				    NULL, "guid is not the correct length: %u",
				    guidlen), "error parsing argument to "
				    "'guid' keyword");
				goto out;
			}
		} else if (strcmp(argv[i], "name") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'name' keyword requires argument");
				goto out;
			}
			name = argv[i];
		} else if (strcmp(argv[i], "key") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'key' keyword requires argument");
				goto out;
			}
			pubkey = sshkey_new(KEY_ECDSA);
			if (pubkey == NULL) {
				error = ERRF_NOMEM;
				goto out;
			}
			p = argv[i];
			rc = sshkey_read(pubkey, &p);
			if (rc) {
				error = errf("SyntaxError", ssherrf(
				    "sshkey_read", rc), "error parsing "
				    "argument to 'key' keyword");
				goto out;
			}
			if (*p != '\0') {
				error = errf("SyntaxError", NULL,
				    "argument to 'key' keyword has trailing "
				    "garbage");
				goto out;
			}
		} else if (strcmp(argv[i], "cak") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'cak' keyword requires argument");
				goto out;
			}
			cak = sshkey_new(KEY_UNSPEC);
			if (cak == NULL) {
				error = ERRF_NOMEM;
				goto out;
			}
			p = argv[i];
			rc = sshkey_read(cak, &p);
			if (rc) {
				error = errf("SyntaxError", ssherrf(
				    "sshkey_read", rc), "error parsing "
				    "argument to 'cak' keyword");
				goto out;
			}
			if (*p != '\0') {
				error = errf("SyntaxError", NULL,
				    "argument to 'cak' keyword has trailing "
				    "garbage");
				goto out;
			}
		} else if (strcmp(argv[i], "local-guid") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'local-guid' keyword requires argument");
				goto out;
			}
			error = parse_hex(argv[i], &guid, &guidlen);
			if (error) {
				error = errf("SyntaxError", error,
				    "error parsing argument to 'local-guid' "
				    "keyword");
				goto out;
			}
			if (guidlen > GUID_LEN) {
				error = errf("SyntaxError", errf("LengthError",
				    NULL, "guid is too long: %u bytes",
				    guidlen), "error parsing argument to "
				    "'local-guid' keyword");
				goto out;
			}
			if (!ebox_ctx_init) {
				rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM,
				    NULL, NULL, &ebox_ctx);
				if (rc != SCARD_S_SUCCESS) {
					errfx(EXIT_ERROR, pcscerrf(
					    "SCardEstablishContext", rc),
					    "failed to initialise libpcsc");
				}
			}
			error = piv_find(ebox_ctx, guid, guidlen, &token);
			if (error) {
				error = errf("LocalGUIDError", error,
				    "failed to resolve local-guid argument "
				    "'%s'", argv[i]);
				goto out;
			}
			if ((error = piv_txn_begin(token)))
				goto out;
			if ((error = piv_select(token)))
				goto out;
			free(guid);
			guid = malloc(GUID_LEN);
			bcopy(piv_token_guid(token), guid, GUID_LEN);
			guidlen = GUID_LEN;
			error = piv_read_cert(token, PIV_SLOT_CARD_AUTH);
			if (error == ERRF_OK) {
				slot = piv_get_slot(token, PIV_SLOT_CARD_AUTH);
				rc = sshkey_demote(piv_slot_pubkey(slot),
				    &cak);
				if (rc) {
					error = ssherrf("sshkey_demote", rc);
					goto out;
				}
			}
			erfree(error);
			if ((error = piv_read_cert(token, PIV_SLOT_KEY_MGMT)))
				goto out;
			slot = piv_get_slot(token, PIV_SLOT_KEY_MGMT);
			rc = sshkey_demote(piv_slot_pubkey(slot), &pubkey);
			if (rc) {
				error = ssherrf("sshkey_demote", rc);
				goto out;
			}
			piv_txn_end(token);
			piv_release(token);
		} else {
			error = errf("SyntaxError", NULL,
			    "unexpected configuration keyword '%s'", argv[i]);
			goto out;
		}
	}

	if (guid == NULL) {
		error = errf("SyntaxError", NULL,
		    "configuration part missing required 'guid' keyword");
		goto out;
	}

	if (pubkey == NULL) {
		error = errf("SyntaxError", NULL,
		    "configuration part missing required 'key' keyword");
		goto out;
	}

	part = ebox_tpl_part_alloc(guid, guidlen, pubkey);
	if (part == NULL)
		return (ERRF_NOMEM);
	ebox_tpl_config_add_part(config, part);

	if (name != NULL)
		ebox_tpl_part_set_name(part, name);
	if (cak != NULL)
		ebox_tpl_part_set_cak(part, cak);

out:
	*idxp = i;
	sshkey_free(pubkey);
	sshkey_free(cak);
	free(guid);
	return (error);
}

static errf_t *
parse_keywords_primary(struct ebox_tpl_config *config, int argc, char *argv[],
    uint *idxp)
{
	uint i = *idxp;
	errf_t *error = NULL;

	for (; i < argc; ++i) {
		if (strcmp(argv[i], "primary") == 0 ||
		    strcmp(argv[i], "recovery") == 0 ||
		    strcmp(argv[i], "add-primary") == 0 ||
		    strcmp(argv[i], "remove-primary") == 0 ||
		    strcmp(argv[i], "add-recovery") == 0 ||
		    strcmp(argv[i], "remove-recovery") == 0) {
			--i;
			break;
		}
		if (strcmp(argv[i], "part") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "unexpected end of arguments after 'part'"
				    " keyword");
				goto out;
			}
		}
		error = parse_keywords_part(config, argc, argv, &i);
		if (error)
			goto out;
	}

out:
	*idxp = i;
	return (error);
}

static errf_t *
parse_keywords_recovery(struct ebox_tpl_config *config, int argc, char *argv[],
    uint *idxp)
{
	uint i = *idxp;
	errf_t *error = NULL;
	unsigned long int parsed;
	char *p;

	for (; i < argc; ++i) {
		if (strcmp(argv[i], "primary") == 0 ||
		    strcmp(argv[i], "recovery") == 0 ||
		    strcmp(argv[i], "add-primary") == 0 ||
		    strcmp(argv[i], "remove-primary") == 0 ||
		    strcmp(argv[i], "add-recovery") == 0 ||
		    strcmp(argv[i], "remove-recovery") == 0) {
			--i;
			break;
		}
		if (strcmp(argv[i], "require") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'require' keyword requires argument");
				goto out;
			}
			errno = 0;
			parsed = strtoul(argv[i], &p, 0);
			if (errno != 0 || *p != '\0') {
				error = errf("SyntaxError",
				    errfno("strtoul", errno, NULL),
				    "error parsing argument to 'require' "
				    "keyword: '%s'", argv[i]);
				goto out;
			}
			error = ebox_tpl_config_set_n(config, parsed);
			if (error) {
				error = errf("SyntaxError", error,
				    "error applying argument to 'require' "
				    "keyword: '%s'", argv[i]);
				goto out;
			}

		} else if (strcmp(argv[i], "part") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'part' keyword requires arguments");
				goto out;
			}
			error = parse_keywords_part(config, argc, argv, &i);
			if (error)
				goto out;

		} else {
			return (errf("SyntaxError", NULL,
			    "unexpected configuration keyword '%s'", argv[i]));
		}
	}

out:
	*idxp = i;
	return (error);
}

static errf_t *
cmd_tpl_create(int argc, char *argv[])
{
	uint i;
	struct ebox_tpl *tpl;
	struct ebox_tpl_config *config = NULL;
	errf_t *error = NULL;
	struct sshbuf *buf;

	tpl = ebox_tpl_alloc();

	for (i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "primary") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'primary' keyword requires arguments");
				goto out;
			}
			config = ebox_tpl_config_alloc(EBOX_PRIMARY);
			ebox_tpl_add_config(tpl, config);
			error = parse_keywords_primary(config, argc, argv, &i);
			if (error)
				return (error);
		} else if (strcmp(argv[i], "recovery") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'recovery' keyword requires arguments");
				goto out;
			}
			config = ebox_tpl_config_alloc(EBOX_RECOVERY);
			ebox_tpl_add_config(tpl, config);
			error = parse_keywords_recovery(config, argc, argv, &i);
			if (error)
				return (error);
		} else {
			return (errf("SyntaxError", NULL,
			    "unexpected configuration keyword '%s'", argv[i]));
		}
	}

	buf = sshbuf_new();
	error = sshbuf_put_ebox_tpl(buf, tpl);
	if (error)
		return (error);
	printwrap(sshbuf_dtob64(buf), 64);

out:
	ebox_tpl_free(tpl);
	return (error);
}

static struct sshbuf *
read_stdin_b64(size_t limit)
{
	char *buf = malloc(limit + 1);
	struct sshbuf *sbuf;
	size_t n;
	int rc;

	n = fread(buf, 1, limit, stdin);
	if (!feof(stdin))
		errx(EXIT_USAGE, "input too long (max %lu bytes)", limit);
	if (n > limit)
		errx(EXIT_USAGE, "input too long (max %lu bytes)", limit);
	buf[n] = '\0';

	sbuf = sshbuf_new();
	if (sbuf == NULL)
		err(EXIT_ERROR, "failed to allocate buffer");
	rc = sshbuf_b64tod(sbuf, buf);
	if (rc) {
		errf_t *error = ssherrf("sshbuf_b64tod", rc);
		errfx(EXIT_ERROR, error, "error parsing input as base64");
	}
	return (sbuf);
}

static errf_t *
cmd_tpl_edit(int argc, char *argv[])
{
	return (errf("NotImplemented", NULL,
	    "Function %s has not yet been implemented", __func__));
}

static errf_t *
cmd_tpl_show(int argc, char *argv[])
{
	errf_t *error;
	struct ebox_tpl_config *config = NULL;
	int rc;

	if (ebox_tpl == NULL) {
		struct sshbuf *sbuf = read_stdin_b64(TPL_MAX_SIZE);
		error = sshbuf_get_ebox_tpl(sbuf, &ebox_tpl);
		if (error) {
			errfx(EXIT_ERROR, error, "failed to parse input as "
			    "a base64-encoded ebox template");
		}
	}

	while ((config = ebox_tpl_next_config(ebox_tpl, config))) {
		fprintf(stderr, "configuration:\n");
		switch (ebox_tpl_config_type(config)) {
		case EBOX_PRIMARY:
			fprintf(stderr, "  type: primary\n");
			break;
		case EBOX_RECOVERY:
			fprintf(stderr, "  type: recovery\n");
			fprintf(stderr, "  required: %u parts\n",
			    ebox_tpl_config_n(config));
			break;
		}
		struct ebox_tpl_part *part = NULL;
		while ((part = ebox_tpl_config_next_part(config, part))) {
			char *guidhex;
			fprintf(stderr, "  part:\n");
			guidhex = buf_to_hex(ebox_tpl_part_guid(part),
			    GUID_LEN, B_FALSE);
			fprintf(stderr, "    guid: %s\n", guidhex);
			free(guidhex);
			if (ebox_tpl_part_name(part) != NULL) {
				fprintf(stderr, "    name: %s\n",
				    ebox_tpl_part_name(part));
			}
			fprintf(stderr, "    key: ");
			rc = sshkey_write(ebox_tpl_part_pubkey(part), stderr);
			if (rc != 0) {
				errfx(EXIT_ERROR, ssherrf("sshkey_write", rc),
				    "failed to print pubkey of ebox part");
			}
			fprintf(stderr, "\n");
			if (ebox_tpl_part_cak(part) != NULL) {
				fprintf(stderr, "    cak: ");
				rc = sshkey_write(ebox_tpl_part_cak(part),
				    stderr);
				if (rc != 0) {
					errfx(EXIT_ERROR,
					    ssherrf("sshkey_write", rc),
					    "failed to print cak of ebox part");
				}
				fprintf(stderr, "\n");
			}
		}
	}

	return (NULL);
}

static errf_t *
cmd_key_generate(int argc, char *argv[])
{
	return (errf("NotImplemented", NULL,
	    "Function %s has not yet been implemented", __func__));
}

static errf_t *
cmd_key_lock(int argc, char *argv[])
{
	return (errf("NotImplemented", NULL,
	    "Function %s has not yet been implemented", __func__));
}

static errf_t *
cmd_key_unlock(int argc, char *argv[])
{
	return (errf("NotImplemented", NULL,
	    "Function %s has not yet been implemented", __func__));
}

static errf_t *
cmd_key_relock(int argc, char *argv[])
{
	return (errf("NotImplemented", NULL,
	    "Function %s has not yet been implemented", __func__));
}

static errf_t *
cmd_stream_encrypt(int argc, char *argv[])
{
	return (errf("NotImplemented", NULL,
	    "Function %s has not yet been implemented", __func__));
}

static errf_t *
cmd_stream_decrypt(int argc, char *argv[])
{
	return (errf("NotImplemented", NULL,
	    "Function %s has not yet been implemented", __func__));
}

static void
usage(void)
{
	exit(EXIT_USAGE);
}

static void
read_tpl_file(const char *tpl)
{
	errf_t *error;
	FILE *tplf;
	struct stat st;
	char *buf;
	struct sshbuf *sbuf;
	size_t len;
	int rc;

	tplf = fopen(tpl, "r");
	if (tplf == NULL) {
		err(EXIT_ERROR, "failed to open template file '%s' for reading",
		    tpl);
	}
	bzero(&st, sizeof (st));
	if (fstat(fileno(tplf), &st))
		err(EXIT_ERROR, "failed to get size of '%s'", tpl);
	if (!S_ISREG(st.st_mode))
		err(EXIT_ERROR, "'%s' is not a regular file", tpl);
	if (st.st_size > TPL_MAX_SIZE)
		err(EXIT_ERROR, "'%s' is too large for an ebox template", tpl);
	buf = malloc(st.st_size);
	if (buf == NULL) {
		err(EXIT_ERROR, "out of memory while allocating template "
		    "read buffer");
	}
	len = fread(buf, 1, st.st_size, tplf);
	if (len < st.st_size && feof(tplf)) {
		errx(EXIT_ERROR, "short read while processing template '%s'",
		    tpl);
	}
	if (ferror(tplf))
		err(EXIT_ERROR, "error reading from template file '%s'", tpl);
	if (fclose(tplf))
		err(EXIT_ERROR, "error closing file '%s'", tpl);
	sbuf = sshbuf_new();
	if (sbuf == NULL) {
		err(EXIT_ERROR, "out of memory while allocating template "
		    "processing buffer");
	}
	if ((rc = sshbuf_b64tod(sbuf, buf))) {
		error = ssherrf("sshbuf_b64tod", rc);
		errfx(EXIT_ERROR, error, "failed to parse contents of '%s' as "
		    "base64-encoded data", tpl);
	}
	if ((error = sshbuf_get_ebox_tpl(sbuf, &ebox_tpl))) {
		errfx(EXIT_ERROR, error, "failed to parse contents of '%s' as "
		    "a base64-encoded ebox template", tpl);
	}
	sshbuf_free(sbuf);
	free(buf);
}

int
main(int argc, char *argv[])
{
	const char *optstring = "blirRP:i:o:f:";
	const char *type, *op, *tplname;
	int c;
	char tpl[PATH_MAX] = { 0 };
	errf_t *error = NULL;

	if (argc < 2) {
		warnx("type and operation required");
		usage();
		return (EXIT_USAGE);
	}
	type = argv[1];
	if (argc < 3) {
		warnx("operation required");
		usage();
		return (EXIT_USAGE);
	}
	op = argv[2];

	argc -= 2;
	argv += 2;

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'b':
			ebox_batch = B_TRUE;
			break;
		case 'r':
			ebox_raw_in = B_TRUE;
			break;
		case 'R':
			ebox_raw_out = B_TRUE;
			break;
		case 'f':
			strlcpy(tpl, optarg, sizeof (tpl));
			break;
		default:
			usage();
			return (EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	if (strcmp(type, "tpl") == 0 || strcmp(type, "template") == 0) {
		if (strcmp(op, "show") == 0) {
			error = cmd_tpl_show(argc, argv);
			goto out;
		}

	} else if (strcmp(type, "key") == 0) {
		if (strcmp(op, "unlock") == 0) {
			error = cmd_key_unlock(argc, argv);
			goto out;
		}

	} else if (strcmp(type, "stream") == 0) {
		if (strcmp(op, "decrypt") == 0) {
			error = cmd_stream_decrypt(argc, argv);
			goto out;
		}

	}

	if (tpl[0] == '\0') {
		const char *home;
		if (argc < 1) {
			warnx("template name or path required");
			usage();
		}
		tplname = argv[0];
		home = getenv("HOME");
		if (home == NULL) {
			errx(EXIT_USAGE, "environment variable HOME not set, "
			    "must use -f to specify full path to template");
		}
		snprintf(tpl, sizeof (tpl), TPL_DEFAULT_PATH,
		    home, tplname);
	}

	if (strcmp(type, "tpl") == 0 || strcmp(type, "template") == 0) {

		if (strcmp(op, "create") == 0) {
			error = cmd_tpl_create(argc, argv);
			goto out;

		} else if (strcmp(op, "edit") == 0) {
			read_tpl_file(tpl);
			error = cmd_tpl_edit(argc, argv);
			goto out;
		}

	} else if (strcmp(type, "key") == 0) {

		if (strcmp(op, "generate") == 0) {
			read_tpl_file(tpl);
			error = cmd_key_generate(argc, argv);
			goto out;

		} else if (strcmp(op, "lock") == 0) {
			read_tpl_file(tpl);
			error = cmd_key_lock(argc, argv);
			goto out;

		} else if (strcmp(op, "unlock") == 0) {
			error = cmd_key_unlock(argc, argv);
			goto out;

		} else if (strcmp(op, "relock") == 0) {
			read_tpl_file(tpl);
			error = cmd_key_relock(argc, argv);
			goto out;
		}

	} else if (strcmp(type, "stream") == 0) {

		if (strcmp(op, "decrypt") == 0) {
			error = cmd_stream_decrypt(argc, argv);
			goto out;

		} else if (strcmp(op, "encrypt") == 0) {
			read_tpl_file(tpl);
			error = cmd_stream_encrypt(argc, argv);
			goto out;
		}
	}
	warnx("unknown operation: '%s %s'", type, op);
	usage();
	return (EXIT_USAGE);

out:
	if (error)
		errfx(EXIT_ERROR, error, "'%s %s' command failed", type, op);
	return (0);
}
