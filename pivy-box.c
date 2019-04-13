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
#include <sys/mman.h>

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

#include "words.h"

static int ebox_authfd;
static SCARDCONTEXT ebox_ctx;
static boolean_t ebox_ctx_init = B_FALSE;
static char *ebox_pin;
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
static boolean_t ebox_interactive = B_FALSE;
static struct ebox_tpl *ebox_stpl;
static size_t ebox_keylen = 32;

#define	TPL_DEFAULT_PATH	"%s/.ebox/tpl/%s"
#define	TPL_MAX_SIZE		4096
#define	EBOX_MAX_SIZE		16384
#define	BASE64_LINE_LEN		65

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
assert_pin(struct piv_token *pk, const char *partname, boolean_t prompt)
{
	errf_t *er;
	uint retries;
	enum piv_pin auth = piv_token_default_auth(pk);
	const char *fmt = "Enter %s for token %s (%s): ";
	if (partname == NULL)
		fmt = "Enter %s for token %s: ";

	if (ebox_pin == NULL && !prompt)
		return;

again:
	if (ebox_pin == NULL && prompt) {
		char prompt[64];
		char *guid = piv_token_shortid(pk);
		snprintf(prompt, 64, fmt,
		    pin_type_to_name(auth), guid, partname);
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
			warnx("a valid PIN must be 6-8 %s in length",
			    charType);
			free(ebox_pin);
			free(guid);
			ebox_pin = NULL;
			goto again;
		}
		ebox_pin = strdup(ebox_pin);
		free(guid);
	}
	retries = ebox_min_retries;
	er = piv_verify_pin(pk, auth, ebox_pin, &retries, B_FALSE);
	if (errf_caused_by(er, "PermissionError")) {
		if (retries == 0) {
			piv_txn_end(pk);
			errx(EXIT_PIN_LOCKED, "token is locked due to too "
			    "many invalid PIN attempts");
		}
		warnx("invalid PIN (%d attempts remaining)", retries);
		free(ebox_pin);
		ebox_pin = NULL;
		goto again;
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
local_unlock(struct piv_ecdh_box *box, struct sshkey *cak, const char *name)
{
	errf_t *err, *agerr = NULL;
	int rc;
	struct piv_slot *slot, *cakslot;
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

	if (cak != NULL) {
		cakslot = piv_get_slot(token, PIV_SLOT_CARD_AUTH);
		if (cakslot == NULL) {
			err = piv_read_cert(token, PIV_SLOT_CARD_AUTH);
			if (err) {
				err = errf("CardAuthenticationError", err,
				    "Failed to validate CAK");
				goto out;
			}
			cakslot = piv_get_slot(token, PIV_SLOT_CARD_AUTH);
		}
		if (cakslot == NULL) {
			err = errf("CardAuthenticationError", NULL,
			    "Failed to validate CAK");
			goto out;
		}
		err = piv_auth_key(token, cakslot, cak);
		if (err) {
			err = errf("CardAuthenticationError", err,
			    "Failed to validate CAK");
			goto out;
		}
	}

	boolean_t prompt = B_FALSE;
pin:
	assert_pin(token, name, prompt);
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
printwrap(FILE *stream, const char *data, size_t col)
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
		fprintf(stream, "%s\n", buf);
		offset += rem;
	}
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

#if defined(__sun)
static GetLine *sungl = NULL;
FILE *devterm = NULL;

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

#define	Q_MAX_LEN	2048
#define	ANS_MAX_LEN	512

struct question {
	struct answer *q_ans;
	struct answer *q_lastans;
	struct answer *q_coms;
	struct answer *q_lastcom;
	void *q_priv;
	size_t q_used;
	char q_prompt[Q_MAX_LEN];
};

struct answer {
	struct answer *a_next;
	struct answer *a_prev;
	char a_key;
	void *a_priv;
	size_t a_used;
	char a_text[ANS_MAX_LEN];
};

void
add_answer(struct question *q, struct answer *a)
{
	if (a->a_prev != NULL || a->a_next != NULL || q->q_lastans == a)
		return;
	if (q->q_lastans == NULL) {
		q->q_ans = a;
	} else {
		q->q_lastans->a_next = a;
		a->a_prev = q->q_lastans;
	}
	q->q_lastans = a;
}

void
add_spacer(struct question *q)
{
	struct answer *a;

	a = calloc(1, sizeof (struct answer));
	add_answer(q, a);
}

void
remove_answer(struct question *q, struct answer *a)
{
	if (a->a_prev != NULL) {
		a->a_prev->a_next = a->a_next;
	} else {
		if (q->q_ans != a && a->a_next == NULL)
			return;
		VERIFY(q->q_ans == a);
		q->q_ans = a->a_next;
	}
	if (a->a_next != NULL) {
		a->a_next->a_prev = a->a_prev;
	} else {
		if (q->q_lastans != a && a->a_prev == NULL)
			return;
		VERIFY(q->q_lastans == a);
		q->q_lastans = a->a_prev;
	}
}

void
answer_printf(struct answer *ans, const char *fmt, ...)
{
	va_list ap;
	size_t wrote;

	va_start(ap, fmt);
	wrote = vsnprintf(&ans->a_text[ans->a_used],
	    sizeof (ans->a_text) - ans->a_used, fmt, ap);
	va_end(ap);
	ans->a_used += wrote;
	if (ans->a_used >= sizeof (ans->a_text))
		ans->a_text[sizeof (ans->a_text) - 1] = '\0';
}

struct answer *
make_answer(char key, const char *fmt, ...)
{
	va_list ap;
	size_t wrote;
	struct answer *ans;

	ans = calloc(1, sizeof (struct answer));
	if (ans == NULL)
		err(EXIT_ERROR, "failed to allocate memory");
	ans->a_key = key;

	va_start(ap, fmt);
	wrote = vsnprintf(&ans->a_text[ans->a_used],
	    sizeof (ans->a_text) - ans->a_used, fmt, ap);
	va_end(ap);
	ans->a_used += wrote;
	if (ans->a_used >= sizeof (ans->a_text))
		ans->a_text[sizeof (ans->a_text) - 1] = '\0';

	return (ans);
}

void
add_command(struct question *q, struct answer *a)
{
	if (q->q_lastcom == NULL) {
		q->q_coms = a;
	} else {
		q->q_lastcom->a_next = a;
		a->a_prev = q->q_lastcom;
	}
	q->q_lastcom = a;
}

void
question_printf(struct question *q, const char *fmt, ...)
{
	va_list ap;
	size_t wrote;

	va_start(ap, fmt);
	wrote = vsnprintf(&q->q_prompt[q->q_used],
	    sizeof (q->q_prompt) - q->q_used, fmt, ap);
	va_end(ap);
	q->q_used += wrote;
	if (q->q_used >= sizeof (q->q_prompt))
		q->q_prompt[sizeof (q->q_prompt) - 1] = '\0';
}

void
question_free(struct question *q)
{
	struct answer *a, *na;

	for (a = q->q_ans; a != NULL; a = na) {
		na = a->a_next;
		free(a);
	}
	for (a = q->q_coms; a != NULL; a = na) {
		na = a->a_next;
		free(a);
	}

	free(q);
}

void
question_prompt(struct question *q, struct answer **ansp)
{
	struct answer *ans;
	char *line = NULL;

again:
	fprintf(stderr, "%s\n", q->q_prompt);
	for (ans = q->q_ans; ans != NULL; ans = ans->a_next) {
		if (ans->a_key == '\0') {
			fprintf(stderr, "\n");
			continue;
		}
		fprintf(stderr, "  [%c] %s\n", ans->a_key, ans->a_text);
	}
	fprintf(stderr, "\nCommands:\n");
	for (ans = q->q_coms; ans != NULL; ans = ans->a_next) {
		if (ans->a_key == '\0') {
			fprintf(stderr, "\n");
			continue;
		}
		fprintf(stderr, "  [%c] %s\n", ans->a_key, ans->a_text);
	}
	free(line);
	line = readline("Choice? ");
	if (line == NULL)
		exit(EXIT_ERROR);
	for (ans = q->q_ans; ans != NULL; ans = ans->a_next) {
		if (ans->a_key != '\0' &&
		    line[0] == ans->a_key && line[1] == '\0') {
			free(line);
			*ansp = ans;
			return;
		}
	}
	for (ans = q->q_coms; ans != NULL; ans = ans->a_next) {
		if (ans->a_key != '\0' &&
		    line[0] == ans->a_key && line[1] == '\0') {
			free(line);
			*ansp = ans;
			return;
		}
	}
	fprintf(stderr, "Invalid choice.\n");
	goto again;
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

static void
make_answer_text_for_part(struct ebox_tpl_part *part, struct answer *a)
{
	const char *name;
	char *guidhex = NULL;

	a->a_text[0] = '\0';
	a->a_used = 0;

	guidhex = buf_to_hex(ebox_tpl_part_guid(part),
	    4, B_FALSE);
	answer_printf(a, "%s", guidhex);
	name = ebox_tpl_part_name(part);
	if (name != NULL) {
		answer_printf(a, " (%s)", name);
	}

	free(guidhex);
}

static void
make_answer_text_for_config(struct ebox_tpl_config *config, struct answer *a)
{
	struct ebox_tpl_part *part, *npart;
	const char *name;
	char *guidhex = NULL;

	a->a_text[0] = '\0';
	a->a_used = 0;

	switch (ebox_tpl_config_type(config)) {
	case EBOX_PRIMARY:
		part = ebox_tpl_config_next_part(config, NULL);
		if (part == NULL) {
			answer_printf(a, "primary: none");
			break;
		}
		free(guidhex);
		guidhex = buf_to_hex(ebox_tpl_part_guid(part),
		    4, B_FALSE);
		answer_printf(a, "primary: %s", guidhex);
		name = ebox_tpl_part_name(part);
		if (name != NULL) {
			answer_printf(a, " (%s)", name);
		}
		break;
	case EBOX_RECOVERY:
		answer_printf(a, "recovery: any %u of: ",
		    ebox_tpl_config_n(config));
		part = ebox_tpl_config_next_part(config, NULL);
		while (part != NULL) {
			npart = ebox_tpl_config_next_part(
			    config, part);
			free(guidhex);
			guidhex = buf_to_hex(
			    ebox_tpl_part_guid(part), 4,
			    B_FALSE);
			answer_printf(a, "%s", guidhex);
			name = ebox_tpl_part_name(part);
			if (name != NULL) {
				answer_printf(a, " (%s)", name);
			}
			if (npart != NULL) {
				answer_printf(a, ", ");
			}
			part = npart;
		}
		break;
	}
	free(guidhex);
}

static void
interactive_edit_tpl_part(struct ebox_tpl *tpl,
    struct ebox_tpl_config *config, struct ebox_tpl_part *part)
{
	struct question *q;
	struct answer *a;
	char *guidhex;
	int rc;
	struct sshbuf *buf;
	struct sshkey *key;
	char *line, *p;
	errf_t *error;

	buf = sshbuf_new();
	if (buf == NULL)
		err(EXIT_ERROR, "memory allocation failed");

	q = calloc(1, sizeof (struct question));
	if (q == NULL)
		err(EXIT_ERROR, "memory allocation failed");
	a = (struct answer *)ebox_tpl_part_private(part);
	if (a == NULL)
		err(EXIT_ERROR, "memory allocation failed");
	question_printf(q, "-- Editing part %c --\n", a->a_key);

	question_printf(q, "Read-only attributes:\n");
	guidhex = buf_to_hex(ebox_tpl_part_guid(part), GUID_LEN, B_FALSE);
	question_printf(q, "  GUID: %s\n", guidhex);
	free(guidhex);
	if ((rc = sshkey_format_text(ebox_tpl_part_pubkey(part), buf))) {
		errfx(EXIT_ERROR, ssherrf("sshkey_format_text", rc),
		    "failed to write part public key");
	}
	if ((rc = sshbuf_put_u8(buf, '\0'))) {
		errfx(EXIT_ERROR, ssherrf("sshbuf_put_u8", rc),
		    "failed to write part public key (null)");
	}
	question_printf(q, "  Key: %s\n", (char *)sshbuf_ptr(buf));
	sshbuf_reset(buf);

	question_printf(q, "\nSelect an attribute to change:");

	a = make_answer('n', "Name: %s", ebox_tpl_part_name(part));
	add_answer(q, a);
	key = ebox_tpl_part_cak(part);
	if (key != NULL) {
		if ((rc = sshkey_format_text(key, buf))) {
			errfx(EXIT_ERROR, ssherrf("sshkey_format_text", rc),
			    "failed to write part public key");
		}
		if ((rc = sshbuf_put_u8(buf, '\0'))) {
			errfx(EXIT_ERROR, ssherrf("sshbuf_put_u8", rc),
			    "failed to write part public key (null)");
		}
		a = make_answer('c', "Card Auth Key: %s",
		    (char *)sshbuf_ptr(buf));
		sshbuf_reset(buf);
	} else {
		a = make_answer('c', "Card Auth Key: (none set)");
	}
	add_answer(q, a);

	a = make_answer('x', "finish and return");
	add_command(q, a);

again:
	question_prompt(q, &a);
	switch (a->a_key) {
	case 'n':
		line = readline("Name for part? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		ebox_tpl_part_set_name(part, line);
		a->a_used = 0;
		answer_printf(a, "Name: %s", line);
		free(line);
		goto again;
	case 'c':
		line = readline("Card auth key? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		key = sshkey_new(KEY_UNSPEC);
		if (key == NULL)
			err(EXIT_ERROR, "failed to allocate memory");
		p = line;
		rc = sshkey_read(key, &p);
		if (rc) {
			error = ssherrf("sshkey_read", rc);
			warnfx(error, "Invalid card auth key");
			erfree(error);
			free(line);
			goto again;
		}
		free(line);
		ebox_tpl_part_set_cak(part, key);
		sshkey_free(key);
		goto again;
	case 'x':
		goto out;
	}
	goto again;
out:
	question_free(q);
}

static void
interactive_select_local_token(struct ebox_tpl_part **ppart)
{
	int rc;
	errf_t *error;
	struct piv_token *tokens = NULL, *token;
	struct piv_slot *slot;
	struct ebox_tpl_part *part;
	struct question *q;
	struct answer *a;
	char *shortid;
	char k = '0';

	if (!ebox_ctx_init) {
		rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
		    &ebox_ctx);
		if (rc != SCARD_S_SUCCESS) {
			errfx(EXIT_ERROR, pcscerrf("SCardEstablishContext", rc),
			    "failed to initialise libpcsc");
		}
	}

	error = piv_enumerate(ebox_ctx, &tokens);
	if (error) {
		warnfx(error, "failed to enumerate PIV tokens on the system");
		*ppart = NULL;
		erfree(error);
		return;
	}

	q = calloc(1, sizeof (struct question));
	question_printf(q, "-- Selecting local PIV token --\n");
	question_printf(q, "Select a token to use:");

	for (token = tokens; token != NULL; token = piv_token_next(token)) {
		shortid = piv_token_shortid(token);
		if (piv_token_is_ykpiv(token) &&
		    ykpiv_token_has_serial(token)) {
			a = make_answer(++k, "%s (in %s) [serial# %u]",
			    shortid, piv_token_rdrname(token),
			    ykpiv_token_serial(token));
		} else {
			a = make_answer(++k, "%s (in %s)",
			    shortid, piv_token_rdrname(token));
		}
		free(shortid);
		a->a_priv = token;
		add_answer(q, a);
	}

	a = make_answer('x', "cancel");
	add_command(q, a);

again:
	question_prompt(q, &a);
	if (a->a_key == 'x') {
		*ppart = NULL;
		question_free(q);
		piv_release(tokens);
		return;
	}
	token = (struct piv_token *)a->a_priv;

	if ((error = piv_txn_begin(token)))
		errfx(EXIT_ERROR, error, "failed to open token");
	if ((error = piv_select(token)))
		errfx(EXIT_ERROR, error, "failed to select PIV applet");
	if ((error = piv_read_cert(token, PIV_SLOT_KEY_MGMT))) {
		warnfx(error, "failed to read key management (9d) slot");
		erfree(error);
		piv_txn_end(token);
		goto again;
	}
	slot = piv_get_slot(token, PIV_SLOT_KEY_MGMT);
	VERIFY(slot != NULL);
	part = ebox_tpl_part_alloc(piv_token_guid(token), GUID_LEN,
	    piv_slot_pubkey(slot));
	VERIFY(part != NULL);
	error = piv_read_cert(token, PIV_SLOT_CARD_AUTH);
	if (error == NULL) {
		slot = piv_get_slot(token, PIV_SLOT_CARD_AUTH);
		ebox_tpl_part_set_cak(part, piv_slot_pubkey(slot));
	} else {
		erfree(error);
	}
	piv_txn_end(token);

	*ppart = part;
	piv_release(tokens);
}

static void
interactive_edit_tpl_config(struct ebox_tpl *tpl,
    struct ebox_tpl_config *config)
{
	struct question *q, *q2;
	struct answer *a;
	struct ebox_tpl_part *part;
	char *line, *p;
	char k = '0';
	unsigned long int parsed;
	errf_t *error;
	uint8_t *guid;
	size_t guidlen;
	struct sshkey *key;
	int rc;

	q = calloc(1, sizeof (struct question));
	a = (struct answer *)ebox_tpl_config_private(config);
	switch (ebox_tpl_config_type(config)) {
	case EBOX_PRIMARY:
		question_printf(q, "-- Editing primary config %c --\n",
		    a->a_key);
		break;
	case EBOX_RECOVERY:
		question_printf(q, "-- Editing recovery config %c --\n",
		    a->a_key);
		a = calloc(1, sizeof (struct answer));
		a->a_key = 'n';
		answer_printf(a, "%u parts required to recover data (change)",
		    ebox_tpl_config_n(config));
		add_command(q, a);
		break;
	}
	question_printf(q, "Select a part to edit:");
	part = NULL;
	while ((part = ebox_tpl_config_next_part(config, part)) != NULL) {
		a = ebox_tpl_part_alloc_private(part, sizeof (struct answer));
		a->a_key = ++k;
		a->a_priv = part;
		make_answer_text_for_part(part, a);
		add_answer(q, a);
	}

	a = make_answer('+', "add new part/device");
	add_command(q, a);
	a = make_answer('&', "add new part based on local device");
	add_command(q, a);
	a = make_answer('-', "remove a part");
	add_command(q, a);
	a = make_answer('x', "finish and return");
	add_command(q, a);

again:
	question_prompt(q, &a);
	switch (a->a_key) {
	case '&':
		interactive_select_local_token(&part);
		if (part == NULL)
			goto again;
		ebox_tpl_config_add_part(config, part);

		a = ebox_tpl_part_alloc_private(part, sizeof (struct answer));
		a->a_key = ++k;
		a->a_priv = part;

		interactive_edit_tpl_part(tpl, config, part);

		make_answer_text_for_part(part, a);
		add_answer(q, a);

		goto again;
	case '+':
		line = readline("GUID (in hex)? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		error = parse_hex(line, &guid, &guidlen);
		if (error) {
			warnfx(error, "Invalid GUID");
			erfree(error);
			free(line);
			goto again;
		}
		if (guidlen != GUID_LEN) {
			fprintf(stderr, "Invalid GUID: not correct length\n");
			free(line);
			goto again;
		}
		line = readline("Key? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		key = sshkey_new(KEY_ECDSA);
		if (key == NULL)
			err(EXIT_ERROR, "failed to allocate memory");
		p = line;
		rc = sshkey_read(key, &p);
		if (rc) {
			error = ssherrf("sshkey_read", rc);
			warnfx(error, "Invalid public key");
			erfree(error);
			free(line);
			goto again;
		}
		free(line);

		part = ebox_tpl_part_alloc(guid, guidlen, key);
		if (part == NULL)
			err(EXIT_ERROR, "failed to allocate memory");
		sshkey_free(key);
		free(guid);
		ebox_tpl_config_add_part(config, part);

		a = ebox_tpl_part_alloc_private(part, sizeof (struct answer));
		a->a_key = ++k;
		a->a_priv = part;

		interactive_edit_tpl_part(tpl, config, part);

		make_answer_text_for_part(part, a);
		add_answer(q, a);

		goto again;
	case '-':
		q2 = calloc(1, sizeof (struct question));
		question_printf(q2, "Remove which part?");
		q2->q_ans = q->q_ans;
		q2->q_lastans = q->q_lastans;
		a = make_answer('x', "cancel");
		add_command(q2, a);

		question_prompt(q2, &a);
		if (a->a_key != 'x') {
			remove_answer(q, a);
			if (k == a->a_key)
				--k;
			part = (struct ebox_tpl_part *)a->a_priv;
			ebox_tpl_config_remove_part(config, part);
			ebox_tpl_part_free(part);
		}
		q2->q_ans = (q2->q_lastans = NULL);
		question_free(q2);
		goto again;
	case 'n':
		line = readline("Number of parts required? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		errno = 0;
		parsed = strtoul(line, &p, 0);
		if (errno != 0 || *p != '\0') {
			free(line);
			fprintf(stderr, "Failed to interpret response as "
			    "a valid number: %s\n", strerror(errno));
			goto again;
		}
		error = ebox_tpl_config_set_n(config, parsed);
		if (error) {
			warnfx(error, "Invalid value for N");
			erfree(error);
		}
		free(line);
		a->a_used = 0;
		answer_printf(a, "%u parts required to recover data (change)",
		    ebox_tpl_config_n(config));
		goto again;
	case 'x':
		goto out;
	}
	part = (struct ebox_tpl_part *)a->a_priv;
	interactive_edit_tpl_part(tpl, config, part);
	make_answer_text_for_part(part, a);
	goto again;
out:
	part = NULL;
	while ((part = ebox_tpl_config_next_part(config, part)) != NULL) {
		a = (struct answer *)ebox_tpl_part_private(part);
		remove_answer(q, a);
		ebox_tpl_part_free_private(part);
	}
	question_free(q);
}

static void
interactive_edit_tpl(struct ebox_tpl *tpl)
{
	struct question *q, *q2;
	struct answer *a;
	struct ebox_tpl_config *config;
	char k = '0';

	q = calloc(1, sizeof (struct question));
	question_printf(q, "-- Editing template --\n");
	question_printf(q, "Select a configuration to edit:");
	config = NULL;
	while ((config = ebox_tpl_next_config(tpl, config)) != NULL) {
		a = ebox_tpl_config_alloc_private(config,
		    sizeof (struct answer));
		a->a_key = ++k;
		a->a_priv = config;
		make_answer_text_for_config(config, a);
		add_answer(q, a);
	}

	a = make_answer('+', "add new configuration");
	add_command(q, a);
	a = make_answer('-', "remove a configuration");
	add_command(q, a);
	a = make_answer('w', "write and exit");
	add_command(q, a);

again:
	question_prompt(q, &a);
	switch (a->a_key) {
	case '+':
		q2 = calloc(1, sizeof (struct question));
		question_printf(q2, "Add what type of configuration?");
		a = make_answer('p', "primary (single device)");
		add_answer(q2, a);
		a = make_answer('r', "recovery (multi-device, N out of M)");
		add_answer(q2, a);

		a = make_answer('x', "cancel");
		add_command(q2, a);

		question_prompt(q2, &a);
		if (a->a_key == 'p') {
			config = ebox_tpl_config_alloc(EBOX_PRIMARY);
		} else if (a->a_key == 'r') {
			config = ebox_tpl_config_alloc(EBOX_RECOVERY);
		} else {
			question_free(q2);
			goto again;
		}
		ebox_tpl_add_config(tpl, config);

		a = ebox_tpl_config_alloc_private(config,
		    sizeof (struct answer));
		a->a_key = ++k;
		a->a_priv = config;

		interactive_edit_tpl_config(tpl, config);

		make_answer_text_for_config(config, a);
		add_answer(q, a);

		question_free(q2);
		goto again;
	case '-':
		q2 = calloc(1, sizeof (struct question));
		question_printf(q2, "Remove which configuration?");
		q2->q_ans = q->q_ans;
		q2->q_lastans = q->q_lastans;
		a = make_answer('x', "cancel");
		add_command(q2, a);

		question_prompt(q2, &a);
		if (a->a_key != 'x') {
			remove_answer(q, a);
			if (k == a->a_key)
				--k;
			config = (struct ebox_tpl_config *)a->a_priv;
			ebox_tpl_remove_config(tpl, config);
			ebox_tpl_config_free(config);
		}
		q2->q_ans = (q2->q_lastans = NULL);
		question_free(q2);
		goto again;
	case 'w':
		goto write;
	}
	config = (struct ebox_tpl_config *)a->a_priv;
	interactive_edit_tpl_config(tpl, config);
	make_answer_text_for_config(config, a);
	goto again;
write:
	return;
}

enum part_intent {
	INTENT_NONE,
	INTENT_LOCAL,
	INTENT_CHAL_RESP
};

struct part_state {
	struct ebox_part *ps_part;
	struct answer *ps_ans;
	enum part_intent ps_intent;
};

static void
make_answer_text_for_pstate(struct part_state *state)
{
	struct ebox_tpl_part *tpart;
	struct answer *a;
	const char *name;
	char *guidhex = NULL;

	a = state->ps_ans;

	a->a_text[0] = '\0';
	a->a_used = 0;

	tpart = ebox_part_tpl(state->ps_part);

	guidhex = buf_to_hex(ebox_tpl_part_guid(tpart), 4, B_FALSE);
	answer_printf(a, "%s", guidhex);
	free(guidhex);

	name = ebox_tpl_part_name(tpart);
	if (name != NULL)
		answer_printf(a, " (%s)", name);

	switch (state->ps_intent) {
	case INTENT_NONE:
		break;
	case INTENT_LOCAL:
		answer_printf(a, "* [local]");
		break;
	case INTENT_CHAL_RESP:
		answer_printf(a, "* [remote/challenge-response]");
		break;
	}
}

static errf_t *
interactive_part_state(struct part_state *state)
{
	struct ebox_tpl_part *tpart;
	struct question *q = NULL;
	struct answer *a;
	char *guidhex = NULL;
	struct sshbuf *buf = NULL;
	int rc;

	tpart = ebox_part_tpl(state->ps_part);

	buf = sshbuf_new();
	if (buf == NULL)
		err(EXIT_ERROR, "memory allocation failed");

	q = calloc(1, sizeof (struct question));
	if (q == NULL)
		err(EXIT_ERROR, "memory allocation failed");
	question_printf(q, "-- Select recovery method for part %c --\n",
	    state->ps_ans->a_key);

	guidhex = buf_to_hex(ebox_tpl_part_guid(tpart), GUID_LEN, B_FALSE);
	question_printf(q, "GUID: %s\n", guidhex);
	free(guidhex);
	guidhex = NULL;

	question_printf(q, "Name: %s\n", ebox_tpl_part_name(tpart));

	if ((rc = sshkey_format_text(ebox_tpl_part_pubkey(tpart), buf))) {
		errfx(EXIT_ERROR, ssherrf("sshkey_format_text", rc),
		    "failed to write part public key");
	}
	if ((rc = sshbuf_put_u8(buf, '\0'))) {
		errfx(EXIT_ERROR, ssherrf("sshbuf_put_u8", rc),
		    "failed to write part public key (null)");
	}
	question_printf(q, "Public key (9d): %s", (char *)sshbuf_ptr(buf));
	sshbuf_reset(buf);

	a = make_answer('x', "Do not use%s",
	    (state->ps_intent == INTENT_NONE) ? "*" : "");
	add_answer(q, a);
	a = make_answer('l',
	    "Use locally (directly attached to this machine)%s",
	    (state->ps_intent == INTENT_LOCAL) ? "*" : "");
	add_answer(q, a);
	a = make_answer('r', "Use remotely (via challenge-response)%s",
	    (state->ps_intent == INTENT_CHAL_RESP) ? "*" : "");
	add_answer(q, a);

	question_prompt(q, &a);
	switch (a->a_key) {
	case 'x':
		state->ps_intent = INTENT_NONE;
		break;
	case 'l':
		state->ps_intent = INTENT_LOCAL;
		break;
	case 'r':
		state->ps_intent = INTENT_CHAL_RESP;
		break;
	}

	free(guidhex);
	sshbuf_free(buf);
	question_free(q);

	return (NULL);
}

static void
read_b64_box(struct piv_ecdh_box **outbox)
{
	char *linebuf, *p, *line;
	size_t len = 1024, pos = 0, llen;
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
		line = readline("> ");
		if (line == NULL)
			exit(EXIT_ERROR);
		llen = strlen(line);
		if (llen >= 2 && line[0] == '-' && line[1] == '-')
			continue;
		while (pos + llen > len) {
			char *nlinebuf;
			len *= 2;
			nlinebuf = malloc(len);
			nlinebuf[0] = 0;
			strcpy(nlinebuf, linebuf);
			free(linebuf);
			linebuf = nlinebuf;
		}
		strcpy(&linebuf[pos], line);
		pos += llen;
		if (sshbuf_b64tod(buf, linebuf) == 0) {
			struct sshbuf *pbuf = sshbuf_fromb(buf);
			pos = 0;
			linebuf[0] = 0;
			if (sshbuf_get_piv_box(pbuf, &box) == 0)
				sshbuf_free(buf);
			sshbuf_free(pbuf);
		}
	} while (box == NULL);

	*outbox = box;
}

static errf_t *
interactive_recovery(struct ebox_config *config)
{
	struct ebox_part *part;
	struct ebox_tpl_config *tconfig;
	struct ebox_tpl_part *tpart;
	struct part_state *state;
	struct question *q;
	struct answer *a, *adone;
	struct sshbuf *buf;
	struct piv_ecdh_box *box;
	const struct ebox_challenge *chal;
	char k = '0';
	uint n, ncur;
	uint i;
	char *line;
	errf_t *error;
	const uint8_t *words;
	size_t wordlen;

	tconfig = ebox_config_tpl(config);
	n = ebox_tpl_config_n(tconfig);

	q = calloc(1, sizeof (struct question));
	a = (struct answer *)ebox_config_private(config);
	question_printf(q, "-- Recovery config %c --\n", a->a_key);
	question_printf(q, "Select %u parts to use for recovery", n);

	part = NULL;
	while ((part = ebox_config_next_part(config, part)) != NULL) {
		tpart = ebox_part_tpl(part);
		state = ebox_part_alloc_private(part,
		    sizeof (struct part_state));
		VERIFY(state != NULL);
		state->ps_part = part;
		state->ps_ans = (a = calloc(1, sizeof (struct answer)));
		a->a_key = ++k;
		a->a_priv = state;
		VERIFY(state->ps_ans != NULL);
		state->ps_intent = INTENT_NONE;
		make_answer_text_for_pstate(state);
		add_answer(q, a);
	}

	adone = make_answer('r', "begin recovery");

again:
	question_prompt(q, &a);
	if (a->a_key == 'r') {
		goto recover;
	}
	state = (struct part_state *)a->a_priv;
	interactive_part_state(state);
	make_answer_text_for_pstate(state);
	ncur = 0;
	part = NULL;
	while ((part = ebox_config_next_part(config, part)) != NULL) {
		state = (struct part_state *)ebox_part_private(part);
		if (state->ps_intent != INTENT_NONE)
			++ncur;
	}
	if (ncur >= n) {
		add_answer(q, adone);
	} else {
		remove_answer(q, adone);
	}
	goto again;

recover:
	fprintf(stderr,
	    "-- Beginning recovery --\n"
	    "Local devices will be attempted in order before remote "
	    "challenge-responses are processed.\n\n");
	ncur = 0;

	part = NULL;
	while ((part = ebox_config_next_part(config, part)) != NULL) {
		state = (struct part_state *)ebox_part_private(part);
		part = state->ps_part;
		tpart = ebox_part_tpl(part);
		if (state->ps_intent != INTENT_LOCAL)
			continue;
		state->ps_intent = INTENT_NONE;
		make_answer_text_for_pstate(state);
		fprintf(stderr, "-- Local device %s --\n",
		    state->ps_ans->a_text);
partagain:
		error = local_unlock(ebox_part_box(part),
		    ebox_tpl_part_cak(tpart), ebox_tpl_part_name(tpart));
		if (error && !errf_caused_by(error, "NotFoundError"))
			return (error);
		if (error) {
			warnfx(error, "failed to find device");
			line = readline("Retry? ");
			free(line);
			goto partagain;
		}
		fprintf(stderr, "Device box decrypted ok.\n");
		++ncur;
		/*
		 * Forget any PIN the user entered, we'll be talking to a
		 * different device next.
		 */
		free(ebox_pin);
		ebox_pin = NULL;
	}

	buf = sshbuf_new();
	VERIFY(buf != NULL);

	part = NULL;
	while ((part = ebox_config_next_part(config, part)) != NULL) {
		state = (struct part_state *)ebox_part_private(part);
		if (state->ps_intent != INTENT_CHAL_RESP)
			continue;
		state->ps_intent = INTENT_NONE;
		make_answer_text_for_pstate(state);
		state->ps_intent = INTENT_CHAL_RESP;
		error = ebox_gen_challenge(config, part,
		    "Recovering pivy-box data for part %s",
		    state->ps_ans->a_text);
		if (error)
			return (error);
		chal = ebox_part_challenge(part);
		sshbuf_reset(buf);
		error = sshbuf_put_ebox_challenge(buf, chal);
		if (error)
			return (error);
		fprintf(stderr, "-- Begin challenge for remote device %s --\n",
		    state->ps_ans->a_text);
		printwrap(stderr, sshbuf_dtob64(buf), BASE64_LINE_LEN);
		fprintf(stderr, "-- End challenge for remote device %s --\n",
		    state->ps_ans->a_text);

		words = ebox_challenge_words(chal, &wordlen);
		fprintf(stderr, "\nVERIFICATION WORDS for %s:",
		    state->ps_ans->a_text);
		for (i = 0; i < wordlen; ++i)
			fprintf(stderr, " %s", wordlist[words[i]]);
		fprintf(stderr, "\n\n");
	}

	while (ncur < n) {
		fprintf(stderr, "\nRemaining responses required:\n");
		part = NULL;
		while ((part = ebox_config_next_part(config, part)) != NULL) {
			state = (struct part_state *)ebox_part_private(part);
			if (state->ps_intent != INTENT_CHAL_RESP)
				continue;
			fprintf(stderr, "  * %s\n", state->ps_ans->a_text);
		}
		fprintf(stderr, "\n-- Enter response followed by newline --\n");
		read_b64_box(&box);
		fprintf(stderr, "-- End response --\n");
		error = ebox_challenge_response(config, box, &part);
		if (error) {
			warnfx(error, "failed to parse input data as a "
			    "valid response");
			continue;
		}
		state = (struct part_state *)ebox_part_private(part);
		if (state->ps_intent != INTENT_CHAL_RESP) {
			fprintf(stderr, "Response already processed for "
			    "device %s!\n", state->ps_ans->a_text);
			continue;
		}
		fprintf(stderr, "Device box for %s decrypted ok.\n",
		    state->ps_ans->a_text);
		state->ps_intent = INTENT_NONE;
		++ncur;
	}
	return (NULL);

}

static errf_t *
interactive_unlock_ebox(struct ebox *ebox)
{
	struct ebox_config *config;
	struct ebox_part *part;
	struct ebox_tpl_part *tpart;
	struct ebox_tpl_config *tconfig;
	errf_t *error;
	struct question *q;
	struct answer *a;
	char k = '0';

	config = NULL;
	while ((config = ebox_next_config(ebox, config)) != NULL) {
		tconfig = ebox_config_tpl(config);
		if (ebox_tpl_config_type(tconfig) == EBOX_PRIMARY) {
			part = ebox_config_next_part(config, NULL);
			tpart = ebox_part_tpl(part);
			error = local_unlock(ebox_part_box(part),
			    ebox_tpl_part_cak(tpart),
			    ebox_tpl_part_name(tpart));
			if (error && !errf_caused_by(error, "NotFoundError"))
				return (error);
			if (error) {
				erfree(error);
				continue;
			}
			error = ebox_unlock(ebox, config);
			if (error)
				return (error);
			goto done;
		}
	}

	q = calloc(1, sizeof (struct question));
	question_printf(q, "-- Recovery mode --\n");
	question_printf(q, "Select a configuration to use for recovery:");
	config = NULL;
	while ((config = ebox_next_config(ebox, config)) != NULL) {
		tconfig = ebox_config_tpl(config);
		if (ebox_tpl_config_type(tconfig) == EBOX_RECOVERY) {
			a = ebox_config_alloc_private(config,
			    sizeof (struct answer));
			a->a_key = ++k;
			a->a_priv = config;
			make_answer_text_for_config(tconfig, a);
			add_answer(q, a);
		}
	}
	question_prompt(q, &a);
	config = (struct ebox_config *)a->a_priv;
	error = interactive_recovery(config);
	if (error)
		return (error);
	error = ebox_recover(ebox, config);
	if (error)
		return (error);

done:
	return (ERRF_OK);
}

static errf_t *
cmd_tpl_create(const char *tplfile, int argc, char *argv[])
{
	uint i;
	size_t len;
	struct ebox_tpl *tpl;
	struct ebox_tpl_config *config = NULL;
	errf_t *error = NULL;
	struct sshbuf *buf;
	FILE *file;
	char *dirpath;

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

	if (ebox_interactive) {
		interactive_edit_tpl(tpl);
	}

	buf = sshbuf_new();
	error = sshbuf_put_ebox_tpl(buf, tpl);
	if (error)
		return (error);

	file = fopen(tplfile, "w");
	if (file == NULL && errno == ENOENT) {
		dirpath = strdup(tplfile);
		len = strlen(dirpath);
		for (i = 1; i < len; ++i) {
			if (dirpath[i] != '/')
				continue;
			dirpath[i] = '\0';
			if (mkdir(dirpath, 0755)) {
				if (errno != EEXIST) {
					return (errfno("mkdir", errno,
					    "creating directory '%s'",
					    dirpath));
				}
			}
			dirpath[i] = '/';
		}
		free(dirpath);
		file = fopen(tplfile, "w");
	}
	if (file == NULL) {
		return (errfno("fopen", errno, "opening template file '%s' "
		    "for writing", tplfile));
	}
	printwrap(file, sshbuf_dtob64(buf), BASE64_LINE_LEN);
	fclose(file);

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
	if (ferror(stdin))
		err(EXIT_USAGE, "error reading input");
	if (!feof(stdin))
		errx(EXIT_USAGE, "input too long (max %lu bytes)", limit);
	if (n > limit)
		errx(EXIT_USAGE, "input too long (max %lu bytes)", limit);

	sbuf = sshbuf_new();
	if (sbuf == NULL)
		err(EXIT_ERROR, "failed to allocate buffer");

	if (!ebox_raw_in) {
		buf[n] = '\0';
		rc = sshbuf_b64tod(sbuf, buf);
		if (rc) {
			errf_t *error = ssherrf("sshbuf_b64tod", rc);
			errfx(EXIT_ERROR, error, "error parsing input as "
			    "base64");
		}
	} else {
		rc = sshbuf_put(sbuf, buf, n);
		if (rc) {
			errf_t *error = ssherrf("sshbuf_put", rc);
			errfx(EXIT_ERROR, error, "error reading input");
		}
	}
	return (sbuf);
}

static errf_t *
cmd_tpl_edit(const char *tplfile, int argc, char *argv[])
{
	uint i;
	size_t len;
	struct ebox_tpl_config *config = NULL, *nconfig;
	errf_t *error = NULL;
	struct sshbuf *buf;
	FILE *file;
	char *dirpath;

	for (i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "add-primary") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'add-primary' keyword requires arguments");
				goto out;
			}
			config = ebox_tpl_config_alloc(EBOX_PRIMARY);
			ebox_tpl_add_config(ebox_stpl, config);
			error = parse_keywords_primary(config, argc, argv, &i);
			if (error)
				return (error);
		} else if (strcmp(argv[i], "add-recovery") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'add-recovery' keyword requires "
				    "arguments");
				goto out;
			}
			config = ebox_tpl_config_alloc(EBOX_RECOVERY);
			ebox_tpl_add_config(ebox_stpl, config);
			error = parse_keywords_recovery(config, argc, argv, &i);
			if (error)
				return (error);
		} else if (strcmp(argv[i], "remove-primary") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'remove-primary' keyword requires "
				    "arguments");
				goto out;
			}
			if (strcmp(argv[i], "all") == 0) {
				nconfig = ebox_tpl_next_config(ebox_stpl, NULL);
				while ((config = nconfig) != NULL) {
					nconfig = ebox_tpl_next_config(
					    ebox_stpl, config);
					if (ebox_tpl_config_type(config) ==
					    EBOX_PRIMARY) {
						ebox_tpl_remove_config(
						    ebox_stpl, config);
						ebox_tpl_config_free(config);
					}
				}
			} else {
				return (errf("SyntaxError", NULL,
				    "unexpected argument to "
				    "remove-primary: '%s'", argv[i]));
			}
		} else if (strcmp(argv[i], "remove-recovery") == 0) {
			if (++i > argc) {
				error = errf("SyntaxError", NULL,
				    "'remove-recovery' keyword requires "
				    "arguments");
				goto out;
			}
			if (strcmp(argv[i], "all") == 0) {
				nconfig = ebox_tpl_next_config(ebox_stpl, NULL);
				while ((config = nconfig) != NULL) {
					nconfig = ebox_tpl_next_config(
					    ebox_stpl, config);
					if (ebox_tpl_config_type(config) ==
					    EBOX_RECOVERY) {
						ebox_tpl_remove_config(
						    ebox_stpl, config);
						ebox_tpl_config_free(config);
					}
				}
			} else {
				return (errf("SyntaxError", NULL,
				    "unexpected argument to "
				    "remove-recovery: '%s'", argv[i]));
			}
		} else {
			return (errf("SyntaxError", NULL,
			    "unexpected configuration keyword '%s'", argv[i]));
		}
	}

	if (ebox_interactive) {
		interactive_edit_tpl(ebox_stpl);
	}

	buf = sshbuf_new();
	error = sshbuf_put_ebox_tpl(buf, ebox_stpl);
	if (error)
		return (error);

	file = fopen(tplfile, "w");
	if (file == NULL && errno == ENOENT) {
		dirpath = strdup(tplfile);
		len = strlen(dirpath);
		for (i = 1; i < len; ++i) {
			if (dirpath[i] != '/')
				continue;
			dirpath[i] = '\0';
			if (mkdir(dirpath, 0755)) {
				if (errno != EEXIST) {
					return (errfno("mkdir", errno,
					    "creating directory '%s'",
					    dirpath));
				}
			}
			dirpath[i] = '/';
		}
		free(dirpath);
		file = fopen(tplfile, "w");
	}
	if (file == NULL) {
		return (errfno("fopen", errno, "opening template file '%s' "
		    "for writing", tplfile));
	}
	printwrap(file, sshbuf_dtob64(buf), BASE64_LINE_LEN);
	fclose(file);

out:
	return (error);
}

static void
print_tpl(FILE *stream, const struct ebox_tpl *tpl)
{
	struct ebox_tpl_config *config = NULL;
	int rc;

	fprintf(stream, "-- template --\n");
	fprintf(stream, "version: %u\n", ebox_tpl_version(tpl));

	while ((config = ebox_tpl_next_config(tpl, config))) {
		fprintf(stream, "configuration:\n");
		switch (ebox_tpl_config_type(config)) {
		case EBOX_PRIMARY:
			fprintf(stream, "  type: primary\n");
			break;
		case EBOX_RECOVERY:
			fprintf(stream, "  type: recovery\n");
			fprintf(stream, "  required: %u parts\n",
			    ebox_tpl_config_n(config));
			break;
		}
		struct ebox_tpl_part *part = NULL;
		while ((part = ebox_tpl_config_next_part(config, part))) {
			char *guidhex;
			fprintf(stream, "  part:\n");
			guidhex = buf_to_hex(ebox_tpl_part_guid(part),
			    GUID_LEN, B_FALSE);
			fprintf(stream, "    guid: %s\n", guidhex);
			free(guidhex);
			if (ebox_tpl_part_name(part) != NULL) {
				fprintf(stream, "    name: %s\n",
				    ebox_tpl_part_name(part));
			}
			fprintf(stream, "    key: ");
			rc = sshkey_write(ebox_tpl_part_pubkey(part), stream);
			if (rc != 0) {
				errfx(EXIT_ERROR, ssherrf("sshkey_write", rc),
				    "failed to print pubkey of ebox part");
			}
			fprintf(stream, "\n");
			if (ebox_tpl_part_cak(part) != NULL) {
				fprintf(stream, "    cak: ");
				rc = sshkey_write(ebox_tpl_part_cak(part),
				    stream);
				if (rc != 0) {
					errfx(EXIT_ERROR,
					    ssherrf("sshkey_write", rc),
					    "failed to print cak of ebox part");
				}
				fprintf(stream, "\n");
			}
		}
	}
}

static errf_t *
cmd_tpl_show(int argc, char *argv[])
{
	errf_t *error;

	if (ebox_stpl == NULL) {
		struct sshbuf *sbuf = read_stdin_b64(TPL_MAX_SIZE);
		error = sshbuf_get_ebox_tpl(sbuf, &ebox_stpl);
		if (error) {
			errfx(EXIT_ERROR, error, "failed to parse input as "
			    "a base64-encoded ebox template");
		}
	}

	print_tpl(stderr, ebox_stpl);

	return (NULL);
}

static errf_t *
cmd_key_generate(int argc, char *argv[])
{
	uint8_t *key;
	struct ebox *ebox;
	errf_t *error;
	struct sshbuf *buf;

	key = calloc(1, ebox_keylen);
	if (key == NULL)
		errx(EXIT_ERROR, "failed to allocate memory");

	(void) mlockall(MCL_CURRENT | MCL_FUTURE);
#if defined(MADV_DONTDUMP)
	(void) madvise(key, ebox_keylen, MADV_DONTDUMP);
#endif

	arc4random_buf(key, ebox_keylen);

	error = ebox_create(ebox_stpl, key, ebox_keylen, NULL, 0, &ebox);
	if (error)
		return (error);

	buf = sshbuf_new();
	if (buf == NULL)
		errx(EXIT_ERROR, "failed to allocate memory");

	error = sshbuf_put_ebox(buf, ebox);
	if (error)
		return (error);

	if (ebox_raw_out) {
		fwrite(sshbuf_ptr(buf), sshbuf_len(buf), 1, stdout);
	} else {
		printwrap(stdout, sshbuf_dtob64(buf), BASE64_LINE_LEN);
	}

	ebox_free(ebox);
	return (ERRF_OK);
}

static errf_t *
cmd_key_lock(int argc, char *argv[])
{
	const uint8_t *key;
	size_t keylen;
	struct ebox *ebox;
	errf_t *error;
	struct sshbuf *buf;

	(void) mlockall(MCL_CURRENT | MCL_FUTURE);

	buf = read_stdin_b64(EBOX_MAX_SIZE);
	key = sshbuf_ptr(buf);
	keylen = sshbuf_len(buf);

#if defined(MADV_DONTDUMP)
	(void) madvise((void *)key, keylen, MADV_DONTDUMP);
#endif

	error = ebox_create(ebox_stpl, key, keylen, NULL, 0, &ebox);
	if (error)
		return (error);

	buf = sshbuf_new();
	if (buf == NULL)
		errx(EXIT_ERROR, "failed to allocate memory");

	error = sshbuf_put_ebox(buf, ebox);
	if (error)
		return (error);

	if (ebox_raw_out) {
		fwrite(sshbuf_ptr(buf), sshbuf_len(buf), 1, stdout);
	} else {
		printwrap(stdout, sshbuf_dtob64(buf), BASE64_LINE_LEN);
	}

	ebox_free(ebox);
	return (ERRF_OK);
}

static errf_t *
cmd_key_relock(int argc, char *argv[])
{
	struct ebox *ebox, *nebox;
	errf_t *error;
	struct sshbuf *buf;
	size_t keylen;
	const uint8_t *key;

	buf = read_stdin_b64(EBOX_MAX_SIZE);
	error = sshbuf_get_ebox(buf, &ebox);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse input as "
		    "a base64-encoded ebox");
	}

	(void) mlockall(MCL_CURRENT | MCL_FUTURE);

	error = interactive_unlock_ebox(ebox);
	if (error)
		return (error);

	key = ebox_key(ebox, &keylen);

	error = ebox_create(ebox_stpl, key, keylen, NULL, 0, &nebox);
	if (error)
		return (error);

	sshbuf_reset(buf);

	error = sshbuf_put_ebox(buf, nebox);
	if (error)
		return (error);

	if (ebox_raw_out) {
		fwrite(sshbuf_ptr(buf), sshbuf_len(buf), 1, stdout);
	} else {
		printwrap(stdout, sshbuf_dtob64(buf), BASE64_LINE_LEN);
	}

	ebox_free(ebox);
	ebox_free(nebox);
	return (ERRF_OK);
}

static errf_t *
cmd_key_info(int argc, char *argv[])
{
	struct sshbuf *buf;
	struct ebox *ebox;
	struct ebox_tpl *tpl;
	errf_t *error;

	buf = read_stdin_b64(EBOX_MAX_SIZE);
	error = sshbuf_get_ebox(buf, &ebox);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse input as "
		    "a base64-encoded ebox");
	}

	fprintf(stderr, "-- ebox --\n");
	fprintf(stderr, "version: %u\n", ebox_version(ebox));
	switch (ebox_type(ebox)) {
	case EBOX_KEY:
		fprintf(stderr, "type: key\n");
		break;
	case EBOX_STREAM:
		fprintf(stderr, "type: stream\n");
		break;
	default:
		break;
	}
	fprintf(stderr, "ephemeral keys: %u\n", ebox_ephem_count(ebox));
	fprintf(stderr, "recovery cipher: %s\n", ebox_cipher(ebox));

	tpl = ebox_tpl(ebox);
	print_tpl(stderr, tpl);

	return (ERRF_OK);
}

static errf_t *
cmd_key_unlock(int argc, char *argv[])
{
	struct ebox *ebox;
	errf_t *error;
	struct sshbuf *buf;
	size_t keylen;
	const uint8_t *key;

	buf = read_stdin_b64(EBOX_MAX_SIZE);
	error = sshbuf_get_ebox(buf, &ebox);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse input as "
		    "a base64-encoded ebox");
	}

	(void) mlockall(MCL_CURRENT | MCL_FUTURE);

	error = interactive_unlock_ebox(ebox);
	if (error)
		return (error);

	key = ebox_key(ebox, &keylen);
	buf = sshbuf_from(key, keylen);
	if (buf == NULL)
		errx(EXIT_ERROR, "failed to allocate memory");
	if (ebox_raw_out) {
		fwrite(sshbuf_ptr(buf), sshbuf_len(buf), 1, stdout);
	} else {
		printwrap(stdout, sshbuf_dtob64(buf), BASE64_LINE_LEN);
	}
	sshbuf_free(buf);
	return (ERRF_OK);
}

static errf_t *
cmd_stream_encrypt(int argc, char *argv[])
{
	struct ebox_stream *es;
	struct ebox_stream_chunk *esc;
	errf_t *error;
	uint8_t *ibuf;
	struct sshbuf *obuf;
	size_t chunksz, nread, nwrote;
	size_t seq = 0;

	(void) mlockall(MCL_CURRENT | MCL_FUTURE);

	error = ebox_stream_new(ebox_stpl, &es);
	if (error)
		return (error);
	chunksz = ebox_stream_chunk_size(es);
	ibuf = malloc(chunksz);
	if (ibuf == NULL)
		errx(EXIT_ERROR, "failed to allocate memory");
	obuf = sshbuf_new();
	if (obuf == NULL)
		errx(EXIT_ERROR, "failed to allocate memory");

	error = sshbuf_put_ebox_stream(obuf, es);
	if (error)
		return (error);
	while (sshbuf_len(obuf) > 0) {
		nwrote = fwrite(sshbuf_ptr(obuf), 1, sshbuf_len(obuf), stdout);
		sshbuf_consume(obuf, nwrote);
	}
	sshbuf_reset(obuf);

	while (!feof(stdin) && !ferror(stdin)) {
		nread = fread(ibuf, 1, chunksz, stdin);
		if (nread < 1)
			continue;
		error = ebox_stream_chunk_new(es, ibuf, nread, ++seq, &esc);
		if (error)
			return (error);
		error = ebox_stream_encrypt_chunk(esc);
		if (error)
			return (error);
		error = sshbuf_put_ebox_stream_chunk(obuf, esc);
		if (error)
			return (error);
		while (sshbuf_len(obuf) > 0) {
			nwrote = fwrite(sshbuf_ptr(obuf), 1, sshbuf_len(obuf),
			    stdout);
			sshbuf_consume(obuf, nwrote);
		}
		sshbuf_reset(obuf);
		ebox_stream_chunk_free(esc);
	}

	ebox_stream_free(es);
	return (ERRF_OK);
}

static errf_t *
cmd_stream_decrypt(int argc, char *argv[])
{
	struct ebox_stream *es = NULL;
	struct ebox_stream_chunk *esc = NULL;
	struct ebox *ebox;
	errf_t *error;
	uint8_t *buf;
	const uint8_t *data;
	struct sshbuf *ibuf, *nbuf;
	size_t nread, nwrote, poff;

	(void) mlockall(MCL_CURRENT | MCL_FUTURE);

	buf = malloc(8192);
	VERIFY(buf != NULL);

	ibuf = sshbuf_new();
	VERIFY(ibuf != NULL);

	while (es == NULL) {
		nread = fread(buf, 1, 8192, stdin);
		if (nread < 1 && ferror(stdin))
			err(EXIT_ERROR, "failed to read input");
		VERIFY0(sshbuf_put(ibuf, buf, nread));

		poff = ibuf->off;
		error = sshbuf_get_ebox_stream(ibuf, &es);
		if (errf_caused_by(error, "IncompleteMessageError")) {
			if (feof(stdin))
				errfx(EXIT_ERROR, error, "input too short");
			ibuf->off = poff;
			erfree(error);
			continue;
		} else if (error) {
			return (error);
		}
		break;
	}

	if (es == NULL) {
		return (errf("IncompleteInputError", NULL,
		    "input was incomplete"));
	}

	ebox = ebox_stream_ebox(es);

	error = interactive_unlock_ebox(ebox);
	if (error)
		return (error);

	while (1) {
		nread = fread(buf, 1, 8192, stdin);
		if (nread < 1 && ferror(stdin))
			err(EXIT_ERROR, "failed to read input");
		else if (nread < 1 && feof(stdin) && sshbuf_len(ibuf) == 0)
			break;
		VERIFY0(sshbuf_put(ibuf, buf, nread));

		poff = ibuf->off;
		error = sshbuf_get_ebox_stream_chunk(ibuf, es, &esc);
		if (errf_caused_by(error, "IncompleteMessageError")) {
			if (feof(stdin))
				errfx(EXIT_ERROR, error, "input too short");
			ibuf->off = poff;
			erfree(error);
			continue;
		} else if (error) {
			return (error);
		}

		error = ebox_stream_decrypt_chunk(esc);
		if (error)
			return (error);

		data = ebox_stream_chunk_data(esc, &nread);

		nwrote = fwrite(data, 1, nread, stdout);
		if (nwrote < nread)
			err(EXIT_ERROR, "failed to write data");

		ebox_stream_chunk_free(esc);
		esc = NULL;

		if (sshbuf_len(ibuf) > 0) {
			nbuf = sshbuf_new();
			VERIFY(nbuf != NULL);
			VERIFY0(sshbuf_put(nbuf, sshbuf_ptr(ibuf),
			    sshbuf_len(ibuf)));
			sshbuf_free(ibuf);
			ibuf = nbuf;
		}
	}

	ebox_stream_free(es);
	ebox_stream_chunk_free(esc);
	return (ERRF_OK);
}

static void
print_challenge(const struct ebox_challenge *chal)
{
	const char *purpose;
	struct tm tmctime;
	time_t ctime;
	char tbuf[128];
	const uint8_t *words;
	size_t wordlen;

	fprintf(stderr, "-- Challenge --\n");
	switch (ebox_challenge_type(chal)) {
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
	fprintf(stderr, "%-20s   %s\n", "Description",
	    ebox_challenge_desc(chal));
	fprintf(stderr, "%-20s   %s\n", "Hostname",
	    ebox_challenge_hostname(chal));

	bzero(&tmctime, sizeof (tmctime));
	ctime = (time_t)ebox_challenge_ctime(chal);
	localtime_r(&ctime, &tmctime);
	strftime(tbuf, sizeof (tbuf), "%Y-%m-%d %H:%M:%S", &tmctime);
	fprintf(stderr, "%-20s   %s (local time)\n", "Generated at", tbuf);

	words = ebox_challenge_words(chal, &wordlen);
	VERIFY3U(wordlen, ==, 4);
	fprintf(stderr, "\n%-20s   %s %s %s %s\n\n", "VERIFICATION WORDS",
	    wordlist[words[0]], wordlist[words[1]],
	    wordlist[words[2]], wordlist[words[3]]);
}

static errf_t *
cmd_challenge_info(int argc, char *argv[])
{
	struct ebox_challenge *chal;
	struct sshbuf *sbuf;
	struct piv_ecdh_box *box;
	errf_t *error;

	sbuf = read_stdin_b64(TPL_MAX_SIZE);
	error = sshbuf_get_piv_box(sbuf, &box);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse input as "
		    "a base64-encoded ebox challenge");
	}

	error = local_unlock(box, NULL, NULL);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to unlock challenge");
	}

	error = sshbuf_get_ebox_challenge(box, &chal);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse contents of "
		    "challenge box");
	}

	print_challenge(chal);

	return (NULL);
}

static errf_t *
cmd_challenge_respond(int argc, char *argv[])
{
	struct ebox_challenge *chal;
	struct sshbuf *sbuf;
	struct piv_ecdh_box *box;
	errf_t *error;
	char *line;

	sbuf = read_stdin_b64(TPL_MAX_SIZE);
	error = sshbuf_get_piv_box(sbuf, &box);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse input as "
		    "a base64-encoded ebox challenge");
	}

	error = local_unlock(box, NULL, NULL);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to unlock challenge");
	}

	error = sshbuf_get_ebox_challenge(box, &chal);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to parse contents of "
		    "challenge box");
	}

	print_challenge(chal);

	fprintf(stderr, "Please check that these verification words match the "
	    "original source via a\nseparate communications channel to the "
	    "one used to transport the challenge\nitself.\n\n");

	line = readline("If these details are correct and you wish to "
	    "respond, type 'YES': ");
	if (line == NULL)
		exit(EXIT_ERROR);
	if (strcmp(line, "YES") != 0)
		exit(EXIT_ERROR);
	free(line);

	box = ebox_challenge_box(chal);
	error = local_unlock(box, NULL, NULL);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to unlock challenge");
	}

	sshbuf_reset(sbuf);
	error = sshbuf_put_ebox_challenge_response(sbuf, chal);
	if (error) {
		errfx(EXIT_ERROR, error, "failed to generate response");
	}

	fprintf(stdout, "-- Begin response --\n");
	printwrap(stdout, sshbuf_dtob64(sbuf), BASE64_LINE_LEN);
	fprintf(stdout, "-- End response --\n");

	return (NULL);
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
	if ((error = sshbuf_get_ebox_tpl(sbuf, &ebox_stpl))) {
		errfx(EXIT_ERROR, error, "failed to parse contents of '%s' as "
		    "a base64-encoded ebox template", tpl);
	}
	sshbuf_free(sbuf);
	free(buf);
}

static void
usage_types(void)
{
	fprintf(stderr,
	    "usage: pivy-box <type> <operation> [options] [tpl]\n"
	    "\n");
	fprintf(stderr,
	    "Creates and manages eboxes, which encrypt data so that it can be\n"
	    "decrypted and authenticated using PIV tokens (or N/M sets of PIV\n"
	    "tokens) supported by pivy.\n"
	    "\n"
	    "Options:\n"
	    "  -b         batch mode, don't talk to terminal\n"
	    "  -r         raw input, don't base64-decode stdin\n"
	    "  -R         raw output, don't base64-encode stdout\n"
	    "  -i         interactive mode (for editing etc)\n"
	    "  -f <path>  full path to tpl file instead of using [tpl] arg\n"
	    "\n");
	fprintf(stderr,
	    "If not using -f, templates are stored in " TPL_DEFAULT_PATH "\n\n",
	    "$HOME", "*");
	fprintf(stderr,
	    "pivy-box <type>:\n"
	    "  tpl|template          Manage templates which track a set of\n"
	    "                        devices and N/M config\n"
	    "  key                   Encrypt small amounts of data (up to 10s\n"
	    "                        of bytes)\n"
	    "  stream                Encrypt larger amounts of data which can\n"
	    "                        be streamed (doesn't have to fit in RAM)\n"
	    "  challenge             Respond to recovery challenges issued by\n"
	    "                        other commands\n");
}

static void
usage_tpl(const char *op)
{
	if (op == NULL) {
		goto noop;
	} else if (strcmp(op, "create") == 0) {
		fprintf(stderr,
		    "usage: pivy-box tpl create [-i] <tpl> [builder...]\n"
		    "\n"
		    "Creates a new template which can then be used with the\n"
		    "pivy-box key or stream commands. Can be invoked either\n"
		    "with a set of 'builder' arguments to specify the template\n"
		    "or with -i to interactively create it through a menu\n"
		    "interface.\n"
		    "\n"
		    "Options:\n"
		    "  -i         interactive mode\n"
		    "\n"
		    "<builder>:\n"
		    "  primary < ... >        Specifies a primary config\n"
		    "    local-guid <guid>    Generates based on a local device\n"
		    "    name <string>\n"
		    "    guid <guid>\n"
		    "    slot <hex>\n"
		    "    key <'ecdsa-sha2-nistp256 AA...'>       Sets 9d key\n"
		    "    cak <'ecdsa-sha2-nistp256 AA...'>       Sets 9e key\n"
		    "  recovery < ... >       Specifies a recovery config\n"
		    "    require <int>        Set # of parts required\n"
		    "    part < ... >         Specifies a part for the config\n"
		    "      name/guid/slot/key\n");
	} else if (strcmp(op, "edit") == 0) {
		fprintf(stderr,
		    "usage: pivy-box tpl edit [-i] <tpl> [builder...]\n"
		    "\n"
		    "Makes changes to an existing template.\n"
		    "\n"
		    "Options:\n"
		    "  -i         interactive mode\n"
		    "\n"
		    "<builder>:\n"
		    "  remove-primary all     Remove all primary configs\n"
		    "  remove-recovery all    Remove all recovery configs\n"
		    "  add-primary < ... >    Add a new primary config\n"
		    "    local-guid <guid>    Generates based on a local device\n"
		    "    name <string>\n"
		    "    guid <guid>\n"
		    "    slot <hex>\n"
		    "    key <'ecdsa-sha2-nistp256 AA...'>       Sets 9d key\n"
		    "    cak <'ecdsa-sha2-nistp256 AA...'>       Sets 9e key\n"
		    "  add-recovery < ...>    Add a new recovery config\n"
		    "    require <int>        Set # of parts required\n"
		    "    part < ... >         Specifies a part for the config\n"
		    "      name/guid/slot/key\n");
	} else if (strcmp(op, "show") == 0) {
		fprintf(stderr,
		    "usage: pivy-box tpl show [-r] [tpl]\n"
		    "\n"
		    "Pretty-prints a template to stdout showing details of\n"
		    "devices and configuration.\n"
		    "\n"
		    "Options:\n"
		    "  -r         raw input, don't base64-decode stdin\n"
		    "\n"
		    "If no [tpl] or -f given, expects template input on stdin.\n");
	} else {
noop:
		fprintf(stderr,
		    "pivy-box tpl <op>:\n"
		    "  create                Create a new template\n"
		    "  edit                  Edit an existing template\n"
		    "  show                  Pretty-print a template to stdout\n");
	}
}

static void
usage_key(const char *op)
{
	if (op == NULL) {
		goto noop;
	} else if (strcmp(op, "generate") == 0) {
		fprintf(stderr,
		    "usage: pivy-box key generate [-R] [-l len] <tpl>\n"
		    "\n"
		    "Generates random key material of a specified length\n"
		    "(default 16 bytes), encrypts it with an ebox and outputs\n"
		    "just the ebox.\n"
		    "\n"
		    "Options:\n"
		    "  -R         raw output, don't base64-encode stdout\n"
		    "  -l len     set length of key in bytes\n"
		    "\n");
	} else if (strcmp(op, "info") == 0) {
		fprintf(stderr,
		    "usage: pivy-box key info [-r]\n"
		    "\n"
		    "Pretty-prints information about a 'key' ebox.\n"
		    "\n"
		    "Options:\n"
		    "  -r         raw input, don't base64-decode stdin\n"
		    "\n");
	} else if (strcmp(op, "lock") == 0) {
		fprintf(stderr,
		    "usage: pivy-box key lock [-rR] <tpl>\n"
		    "\n"
		    "Takes pre-generated key material and encrypts it with\n"
		    "a 'key' ebox. This is not suitable for large amounts\n"
		    "of data.\n"
		    "\n"
		    "Options:\n"
		    "  -r         raw input, don't base64-decode stdin\n"
		    "  -R         raw output, don't base64-encode stdout\n"
		    "\n");
	} else if (strcmp(op, "unlock") == 0) {
		fprintf(stderr,
		    "usage: pivy-box key unlock [-brR]\n"
		    "\n"
		    "Decrypts a 'key' ebox and outputs the contents.\n"
		    "\n"
		    "Options:\n"
		    "  -b         batch mode, don't talk to terminal\n"
		    "  -r         raw input, don't base64-decode stdin\n"
		    "  -R         raw output, don't base64-encode stdout\n"
		    "\n");
	} else if (strcmp(op, "relock") == 0) {
		fprintf(stderr,
		    "usage: pivy-box key relock [-brR] <newtpl>\n"
		    "\n"
		    "Decrypts a 'key' ebox and then re-encrypts it with a new\n"
		    "template. Can be used to update an ebox after editing\n"
		    "the template to add/remove devices.\n"
		    "\n"
		    "Options:\n"
		    "  -b         batch mode, don't talk to terminal\n"
		    "  -r         raw input, don't base64-decode stdin\n"
		    "  -R         raw output, don't base64-encode stdout\n"
		    "\n");
	} else {
noop:
		fprintf(stderr,
		    "pivy-box key <op>:\n"
		    "  generate              Generate a random key and ebox it\n"
		    "  lock                  Ebox a pre-generated key\n"
		    "  info                  Prints information about a key ebox\n"
		    "  unlock                Unlock a key ebox\n"
		    "  relock                Unlock + lock to new template\n");
	}
}

static void
usage_stream(const char *op)
{
	if (op == NULL) {
		goto noop;
	} else if (strcmp(op, "encrypt") == 0) {
		fprintf(stderr,
		    "usage: pivy-box stream encrypt <tpl>\n"
		    "\n"
		    "Accepts streaming data on stdin and encrypts it to the\n"
		    "given template in chunks. Output is binary.\n");
	} else if (strcmp(op, "decrypt") == 0) {
		fprintf(stderr,
		    "usage: pivy-box stream decrypt [-b]\n"
		    "\n"
		    "Accepts output from 'stream encrypt' on stdin, decrypts\n"
		    "it and outputs the plaintext. Data is only output after\n"
		    "it has been authenticated/validated.\n"
		    "\n"
		    "Options:\n"
		    "  -b         batch mode, don't talk to terminal\n"
		    "\n");
	} else {
noop:
		fprintf(stderr,
		    "pivy-box stream <op>:\n"
		    "  encrypt               Encrypt streaming data\n"
		    "  decrypt               Decrypt streaming data\n");
	}
}

static void
usage_challenge(const char *op)
{
	if (op == NULL) {
		goto noop;
	} else if (strcmp(op, "info") == 0) {
		fprintf(stderr,
		    "usage: pivy-box challenge info\n"
		    "\n"
		    "Takes a recovery challenge (such as that output by\n"
		    "the 'key unlock' or 'stream decrypt' commands), decrypts\n"
		    "it, and prints the contained information to stdout.\n");
	} else if (strcmp(op, "respond") == 0) {
		fprintf(stderr,
		    "usage: pivy-box challenge respond\n"
		    "\n"
		    "Takes a recovery challenge (such as that output by\n"
		    "the 'key unlock' or 'stream decrypt' commands), decrypts\n"
		    "it, prints the contained information to stdout, then\n"
		    "waits for user confirmation before generating a response.\n"
		    "\n"
		    "The response must then be transported back to the program\n"
		    "which generated the challenge to complete the process.\n");
	} else {
noop:
		fprintf(stderr,
		    "pivy-box challenge <op>:\n"
		    "  info                  Show information about a recovery\n"
		    "                        challenge without responding\n"
		    "  respond               Respond to a recovery challenge\n");
	}
}

static void
usage(const char *type, const char *op)
{
	if (type == NULL) {
		usage_types();
	} else if (strcmp(type, "tpl") == 0 || strcmp(type, "template") == 0) {
		usage_tpl(op);
	} else if (strcmp(type, "key") == 0) {
		usage_key(op);
	} else if (strcmp(type, "stream") == 0) {
		usage_stream(op);
	} else if (strcmp(type, "challenge") == 0) {
		usage_challenge(op);
	} else {
		usage_types();
	}
	return;
	fprintf(stderr,
	    "\n"
	    "- pivy-box stream <op>\n"
	    "\n"
	    "  - pivy-box stream encrypt <tpl>\n"
	    "      Encrypt streaming data on stdin to the given ebox template\n"
	    "      Outputs the encrypted stream on stdout in chunks.\n"
	    "\n"
	    "  - pivy-box stream decrypt\n"
	    "      Decrypt a stream from `stream encrypt' on stdin, outputting\n"
	    "      the decrypted data on stdout in chunks.\n"
	    "\n"
	    "- pivy-box challenge <op>\n"
	    "\n"
	    "  - pivy-box challenge info\n"
	    "      Print info about a recovery challenge provided on stdin,\n"
	    "      without generating a response.\n"
	    "\n"
	    "  - pivy-box challenge respond\n"
	    "      Generate a response to a recovery challenge provided on stdin.\n"
	    "\n");
	exit(EXIT_USAGE);
}

int
main(int argc, char *argv[])
{
	const char *optstring = "bl:irRP:i:o:f:";
	const char *type = NULL, *op = NULL, *tplname;
	int c;
	char tpl[PATH_MAX] = { 0 };
	errf_t *error = NULL;
	unsigned long int parsed;
	char *p;

#if defined(RL_READLINE_VERSION)
	rl_instream = fopen("/dev/tty", "w+");
	rl_outstream = rl_instream;
#endif
#if defined(__sun)
	devterm = fopen("/dev/tty", "w+");
	gl_change_terminal(sungl, devterm, devterm, getenv("TERM"));
#endif

	if (argc < 2) {
		warnx("type and operation required");
		usage(type, op);
		return (EXIT_USAGE);
	}
	type = argv[1];
	if (argc < 3) {
		warnx("operation required");
		usage(type, op);
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
		case 'i':
			ebox_interactive = B_TRUE;
			break;
		case 'l':
			if (strcmp(type, "key") != 0 ||
			    strcmp(op, "generate") != 0) {
				warnx("option -l only supported with "
				    "'key generate' subcommand");
				usage(type, op);
				return (EXIT_USAGE);
			}
			errno = 0;
			parsed = strtoul(optarg, &p, 0);
			if (errno != 0 || *p != '\0') {
				errx(EXIT_USAGE,
				    "invalid argument for -l: '%s'", optarg);
			}
			ebox_keylen = parsed;
			break;
		default:
			usage(type, op);
			return (EXIT_USAGE);
		}
	}

	argc -= optind;
	argv += optind;

	if (strcmp(type, "tpl") == 0 || strcmp(type, "template") == 0) {
		if (strcmp(op, "show") == 0 && argc == 0 && tpl[0] == 0) {
			error = cmd_tpl_show(argc, argv);
			goto out;
		}

	} else if (strcmp(type, "key") == 0) {
		if (strcmp(op, "unlock") == 0) {
			error = cmd_key_unlock(argc, argv);
			goto out;
		} else if (strcmp(op, "info") == 0) {
			error = cmd_key_info(argc, argv);
			goto out;
		}

	} else if (strcmp(type, "stream") == 0) {
		if (strcmp(op, "decrypt") == 0) {
			error = cmd_stream_decrypt(argc, argv);
			goto out;
		}

	} else if (strcmp(type, "challenge") == 0) {
		if (strcmp(op, "info") == 0) {
			error = cmd_challenge_info(argc, argv);
			goto out;

		} else if (strcmp(op, "respond") == 0) {
			error = cmd_challenge_respond(argc, argv);
			goto out;
		}
		goto badop;
	}

	if (tpl[0] == '\0') {
		const char *home;
		if (argc < 1) {
			warnx("template name or path required");
			usage(type, op);
			return (EXIT_USAGE);
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
			error = cmd_tpl_create(tpl, argc, argv);
			goto out;

		} else if (strcmp(op, "edit") == 0) {
			read_tpl_file(tpl);
			error = cmd_tpl_edit(tpl, argc, argv);
			goto out;

		} else if (strcmp(op, "show") == 0) {
			read_tpl_file(tpl);
			error = cmd_tpl_show(argc, argv);
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
badop:
	warnx("unknown operation: '%s %s'", type, op);
	usage(type, op);
	return (EXIT_USAGE);

out:
	if (error)
		errfx(EXIT_ERROR, error, "'%s %s' command failed", type, op);
	return (0);
}
