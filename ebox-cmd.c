/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019, Joyent Inc
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
#include <dirent.h>

#include "debug.h"

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

#include "openssh/config.h"
#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"
#include "openssh/authfd.h"

#include "sss/hazmat.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "tlv.h"
#include "errf.h"
#include "ebox.h"
#include "piv.h"
#include "bunyan.h"
#include "ebox-cmd.h"

#include "words.h"

#if !defined(EBOX_USER_TPL_PATH)
#define	EBOX_USER_TPL_PATH	"$HOME/.pivy/tpl/$TPL"
#endif
#if !defined(EBOX_SYSTEM_TPL_PATH)
#define	EBOX_SYSTEM_TPL_PATH	"/etc/pivy/tpl/$TPL"
#endif

int ebox_authfd = -1;
struct piv_ctx *ebox_ctx = NULL;
char *ebox_pin;
uint ebox_min_retries = 1;
boolean_t ebox_batch = B_FALSE;
struct piv_token *ebox_enum_tokens = NULL;

#if defined(__sun)
static GetLine *sungl = NULL;
static FILE *devterm = NULL;

char *
readline(const char *prompt)
{
	char *line;
	size_t len;
	if (sungl == NULL)
		qa_term_setup();
	line = gl_get_line(sungl, prompt, NULL, -1);
	if (line != NULL) {
		line = strdup(line);
		len = strlen(line);
		while (line[len - 1] == '\n' || line[len - 1] == '\r')
			line[--len] = '\0';
	}
	return (line);
}
#endif

void
qa_term_setup(void)
{
#if defined(RL_READLINE_VERSION)
	rl_instream = fopen("/dev/tty", "w+");
	rl_outstream = rl_instream;
#endif
#if defined(__sun)
	sungl = new_GetLine(1024, 2048);
	devterm = fopen("/dev/tty", "w+");
	gl_change_terminal(sungl, devterm, devterm, getenv("TERM"));
#endif
}

void
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

	free(buf);
}

char *
piv_token_shortid(struct piv_token *pk)
{
	char *guid;
	guid = strdup(piv_token_guid_hex(pk));
	guid[8] = '\0';
	return (guid);
}

const char *
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

void
assert_pin(struct piv_token *pk, struct piv_slot *slot, const char *partname,
    boolean_t prompt)
{
	errf_t *er;
	uint retries;
	enum piv_pin auth = piv_token_default_auth(pk);
	boolean_t touch = B_FALSE;

	const char *fmt = "Enter %s for token %s (%s): ";
	if (partname == NULL)
		fmt = "Enter %s for token %s: ";

	if (slot != NULL) {
		enum piv_slot_auth rauth = piv_slot_get_auth(pk, slot);
		if ((rauth & PIV_SLOT_AUTH_PIN) && !ebox_batch)
			prompt = B_TRUE;
		if (rauth & PIV_SLOT_AUTH_TOUCH)
			touch = B_TRUE;
	}

again:
	if (ebox_pin == NULL && !prompt)
		return;
	if (ebox_pin == NULL && prompt) {
		char prompt[64];
		char pinbuf[16];
		char *guid = piv_token_shortid(pk);
		snprintf(prompt, 64, fmt,
		    pin_type_to_name(auth), guid, partname);
		do {
			ebox_pin = readpassphrase(prompt, pinbuf,
			    sizeof (pinbuf), RPP_ECHO_OFF);
		} while (ebox_pin == NULL && errno == EINTR);
		if ((ebox_pin == NULL && errno == ENOTTY) ||
		    strlen(ebox_pin) < 1) {
			piv_txn_end(pk);
			errx(EXIT_PIN, "a PIN is required to unlock "
			    "token %s", guid);
		} else if (ebox_pin == NULL) {
			piv_txn_end(pk);
			err(EXIT_PIN, "failed to read PIN");
		} else if (strlen(ebox_pin) < 4 || strlen(ebox_pin) > 8) {
			const char *charType = "digits";
			if (piv_token_is_ykpiv(pk))
				charType = "characters";
			warnx("a valid PIN must be 4-8 %s in length",
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
		errf_free(er);
		goto again;
	} else if (errf_caused_by(er, "MinRetriesError")) {
		piv_txn_end(pk);
		if (retries == 0) {
			errx(EXIT_PIN_LOCKED, "token is locked due to too "
			    "many invalid PIN attempts");
		}
		errx(EXIT_PIN, "refusing to attempt PIN: only %d PIN retries "
		    "remaining. use pivy-tool with -f to clear counter.",
		    retries);
	} else if (er) {
		piv_txn_end(pk);
		errfx(EXIT_PIN, er, "failed to verify PIN");
	}

	if (touch) {
		fprintf(stderr, "Touch button confirmation may be required.\n");
	}
}

errf_t *
local_unlock_agent(struct piv_ecdh_box *box)
{
	struct sshkey *pubkey;
	errf_t *err;
	int rc;
	uint i;
	struct ssh_identitylist *idl = NULL;
	boolean_t found = B_FALSE;

	if (ebox_authfd == -1 &&
	    (rc = ssh_get_authentication_socket(&ebox_authfd)) != 0) {
		err = ssherrf("ssh_get_authentication_socket", rc);
		goto out;
	}

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
		err = errf("KeyNotFoundError", NULL, "No matching key found in "
		    "ssh agent");
		goto out;
	}

	if (!ebox_batch) {
		fprintf(stderr, "Using key '%s' in ssh-agent...\n",
		    idl->comments[i]);
	}

	err = piv_box_open_agent(ebox_authfd, box);

out:
	ssh_free_identitylist(idl);
	return (err);
}

void
release_context(void)
{
	if (ebox_enum_tokens != NULL)
		piv_release(ebox_enum_tokens);
	ebox_enum_tokens = NULL;
	if (ebox_ctx != NULL)
		piv_close(ebox_ctx);
	ebox_ctx = NULL;
}

boolean_t
can_local_unlock(struct piv_ecdh_box *box)
{
	errf_t *err;
	int rc;
	uint i;
	struct piv_slot *slot;
	struct piv_token *tokens = NULL, *token;
	struct ssh_identitylist *idl = NULL;
	struct sshkey *pubkey;
	boolean_t found = B_FALSE;

	if (ebox_authfd != -1 ||
	    ssh_get_authentication_socket(&ebox_authfd) == 0) {
		pubkey = piv_box_pubkey(box);

		rc = ssh_fetch_identitylist(ebox_authfd, &idl);
		if (rc)
			goto out;

		for (i = 0; i < idl->nkeys; ++i) {
			if (sshkey_equal_public(idl->keys[i], pubkey)) {
				found = B_TRUE;
				break;
			}
		}
		if (found)
			goto out;
	}

	if (!piv_box_has_guidslot(box))
		goto out;

	if (ebox_ctx == NULL) {
		ebox_ctx = piv_open();
		VERIFY(ebox_ctx != NULL);
		err = piv_establish_context(ebox_ctx, SCARD_SCOPE_SYSTEM);
		if (err && errf_caused_by(err, "ServiceError")) {
			errf_free(err);
		} else if (err) {
			goto out;
		}
	}

	/*
	 * We might try to call local_unlock on a whole lot of configs in a
	 * row (looking for one that works). If we resort to enumerating all
	 * the tokens on the system at any point, cache them in
	 * ebox_enum_tokens so that things are a bit faster.
	 */
	if (ebox_enum_tokens != NULL) {
		tokens = ebox_enum_tokens;

	} else {
		err = piv_find(ebox_ctx, piv_box_guid(box), GUID_LEN, &tokens);
		if (err == ERRF_OK) {
			found = B_TRUE;
		} else if (errf_caused_by(err, "NotFoundError")) {
			errf_free(err);
			err = piv_enumerate(ebox_ctx, &tokens);
			if (err) {
				errf_free(err);
			} else {
				ebox_enum_tokens = tokens;
			}
		} else {
			errf_free(err);
		}
	}
	if (found)
		goto out;

	err = piv_box_find_token(tokens, box, &token, &slot);
	if (err) {
		errf_free(err);
		goto out;
	}
	found = B_TRUE;

out:
	if (tokens != ebox_enum_tokens)
		piv_release(tokens);
	ssh_free_identitylist(idl);
	return (found);
}

errf_t *
local_unlock(struct piv_ecdh_box *box, struct sshkey *cak, const char *name)
{
	errf_t *err, *agerr = NULL;
	struct piv_slot *slot, *cakslot;
	struct piv_token *tokens = NULL, *token;

	agerr = local_unlock_agent(box);
	if (agerr == ERRF_OK)
		return (ERRF_OK);

	if (!piv_box_has_guidslot(box)) {
		if (agerr) {
			return (errf("AgentError", agerr, "ssh-agent unlock "
			    "failed, and box does not have GUID/slot info"));
		}
		return (errf("NoGUIDSlot", NULL, "box does not have GUID "
		    "and slot information, can't unlock with local hardware"));
	}

	if (ebox_ctx == NULL) {
		ebox_ctx = piv_open();
		VERIFY(ebox_ctx != NULL);
		err = piv_establish_context(ebox_ctx, SCARD_SCOPE_SYSTEM);
		if (err && errf_caused_by(err, "ServiceError")) {
			errf_free(err);
		} else if (err) {
			errfx(EXIT_ERROR, err, "failed to initialise libpcsc");
		}
	}

	/*
	 * We might try to call local_unlock on a whole lot of configs in a
	 * row (looking for one that works). If we resort to enumerating all
	 * the tokens on the system at any point, cache them in
	 * ebox_enum_tokens so that things are a bit faster.
	 */
	if (ebox_enum_tokens != NULL) {
		tokens = ebox_enum_tokens;
		err = NULL;
	} else {
		err = piv_find(ebox_ctx, piv_box_guid(box), GUID_LEN, &tokens);
		if (errf_caused_by(err, "NotFoundError")) {
			errf_free(err);
			err = piv_enumerate(ebox_ctx, &tokens);
			if (err && agerr) {
				err = errf("AgentError", agerr, "ssh-agent "
				    "unlock failed, and no PIV tokens were "
				    "detected on the local system");
			} else {
				ebox_enum_tokens = tokens;
			}
		}
	}
	if (err)
		goto out;

	err = piv_box_find_token(tokens, box, &token, &slot);
	if (err) {
		err = errf("LocalUnlockError", err, "failed to find token "
		    "with GUID %s and key for box",
		    piv_box_guid_hex(box));
		goto out;
	}

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
				piv_txn_end(token);
				goto out;
			}
			cakslot = piv_get_slot(token, PIV_SLOT_CARD_AUTH);
		}
		if (cakslot == NULL) {
			err = errf("CardAuthenticationError", NULL,
			    "Failed to validate CAK");
			piv_txn_end(token);
			goto out;
		}
		err = piv_auth_key(token, cakslot, cak);
		if (err) {
			err = errf("CardAuthenticationError", err,
			    "Failed to validate CAK");
			piv_txn_end(token);
			goto out;
		}
	}

	boolean_t prompt = B_FALSE;
pin:
	assert_pin(token, slot, name, prompt);
	err = piv_box_open(token, slot, box);
	if (errf_caused_by(err, "PermissionError") && !prompt) {
		if (!ebox_batch) {
			errf_free(err);
			prompt = B_TRUE;
			goto pin;
		} else {
			errf_free(err);
			piv_txn_end(token);
			err = errf("InteractiveError", agerr,
			    "PIN input is required to use PIV device directly "
			    "(not via agent), failed to use agent, and -b "
			    "batch option was given");
			goto out;
		}
	} else if (err) {
		errf_free(agerr);
		piv_txn_end(token);
		err = errf("LocalUnlockError", err, "failed to unlock box");
		goto out;
	}

	errf_free(agerr);
	piv_txn_end(token);
	err = ERRF_OK;

out:
	if (tokens != ebox_enum_tokens)
		piv_release(tokens);
	return (err);
}

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
	a->a_next = NULL;
	a->a_prev = NULL;
}

void
remove_command(struct question *q, struct answer *a)
{
	if (a->a_prev != NULL) {
		a->a_prev->a_next = a->a_next;
	} else {
		if (q->q_coms != a && a->a_next == NULL)
			return;
		VERIFY(q->q_coms == a);
		q->q_coms = a->a_next;
	}
	if (a->a_next != NULL) {
		a->a_next->a_prev = a->a_prev;
	} else {
		if (q->q_lastcom != a && a->a_prev == NULL)
			return;
		VERIFY(q->q_lastcom == a);
		q->q_lastcom = a->a_prev;
	}
	a->a_next = NULL;
	a->a_prev = NULL;
}

void
answer_printf(struct answer *ans, const char *fmt, ...)
{
	va_list ap;
	int wrote;

	va_start(ap, fmt);
	wrote = vsnprintf(&ans->a_text[ans->a_used],
	    sizeof (ans->a_text) - ans->a_used, fmt, ap);
	VERIFY(wrote >= 0);
	va_end(ap);
	ans->a_used += wrote;
	if (ans->a_used >= sizeof (ans->a_text))
		ans->a_text[sizeof (ans->a_text) - 1] = '\0';
}

struct answer *
make_answer(char key, const char *fmt, ...)
{
	va_list ap;
	int wrote;
	struct answer *ans;

	ans = calloc(1, sizeof (struct answer));
	if (ans == NULL)
		err(EXIT_ERROR, "failed to allocate memory");
	ans->a_key = key;

	va_start(ap, fmt);
	wrote = vsnprintf(&ans->a_text[ans->a_used],
	    sizeof (ans->a_text) - ans->a_used, fmt, ap);
	VERIFY(wrote >= 0);
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
	int wrote;

	va_start(ap, fmt);
	wrote = vsnprintf(&q->q_prompt[q->q_used],
	    sizeof (q->q_prompt) - q->q_used, fmt, ap);
	VERIFY(wrote >= 0);
	va_end(ap);
	q->q_used += wrote;
	if (q->q_used >= sizeof (q->q_prompt))
		q->q_prompt[sizeof (q->q_prompt) - 1] = '\0';
}

void
question_free(struct question *q)
{
	struct answer *a, *na;

	if (q == NULL)
		return;

	for (a = q->q_ans; a != NULL; a = na) {
		na = a->a_next;
		if (a->a_priv == NULL)
			free(a);
	}
	for (a = q->q_coms; a != NULL; a = na) {
		na = a->a_next;
		if (a->a_priv == NULL)
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

errf_t *
interactive_recovery(struct ebox_config *config, const char *what)
{
	struct ebox_part *part;
	struct ebox_tpl_config *tconfig;
	struct ebox_tpl_part *tpart;
	struct part_state *state;
	struct question *q;
	struct answer *a, *adone;
	struct sshbuf *buf = NULL, *b64buf;
	struct piv_ecdh_box *box;
	const struct ebox_challenge *chal;
	struct ans_config *ac;
	char k = '0';
	uint n, ncur;
	uint i;
	char *line;
	char *b64;
	errf_t *error;
	const uint8_t *words;
	size_t wordlen;
	int rc;
	boolean_t adone_in = B_FALSE;

	tconfig = ebox_config_tpl(config);
	n = ebox_tpl_config_n(tconfig);

	if (ebox_batch) {
		error = errf("InteractiveError", NULL,
		    "interactive recovery is required but the -b batch option "
		    "was provided");
		return (error);
	}

	q = calloc(1, sizeof (struct question));
	ac = (struct ans_config *)ebox_config_private(config);
	a = ac->ac_ans;
	question_printf(q, "-- Recovery config %c --\n", a->a_key);
	question_printf(q, "Select %u parts to use for recovery", n);

	part = NULL;
	ncur = 0;
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
		if (can_local_unlock(ebox_part_box(part))) {
			state->ps_intent = INTENT_LOCAL;
			++ncur;
		}
		make_answer_text_for_pstate(state);
		add_answer(q, a);
	}

	adone = make_answer('r', "begin recovery");
	if (ncur >= n) {
		add_command(q, adone);
		adone_in = B_TRUE;
	}

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
		if (!adone_in) {
			add_command(q, adone);
			adone_in = B_TRUE;
		}
	} else {
		if (adone_in) {
			remove_command(q, adone);
			adone_in = B_FALSE;
		}
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
		release_context();
		error = local_unlock(ebox_part_box(part),
		    ebox_tpl_part_cak(tpart), ebox_tpl_part_name(tpart));
		if (error && !errf_caused_by(error, "NotFoundError"))
			goto out;
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
		    "Recovering %s with part %s", what, state->ps_ans->a_text);
		if (error)
			goto out;
		chal = ebox_part_challenge(part);
		sshbuf_reset(buf);
		error = sshbuf_put_ebox_challenge(buf, chal);
		if (error)
			goto out;
		b64buf = sshbuf_new();
		VERIFY(b64buf != NULL);
		rc = sshbuf_dtob64(buf, b64buf, 0);
		if (rc != 0) {
			error = ssherrf("sshbuf_dtob64", rc);
			goto out;
		}
		b64 = sshbuf_dup_string(b64buf);
		sshbuf_free(b64buf);
		VERIFY(b64 != NULL);
		fprintf(stderr, "-- Begin challenge for remote device %s --\n",
		    state->ps_ans->a_text);
		printwrap(stderr, b64, BASE64_LINE_LEN);
		fprintf(stderr, "-- End challenge for remote device %s --\n",
		    state->ps_ans->a_text);
		free(b64);
		b64 = NULL;

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

	error = ERRF_OK;

out:
	sshbuf_free(buf);

	part = NULL;
	while ((part = ebox_config_next_part(config, part)) != NULL) {
		state = (struct part_state *)ebox_part_private(part);
		if (state != NULL) {
			state->ps_ans->a_priv = NULL;
			ebox_part_free_private(part);
		}
	}
	question_free(q);

	return (error);
}

struct ebox_tpl_path_ent *ebox_tpl_path = NULL;

static struct ebox_tpl_path_seg *
parse_tpl_path_segs(const char *path)
{
	struct ebox_tpl_path_seg *seg, *first = NULL, *last = NULL;
	const char *basep, *p;
	size_t n;

	p = path;
	basep = NULL;

	while (1) {
		if (*p == '$' || *p == '\0') {
			/* end current segment */
			if (basep != NULL) {
				seg = calloc(1, sizeof (*seg));
				seg->tps_type = PATH_SEG_FIXED;
				n = p - basep;
				seg->tps_fixed = malloc(n + 1);
				strlcpy(seg->tps_fixed, basep, n + 1);
				if (first == NULL)
					first = seg;
				if (last != NULL)
					last->tps_next = seg;
				last = seg;
				basep = NULL;
			}
			if (*p == '$') {
				if (strncmp(p, "$TPL", 4) == 0) {
					p += 4;
					seg = calloc(1, sizeof (*seg));
					seg->tps_type = PATH_SEG_TPL;
					if (first == NULL)
						first = seg;
					if (last != NULL)
						last->tps_next = seg;
					last = seg;
					continue;
				}
				basep = ++p;
				while (*p != '\0' && (
				    (*p >= 'A' && *p <= 'Z') ||
				    (*p >= 'a' && *p <= 'z') ||
				    (*p >= '0' && *p <= '9'))) {
					++p;
				}
				seg = calloc(1, sizeof (*seg));
				seg->tps_type = PATH_SEG_ENV;
				n = p - basep;
				seg->tps_env = malloc(n + 1);
				strlcpy(seg->tps_fixed, basep, n + 1);
				if (first == NULL)
					first = seg;
				if (last != NULL)
					last->tps_next = seg;
				last = seg;
				basep = NULL;
			} else {
				break;
			}
		} else {
			if (basep == NULL)
				basep = p;
			++p;
		}
	}

	return (first);
}

void
parse_tpl_path_env(void)
{
	struct ebox_tpl_path_ent *tpe, *last = NULL;
	const char *env;
	char *tmp;
	char *token, *saveptr = NULL;

	tpe = calloc(1, sizeof (*tpe));
	if (ebox_tpl_path == NULL)
		ebox_tpl_path = tpe;
	if (last != NULL)
		last->tpe_next = tpe;
	tpe->tpe_path_tpl = strdup(EBOX_USER_TPL_PATH);
	tpe->tpe_segs = parse_tpl_path_segs(tpe->tpe_path_tpl);
	last = tpe;

#if !defined(NO_LEGACY_EBOX_TPL_PATH)
	tpe = calloc(1, sizeof (*tpe));
	if (ebox_tpl_path == NULL)
		ebox_tpl_path = tpe;
	if (last != NULL)
		last->tpe_next = tpe;
	tpe->tpe_path_tpl = strdup("$HOME/.ebox/tpl/$TPL");
	tpe->tpe_segs = parse_tpl_path_segs(tpe->tpe_path_tpl);
	last = tpe;
#endif

	env = getenv("PIVY_EBOX_TPL_PATH");
	if (env != NULL) {
		tmp = strdup(env);

		while (1) {
			token = strtok_r(tmp, ":", &saveptr);
			if (token == NULL)
				break;
			tmp = NULL;

			tpe = calloc(1, sizeof (*tpe));
			if (ebox_tpl_path == NULL)
				ebox_tpl_path = tpe;
			if (last != NULL)
				last->tpe_next = tpe;
			tpe->tpe_path_tpl = strdup(token);
			tpe->tpe_segs = parse_tpl_path_segs(tpe->tpe_path_tpl);
			last = tpe;
		}
	}

	tpe = calloc(1, sizeof (*tpe));
	if (ebox_tpl_path == NULL)
		ebox_tpl_path = tpe;
	if (last != NULL)
		last->tpe_next = tpe;
	tpe->tpe_path_tpl = strdup(EBOX_SYSTEM_TPL_PATH);
	tpe->tpe_segs = parse_tpl_path_segs(tpe->tpe_path_tpl);
	last = tpe;
}

char *
compose_path(const struct ebox_tpl_path_seg *segs, const char *tpl)
{
	char *buf;
	const char *tmp;
	const struct ebox_tpl_path_seg *seg;

	buf = malloc(PATH_MAX);
	buf[0] = '\0';

	seg = segs;
	while (seg != NULL) {
		switch (seg->tps_type) {
		case PATH_SEG_FIXED:
			xstrlcat(buf, seg->tps_fixed, PATH_MAX);
			break;
		case PATH_SEG_ENV:
			tmp = getenv(seg->tps_env);
			if (tmp != NULL)
				xstrlcat(buf, tmp, PATH_MAX);
			break;
		case PATH_SEG_TPL:
			xstrlcat(buf, tpl, PATH_MAX);
			break;
		}
		seg = seg->tps_next;
	}

	return (buf);
}

char *
access_tpl_file(const char *tpl, int amode)
{
	char *path;
	const struct ebox_tpl_path_ent *tpe;
	int r;
	uint i, len;

	if ((amode & W_OK) == 0) {
		/*
		 * If we're not writing, try the name as a full path --
		 * this is useful in tools like pivy-zfs without a separate
		 * -f option for tpl path.
		 */
		r = access(tpl, amode);
		if (r == 0)
			return (strdup(tpl));
	}

	/* First, see if we can find an actual tpl file with this name. */
	tpe = ebox_tpl_path;
	while (tpe != NULL) {
		path = compose_path(tpe->tpe_segs, tpl);
		r = access(path, amode);
		if (r == 0)
			return (path);
		free(path);
		tpe = tpe->tpe_next;
	}

	/*
	 * If we don't have a tpl file with the name and we're not writing,
	 * give up now.
	 */
	if ((amode & W_OK) == 0)
		return (NULL);

	/*
	 * Next, look for a dir on the paths list which already exists and is
	 * writable. If we have one, use that.
	 */
	tpe = ebox_tpl_path;
	while (tpe != NULL) {
		path = compose_path(tpe->tpe_segs, "");
		r = access(path, amode);
		if (r == 0) {
			free(path);
			path = compose_path(tpe->tpe_segs, tpl);
			return (path);
		}
		free(path);
		tpe = tpe->tpe_next;
	}

	/*
	 * Finally, look for a dir on the paths list which we can recursively
	 * mkdir. Try to mkdir it now. If it all works, use that one.
	 */
	tpe = ebox_tpl_path;
	while (tpe != NULL) {
		path = compose_path(tpe->tpe_segs, "");
		len = strlen(path);
		for (i = 1; i < len; ++i) {
			if (path[i] != '/')
				continue;
			path[i] = '\0';
			if (mkdir(path, 0755)) {
				if (errno != EEXIST)
					break;
			}
			path[i] = '/';
		}
		r = access(path, amode);
		if (r == 0) {
			free(path);
			path = compose_path(tpe->tpe_segs, tpl);
			return (path);
		}
		free(path);
		tpe = tpe->tpe_next;
	}

	return (NULL);
}

FILE *
open_tpl_file(const char *tpl, const char *mode)
{
	char *path;
	FILE *f;
	const struct ebox_tpl_path_ent *tpe;

	if (strchr(mode, 'w') == NULL) {
		f = fopen(tpl, mode);
		if (f != NULL)
			return (f);
	}

	tpe = ebox_tpl_path;
	while (tpe != NULL) {
		path = compose_path(tpe->tpe_segs, tpl);
		f = fopen(path, mode);
		free(path);
		if (f != NULL)
			return (f);
		tpe = tpe->tpe_next;
	}

	return (NULL);
}

errf_t *
read_tpl_file_err(const char *tpl, struct ebox_tpl **ptpl)
{
	errf_t *err;
	FILE *tplf = NULL;
	struct stat st;
	char *buf = NULL;
	struct sshbuf *sbuf = NULL;
	size_t len;
	int rc;
	struct ebox_tpl *stpl = NULL;

	tplf = open_tpl_file(tpl, "r");
	rc = errno;
	if (tplf == NULL) {
		err = errf("FileNotFound", errfno("fopen", errno, "%s", tpl),
		    "failed to open template file '%s' for reading", tpl);
		goto out;
	}
	bzero(&st, sizeof (st));
	if (fstat(fileno(tplf), &st)) {
		err = errfno("fstat", errno, "%s", tpl);
		goto out;
	}
	if (!S_ISREG(st.st_mode)) {
		err = errf("BadFileType", NULL, "'%s' is not a regular file",
		    tpl);
		goto out;
	}
	if (st.st_size > TPL_MAX_SIZE) {
		err = errf("FileTooLarge", NULL, "'%s' is too large for an "
		    "ebox template file", tpl);
		goto out;
	}
	buf = malloc(st.st_size + 1);
	if (buf == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	len = fread(buf, 1, st.st_size, tplf);
	if (len < 0 && ferror(tplf)) {
		err = errfno("fread", errno, "template file '%s'", tpl);
		goto out;
	}
	if (len < st.st_size) {
		err = errf("ShortRead", NULL, "short read while processing "
		    "template '%s'", tpl);
		goto out;
	}
	buf[len] = '\0';
	if (fclose(tplf)) {
		err = errfno("fclose", errno, "closing tpl file '%s'", tpl);
		goto out;
	}
	tplf = NULL;
	sbuf = sshbuf_new();
	if (sbuf == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	if ((rc = sshbuf_b64tod(sbuf, buf))) {
		err = errf("TemplateFormatError", ssherrf("sshbuf_b64tod", rc),
		    "failed to parse the contents of '%s' as base64-encoded "
		    "data", tpl);
		goto out;
	}
	if ((err = sshbuf_get_ebox_tpl(sbuf, &stpl))) {
		err = errf("TemplateFormatError", err, "failed to parse contents of "
		    "'%s' as an ebox template", tpl);
		goto out;
	}

	*ptpl = stpl;
	stpl = NULL;
	err = ERRF_OK;

out:
	sshbuf_free(sbuf);
	free(buf);
	if (tplf != NULL)
		fclose(tplf);
	ebox_tpl_free(stpl);
	return (err);
}

struct ebox_tpl *
read_tpl_file(const char *tpl)
{
	errf_t *err;
	struct ebox_tpl *stpl = NULL;

	err = read_tpl_file_err(tpl, &stpl);
	if (err != ERRF_OK)
		errfx(EXIT_ERROR, err, "reading tpl '%s'", tpl);
	return (stpl);
}

void
interactive_select_local_token(struct ebox_tpl_part **ppart)
{
	errf_t *error;
	struct piv_token *tokens = NULL, *token;
	struct piv_slot *slot;
	struct ebox_tpl_part *part;
	struct question *q;
	struct answer *a;
	char *shortid;
	enum piv_slotid slotid = PIV_SLOT_KEY_MGMT;
	char k = '0';
	char *line;

	if (ebox_ctx == NULL) {
		ebox_ctx = piv_open();
		VERIFY(ebox_ctx != NULL);
		error = piv_establish_context(ebox_ctx, SCARD_SCOPE_SYSTEM);
		if (error && errf_caused_by(error, "ServiceError")) {
			errf_free(error);
		} else if (error) {
			errfx(EXIT_ERROR, error,
			    "failed to initialise libpcsc");
		}
	}

reenum:
	error = piv_enumerate(ebox_ctx, &tokens);
	if (error) {
		warnfx(error, "failed to enumerate PIV tokens on the system");
		*ppart = NULL;
		errf_free(error);
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

	a = make_answer('s', "change key slot (%02X)", slotid);
	add_command(q, a);

	a = make_answer('r', "re-scan");
	add_command(q, a);

	a = make_answer('x', "cancel");
	add_command(q, a);

again:
	question_prompt(q, &a);
	if (a->a_key == 'x') {
		*ppart = NULL;
		question_free(q);
		piv_release(tokens);
		return;
	} else if (a->a_key == 'r') {
		*ppart = NULL;
		k = '0';
		question_free(q);
		piv_release(tokens);
		goto reenum;
	} else if (a->a_key == 's') {
		line = readline("Slot ID (hex or name)? ");
		if (line == NULL)
			exit(EXIT_ERROR);
		errno = 0;
		error = piv_slotid_from_string(line, &slotid);
		if (error != ERRF_OK) {
			warnfx(error, "error parsing '%s' as slot id",
			    line);
			errf_free(error);
			free(line);
			goto again;
		}
		a->a_used = 0;
		answer_printf(a, "change key slot (%02X)", slotid);
		free(line);
		goto again;
	}
	token = (struct piv_token *)a->a_priv;

	if ((error = piv_txn_begin(token)))
		errfx(EXIT_ERROR, error, "failed to open token");
	if ((error = piv_select(token)))
		errfx(EXIT_ERROR, error, "failed to select PIV applet");
	if ((error = piv_read_cert(token, slotid))) {
		warnfx(error, "failed to read key management (9d) slot");
		errf_free(error);
		piv_txn_end(token);
		goto again;
	}
	slot = piv_get_slot(token, slotid);
	VERIFY(slot != NULL);
	part = ebox_tpl_part_alloc(piv_token_guid(token), GUID_LEN,
	    piv_slot_id(slot), piv_slot_pubkey(slot));
	VERIFY(part != NULL);
	error = piv_read_cert(token, PIV_SLOT_CARD_AUTH);
	if (error == NULL) {
		slot = piv_get_slot(token, PIV_SLOT_CARD_AUTH);
		ebox_tpl_part_set_cak(part, piv_slot_pubkey(slot));
	} else {
		errf_free(error);
	}
	piv_txn_end(token);

	*ppart = part;
	piv_release(tokens);
}

void
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

void
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

errf_t *
interactive_unlock_ebox(struct ebox *ebox, const char *fn)
{
	struct ebox_config *config;
	struct ebox_part *part;
	struct ebox_tpl_part *tpart;
	struct ebox_tpl_config *tconfig;
	errf_t *agerror = NULL, *error = NULL;
	struct ans_config *ac;
	struct question *q = NULL;
	struct answer *a;
	uint nconfigs = 0;
	char k = '0';

	if (fn == NULL)
		fn = "pivy-box data";

	if (ebox_is_unlocked(ebox))
		return (ERRF_OK);

	/* Try to use the pivy-agent to unlock first if we have one. */
	config = NULL;
	while ((config = ebox_next_config(ebox, config)) != NULL) {
		tconfig = ebox_config_tpl(config);
		if (ebox_tpl_config_type(tconfig) == EBOX_PRIMARY) {
			part = ebox_config_next_part(config, NULL);
			tpart = ebox_part_tpl(part);
			errf_free(agerror);
			agerror = local_unlock_agent(ebox_part_box(part));
			if (agerror &&
			    !errf_caused_by(agerror, "KeyNotFoundError") &&
			    !errf_caused_by(agerror, "AgentNotPresentError") &&
			    !errf_caused_by(agerror, "AgentEmptyError")) {
				warnfx(agerror, "failed to unlock ebox with "
				    "agent");
			}
			if (agerror)
				continue;
			agerror = ebox_unlock(ebox, config);
			if (agerror)
				return (agerror);
			goto done;
		}
	}

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
				errf_free(error);
				continue;
			}
			error = ebox_unlock(ebox, config);
			if (error)
				return (error);
			goto done;
		}
	}

	if (ebox_batch) {
		error = errf("InteractiveError", agerror,
		    "interactive recovery is required but the -b batch option "
		    "was provided");
		return (error);
	}
	errf_free(agerror);

	q = calloc(1, sizeof (struct question));
	question_printf(q, "-- Recovery mode --\n");
	question_printf(q, "No primary configuration could proceed using a "
	    "token currently available\non the system. You may either select "
	    "a primary config to retry, or select\na recovery config to "
	    "begin the recovery process.\n\n");
	question_printf(q, "Select a configuration to use:");
	config = NULL;
	while ((config = ebox_next_config(ebox, config)) != NULL) {
		tconfig = ebox_config_tpl(config);
		ac = ebox_config_alloc_private(config,
		    sizeof (struct ans_config));
		VERIFY(ac != NULL);
		a = calloc(1, sizeof (struct answer));
		VERIFY(a != NULL);
		ac->ac_ans = a;
		ac->ac_config = config;
		a->a_key = ++k;
		a->a_priv = ac;
		make_answer_text_for_config(tconfig, a);
		add_answer(q, a);
		++nconfigs;
	}
again:
	if (nconfigs == 1) {
		/* Only one config */
		config = ebox_next_config(ebox, NULL);
	} else {
		question_prompt(q, &a);
		ac = (struct ans_config *)a->a_priv;
		VERIFY3P(ac->ac_ans, ==, a);
		config = ac->ac_config;

	}
	tconfig = ebox_config_tpl(config);
	if (ebox_tpl_config_type(tconfig) == EBOX_PRIMARY) {
		part = ebox_config_next_part(config, NULL);
		tpart = ebox_part_tpl(part);
		release_context();
		error = local_unlock(ebox_part_box(part),
		    ebox_tpl_part_cak(tpart),
		    ebox_tpl_part_name(tpart));
		if (error) {
			warnfx(error, "failed to activate config %c", a->a_key);
			errf_free(error);
			goto again;
		}
		error = ebox_unlock(ebox, config);
		if (error)
			return (error);
		goto done;
	}
	error = interactive_recovery(config, fn);
	if (error) {
		warnfx(error, "failed to activate config %c", a->a_key);
		errf_free(error);
		goto again;
	}
	error = ebox_recover(ebox, config);
	if (error)
		return (error);

done:
	config = NULL;
	while ((config = ebox_next_config(ebox, config)) != NULL) {
		ac = ebox_config_private(config);
		if (ac == NULL)
			continue;
		VERIFY3P(ac->ac_config, ==, config);
		ac->ac_ans->a_priv = NULL;
		ebox_config_free_private(config);
	}
	question_free(q);
	return (ERRF_OK);
}

struct tpl_selector {
	char		 ts_path[PATH_MAX];
	struct ebox_tpl	*ts_tpl;
	struct answer	*ts_ans;
};

errf_t *
interactive_select_tpl(struct ebox_tpl **ptpl)
{
	struct question *q;
	struct answer *a;
	struct answer atmp;
	char k = '0';
	char *dpath, *fpath;
	DIR *d;
	struct dirent *ent;
	const struct ebox_tpl_path_ent *tpe;
	errf_t *err = ERRF_OK;
	struct ebox_tpl *tpl;
	struct ebox_tpl_config *c;
	struct tpl_selector *sel;
	char *line;

	q = calloc(1, sizeof (struct question));
	question_printf(q, "-- Select a template --\n");
	question_printf(q, "Select an ebox template to use:");

	tpe = ebox_tpl_path;
	while (tpe != NULL) {
		dpath = compose_path(tpe->tpe_segs, "");

		d = opendir(dpath);
		if (d == NULL) {
			errf_free(err);
			err = errfno("opendir", errno, "%s", dpath);
			goto next;
		}

		while ((ent = readdir(d)) != NULL) {
			if (ent->d_name[0] == '.')
				continue;

			fpath = compose_path(tpe->tpe_segs, ent->d_name);
			tpl = read_tpl_file(fpath);

			a = make_answer(k++, "%s: ", ent->d_name);

			sel = calloc(1, sizeof (struct tpl_selector));
			sel->ts_ans = a;
			sel->ts_tpl = tpl;
			strlcpy(sel->ts_path, fpath, sizeof (sel->ts_path));

			a->a_priv = sel;

			c = NULL;
			while ((c = ebox_tpl_next_config(tpl, c)) != NULL) {
				bzero(&atmp, sizeof (atmp));
				make_answer_text_for_config(c, &atmp);
				answer_printf(a, "%s; ", atmp.a_text);
			}

			add_answer(q, a);

			free(fpath);
		}

		closedir(d);

		free(dpath);

next:
		tpe = tpe->tpe_next;
	}

	a = make_answer('/', "specify path");
	add_command(q, a);

	a = make_answer('x', "cancel");
	add_command(q, a);

again:
	question_prompt(q, &a);
	if (a->a_key == 'x') {
		err = errf("Interrupted", NULL, "Selection of ebox template "
		    "was cancelled by user");
		goto out;
	}
	if (a->a_key == '/') {
		line = readline("Path? ");
		if (line == NULL) {
			err = errf("Interrupted", NULL, "Selection of ebox "
			    "template was cancelled by user");
			goto out;
		}
		err = read_tpl_file_err(line, &tpl);
		if (err != ERRF_OK) {
			warnfx(err, "failed to read template '%s'", line);
			errf_free(err);
			free(line);
			goto again;
		}
		goto out;
	}
	sel = a->a_priv;
	tpl = sel->ts_tpl;
	err = ERRF_OK;

out:
	for (a = q->q_ans; a != NULL; a = a->a_next) {
		sel = a->a_priv;
		if (sel->ts_tpl != NULL && sel->ts_tpl != tpl)
			ebox_tpl_free(sel->ts_tpl);
		sel->ts_tpl = NULL;
	}

	*ptpl = tpl;
	question_free(q);

	return (err);
}
