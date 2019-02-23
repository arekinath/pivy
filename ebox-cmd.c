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
static const char *ebox_pin;
static uint ebox_min_retries = 1;

enum ebox_exit_status {
	EXIT_OK = 0,
	EXIT_PIN = 4,
	EXIT_PIN_LOCKED = 5,
};

#ifndef LINT
#define pcscerrf(call, rv)	\
    errf("PCSCError", NULL, call " failed: %d (%s)", \
    rv, pcsc_stringify_error(rv))
#endif

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

int
main(int argc, char *argv[])
{
	struct piv_ecdh_box *box;
	errf_t *err;
	int rc;

	read_b64_box(&box);

	rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ebox_ctx);
	if (rc != SCARD_S_SUCCESS) {
		errfx(1, pcscerrf("SCardEstablishContext", rc),
		    "failed to initialise libpcsc");
	}

	err = local_unlock(box);
	if (err) {
		errfx(1, err, "failed to unlock box");
	}
	return (0);
}
