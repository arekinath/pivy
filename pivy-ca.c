/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2021, The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
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
#if defined(__sun)
#include <sys/fork.h>
#endif
#include <sys/wait.h>

#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <json_object.h>
#include <json_tokener.h>

int PEM_write_X509(FILE *fp, X509 *x);

#include "utils.h"
#include "tlv.h"
#include "piv.h"
#include "bunyan.h"
#include "utils.h"
#include "debug.h"
#include "pkinit_asn1.h"
#include "piv-ca.h"

/* We need the piv_cert_comp enum */
#include "piv-internal.h"

#if defined(__sun) || defined(__APPLE__)
#include <netinet/in.h>
#define	be16toh(v)	(ntohs(v))
#else
#include <endian.h>
#endif

boolean_t debug = B_FALSE;
static boolean_t parseable = B_FALSE;
static boolean_t enum_all_retired = B_FALSE;
static const char *cn = NULL;
static const char *upn = NULL;
static boolean_t save_pinfo_admin = B_TRUE;
static uint8_t *guid = NULL;
static size_t guid_len = 0;
static uint min_retries = 1;
static struct sshkey *opubkey = NULL;
static const char *pin = NULL;
static const uint8_t DEFAULT_ADMIN_KEY[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};
static const uint8_t *admin_key = DEFAULT_ADMIN_KEY;

static enum ykpiv_pin_policy pinpolicy = YKPIV_PIN_DEFAULT;
static enum ykpiv_touch_policy touchpolicy = YKPIV_TOUCH_DEFAULT;

static struct piv_token *ks = NULL;
static struct piv_token *selk = NULL;
//static struct piv_token *sysk = NULL;
static struct piv_slot *override = NULL;

SCARDCONTEXT ctx;

#ifndef LINT
#define	funcerrf(cause, fmt, ...)	\
    errf(__func__, cause, fmt , ##__VA_ARGS__)
#define pcscerrf(call, rv)	\
    errf("PCSCError", NULL, call " failed: %d (%s)", \
    rv, pcsc_stringify_error(rv))
#endif

enum pivtool_exit_status {
	EXIT_OK = 0,
	EXIT_IO_ERROR = 1,
	EXIT_BAD_ARGS = 2,
	EXIT_NO_CARD = 3,
	EXIT_PIN = 4,
	EXIT_PIN_LOCKED = 5,
};

static boolean_t
sniff_hex(uint8_t *buf, uint len)
{
	uint i, count = 0;
	len = len > 16 ? 16 : len;
	for (i = 0; i < len; ++i) {
		char c;
		if (buf[i] > CHAR_MAX)
			return (B_FALSE);
		c = buf[i];
		if (c >= '0' && c <= '9') {
			++count;
			continue;
		}
		if (c >= 'a' && c <= 'f') {
			++count;
			continue;
		}
		if (c == ':' || c == ' ' || c == '\t' || c == '\n' ||
		    c == '\r') {
			++count;
			continue;
		}
		return (B_FALSE);
	}
	if (count >= 8)
		return (B_TRUE);
	return (B_FALSE);
}

static boolean_t
buf_is_zero(const uint8_t *buf, size_t len)
{
	uint8_t v = 0;
	size_t i;
	for (i = 0; i < len; ++i)
		v |= buf[i];
	return (v == 0);
}

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
			errx(EXIT_BAD_ARGS, "invalid hex digit: '%c'", c);
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
	if (shift == 0)
		errx(EXIT_BAD_ARGS, "odd number of hex digits (incomplete)");
	*outlen = idx;
	return (data);
}

#define	MAX_KEYFILE_LEN		(1024)

static uint8_t *
read_key_file(const char *fname, uint *outlen)
{
	FILE *f;
	uint len;
	uint8_t *buf;

	f = fopen(fname, "r");
	if (f == NULL)
		err(EXIT_BAD_ARGS, "failed to open '%s'", fname);

	buf = calloc(1, MAX_KEYFILE_LEN);
	VERIFY(buf != NULL);

	len = fread(buf, 1, MAX_KEYFILE_LEN, f);
	if (len == 0)
		errx(EXIT_BAD_ARGS, "keyfile '%s' is too short", fname);
	if (!feof(f))
		errx(EXIT_BAD_ARGS, "keyfile '%s' is too long", fname);

	*outlen = len;

	fclose(f);

	return (buf);
}

static uint8_t *
read_stdin(size_t limit, size_t *outlen)
{
	uint8_t *buf = calloc(1, limit * 3);
	size_t n;

	n = fread(buf, 1, limit * 3 - 1, stdin);
	if (!feof(stdin))
		errx(EXIT_BAD_ARGS, "input too long (max %zu bytes)", limit);

	if (n > limit)
		errx(EXIT_BAD_ARGS, "input too long (max %zu bytes)", limit);

	*outlen = n;
	return (buf);
}

static char *
piv_token_shortid(struct piv_token *pk)
{
	char *guid;
	if (piv_token_has_chuid(pk)) {
		guid = strdup(piv_token_guid_hex(pk));
	} else {
		guid = strdup("0000000000");
	}
	guid[8] = '\0';
	return (guid);
}

static void
assert_select(struct piv_token *tk)
{
	errf_t *err;

	err = piv_select(tk);
	if (err) {
		piv_txn_end(tk);
		errfx(1, err, "error while selecting applet");
	}
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
assert_slotid(uint slotid)
{
	if (slotid >= 0x9A && slotid <= 0x9E && slotid != 0x9B)
		return;
	if (slotid >= PIV_SLOT_RETIRED_1 && slotid <= PIV_SLOT_RETIRED_20)
		return;
	errx(EXIT_BAD_ARGS, "PIV slot %02X cannot be used for asymmetric "
	    "signing", slotid);
}

static void
assert_pin(struct piv_token *pk, struct piv_slot *slot, boolean_t prompt)
{
	errf_t *er;
	uint retries = min_retries;
	enum piv_pin auth = piv_token_default_auth(pk);
	boolean_t touch = B_FALSE;

#if 0
	if (pin == NULL && pk == sysk) {
		rv = piv_system_token_auth(pk);
		if (rv == 0)
			return;
	}
#endif

	if (slot != NULL) {
		enum piv_slot_auth rauth = piv_slot_get_auth(pk, slot);
		if (rauth & PIV_SLOT_AUTH_PIN)
			prompt = B_TRUE;
		if (rauth & PIV_SLOT_AUTH_TOUCH)
			touch = B_TRUE;
	}

	if (pin == NULL && !prompt)
		return;

	if (pin == NULL && prompt) {
		char prompt[64];
		char *guid = piv_token_shortid(pk);
		snprintf(prompt, 64, "Enter %s for token %s: ",
		    pin_type_to_name(auth), guid);
		do {
			pin = getpass(prompt);
		} while (pin == NULL && errno == EINTR);
		if ((pin == NULL && errno == ENXIO) || strlen(pin) < 1) {
			piv_txn_end(pk);
			errx(EXIT_PIN, "a PIN is required to unlock "
			    "token %s", guid);
		} else if (pin == NULL) {
			piv_txn_end(pk);
			err(EXIT_PIN, "failed to read PIN");
		} else if (strlen(pin) < 6 || strlen(pin) > 8) {
			const char *charType = "digits";
			if (piv_token_is_ykpiv(selk))
				charType = "characters";
			errx(EXIT_PIN, "a valid PIN must be 6-8 %s in length",
			    charType);
		}
		pin = strdup(pin);
		free(guid);
	}
	er = piv_verify_pin(pk, auth, pin, &retries, B_FALSE);
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

	if (touch) {
		fprintf(stderr, "Touch button confirmation may be required.\n");
	}
}

#if defined(__sun)
const char *
_umem_debug_init()
{
	return ("guards");
}
#endif

void
usage(void)
{
	exit(EXIT_BAD_ARGS);
}

static errf_t *
cmd_setup(void)
{
	/*
	 * collect info:
	 *  - CA's DN,
	 *  - CRL URLs
	 *  - constraints (e.g. nameconstraints)
	 *  - CRL timing settings
	 *  - key gen settings
	 *
	 * provision config:
	 *  - pin, puk and admin key
	 *  - require attestation? choose attestation CAs
	 *  - templates and slots
	 *  - variable definitions (and free variables)
	 */

}

const char *optstring = "";

int
main(int argc, char *argv[])
{
	LONG rv;
	errf_t *err = ERRF_OK;
	extern char *optarg;
	extern int optind;
	int c;
	uint len;
	char *ptr;
	uint8_t *buf;
	uint d_level = 0;
	enum piv_alg overalg = 0;
	boolean_t hasover = B_FALSE;
	char *v;

	bunyan_init();
	bunyan_set_name("pivy-ca");

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'd':
			bunyan_set_level(BNY_TRACE);
			if (++d_level > 1)
				piv_full_apdu_debug = B_TRUE;
			break;
		}
	}

	if (optind >= argc) {
		warnx("operation required");
		usage();
	}

	const char *op = argv[optind++];

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
	if (rv != SCARD_S_SUCCESS) {
		errfx(EXIT_IO_ERROR, pcscerrf("SCardEstablishContext", rv),
		    "failed to initialise libpcsc");
	}

	struct sshbuf *b, *b2;
	uint8_t *data;
	size_t dlen;
	struct piv_fascn *fascn;

	b = sshbuf_new();
	sshbuf_b64tod(b, "0EOUWCEMLBmghG2DaFoQghCM5zmEEIyj/A==");

	err = piv_fascn_decode(sshbuf_ptr(b), sshbuf_len(b), &fascn);
	if (err != ERRF_OK)
		errfx(EXIT_FAILURE, err, "what");

	fprintf(stderr, "%s\n", piv_fascn_to_string(fascn));

	piv_fascn_set_indiv_cred_issue(fascn, "2");

	fprintf(stderr, "%s\n", piv_fascn_to_string(fascn));

	err = piv_fascn_encode(fascn, &data, &dlen);
	if (err != ERRF_OK)
		errfx(EXIT_FAILURE, err, "what");

	b2 = sshbuf_from(data, dlen);
	sshbuf_reset(b);
	sshbuf_dtob64(b2, b, 0);
	fprintf(stderr, "%s\n", sshbuf_dup_string(b));

	return (0);
}

void
cleanup_exit(int i)
{
	exit(i);
}
