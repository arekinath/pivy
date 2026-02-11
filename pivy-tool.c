/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Copyright 2021 The University of Queensland
 *
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
#if defined(__sun)
#include <sys/fork.h>
#endif
#include <sys/wait.h>

#include "openssh/config.h"
#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "utils.h"
#include "tlv.h"
#include "piv.h"
#include "bunyan.h"
#include "utils.h"
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
static boolean_t json = B_FALSE;
static boolean_t enum_all_retired = B_FALSE;
static boolean_t save_pinfo_admin = B_TRUE;
static uint8_t *guid = NULL;
static size_t guid_len = 0;
static uint min_retries = 1;
static struct sshkey *opubkey = NULL;
static const char *pin = NULL;
static const char *newpin = NULL;
static const uint8_t DEFAULT_ADMIN_KEY[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};
#define DEFAULT_KEY_LENGTH 24
static const uint8_t *admin_key = DEFAULT_ADMIN_KEY;
static int key_length = DEFAULT_KEY_LENGTH;
static enum piv_alg key_alg = PIV_ALG_3DES;
static enum piv_alg key_new_alg = 0;
static boolean_t user_specified_alg = B_FALSE;

static enum ykpiv_pin_policy pinpolicy = YKPIV_PIN_DEFAULT;
static enum ykpiv_touch_policy touchpolicy = YKPIV_TOUCH_DEFAULT;

static struct piv_token *ks = NULL;
static struct piv_token *selk = NULL;
//static struct piv_token *sysk = NULL;
static struct piv_slot *override = NULL;

static struct cert_var_scope *cvroot = NULL;
const char *cvtpl_name = NULL;

static struct piv_ctx *piv_ctx;

static errf_t *set_default_slot_cert_vars(uint slotid);

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

static size_t
len_for_admin_alg(enum piv_alg alg)
{
	switch (alg) {
	case PIV_ALG_3DES:
		return (24);
	case PIV_ALG_AES128:
		return (16);
	case PIV_ALG_AES192:
		return (24);
	case PIV_ALG_AES256:
		return (32);
	default:
		return (0);
	}
}

static const char *
admin_alg_name(enum piv_alg alg)
{
	const char *name = piv_alg_to_string(alg);
	return (name != NULL ? name : "UNKNOWN");
}

static errf_t *
diagnose_admin_auth_failure(struct piv_token *tk, enum piv_alg attempted_alg,
    errf_t *auth_err)
{
	errf_t *err;

	/* Only YubicoPIV >= 5.3.0 can query algorithm */
	if (!piv_token_is_ykpiv(tk) ||
	    ykpiv_version_compare(tk, 5, 3, 0) < 0) {
		return errf("AdminAuthError", auth_err,
		    "PIV admin authentication failed with %s algorithm\n"
		    "  Possible solutions:\n"
		    "  1. Verify key value: pivy-tool -K <hexkey> <command>\n"
		    "  2. Try different algorithm: pivy-tool -A AES192 <command>\n"
		    "  3. Factory reset (DESTRUCTIVE): pivy-tool factory-reset",
		    admin_alg_name(attempted_alg));
	}

	/* Query actual algorithm from card */
	enum piv_alg actual_alg;
	boolean_t is_default;

	err = ykpiv_admin_auth_info(tk, &actual_alg, &is_default, NULL);
	if (err != ERRF_OK) {
		errf_free(err);
		return errf("AdminAuthError", auth_err,
		    "PIV admin authentication failed (algorithm unknown)\n"
		    "  Attempted: %s\n"
		    "  Possible solutions:\n"
		    "  1. Verify key value: pivy-tool -K <hexkey> <command>\n"
		    "  2. Try common algorithms: pivy-tool -A AES192 <command>",
		    admin_alg_name(attempted_alg));
	}

	/* Compare algorithms */
	if (actual_alg != attempted_alg) {
		return errf("AlgorithmMismatch", auth_err,
		    "Management key algorithm mismatch detected\n"
		    "  Attempted: %s (%zu-byte key)\n"
		    "  Card configured for: %s (%zu-byte key)\n"
		    "  Possible solutions:\n"
		    "  1. Retry with correct algorithm: pivy-tool -A %s <command>\n"
		    "  2. Factory reset (DESTRUCTIVE): pivy-tool factory-reset",
		    admin_alg_name(attempted_alg), len_for_admin_alg(attempted_alg),
		    admin_alg_name(actual_alg), len_for_admin_alg(actual_alg),
		    admin_alg_name(actual_alg));
	}

	/* Algorithms match, must be wrong key value */
	return errf("AdminAuthError", auth_err,
	    "Management key value is incorrect (algorithm %s is correct)\n"
	    "  Possible solutions:\n"
	    "  1. Verify key: pivy-tool -K <hexkey> <command>\n"
	    "  2. If PINFO exists, ensure PIN is correct\n"
	    "  3. Factory reset (DESTRUCTIVE): pivy-tool factory-reset",
	    admin_alg_name(actual_alg));
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
		char pinbuf[16];
		char *guid = piv_token_shortid(pk);
		snprintf(prompt, 64, "Enter %s for token %s: ",
		    pin_type_to_name(auth), guid);
		do {
			pin = readpassphrase(prompt, pinbuf, sizeof (pinbuf),
			    RPP_ECHO_OFF);
		} while (pin == NULL && errno == EINTR);
		if ((pin == NULL && errno == ENOTTY) || strlen(pin) < 1) {
			piv_txn_end(pk);
			errx(EXIT_PIN, "a PIN is required to unlock "
			    "token %s", guid);
		} else if (pin == NULL) {
			piv_txn_end(pk);
			err(EXIT_PIN, "failed to read PIN");
		} else if (strlen(pin) < 4 || strlen(pin) > 8) {
			const char *charType = "digits";
			if (piv_token_is_ykpiv(selk))
				charType = "characters";
			errx(EXIT_PIN, "a valid PIN must be 4-8 %s in length",
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
		errx(EXIT_PIN, "operation aborted: only %d PIN retries "
		    "remaining, cowardly refusing to attempt PIN without -f",
		    retries);
	} else if (er) {
		piv_txn_end(pk);
		errfx(EXIT_PIN, er, "failed to verify PIN");
	}

	if (touch) {
		fprintf(stderr, "Touch button confirmation may be required.\n");
	}
}

static errf_t *
enum_all_retired_slots(struct piv_token *pk)
{
	errf_t *err;
	uint i;

	for (i = PIV_SLOT_RETIRED_1; i <= PIV_SLOT_RETIRED_20; ++i) {
		err = piv_read_cert(pk, i);
		if (err && !errf_caused_by(err, "NotFoundError") &&
		    !errf_caused_by(err, "PermissionError") &&
		    !errf_caused_by(err, "NotSupportedError")) {
			return (err);
		} else if (err) {
			errf_free(err);
		}
	}

	return (ERRF_OK);
}

static char *
escape_qstr(const char *inp)
{
	struct sshbuf *buf = sshbuf_new();
	const char *p;
	char *ret;

	for (p = inp; *p != '\0'; ++p) {
		if (*p == '"' || *p == '\\' || *p == '\'')
			sshbuf_put_u8(buf, '\\');
		if (*p == '\n') {
			sshbuf_putf(buf, "\\n");
			continue;
		}
		sshbuf_put_u8(buf, *p);
	}

	ret = sshbuf_dup_string(buf);
	sshbuf_free(buf);

	return (ret);
}

static errf_t *
cmd_list(void)
{
	struct piv_token *pk;
	struct piv_slot *slot = NULL;
	uint i;
	char *buf = NULL;
	const uint8_t *temp;
	const char *str;
	size_t len;
	enum piv_pin defauth;
	errf_t *err;
	boolean_t first;
	const struct piv_chuid *chuid;
	const struct piv_fascn *fascn;
	struct piv_cardcap *cardcap;

	for (pk = ks; pk != NULL; pk = piv_token_next(pk)) {
		const uint8_t *tguid = piv_token_guid(pk);
		if (guid != NULL &&
		    bcmp(tguid, guid, guid_len) != 0) {
			continue;
		}

		if ((err = piv_txn_begin(pk)))
			return (err);
		assert_select(pk);
		if ((err = piv_read_cardcap(pk, &cardcap))) {
			if (!errf_caused_by(err, "NotFoundError"))
				warnfx(err, "failed to read cardcap");
			cardcap = NULL;
			errf_free(err);
		}
		if ((err = piv_read_all_certs(pk))) {
			piv_txn_end(pk);
			return (err);
		}
		if (enum_all_retired) {
			if ((err = enum_all_retired_slots(pk))) {
				piv_txn_end(pk);
				return (err);
			}
		}
		piv_txn_end(pk);

		chuid = piv_token_chuid(pk);
		if (chuid != NULL)
			fascn = piv_chuid_get_fascn(chuid);
		else
			fascn = NULL;

		if (json) {
			printf("{");
			buf = piv_token_shortid(pk);
			printf("\"short_id\":\"%s\"", buf);
			free(buf);
			printf(",\"guid\":\"%s\"", piv_token_guid_hex(pk));
			printf(",\"reader\":\"%s\"", piv_token_rdrname(pk));
			printf(",\"chuid\":");
			if (chuid == NULL) {
				printf("null");
			} else {
				printf("{");
				printf("\"signed\":%s",
				    piv_token_has_signed_chuid(pk) ? "true" :
				    "false");
				if (chuid != NULL &&
				    (temp = piv_chuid_get_chuuid(chuid)) != NULL) {
					buf = buf_to_hex(temp, 16, B_FALSE);
					printf(",\"cardholder\":\"%s\"", buf);
					free(buf);
				}
				printf(",\"fasc-n\":\"%s\"",
				    piv_fascn_to_string(fascn));
				printf(",\"expiry\":\"");
				temp = piv_chuid_get_expiry(chuid, &len);
				for (i = 0; i < len; ++i)
					putchar(temp[i]);
				printf("\"");
				printf(",\"expired\":%s",
				    piv_chuid_is_expired(chuid) ? "true" :
				    "false");
				printf("}");
			}
			printf(",\"ykpiv\":%s",
			    piv_token_is_ykpiv(pk) ? "true" : "false");
			if (piv_token_is_ykpiv(pk)) {
				if (ykpiv_token_has_serial(pk)) {
					printf(",\"serial\":%u",
					    ykpiv_token_serial(pk));
				}
				temp = ykpiv_token_version(pk);
				printf(",\"ykpiv_version\":\"%u.%u.%u\"",
				    temp[0], temp[1], temp[2]);
			}
			if ((str = piv_token_app_uri(pk)) != NULL) {
				printf(",\"applet_uri\":\"%s\"", str);
			}
			if ((str = piv_token_app_label(pk)) != NULL) {
				printf(",\"applet\":\"%s\"", str);
			}
			defauth = piv_token_default_auth(pk);

			printf(",\"auth\":{");
			printf("\"pin\":{\"supported\":%s,\"default\":%s}",
			    piv_token_has_auth(pk, PIV_PIN) ? "true" : "false",
			    (defauth == PIV_PIN) ? "true" : "false");
			printf(",\"global_pin\":{\"supported\":%s,\"default\":%s}",
			    piv_token_has_auth(pk, PIV_GLOBAL_PIN) ? "true" : "false",
			    (defauth == PIV_GLOBAL_PIN) ? "true" : "false");
			printf(",\"biometrics\":{\"supported\":%s,\"default\":%s}",
			    piv_token_has_auth(pk, PIV_OCC) ? "true" : "false",
			    (defauth == PIV_OCC) ? "true" : "false");
			printf("}");

			printf(",\"vci_supported\":%s",
			    piv_token_has_vci(pk) ? "true" : "false");

			printf(",\"algorithms\":[");
			for (i = 0; i < piv_token_nalgs(pk); ++i) {
				printf("%s\"%s\"",
				    (i == 0) ? "" : ",",
				    piv_alg_to_string(piv_token_alg(pk, i)));
			}
			printf("]");

			printf(",\"slots\":{");
			slot = NULL;
			first = B_TRUE;
			while ((slot = piv_slot_next(pk, slot)) != NULL) {
				const struct sshkey *pubkey = piv_slot_pubkey(slot);
				enum piv_slotid id = piv_slot_id(slot);
				char *slotname, *dn;

				printf("%s\"%02x\":{", first ? "" : ",", id);

				slotname = piv_slotid_to_string(id);
				printf("\"name\":\"%s\"", slotname);
				free(slotname);

				printf(",\"algorithm\":\"%s\"",
				    piv_alg_to_string(piv_slot_alg(slot)));

				printf(",\"key_type\":\"%s\"", sshkey_type(pubkey));
				printf(",\"key_size\":%u", sshkey_size(pubkey));

				dn = escape_qstr(piv_slot_subject(slot));
				printf(",\"subject\":\"%s\"", dn);
				free(dn);

				dn = escape_qstr(piv_slot_issuer(slot));
				printf(",\"issuer\":\"%s\"", dn);
				free(dn);

				printf(",\"cert_serial\":\"%s\"", piv_slot_serial_hex(slot));

				printf(",\"pubkey\":\"");
				sshkey_write(pubkey, stdout);
				printf("\"");

				printf("}");

				first = B_FALSE;
			}
			printf("}");

			printf("}\n");
			continue;
		}

		if (parseable) {
			uint8_t nover[] = { 0, 0, 0 };
			const uint8_t *ver = nover;
			if (piv_token_is_ykpiv(pk))
				ver = ykpiv_token_version(pk);
			printf("%s:%s:%s:%s:%d.%d.%d:%d:",
			    piv_token_rdrname(pk),
			    piv_token_guid_hex(pk),
			    piv_token_has_chuid(pk) ? "true" : "false",
			    piv_token_is_ykpiv(pk) ? "true" : "false",
			    ver[0], ver[1], ver[2],
			    piv_token_is_ykpiv(pk) && ykpiv_token_has_serial(pk) ?
			    ykpiv_token_serial(pk) : 0);
			for (i = 0; i < piv_token_nalgs(pk); ++i) {
				enum piv_alg alg = piv_token_alg(pk, i);
				printf("%s%s", piv_alg_to_string(alg),
				    (i + 1 < piv_token_nalgs(pk)) ? "," : "");
			}
			for (i = 0x9A; i < 0x9F; ++i) {
				slot = piv_get_slot(pk, i);
				if (slot == NULL) {
					printf(":%02X", i);
				} else {
					struct sshkey *key =
					    piv_slot_pubkey(slot);
					printf(":%02X;%s;%s;%u",
					    i, piv_slot_subject(slot),
					    sshkey_type(key),
					    sshkey_size(key));
				}
			}
			printf("\n");
			continue;
		}


		buf = piv_token_shortid(pk);
		printf("%10s: %s\n", "card", buf);
		free(buf);
		printf("%10s: %s\n", "device", piv_token_rdrname(pk));
		if (!piv_token_has_chuid(pk)) {
			printf("%10s: %s\n", "chuid", "not set "
			    "(needs initialization)");
		} else if (piv_token_has_signed_chuid(pk)) {
			printf("%10s: %s\n", "chuid", "ok, signed");
		} else {
			printf("%10s: %s\n", "chuid", "ok");
		}
		printf("%10s: %s\n", "guid", piv_token_guid_hex(pk));
		if (chuid != NULL &&
		    (temp = piv_chuid_get_chuuid(chuid)) != NULL) {
			buf = buf_to_hex(temp, 16, B_FALSE);
			printf("%10s: %s\n", "owner", buf);
			free(buf);
		}
		if (fascn != NULL) {
			printf("%10s: %s\n", "fasc-n",
			    piv_fascn_to_string(fascn));
		}
		if (chuid != NULL &&
		    (temp = piv_chuid_get_expiry(chuid, &len)) != NULL &&
		    len == 8 && temp[0] >= '0' && temp[0] <= '9') {
			printf("%10s: %c%c%c%c-%c%c-%c%c\n", "expiry",
			    temp[0], temp[1], temp[2], temp[3],
			    temp[4], temp[5], temp[6], temp[7]);
		}
		if (piv_token_has_xlen_apdu(pk)) {
			printf("%10s: supports extended-length APDUs\n",
			    "xapdu");
		}
		if (piv_token_is_ykpiv(pk)) {
			temp = ykpiv_token_version(pk);
			printf("%10s: implements YubicoPIV extensions "
			    "(v%d.%d.%d)\n", "yubico", temp[0], temp[1],
			    temp[2]);
			if (ykpiv_token_has_serial(pk)) {
				printf("%10s: %u\n", "serial",
				    ykpiv_token_serial(pk));
			}
		}
		if (piv_token_app_label(pk) != NULL) {
			printf("%10s: %s\n", "applet", piv_token_app_label(pk));
		}
		if (piv_token_app_uri(pk) != NULL) {
			printf("%10s: %s\n", "uri", piv_token_app_uri(pk));
		}
		if (cardcap != NULL) {
			printf("%10s:", "cardcap");
			switch (piv_cardcap_data_model(cardcap)) {
			case PIV_CARDCAP_MODEL_PIV:
				printf(" PIV data model");
				break;
			default:
				printf(" ??? data model (%02X)",
				    piv_cardcap_data_model(cardcap));
				break;
			}
			switch (piv_cardcap_type(cardcap)) {
			case PIV_CARDCAP_FS:
				printf(", FS");
				break;
			case PIV_CARDCAP_JAVACARD:
				printf(", JavaCard");
				break;
			case PIV_CARDCAP_MULTOS:
				printf(", MultOS");
				break;
			case PIV_CARDCAP_JAVACARD_FS:
				printf(", JavaCard+FS");
				break;
			default:
				printf(", Unknown OS (%02X)",
				    piv_cardcap_type(cardcap));
				break;
			}
			printf(", Manuf %02X", piv_cardcap_manufacturer(cardcap));
			printf(", ID: %s", piv_cardcap_id_hex(cardcap));
			if (piv_cardcap_has_pkcs15(cardcap))
				printf(", PKCS#15 support");
			printf("\n");
			piv_cardcap_free(cardcap);
		}
		printf("%10s:", "auth");
		defauth = piv_token_default_auth(pk);
		if (piv_token_has_auth(pk, PIV_PIN)) {
			if (defauth == PIV_PIN)
				printf(" PIN*");
			else
				printf(" PIN");
		}
		if (piv_token_has_auth(pk, PIV_GLOBAL_PIN)) {
			if (defauth == PIV_GLOBAL_PIN)
				printf(" GlobalPIN*");
			else
				printf(" GlobalPIN");
		}
		if (piv_token_has_auth(pk, PIV_OCC)) {
			if (defauth == PIV_OCC)
				printf(" Biometrics*");
			else
				printf(" Biometrics");
		}
		printf("\n");
		if (piv_token_has_vci(pk)) {
			printf("%10s: supports VCI (secure contactless)\n",
			    "vci");
		}
		if (piv_token_nalgs(pk) > 0) {
			printf("%10s: ", "algos");
			for (i = 0; i < piv_token_nalgs(pk); ++i) {
				printf("%s ", piv_alg_to_string(
				    piv_token_alg(pk, i)));
			}
			printf("\n");
		}
		if (!piv_token_has_chuid(pk)) {
			printf("%10s:\n", "action");
			printf("%10s Initialize this card using 'pivy-tool "
			    "init'\n", "");
			printf("%10s No keys can be stored on an uninitialized"
			    " card\n", "");
			printf("\n");
			continue;
		}

		printf("%10s:\n", "slots");
		printf("%10s %-3s  %-7s  %-4s  %-30s\n", "", "ID", "TYPE",
		    "BITS", "CERTIFICATE");
		while ((slot = piv_slot_next(pk, slot)) != NULL) {
			struct sshkey *pubkey = piv_slot_pubkey(slot);
			printf("%10s %-3x  %-7s  %-4u  %-30s\n", "",
			    piv_slot_id(slot), sshkey_type(pubkey),
			    sshkey_size(pubkey), piv_slot_subject(slot));
		}
		printf("\n");
	}

	return (ERRF_OK);
}

static errf_t *
save_pinfo_admin_key(struct piv_token *tk)
{
	struct piv_pinfo *pinfo;
	errf_t *err;
	assert_pin(tk, NULL, B_FALSE);
again:
	err = piv_read_pinfo(tk, &pinfo);
	if (err && errf_caused_by(err, "PermissionError")) {
		assert_pin(tk, NULL, B_TRUE);
		goto again;
	}
	if (err) {
		errf_free(err);
		pinfo = piv_pinfo_new();
	}
	ykpiv_pinfo_set_admin_key(pinfo, admin_key, key_length);
	err = piv_write_pinfo(tk, pinfo);
	piv_pinfo_free(pinfo);
	return (err);
}

static errf_t *
try_pinfo_admin_key(struct piv_token *tk)
{
	errf_t *err;
	struct piv_pinfo *pinfo;

	assert_pin(tk, NULL, B_FALSE);
again:
	err = piv_read_pinfo(tk, &pinfo);
	if (err && errf_caused_by(err, "PermissionError")) {
		assert_pin(tk, NULL, B_TRUE);
		goto again;
	}
	if (err == ERRF_OK) {
		const uint8_t *key;
		size_t keylen, ekeylen;

		key = ykpiv_pinfo_get_admin_key(pinfo, &keylen);
		ekeylen = len_for_admin_alg(key_alg);
		if (key != NULL && keylen == ekeylen) {
			key_length = keylen;
			admin_key = malloc(keylen);
			bcopy(key, (uint8_t *)admin_key, keylen);
			err = ERRF_OK;
		} else if (key == NULL) {
			err = errf("NoAdminKey", NULL, "PIV PINFO file "
			    "does not contain Yubico admin key extension");
			goto out;
		} else {
			err = errf("BadLength", NULL, "Data is wrong length "
			    "for an admin key (%d bytes)", keylen);
			goto out;
		}
		bunyan_log(BNY_DEBUG, "using admin key from printedinfo file",
		    NULL);
		piv_pinfo_free(pinfo);
	}

out:
	if (err) {
		err = errf("AdminAuthError", err, "PIV admin auth with "
		    "default key failed, and failed to retrieve PIN-protected "
		    "admin key data");
	}
	return (err);
}

static errf_t *
try_admin_auth_with_recovery(struct piv_token *tk, enum piv_alg *used_alg)
{
	errf_t *err, *err_pinfo, *err_query, *err2;

	/* Attempt 1: Try with current key_alg */
	bunyan_log(BNY_TRACE, "attempting admin auth",
	    "algorithm", BNY_STRING, admin_alg_name(key_alg),
	    NULL);

	err = piv_auth_admin(tk, admin_key, key_length, key_alg);
	if (err == ERRF_OK) {
		*used_alg = key_alg;
		return (ERRF_OK);
	}

	/* Only retry on permission/argument errors */
	if (!errf_caused_by(err, "PermissionError") &&
	    !errf_caused_by(err, "ArgumentError")) {
		*used_alg = key_alg;
		return (err);
	}

	/* Attempt 2: Try PINFO key if using default */
	if (admin_key == DEFAULT_ADMIN_KEY) {
		bunyan_log(BNY_DEBUG, "admin auth failed with default key, "
		    "trying PINFO",
		    NULL);

		err_pinfo = try_pinfo_admin_key(tk);
		if (err_pinfo == ERRF_OK) {
			/* Key updated, retry authentication */
			err2 = piv_auth_admin(tk, admin_key, key_length, key_alg);
			if (err2 == ERRF_OK) {
				errf_free(err);
				*used_alg = key_alg;
				bunyan_log(BNY_INFO, "admin auth succeeded with PINFO key",
				    NULL);
				return (ERRF_OK);
			}
			/* PINFO auth failed too, continue to algorithm retry */
			errf_free(err);
			err = err2;
		} else {
			errf_free(err_pinfo);
		}
	}

	/* Attempt 3: Try algorithm detection/retry (YubiKey >= 5.3.0 only) */
	/* Skip if user explicitly specified algorithm */
	if (user_specified_alg) {
		bunyan_log(BNY_DEBUG, "skipping algorithm retry (user specified -A)",
		    NULL);
		goto diagnose;
	}

	if (!piv_token_is_ykpiv(tk) ||
	    ykpiv_version_compare(tk, 5, 3, 0) < 0) {
		goto diagnose;
	}

	/* Query actual algorithm */
	enum piv_alg actual_alg;
	boolean_t is_default;

	err_query = ykpiv_admin_auth_info(tk, &actual_alg, &is_default, NULL);
	if (err_query != ERRF_OK) {
		errf_free(err_query);
		goto diagnose;
	}

	/* Only retry if algorithm differs */
	if (actual_alg == key_alg) {
		bunyan_log(BNY_DEBUG, "algorithm matches, not retrying",
		    "algorithm", BNY_STRING, admin_alg_name(key_alg),
		    NULL);
		goto diagnose;
	}

	/* Check if key length matches new algorithm */
	size_t new_len = len_for_admin_alg(actual_alg);
	if (new_len != key_length) {
		bunyan_log(BNY_DEBUG, "algorithm mismatch, but key length incompatible",
		    "current_alg", BNY_STRING, admin_alg_name(key_alg),
		    "detected_alg", BNY_STRING, admin_alg_name(actual_alg),
		    "current_len", BNY_UINT, (uint)key_length,
		    "required_len", BNY_UINT, (uint)new_len,
		    NULL);
		goto diagnose;
	}

	/* Retry with detected algorithm */
	bunyan_log(BNY_INFO, "retrying admin auth with detected algorithm",
	    "attempted", BNY_STRING, admin_alg_name(key_alg),
	    "detected", BNY_STRING, admin_alg_name(actual_alg),
	    NULL);

	err2 = piv_auth_admin(tk, admin_key, key_length, actual_alg);
	if (err2 == ERRF_OK) {
		errf_free(err);
		key_alg = actual_alg;  /* Update global */
		*used_alg = actual_alg;
		bunyan_log(BNY_INFO, "admin auth succeeded with corrected algorithm",
		    "algorithm", BNY_STRING, admin_alg_name(actual_alg),
		    NULL);
		return (ERRF_OK);
	}

	/* Algorithm retry failed too */
	errf_free(err);
	err = err2;

diagnose:
	/* Generate enhanced diagnostic error */
	err = diagnose_admin_auth_failure(tk, key_alg, err);
	*used_alg = key_alg;
	return (err);
}

static errf_t *
cmd_pinfo(void)
{
	struct piv_pinfo *pinfo;
	errf_t *err;
	size_t len;
	const char *org1, *org2;

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	assert_pin(selk, NULL, B_FALSE);
again:
	err = piv_read_pinfo(selk, &pinfo);
	if (errf_caused_by(err, "PermissionError")) {
		errf_free(err);
		assert_pin(selk, NULL, B_TRUE);
		goto again;
	}
	piv_txn_end(selk);
	if (err) {
		err = funcerrf(err, "failed to read pinfo");
		return (err);
	}

	printf("%12s: %s\n", "name", piv_pinfo_get_name(pinfo));
	printf("%12s: %s\n", "affiliation", piv_pinfo_get_affiliation(pinfo));
	printf("%12s: %s\n", "expiry", piv_pinfo_get_expiry(pinfo));
	printf("%12s: %s\n", "serial", piv_pinfo_get_serial(pinfo));
	printf("%12s: %s\n", "issuer", piv_pinfo_get_issuer(pinfo));

	org1 = piv_pinfo_get_org_line_1(pinfo);
	org2 = piv_pinfo_get_org_line_2(pinfo);
	if (org1 != NULL || org2 != NULL) {
		printf("%12s: %s\n", "organization", org1 ? org1 : "");
		printf("%12s  %s\n", "", org2 ? org2 : "");
	}

	if (ykpiv_pinfo_get_admin_key(pinfo, &len) != NULL && len > 0)
		printf("%12s: contains admin key\n", "yubico");

	piv_pinfo_free(pinfo);

	return (ERRF_OK);
}

static errf_t *
cmd_update_keyhist(void)
{
	uint oncard, offcard;
	const char *url;
	struct piv_slot *slot;
	errf_t *err;

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	if ((err = piv_read_all_certs(selk))) {
		piv_txn_end(selk);
		return (err);
	}
	if ((err = enum_all_retired_slots(selk))) {
		piv_txn_end(selk);
		return (err);
	}
	oncard = 0;
	slot = NULL;
	while ((slot = piv_slot_next(selk, slot)) != NULL) {
		uint slotid = piv_slot_id(slot);
		if (slotid >= PIV_SLOT_RETIRED_1 &&
		    slotid <= PIV_SLOT_RETIRED_20) {
			uint index = (slotid - PIV_SLOT_RETIRED_1) + 1;
			if (index > oncard)
				oncard = index;
		}
	}
	offcard = piv_token_keyhistory_offcard(selk);
	url = piv_token_offcard_url(selk);

	enum piv_alg used_alg;
	err = try_admin_auth_with_recovery(selk, &used_alg);
	if (err == ERRF_OK) {
		err = piv_write_keyhistory(selk, oncard, offcard, url);
	}
	piv_txn_end(selk);

	if (err) {
		err = funcerrf(err, "failed to update keyhistory object");
		return (err);
	}

	return (ERRF_OK);
}

static errf_t *
cmd_init(void)
{
	errf_t *err;
	struct piv_chuid *chuid;
	struct piv_fascn *fascn;
	struct piv_pinfo *pinfo;
	struct piv_cardcap *cardcap;
	char *tmp, *p;
	unsigned long lifetime_secs;
	char serial[32] = {0};

	cardcap = piv_cardcap_new();
	piv_cardcap_set_random_id(cardcap);

	/* Now, set up the CHUID file */
	chuid = piv_chuid_new();

	fascn = piv_fascn_zero();

	err = scope_eval(cvroot, "agency_code", &tmp);
	if (err == ERRF_OK) {
		piv_fascn_set_agency_code(fascn, tmp);
		free(tmp);
	}
	errf_free(err);

	err = scope_eval(cvroot, "system_code", &tmp);
	if (err == ERRF_OK) {
		piv_fascn_set_system_code(fascn, tmp);
		free(tmp);
	}
	errf_free(err);

	err = scope_eval(cvroot, "cred_number", &tmp);
	if (err == ERRF_OK) {
		piv_fascn_set_cred_number(fascn, tmp);
		free(tmp);
	}
	errf_free(err);

	err = scope_eval(cvroot, "person_id", &tmp);
	if (err == ERRF_OK) {
		piv_fascn_set_person_id(fascn, PIV_FASCN_POA_EMPLOYEE, tmp);
		free(tmp);
	}
	errf_free(err);

	piv_chuid_set_fascn(chuid, fascn);
	piv_fascn_free(fascn);

	piv_chuid_set_random_guid(chuid);

	lifetime_secs = 3600*24*365*10;
	err = scope_eval(cvroot, "lifetime", &tmp);
	if (err == ERRF_OK) {
		errno = 0;
		lifetime_secs = strtoul(tmp, &p, 10);
		if (errno != 0) {
			return (errf("SyntaxError", errfno("strtoul", errno,
			    NULL), "Error parsing contents of 'lifetime' "
			    "variable: '%s'", tmp));
		}
		if (*p == 'h' && *(p + 1) == '\0') {
			++p;
			lifetime_secs *= 3600;
		} else if (*p == 'd' && *(p + 1) == '\0') {
			++p;
			lifetime_secs *= 3600*24;
		} else if (*p == 'w' && *(p + 1) == '\0') {
			++p;
			lifetime_secs *= 3600*24*7;
		} else if (*p == 'y' && *(p + 1) == '\0') {
			++p;
			lifetime_secs *= 3600*24*365;
		}
		if (*p != '\0') {
			return (errf("SyntaxError", NULL, "Error parsing "
			    "contents of 'lifetime' variable: "
			    "trailing garbage '%s'", p));
		}
		free(tmp);
	}
	errf_free(err);
	piv_chuid_set_expiry_rel(chuid, lifetime_secs);

	/* And set up printed info */
	pinfo = piv_pinfo_new();

	piv_pinfo_set_name(pinfo, "pivy user");
	err = scope_eval(cvroot, "name", &tmp);
	if (err == ERRF_OK) {
		piv_pinfo_set_name(pinfo, tmp);
		free(tmp);
	}
	errf_free(err);

	err = scope_eval(cvroot, "affiliation", &tmp);
	if (err == ERRF_OK) {
		piv_pinfo_set_affiliation(pinfo, tmp);
		free(tmp);
	}
	errf_free(err);

	err = scope_eval(cvroot, "issuer", &tmp);
	if (err == ERRF_OK) {
		piv_pinfo_set_issuer(pinfo, tmp);
		free(tmp);
	}
	errf_free(err);

	piv_pinfo_set_expiry_rel(pinfo, lifetime_secs);
	if (ykpiv_token_has_serial(selk)) {
		snprintf(serial, sizeof (serial), "%u",
		    ykpiv_token_serial(selk));
		piv_pinfo_set_serial(pinfo, serial);
	}
	err = scope_eval(cvroot, "serial", &tmp);
	if (err == ERRF_OK) {
		piv_pinfo_set_serial(pinfo, tmp);
		free(tmp);
	}
	errf_free(err);
	piv_pinfo_set_kv_string(pinfo, "generator", "pivy");

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	enum piv_alg used_alg;
	err = try_admin_auth_with_recovery(selk, &used_alg);
	if (err == ERRF_OK) {
		err = piv_write_cardcap(selk, cardcap);
	}
	if (err == ERRF_OK) {
		err = piv_write_chuid(selk, chuid);
	}
	if (err == ERRF_OK) {
		err = piv_write_pinfo(selk, pinfo);
	}
	piv_txn_end(selk);

	if (errf_caused_by(err, "DeviceOutOfMemoryError")) {
		err = funcerrf(err, "out of EEPROM to write CHUID "
		    "and CARDCAP");
		return (err);
	} else if (errf_caused_by(err, "PermissionError")) {
		err = funcerrf(err, "cannot write init data due to failed "
		    "admin authentication");
		return (err);
	} else if (err) {
		err = funcerrf(err, "failed to write to card");
		return (err);
	}

	/* This is for cmd_setup */
	guid = malloc(GUID_LEN);
	bcopy(piv_chuid_get_guid(chuid), guid, GUID_LEN);
	guid_len = GUID_LEN;

	fprintf(stdout, "%s\n", piv_chuid_get_guidhex(chuid));

	piv_chuid_free(chuid);
	piv_pinfo_free(pinfo);

	return (ERRF_OK);
}

static errf_t *
cmd_set_admin(uint8_t *new_admin_key, size_t len)
{
	errf_t *err;

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	enum piv_alg used_alg;
	err = try_admin_auth_with_recovery(selk, &used_alg);
	if (err) {
		err = funcerrf(err, "Failed to authenticate with old admin key");
	} else {
		err = ykpiv_set_admin(selk, new_admin_key, len, key_new_alg,
		    touchpolicy);
		if (err) {
			err = funcerrf(err, "Failed to set new admin key");
		}
		if (!err && save_pinfo_admin) {
			admin_key = new_admin_key;
			key_length = len;
			if ((err = save_pinfo_admin_key(selk))) {
				err = funcerrf(err, "Failed to write new "
				    "admin key to printed info object");
			}
		}
	}
	piv_txn_end(selk);

	if (err)
		return (err);
	return (ERRF_OK);
}

static errf_t *
cmd_change_pin(enum piv_pin pintype)
{
	errf_t *err;
	char prompt[64];
	char *p, *guidhex;
	const char *charType = "digits";
	if (piv_token_is_ykpiv(selk))
		charType = "characters";

	guidhex = piv_token_shortid(selk);

	if (pin == NULL) {
		char pinbuf[16];
		snprintf(prompt, 64, "Enter current %s (%s): ",
		    pin_type_to_name(pintype), guidhex);
		do {
			p = readpassphrase(prompt, pinbuf, sizeof (pinbuf),
			    RPP_ECHO_OFF | RPP_REQUIRE_TTY);
		} while (p == NULL && errno == EINTR);
		if (p == NULL) {
			err = errfno("readpassphrase", errno, "");
			return (err);
		}
		pin = strdup(p);
	}

	if (newpin == NULL) {
		char pinbuf[16];
again:
		snprintf(prompt, 64, "Enter new %s (%s): ",
		    pin_type_to_name(pintype), guidhex);
		do {
			p = readpassphrase(prompt, pinbuf, sizeof (pinbuf),
			    RPP_ECHO_OFF | RPP_REQUIRE_TTY);
		} while (p == NULL && errno == EINTR);
		if (p == NULL) {
			err = errfno("readpassphrase", errno, "");
			return (err);
		}
		if (strlen(p) < 4 || strlen(p) > 8) {
			warnx("PIN must be 4-8 %s", charType);
			goto again;
		}
		newpin = strdup(p);
		snprintf(prompt, 64, "Confirm new %s (%s): ",
		    pin_type_to_name(pintype), guidhex);
		do {
			p = readpassphrase(prompt, pinbuf, sizeof (pinbuf),
			    RPP_ECHO_OFF | RPP_REQUIRE_TTY);
		} while (p == NULL && errno == EINTR);
		if (p == NULL) {
			err = errfno("readpassphrase", errno, "");
			return (err);
		}
		if (strcmp(p, newpin) != 0) {
			warnx("PINs do not match");
			goto again;
		}
	}
	if (strlen(newpin) < 4 || strlen(newpin) > 8) {
		warnx("PIN must be 4-8 %s", charType);
		goto again;
	}
	free(guidhex);

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	err = piv_change_pin(selk, pintype, pin, newpin);
	piv_txn_end(selk);

	if (errf_caused_by(err, "PermissionError")) {
		err = funcerrf(err, "current PIN was incorrect; PIN "
		    "change attempt failed");
		return (err);
	} else if (err) {
		err = funcerrf(err, "failed to set new PIN");
		return (err);
	}

	return (ERRF_OK);
}

static errf_t *
cmd_reset_pin(void)
{
	errf_t *err;
	char prompt[64];
	char *p, *guidhex;
	const char *charType = "digits";
	if (piv_token_is_ykpiv(selk))
		charType = "characters";

	guidhex = piv_token_shortid(selk);
	if (pin == NULL) {
		char pinbuf[16];
		snprintf(prompt, 64, "Enter PUK (%s): ", guidhex);
		do {
			p = readpassphrase(prompt, pinbuf, sizeof (pinbuf),
			    RPP_ECHO_OFF | RPP_REQUIRE_TTY);
		} while (p == NULL && errno == EINTR);
		if (p == NULL) {
			err = errfno("readpassphrase", errno, "");
			return (err);
		}
		pin = strdup(p);
	}

	if (newpin == NULL) {
		char pinbuf[16];
again:
		snprintf(prompt, 64, "Enter new PIV PIN (%s): ", guidhex);
		do {
			p = readpassphrase(prompt, pinbuf, sizeof (pinbuf),
			    RPP_ECHO_OFF | RPP_REQUIRE_TTY);
		} while (p == NULL && errno == EINTR);
		if (p == NULL) {
			err = errfno("readpassphrase", errno, "");
			return (err);
		}
		if (strlen(p) < 4 || strlen(p) > 8) {
			warnx("PIN must be 4-8 %s", charType);
			goto again;
		}
		newpin = strdup(p);
		snprintf(prompt, 64, "Confirm new PIV PIN (%s): ", guidhex);
		do {
			p = readpassphrase(prompt, pinbuf, sizeof (pinbuf),
			    RPP_ECHO_OFF | RPP_REQUIRE_TTY);
		} while (p == NULL && errno == EINTR);
		if (p == NULL) {
			err = errfno("readpassphrase", errno, "");
			return (err);
		}
		if (strcmp(p, newpin) != 0) {
			warnx("PINs do not match");
			goto again;
		}
	}
	if (strlen(newpin) < 4 || strlen(newpin) > 8) {
		warnx("PIN must be 4-8 %s", charType);
		goto again;
	}
	free(guidhex);

	if ((err = piv_txn_begin(selk)))
		errfx(1, err, "failed to open transaction");
	assert_select(selk);
	err = piv_reset_pin(selk, PIV_PIN, pin, newpin);
	piv_txn_end(selk);

	if (errf_caused_by(err, "PermissionError")) {
		err = funcerrf(err, "PUK was incorrect; PIN reset "
		    "attempt failed");
		return (err);
	} else if (err) {
		err = funcerrf(err, "failed to set new PIN");
		return (err);
	}

	return (ERRF_OK);
}

static errf_t *
selfsign_slot(uint slotid, enum piv_alg alg, struct sshkey *pub)
{
	int rv;
	errf_t *err;
	X509 *cert;
	uint8_t *cdata = NULL;
	size_t cdlen;
	uint flags;
	BIGNUM *serial;
	ASN1_INTEGER *serial_asn1;
	const char *guidhex;
	struct cert_var_scope *scope;
	const struct cert_tpl *tpl;
	EVP_PKEY *pkey;

	guidhex = piv_token_shortid(selk);
	(void) scope_set(cvroot, "guid", guidhex);

	err = set_default_slot_cert_vars(slotid);
	if (err != ERRF_OK)
		return (err);

	tpl = cert_tpl_find(cvtpl_name);
	if (tpl == NULL) {
		return (errf("TemplateNotFound", NULL, "No such certificate "
		    "template: %s", cvtpl_name));
	}
	scope = scope_new_for_tpl(cvroot, tpl);

	serial = BN_new();
	serial_asn1 = ASN1_INTEGER_new();
	VERIFY(serial != NULL);
	VERIFY(BN_pseudo_rand(serial, 160, 0, 0) == 1);
	VERIFY(BN_to_ASN1_INTEGER(serial, serial_asn1) != NULL);

	cert = X509_new();
	VERIFY(cert != NULL);
	VERIFY(X509_set_version(cert, 2) == 1);
	VERIFY(X509_set_serialNumber(cert, serial_asn1) == 1);

	if ((err = sshkey_to_evp_pkey(pub, &pkey))) {
		X509_free(cert);
		return (funcerrf(err, "Error converting pubkey to EVP_PKEY"));
	}
	VERIFY(X509_set_pubkey(cert, pkey) == 1);
	EVP_PKEY_free(pkey);

	err = cert_tpl_populate(tpl, scope, cert);
	if (err != ERRF_OK) {
		return (funcerrf(err, "Error populating certificate "
		    "attributes"));
	}

	VERIFY(X509_set_issuer_name(cert, X509_get_subject_name(cert)) == 1);

	assert_pin(selk, override, B_FALSE);

signagain:
	err = piv_selfsign_cert(selk, override, pub, cert);

	if (errf_caused_by(err, "PermissionError")) {
		assert_pin(selk, override, B_TRUE);
		goto signagain;
	} else if (err) {
		err = funcerrf(err, "failed to sign cert with key");
		return (err);
	}

	rv = i2d_X509(cert, &cdata);
	if (cdata == NULL || rv <= 0) {
		make_sslerrf(err, "i2d_X509", "generating cert");
		err = errf("generate", err, "failed to generate signed cert");
		return (err);
	}
	cdlen = (size_t)rv;

	flags = PIV_COMP_NONE;
	err = piv_write_cert(selk, slotid, cdata, cdlen, flags);

	if (err == ERRF_OK &&
	    slotid >= PIV_SLOT_RETIRED_1 && slotid <= PIV_SLOT_RETIRED_20) {
		uint index;
		uint oncard, offcard;
		const char *url;

		index = (slotid - PIV_SLOT_RETIRED_1) + 1;

		oncard = piv_token_keyhistory_oncard(selk);
		offcard = piv_token_keyhistory_offcard(selk);
		url = piv_token_offcard_url(selk);

		if (index > oncard) {
			err = piv_write_keyhistory(selk, index, offcard, url);

			if (err) {
				warnfx(err, "failed to update key "
				    "history object with new cert, trying to "
				    "continue anyway...");
				err = ERRF_OK;
			}
		}
	}

	if (err) {
		err = errf("generate", err, "failed to write new cert");
		return (err);
	}

	return (NULL);
}

static errf_t *
cmd_import(uint slotid)
{
	errf_t *err;
	struct sshkey *pub = NULL, *priv = NULL;
	char *comment;
	char *pass;
	uint8_t *rbuf;
	struct sshbuf *buf;
	size_t boff;
	int rv;
	enum piv_alg alg = PIV_ALG_RSA1024;

	rbuf = read_stdin(16384, &boff);
	VERIFY(rbuf != NULL);

	buf = sshbuf_from(rbuf, boff);
	VERIFY(buf != NULL);

	rv = sshkey_parse_private_fileblob(buf, "", &priv, &comment);
	if (rv == SSH_ERR_KEY_WRONG_PASSPHRASE) {
		char passbuf[256];
		do {
			pass = readpassphrase("Enter passphrase for key: ",
			    passbuf, sizeof (passbuf), RPP_ECHO_OFF |
			    RPP_REQUIRE_TTY);
		} while (pass == NULL && errno == EINTR);
		if ((pass == NULL && errno == ENOTTY) || strlen(pass) < 1) {
			errx(EXIT_PIN, "a passphrase is required to unlock "
			    "the given public key");
		}
		rv = sshkey_parse_private_fileblob(buf, pass, &priv, &comment);
	}
	if (rv != 0) {
		err = funcerrf(ssherrf("sshkey_parse_private_fileblob", rv),
		    "failed to parse key input");
		return (err);
	}
	sshbuf_free(buf);
	buf = NULL;
	free(rbuf);
	rbuf = NULL;

	if ((rv = sshkey_demote(priv, &pub))) {
		err = funcerrf(ssherrf("sshkey_demote", rv),
		    "failed to get public key from private");
		return (err);
	}

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	enum piv_alg used_alg;
	err = try_admin_auth_with_recovery(selk, &used_alg);
	if (err == ERRF_OK) {
		err = ykpiv_import(selk, slotid, priv, pinpolicy, touchpolicy);
	}

	if (err) {
		piv_txn_end(selk);
		err = funcerrf(err, "failed to import key");
		return (err);
	}

	switch (pub->type) {
	case KEY_RSA:
		switch (sshkey_size(pub)) {
		case 1024:
			alg = PIV_ALG_RSA1024;
			break;
		case 2048:
			alg = PIV_ALG_RSA2048;
			break;
		}
		break;
	case KEY_ECDSA:
		switch (sshkey_size(pub)) {
		case 256:
			alg = PIV_ALG_ECCP256;
			break;
		case 384:
			alg = PIV_ALG_ECCP384;
			break;
		}
		break;
	}

	override = piv_force_slot(selk, slotid, alg);
	err = selfsign_slot(slotid, alg, pub);
	piv_txn_end(selk);

	if (err) {
		err = funcerrf(err, "cert generation failed");
		return (err);
	}

	return (ERRF_OK);
}

static errf_t *
cmd_generate(uint slotid, enum piv_alg alg)
{
	errf_t *err;
	struct sshkey *pub = NULL;
	int rv;

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	enum piv_alg used_alg;
	err = try_admin_auth_with_recovery(selk, &used_alg);
	if (err == ERRF_OK) {
		if (pinpolicy == YKPIV_PIN_DEFAULT &&
		    touchpolicy == YKPIV_TOUCH_DEFAULT) {
			err = piv_generate(selk, slotid, alg, &pub);
		} else {
			err = ykpiv_generate(selk, slotid, alg, pinpolicy,
			    touchpolicy, &pub);
		}
	}

	if (err) {
		piv_txn_end(selk);
		err = funcerrf(err, "key generation failed");
		return (err);
	}

	err = selfsign_slot(slotid, alg, pub);
	piv_txn_end(selk);

	if (err) {
		err = funcerrf(err, "key generation failed");
		return (err);
	}

	rv = sshkey_write(pub, stdout);
	if (rv != 0) {
		err = errf("generate", ssherrf("sshkey_write", rv),
		    "failed to write public key to stdout");
		return (err);
	}
	fprintf(stdout, " PIV_slot_%02X@%s\n", slotid,
	    piv_token_guid_hex(selk));
	return (ERRF_OK);
}

static errf_t *
cmd_attest(uint slotid)
{
	struct piv_slot *slot = NULL;
	uint8_t *cert = NULL, *chain = NULL, *ptr;
	size_t certlen, chainlen, len;
	struct tlv_state *tlv;
	X509 *x509;
	errf_t *err;
	uint tag;

	assert_slotid(slotid);

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	err = piv_read_cert(selk, slotid);
	if (err == ERRF_OK) {
		slot = piv_get_slot(selk, slotid);
		VERIFY(slot != NULL);
		err = ykpiv_attest(selk, slot, &cert, &certlen);
		if (err == ERRF_OK) {
			err = piv_read_file(selk, PIV_TAG_CERT_YK_ATTESTATION,
			    &chain, &chainlen);
		}
	}
	piv_txn_end(selk);

	if (err != ERRF_OK)
		goto error;

	ptr = cert;
	x509 = d2i_X509(NULL, (const uint8_t **)&ptr, certlen);
	if (x509 == NULL) {
		make_sslerrf(err, "d2i_X509", "parsing attestation cert "
		    "for slot %02x", piv_slot_id(slot));
		goto error;
	}
	PEM_write_X509(stdout, x509);
	X509_free(x509);

	ptr = NULL;
	len = 0;
	tlv = tlv_init(chain, 0, chainlen);
	if ((err = tlv_read_tag(tlv, &tag)))
		goto error;
	if (tag != 0x70) {
		err = errf("PIVTagError", NULL,
		    "Got TLV tag 0x%x instead of 0x70", tag);
		goto error;
	}
	ptr = tlv_ptr(tlv);
	len = tlv_rem(tlv);

	x509 = d2i_X509(NULL, (const uint8_t **)&ptr, len);
	if (x509 == NULL) {
		make_sslerrf(err, "d2i_X509", "parsing attestation device cert");
		goto error;
	}
	PEM_write_X509(stdout, x509);
	X509_free(x509);

	tlv_skip(tlv);
	tlv_free(tlv);

	free(cert);
	piv_file_data_free(chain, chainlen);
	return (ERRF_OK);
error:
	err = funcerrf(err, "attestation failed");
	return (err);
}

static errf_t *
cmd_pubkey(uint slotid)
{
	struct piv_slot *cert;
	errf_t *err;
	int rv;

	assert_slotid(slotid);

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	err = piv_read_cert(selk, slotid);
	piv_txn_end(selk);

	cert = piv_get_slot(selk, slotid);

	if (cert == NULL && errf_caused_by(err, "NotFoundError")) {
		err = funcerrf(err, "PIV slot %02X has no key present",
		    slotid);
		return (err);
	} else if (cert == NULL) {
		err = funcerrf(err, "failed to read cert in slot %02X",
		    slotid);
		return (err);
	}

	rv = sshkey_write(piv_slot_pubkey(cert), stdout);
	if (rv != 0) {
		err = funcerrf(ssherrf("sshkey_write", rv),
		    "failed to write public key to stdout");
		return (err);
	}
	fprintf(stdout, " PIV_slot_%02X@%s \"%s\"\n", slotid,
	    piv_token_guid_hex(selk), piv_slot_subject(cert));
	return (ERRF_OK);
}

static errf_t *
cmd_cert(uint slotid)
{
	struct piv_slot *cert;
	errf_t *err;

	assert_slotid(slotid);

	if ((err = piv_txn_begin(selk)))
		errfx(1, err, "failed to open transaction");
	assert_select(selk);
	err = piv_read_cert(selk, slotid);
	piv_txn_end(selk);

	cert = piv_get_slot(selk, slotid);

	if (cert == NULL || err) {
		err = funcerrf(err, "failed to read cert in slot %02X", slotid);
		return (err);
	}

	PEM_write_X509(stdout, piv_slot_cert(cert));

	return (ERRF_OK);
}

static errf_t *
cmd_delete_cert(uint slotid)
{
	errf_t *err;
	struct piv_slot *slot;

	assert_slotid(slotid);

	if ((err = piv_txn_begin(selk)))
		errfx(1, err, "failed to open transaction");
	assert_select(selk);

	err = piv_read_cert(selk, slotid);
	if (err)
		errf_free(err);

	slot = piv_get_slot(selk, slotid);
	if (slot == NULL)
		slot = piv_force_slot(selk, slotid, PIV_ALG_3DES);

	enum piv_alg used_alg;
	err = try_admin_auth_with_recovery(selk, &used_alg);

	if (piv_token_is_ykpiv(selk) &&
	    ykpiv_version_compare(selk, 5, 7, 0) >= 0) {
		err = ykpiv_delete_key(selk, slot);
		if (err != ERRF_OK) {
			warnfx(err, "failed to delete private key, "
			    "will just clear cert");
			errf_free(err);
			err = ERRF_OK;
		}
	}

	if (err == ERRF_OK)
		err = piv_write_cert(selk, slotid, NULL, 0, PIV_COMP_NONE);

	if (err == ERRF_OK && slotid >= 0x82 && slotid <= 0x95 &&
	    piv_token_keyhistory_oncard(selk) >= slotid - 0x82) {
		uint oncard, offcard;
		const char *url;

		oncard = piv_token_keyhistory_oncard(selk);
		offcard = piv_token_keyhistory_offcard(selk);
		url = piv_token_offcard_url(selk);

		if (oncard > 0)
			--oncard;

		err = piv_write_keyhistory(selk, oncard, offcard, url);

		if (err) {
			warnfx(err, "failed to update key "
			    "history object with new cert, trying to "
			    "continue anyway...");
			err = ERRF_OK;
		}
	}

	piv_txn_end(selk);

	if (err) {
		err = errf("write_cert", err, "failed to delete cert");
		return (err);
	}

	return (ERRF_OK);
}

static errf_t *
cmd_write_cert(uint slotid)
{
	errf_t *err;
	uint8_t *cbuf;
	const unsigned char *p;
	size_t clen;
	X509 *x;
	BIO *bio;
	int rc;

	assert_slotid(slotid);

	cbuf = read_stdin(16384, &clen);
	VERIFY(cbuf != NULL);

	p = cbuf;
	x = d2i_X509(NULL, &p, clen);
	if (x == NULL) {
		bio = BIO_new_mem_buf(cbuf, clen);
		VERIFY(bio != NULL);
		x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		BIO_free(bio);
		if (x == NULL) {
			make_sslerrf(err, "d2i_X509", "parsing X509 "
			    "certificate");
			err = errf("write_cert", err,
			    "Invalid certificate input provided (expected DER "
			    "or PEM on stdin)");
			return (err);
		}
		free(cbuf);
		cbuf = NULL;
		rc = i2d_X509(x, &cbuf);
		if (rc < 0) {
			make_sslerrf(err, "i2d_X509", "converting X509 cert "
			    "to DER");
			err = errf("write_cert", err,
			    "Failed to convert cert to DER for upload to "
			    "card");
			return (err);
		}
		clen = rc;
	}
	X509_free(x);

	if ((err = piv_txn_begin(selk)))
		errfx(1, err, "failed to open transaction");
	assert_select(selk);
	enum piv_alg used_alg;
	err = try_admin_auth_with_recovery(selk, &used_alg);

	if (err == ERRF_OK)
		err = piv_write_cert(selk, slotid, cbuf, clen, PIV_COMP_NONE);

	if (err == ERRF_OK && slotid >= 0x82 && slotid <= 0x95 &&
	    piv_token_keyhistory_oncard(selk) <= slotid - 0x82) {
		uint oncard, offcard;
		const char *url;

		oncard = piv_token_keyhistory_oncard(selk);
		offcard = piv_token_keyhistory_offcard(selk);
		url = piv_token_offcard_url(selk);

		++oncard;

		err = piv_write_keyhistory(selk, oncard, offcard, url);

		if (err) {
			warnfx(err, "failed to update key "
			    "history object with new cert, trying to "
			    "continue anyway...");
			err = ERRF_OK;
		}
	}

	piv_txn_end(selk);

	if (err) {
		err = errf("write_cert", err, "failed to write new cert");
		return (err);
	}

	return (ERRF_OK);
}

static errf_t *
set_default_slot_cert_vars(uint slotid)
{
	char name[64];
	errf_t *err;

	switch (slotid) {
	case 0x9A:
		err = scope_set(cvroot, "slot", "piv-auth");
		break;
	case 0x9C:
		err = scope_set(cvroot, "slot", "piv-sign");
		break;
	case 0x9D:
		err = scope_set(cvroot, "slot", "piv-key-mgmt");
		break;
	case 0x9E:
		err = scope_set(cvroot, "slot", "piv-card-auth");
		break;
	case 0x82:
	case 0x83:
	case 0x84:
	case 0x85:
	case 0x86:
	case 0x87:
	case 0x88:
	case 0x89:
	case 0x8A:
	case 0x8B:
	case 0x8C:
	case 0x8D:
	case 0x8E:
	case 0x8F:
	case 0x90:
	case 0x91:
	case 0x92:
	case 0x93:
	case 0x94:
	case 0x95:
		snprintf(name, sizeof (name), "piv-retired-%u",
		    slotid - 0x81);
		err = scope_set(cvroot, "slot", name);
		break;
	default:
		err = funcerrf(NULL, "PIV slot %02X cannot be "
		    "used for asymmetric crypto\n", slotid);
	}

	if (err != ERRF_OK)
		return (err);

	if (cvtpl_name == NULL) {
		switch (slotid) {
		case 0x9A:
			cvtpl_name = "user-auth";
			break;
		case 0x9C:
			cvtpl_name = "user-email";
			break;
		case 0x9D:
			cvtpl_name = "user-key-mgmt";
			break;
		case 0x9E:
			cvtpl_name = "user-auth";
			break;
		case 0x82:
		case 0x83:
		case 0x84:
		case 0x85:
		case 0x86:
		case 0x87:
		case 0x88:
		case 0x89:
		case 0x8A:
		case 0x8B:
		case 0x8C:
		case 0x8D:
		case 0x8E:
		case 0x8F:
		case 0x90:
		case 0x91:
		case 0x92:
		case 0x93:
		case 0x94:
		case 0x95:
			cvtpl_name = "user-auth";
			break;
		}
	}
	return (err);
}

static errf_t *
cmd_req_cert(uint slotid)
{
	errf_t *err = ERRF_OK;
	struct piv_slot *slot;
	X509_REQ *req;
	struct sshkey *pub;
	struct cert_var_scope *scope;
	const struct cert_tpl *tpl;
	char *guidhex;
	EVP_PKEY *pkey;

	guidhex = piv_token_shortid(selk);
	(void) scope_set(cvroot, "guid", guidhex);
	free(guidhex);

	err = set_default_slot_cert_vars(slotid);
	if (err != ERRF_OK)
		return (err);

	tpl = cert_tpl_find(cvtpl_name);
	if (tpl == NULL) {
		return (errf("TemplateNotFound", NULL, "No such certificate "
		    "template: %s", cvtpl_name));
	}
	scope = scope_new_for_tpl(cvroot, tpl);

	if (override == NULL) {
		if ((err = piv_txn_begin(selk)))
			return (err);
		assert_select(selk);
		err = piv_read_cert(selk, slotid);
		piv_txn_end(selk);

		slot = piv_get_slot(selk, slotid);
	} else {
		slot = override;
	}

	if (slot == NULL || err) {
		err = funcerrf(err, "failed to read cert for signing key in "
		    "slot %02X", slotid);
		return (err);
	}

	pub = piv_slot_pubkey(slot);

	req = X509_REQ_new();
	VERIFY(req != NULL);

	VERIFY(X509_REQ_set_version(req, 0) == 1);

	if ((err = sshkey_to_evp_pkey(pub, &pkey))) {
		X509_REQ_free(req);
		return (funcerrf(err, "Error converting pubkey to EVP_PKEY"));
	}
	VERIFY(X509_REQ_set_pubkey(req, pkey) == 1);
	EVP_PKEY_free(pkey);

	err = cert_tpl_populate_req(tpl, scope, req);
	if (err != ERRF_OK) {
		X509_REQ_free(req);
		return (funcerrf(err, "Error populating certificate "
		    "attributes"));
	}

	if ((err = piv_txn_begin(selk))) {
		X509_REQ_free(req);
		return (err);
	}

	assert_select(selk);
	assert_pin(selk, slot, B_FALSE);

signagain:
	err = piv_sign_cert_req(selk, slot, pub, req);

	if (errf_caused_by(err, "PermissionError")) {
		assert_pin(selk, slot, B_TRUE);
		goto signagain;
	}

	piv_txn_end(selk);

	if (err) {
		err = funcerrf(err, "failed to sign cert req with key");
		return (err);
	}

	PEM_write_X509_REQ(stdout, req);
	X509_REQ_free(req);

	return (NULL);
}

static errf_t *
cmd_sign(uint slotid)
{
	struct piv_slot *cert;
	uint8_t *buf, *sig;
	enum sshdigest_types hashalg;
	size_t inplen, siglen;
	errf_t *err = ERRF_OK;

	assert_slotid(slotid);

	if (override == NULL) {
		if ((err = piv_txn_begin(selk)))
			return (err);
		assert_select(selk);
		err = piv_read_cert(selk, slotid);
		piv_txn_end(selk);

		cert = piv_get_slot(selk, slotid);
	} else {
		cert = override;
	}

	if (cert == NULL || err) {
		err = funcerrf(err, "failed to read cert for signing key in "
		    "slot %02X", slotid);
		return (err);
	}

	buf = read_stdin(16384, &inplen);
	assert(buf != NULL);

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	assert_pin(selk, cert, B_FALSE);
again:
	hashalg = 0;
	err = piv_sign(selk, cert, buf, inplen, &hashalg, &sig, &siglen);
	if (errf_caused_by(err, "PermissionError")) {
		assert_pin(selk, cert, B_TRUE);
		goto again;
	}
	piv_txn_end(selk);
	if (err) {
		err = funcerrf(err, "failed to sign data");
		return (err);
	}

	fwrite(sig, 1, siglen, stdout);
	free(sig);
	free(buf);

	return (ERRF_OK);
}

static errf_t *
cmd_box(uint slotid)
{
	struct piv_slot *slot = NULL;
	struct piv_ecdh_box *box;
	errf_t *err;
	size_t len;
	uint8_t *buf;

	if (slotid != 0 || opubkey == NULL) {
		if ((err = piv_txn_begin(selk)))
			return (err);
		assert_select(selk);
		err = piv_read_cert(selk, slotid);
		piv_txn_end(selk);
		if (err) {
			err = funcerrf(err, "while reading cert for slot "
			    "%02X", slotid);
			return (err);
		}

		slot = piv_get_slot(selk, slotid);
		VERIFY3P(slot, !=, NULL);
	}

	box = piv_box_new();
	VERIFY3P(box, !=, NULL);

	buf = read_stdin(8192, &len);
	assert(buf != NULL);
	VERIFY3U(len, >, 0);
	VERIFY0(piv_box_set_data(box, buf, len));
	explicit_bzero(buf, len);
	free(buf);

	if (opubkey == NULL) {
		err = piv_box_seal(selk, slot, box);
	} else {
		err = piv_box_seal_offline(opubkey, box);
	}
	if (err) {
		if (slotid != 0) {
			err = errf("box", err, "failed sealing new box to key "
			    "in slot %02x", slotid);
		} else {
			err = errf("box", err, "failed sealing to given pubkey");
		}
		return (err);
	}

	VERIFY0(piv_box_to_binary(box, &buf, &len));
	piv_box_free(box);

	fwrite(buf, 1, len, stdout);
	explicit_bzero(buf, len);
	free(buf);

	return (ERRF_OK);
}

static errf_t *
cmd_unbox(void)
{
	struct piv_token *tk;
	struct piv_slot *sl;
	struct piv_ecdh_box *box;
	errf_t *err;
	size_t len;
	uint8_t *buf;

	buf = read_stdin(8192, &len);
	assert(buf != NULL);
	VERIFY3U(len, >, 0);

	if ((err = piv_box_from_binary(buf, len, &box)))
		return (err);
	free(buf);

	if (piv_box_has_guidslot(box))
		err = piv_find(piv_ctx, piv_box_guid(box), GUID_LEN, &tk);
	if (err || !piv_box_has_guidslot(box))
		err = piv_enumerate(piv_ctx, &tk);
	if (err)
		return (err);
	ks = (selk = tk);
	err = piv_box_find_token(ks, box, &tk, &sl);
	if (errf_caused_by(err, "NotFoundError")) {
		if (!piv_box_has_guidslot(box)) {
			err = funcerrf(NULL, "box has no hardware GUID + slot "
			    "information; no token found on system that"
			    "can unlock it");
		} else {
			err = funcerrf(err, "no token found on system that can "
			    "unlock this box");
		}
		return (err);
	} else if (err) {
		return (err);
	}

	if ((err = piv_txn_begin(tk)))
		return (err);
	assert_select(tk);
	assert_pin(tk, sl, B_FALSE);
again:
	err = piv_box_open(tk, sl, box);
	if (errf_caused_by(err, "PermissionError")) {
		assert_pin(tk, sl, B_TRUE);
		goto again;
	}
	piv_txn_end(tk);

	if (err) {
		return (funcerrf(err, "failed to open box"));
	}

	if ((err = piv_box_take_data(box, &buf, &len))) {
		explicit_bzero(buf, len);
		free(buf);
		return (err);
	}

	fwrite(buf, 1, len, stdout);
	explicit_bzero(buf, len);
	free(buf);

	return (ERRF_OK);
}


struct sgdebugbuf {
	uint8_t sb_id;
	uint8_t sb_flags;
	uint16_t sb_size;
	uint16_t sb_offset;
	uint16_t sb_len;
} __attribute__((packed));
struct sgdebugdata {
	uint16_t sg_buf;
	uint16_t sg_off;
	struct sgdebugbuf sg_bufs[1];
} __attribute__((packed));

static errf_t *
cmd_sgdebug(void)
{
	struct apdu *apdu;
	errf_t *err;

	apdu = piv_apdu_make(CLA_ISO, 0xE0, 0x00, 0x00);
	VERIFY(apdu != NULL);

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	err = piv_apdu_transceive_chain(selk, apdu);
	piv_txn_end(selk);

	if (err) {
		err = errf("sgdebug", err, "failed to fetch debug info");
		return (err);
	}

	const uint8_t *reply;
	size_t len;
	reply = piv_apdu_get_reply(apdu, &len);

	struct sgdebugdata *data = (struct sgdebugdata *)reply;
	struct sgdebugbuf *buf;
	data->sg_buf = be16toh(data->sg_buf);
	data->sg_off = be16toh(data->sg_off);
	printf("== SGList debug data ==\n");
	printf("current position = %d + 0x%04x\n", data->sg_buf, data->sg_off);
	buf = data->sg_bufs;
	while ((char *)buf - (char *)data < len) {
		buf->sb_size = be16toh(buf->sb_size);
		buf->sb_offset = be16toh(buf->sb_offset);
		buf->sb_len = be16toh(buf->sb_len);
		printf("buf %-3d: ", buf->sb_id);
		if (buf->sb_flags & 0x02)
			printf("transient ");
		if (buf->sb_flags & 0x01)
			printf("dynamic ");
		printf("size=%04x offset=%04x len=%04x\n",
		    buf->sb_size, buf->sb_offset, buf->sb_len);
		++buf;
	}

	piv_apdu_free(apdu);

	return (ERRF_OK);
}

static errf_t *
cmd_box_info(void)
{
	struct piv_ecdh_box *box;
	size_t len;
	uint8_t *buf;
	char *hex;
	errf_t *err;

	buf = read_stdin(8192, &len);
	assert(buf != NULL);
	VERIFY3U(len, >, 0);

	if ((err = piv_box_from_binary(buf, len, &box)))
		return (err);
	free(buf);

	printf("version:      %u\n", piv_box_version(box));

	if (piv_box_has_guidslot(box)) {
		printf("type:         hardware (has guid + slot)\n");
		hex = buf_to_hex(piv_box_guid(box), 16, B_FALSE);
		printf("guid:         %s\n", hex);
		free(hex);
		printf("slot:         %02X\n", piv_box_slot(box));
	} else {
		printf("type:         virtual (no guid or slot)\n");
	}

	printf("pubkey:       ");
	VERIFY0(sshkey_write(piv_box_pubkey(box), stdout));
	printf("\n");

	printf("ephem_pubkey: ");
	VERIFY0(sshkey_write(piv_box_ephem_pubkey(box), stdout));
	printf("\n");

	printf("cipher:       %s\n", piv_box_cipher(box));
	printf("kdf:          %s\n", piv_box_kdf(box));
	printf("encsize:      %zu bytes\n", piv_box_encsize(box));
	printf("nonce:        %zu bytes\n", piv_box_nonce_size(box));

	return (ERRF_OK);
}

static errf_t *
cmd_bench(uint slotid)
{
	struct piv_slot *cert;
	struct sshkey *pubkey;
	errf_t *err = NULL;
	uint i, n = 60;
	struct timespec t1;
	struct timespec t2;

	switch (slotid) {
	case 0x9A:
	case 0x9C:
	case 0x9D:
	case 0x9E:
		break;
	default:
		if (slotid >= 0x82 && slotid <= 0x95)
			break;
		err = funcerrf(NULL, "PIV slot %02X cannot be "
		    "used for signing", slotid);
		return (err);
	}

	if (override == NULL) {
		if ((err = piv_txn_begin(selk)))
			return (err);
		assert_select(selk);
		err = piv_read_cert(selk, slotid);
		piv_txn_end(selk);

		cert = piv_get_slot(selk, slotid);
	} else {
		cert = override;
	}

	if (cert == NULL || err) {
		err = funcerrf(err, "failed to read cert for signing key");
		return (err);
	}

	pubkey = piv_slot_pubkey(cert);

	if ((err = piv_txn_begin(selk)))
		errfx(1, err, "failed to open transaction");
	assert_select(selk);
	assert_pin(selk, cert, B_FALSE);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	for (i = 0; i < n; ++i) {
again:
		if (err != NULL)
			errf_free(err);
		err = piv_auth_key(selk, cert, pubkey);
		if (errf_caused_by(err, "PermissionError")) {
			assert_pin(selk, cert, B_TRUE);
			goto again;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &t2);
	piv_txn_end(selk);
	const double t1d = t1.tv_sec + ((double)t1.tv_nsec / 1000000000.0f);
	const double t2d = t2.tv_sec + ((double)t2.tv_nsec / 1000000000.0f);
	const double delta = (t2d - t1d) / ((double)n);
	fprintf(stderr, "time per sign = %.1f ms\n", delta * 1000);
	if (err) {
		err = funcerrf(err, "key authentication failed");
		return (err);
	}

	return (ERRF_OK);
}

static errf_t *
cmd_auth(uint slotid)
{
	struct piv_slot *cert;
	struct sshkey *pubkey;
	uint8_t *buf;
	char *ptr;
	size_t boff;
	errf_t *err = NULL;
	int rv;

	switch (slotid) {
	case 0x9A:
	case 0x9C:
	case 0x9D:
	case 0x9E:
		break;
	default:
		if (slotid >= 0x82 && slotid <= 0x95)
			break;
		err = funcerrf(NULL, "PIV slot %02X cannot be "
		    "used for signing", slotid);
		return (err);
	}

	if (override == NULL) {
		if ((err = piv_txn_begin(selk)))
			return (err);
		assert_select(selk);
		err = piv_read_cert(selk, slotid);
		piv_txn_end(selk);

		cert = piv_get_slot(selk, slotid);
	} else {
		cert = override;
	}

	if (cert == NULL || err) {
		err = funcerrf(err, "failed to read cert for signing key");
		return (err);
	}

	buf = read_stdin(16384, &boff);
	assert(buf != NULL);
	buf[boff] = 0;

	pubkey = sshkey_new(piv_slot_pubkey(cert)->type);
	VERIFY(pubkey != NULL);
	ptr = (char *)buf;
	rv = sshkey_read(pubkey, &ptr);
	free(buf);
	if (rv != 0) {
		err = funcerrf(ssherrf("sshkey_read", rv),
		    "failed to parse public key input");
		sshkey_free(pubkey);
		return (err);
	}

	if ((err = piv_txn_begin(selk)))
		errfx(1, err, "failed to open transaction");
	assert_select(selk);
	assert_pin(selk, cert, B_FALSE);
again:
	err = piv_auth_key(selk, cert, pubkey);
	if (errf_caused_by(err, "PermissionError")) {
		assert_pin(selk, cert, B_TRUE);
		goto again;
	}
	piv_txn_end(selk);
	if (err) {
		err = funcerrf(err, "key authentication failed");
		return (err);
	}
	sshkey_free(pubkey);
	return (ERRF_OK);
}

static errf_t *
cmd_ecdh(uint slotid)
{
	struct piv_slot *cert;
	struct sshkey *pubkey;
	uint8_t *buf, *secret;
	char *ptr;
	size_t boff, seclen;
	errf_t *err = ERRF_OK;
	int rv;

	switch (slotid) {
	case 0x9A:
	case 0x9C:
	case 0x9D:
	case 0x9E:
		break;
	default:
		err = funcerrf(NULL, "PIV slot %02X cannot be used for ECDH",
		    slotid);
		return (err);
	}

	if (override == NULL) {
		if ((err = piv_txn_begin(selk)))
			return (err);
		assert_select(selk);
		err = piv_read_cert(selk, slotid);
		piv_txn_end(selk);

		cert = piv_get_slot(selk, slotid);
	} else {
		cert = override;
	}

	if (cert == NULL || err) {
		err = funcerrf(err, "failed to read cert in PIV slot %02X",
		    slotid);
		return (err);
	}

	switch (piv_slot_alg(cert)) {
	case PIV_ALG_ECCP256:
	case PIV_ALG_ECCP384:
		break;
	default:
		err = funcerrf(NULL, "PIV slot %02X does not contain an EC key",
		    slotid);
		return (err);
	}

	buf = read_stdin(8192, &boff);
	assert(buf != NULL);
	buf[boff] = 0;

	pubkey = sshkey_new(piv_slot_pubkey(cert)->type);
	assert(pubkey != NULL);
	ptr = (char *)buf;
	rv = sshkey_read(pubkey, &ptr);
	if (rv != 0) {
		err = errf("ecdh", ssherrf("sshkey_read", rv),
		    "failed to parse public key input");
		return (err);
	}

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	assert_pin(selk, cert, B_FALSE);
again:
	err = piv_ecdh(selk, cert, pubkey, &secret, &seclen);
	if (errf_caused_by(err, "PermissionError")) {
		assert_pin(selk, cert, B_TRUE);
		goto again;
	}
	piv_txn_end(selk);
	if (err) {
		err = funcerrf(err, "failed to compute ECDH");
		return (err);
	}

	fwrite(secret, 1, seclen, stdout);

	return (ERRF_OK);
}

static void
check_select_key(void)
{
	struct piv_token *t;
	errf_t *err;
	size_t len;

	if (guid_len == 0) {
		err = piv_enumerate(piv_ctx, &t);
		if (err) {
			errfx(EXIT_IO_ERROR, err,
			    "failed to enumerate PIV tokens");
		}
		if (t == NULL) {
			errx(EXIT_NO_CARD, "no PIV cards/tokens found");
		}
		if (piv_token_next(t) != NULL) {
			errx(EXIT_NO_CARD, "multiple PIV cards "
			    "present and no system token set; you "
			    "must provide -g|--guid to select one");
		}
		selk = (ks = t);
		return;
	}

	len = guid_len;
	if (buf_is_zero(guid, guid_len))
		len = 0;

	err = piv_find(piv_ctx, guid, len, &t);
	if (errf_caused_by(err, "DuplicateError"))
		errx(EXIT_NO_CARD, "GUID prefix specified is not unique");
	if (errf_caused_by(err, "NotFoundError")) {
		errx(EXIT_NO_CARD, "no PIV card present matching given "
		    "GUID");
	}
	if (err)
		errfx(EXIT_IO_ERROR, err, "while finding PIV token with GUID");
	selk = (ks = t);

	/* YubicoPIV 5.7 and later default to AES192 admin key. */
	if (piv_token_is_ykpiv(selk) &&
	    ykpiv_version_compare(selk, 5, 4, 0) >= 0) {
		enum piv_alg alg;
		boolean_t is_default;

		if ((err = piv_txn_begin(selk)))
			return;
		assert_select(selk);

		err = ykpiv_admin_auth_info(selk, &alg, &is_default, NULL);
		if (err == ERRF_OK) {
			key_alg = alg;
			if (is_default) {
				admin_key = DEFAULT_ADMIN_KEY;
				key_length = DEFAULT_KEY_LENGTH;
			}
		} else {
			errf_free(err);
		}

		piv_txn_end(selk);
	}
}

static errf_t *
cmd_factory_reset(void)
{
	char *resp;
	char respbuf[16];
	errf_t *err;

	if (!piv_token_is_ykpiv(selk)) {
		err = funcerrf(NULL, "factory-reset command is only for "
		    "YubiKeys");
		return (err);
	}

	fprintf(stderr, "Resetting Yubikey %s (%s)\n",
	    piv_token_shortid(selk), piv_token_rdrname(selk));
	if (ykpiv_token_has_serial(selk)) {
		fprintf(stderr, "Serial #%u\n", ykpiv_token_serial(selk));
	}

	fprintf(stderr, "WARNING: this will completely reset the PIV applet "
	    "on this Yubikey, erasing all keys and certificates!\n");
	do {
		resp = readpassphrase("Type 'YES' to continue: ",
		    respbuf, sizeof (respbuf), RPP_ECHO_OFF | RPP_REQUIRE_TTY);
	} while (resp == NULL && errno == EINTR);
	if (resp == NULL || strcmp(resp, "YES") != 0) {
		return (ERRF_OK);
	}

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	err = ykpiv_reset(selk);
	piv_txn_end(selk);

	if (err)
		return (err);
	return (ERRF_OK);
}

static errf_t *
cmd_setup(void)
{
	boolean_t usetouch = B_FALSE;
	errf_t *err;
	const char *realpin;
	struct piv_slot *slot;

	if (!piv_token_is_ykpiv(selk)) {
		err = funcerrf(NULL, "setup command is only for YubiKeys");
		return (err);
	}

	if (ykpiv_version_compare(selk, 4, 3, 0) == 1) {
		usetouch = B_TRUE;
	}

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	err = piv_read_all_certs(selk);
	piv_txn_end(selk);

	slot = NULL;
	while ((slot = piv_slot_next(selk, slot)) != NULL) {
		if (piv_slot_pubkey(slot) != NULL) {
			err = funcerrf(NULL, "PIV token has already generated"
			    " keys. Use factory-reset to clear them");
			return (err);
		}
	}

	if (!piv_token_has_chuid(selk)) {
		fprintf(stderr, "Initializing CCC and CHUID files...\n");
		if ((err = cmd_init())) {
			return (funcerrf(err,
			    "initializing CCC and CHUID files"));
		}
		piv_release(ks);
		selk = NULL;
		check_select_key();
	}

	touchpolicy = YKPIV_TOUCH_DEFAULT;
	pinpolicy = YKPIV_PIN_DEFAULT;
	pin = "123456";

	fprintf(stderr, "Generating standard keys...\n");

	if ((err = piv_txn_begin(selk)))
		return (err);
	assert_select(selk);
	err = piv_read_cert(selk, 0x9E);
	piv_txn_end(selk);

	if (err) {
		errf_free(err);
		override = piv_force_slot(selk, 0x9E, PIV_ALG_ECCP256);
		err = cmd_generate(piv_slot_id(override),
		    piv_slot_alg(override));
		if (err)
			return (err);
	}
	override = piv_force_slot(selk, 0x9A, PIV_ALG_ECCP256);
	if ((err = cmd_generate(piv_slot_id(override), piv_slot_alg(override))))
		return (err);

	override = piv_force_slot(selk, 0x9C, PIV_ALG_RSA2048);
	if ((err = cmd_generate(piv_slot_id(override), piv_slot_alg(override))))
		return (err);

	if (usetouch) {
		touchpolicy = YKPIV_TOUCH_CACHED;
		fprintf(stderr, "Using touch button confirmation for 9D key\n");
		fprintf(stderr, "Please touch YubiKey when it is flashing\n");
	}
again9d:
	override = piv_force_slot(selk, 0x9D, PIV_ALG_ECCP256);
	err = cmd_generate(piv_slot_id(override), piv_slot_alg(override));
	if (errf_caused_by(err, "ArgumentError") ||
	    errf_caused_by(err, "NotSupportedError") ||
	    errf_caused_by(err, "APDUError")) {
		touchpolicy = YKPIV_TOUCH_DEFAULT;
		usetouch = B_FALSE;
		goto again9d;
	}
	if (err)
		return (err);

	touchpolicy = YKPIV_TOUCH_DEFAULT;

	fprintf(stderr, "Changing PIN and PUK...\n");
	if ((err = cmd_change_pin(PIV_PIN)))
		return (err);
	/* Stash the new PIN, we'll need it later to write to PINFO */
	realpin = newpin;

	pin = "12345678";
	if ((err = cmd_change_pin(PIV_PUK)))
		return (err);

	fprintf(stderr, "Generating final admin key...\n");
	key_new_alg = PIV_ALG_3DES;
	if (piv_token_is_ykpiv(selk) &&
	    ykpiv_version_compare(selk, 5, 4, 0) >= 0) {
		key_new_alg = PIV_ALG_AES192;
	}
	size_t admin_key_len = len_for_admin_alg(key_new_alg);
	uint8_t *admin_key = malloc(admin_key_len);
	char *hex;
	VERIFY(admin_key != NULL);
	arc4random_buf(admin_key, admin_key_len);
	if (usetouch)
		touchpolicy = YKPIV_TOUCH_ALWAYS;

	/* cmd_set_admin will use the PIN to write to PINFO */
	pin = realpin;
	if ((err = cmd_set_admin(admin_key, admin_key_len)))
		return (err);

	if (!save_pinfo_admin) {
		hex = buf_to_hex(admin_key, admin_key_len, B_FALSE);
		printf("Admin key: %s\n", hex);
	}

	fprintf(stderr, "Done!\n");

	return (ERRF_OK);
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
	fprintf(stderr,
	    "usage: pivy-tool [options] <operation>\n"
	    "Available operations:\n"
	    "  list                   Lists PIV tokens present\n"
	    "  pinfo                  Shows contents of Printed Info file\n"
	    "  pubkey <slot>          Outputs a public key in SSH format\n"
	    "  cert <slot>            Outputs PEM certificate from slot\n"
	    "  version                Print pivy's version\n"
	    "\n"
	    "  init                   Writes GUID and card capabilities\n"
	    "                         (used to init a new Yubico PIV)\n"
	    "  setup                  Quick setup procedure for new YubiKey\n"
	    "                         (does init + generate + change-pin +\n"
	    "                         change-puk + set-admin)\n"
	    "  generate <slot>        Generate a new private key and a\n"
	    "                         self-signed cert\n"
	    "  import <slot>          Accept a SSH private key on stdin\n"
	    "                         and import it to a Yubikey (generates\n"
	    "                         a self-signed cert to go with it)\n"
	    "  write-cert <slot>      Takes a DER X.509 certificate on stdin\n"
	    "                         and replaces the cert in the given slot\n"
	    "  req-cert <slot>        Generates an X.509 CSR for the key in\n"
	    "                         the given slot (for user auth)\n"
	    "  delete-cert <slot>     Clears the certificate from the given slot\n"
	    "  change-pin             Changes the PIV PIN\n"
	    "  change-puk             Changes the PIV PUK\n"
	    "  reset-pin              Resets the PIN using the PUK\n"
	    "  factory-reset          Factory reset the PIV applet on a\n"
	    "                         Yubikey, once the PIN and PUK are both\n"
	    "                         locked (max retries used)\n"
	    "  set-admin <hex|@file>  Sets the admin key\n"
	    "  update-keyhist         Scan all retired key slots and then\n"
	    "                         re-generate the PIV Key History object\n"
	    "\n"
	    "  sign <slot>            Signs data on stdin\n"
	    "  ecdh <slot>            Do ECDH with pubkey on stdin\n"
	    "  auth <slot>            Does a round-trip signature test to\n"
	    "                         verify that the pubkey on stdin\n"
	    "                         matches the one in the slot\n"
	    "  attest <slot>          (Yubikey only) Output attestation cert\n"
	    "                         and chain for a given slot.\n"
	    "\n"
	    "  box [slot]             Encrypts stdin data with an ECDH box\n"
	    "  unbox                  Decrypts stdin data with an ECDH box\n"
	    "                         Chooses token and slot automatically\n"
	    "  box-info               Prints metadata about a box from stdin\n"
	    "\n"
	    "General options:\n"
	    "  -g <hex>               GUID of the PIV token to use\n"
	    "                         (Required if >1 token on system)\n"
	    "  -P <code>              PIN code to authenticate with\n"
	    "                         (defaults to reading from terminal)\n"
	    "  -f                     Attempt to unlock with PIN code even\n"
	    "                         if there is only 1 attempt left before\n"
	    "                         card lock\n"
	    "  -A <key type>          The key algorithm (3des, aes128, aes192\n"
	    "                         or aes256) of the admin key. Always use\n"
	    "                         *before* -K.\n"
	    "  -K <hex|@file>         Provides the admin key to use for\n"
	    "                         auth to the card with admin ops (e.g.\n"
	    "                         generate or init)\n"
	    "  -d                     Output debug info to stderr\n"
	    "                         (use twice to include APDU trace)\n"
	    "  -X                     Always enumerate all retired key slots\n"
	    "                         (ignore the PIV Key History object)\n"
	    "\n"
	    "Options for 'list':\n"
	    "  -p                     Generate parseable output\n"
	    "  -j                     Generate JSON output\n"
	    "\n"
	    "Options for 'generate'/'req-cert':\n"
	    "  -a <algo>              Choose algorithm of new key\n"
	    "                         EC algos: eccp256, eccp384\n"
	    "                         RSA algos: rsa1024, rsa2048, rsa3072\n"
	    "  -n <cn>                Set a CN= attribute to be used on\n"
	    "                         the new slot's certificate\n"
	    "  -u <upn>               Set a UPN= attribute to be used on\n"
	    "                         the new slot's certificate\n"
	    "  -r <principal>         Set a KRB5 PKINIT principal name to be\n"
	    "                         used on the new slot's certificate\n"
	    "  -D <param>=<value>     Define a certificate parameter\n"
	    "  -T <tplname>           Set certificate template\n"
	    "  -t <never|always|cached>\n"
	    "                         Set the touch policy. Only supported\n"
	    "                         with YubiKeys\n"
	    "  -i <never|always|once> Set the PIN policy. Only supported\n"
	    "                         with YubiKeys\n"
	    "\n"
	    "Options for 'box'/'unbox':\n"
	    "  -k <pubkey>            Use a public key for box operation\n"
	    "                         instead of a slot\n"
	    "\n"
	    "Options for 'set-admin'/'setup':\n"
	    "  -R                     Don't save admin key in the PIV\n"
	    "                         'printed info' object (compat with\n"
	    "                         Yubico PIV manager)\n"
	    "  -N <new key type>      Change the type of admin key, same\n"
	    "                         args as -A.\n");
	exit(EXIT_BAD_ARGS);
}

const char *optstring = "djpg:P:a:fK:k:n:t:i:u:RXA:N:r:D:T:";

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

	bunyan_init();
	bunyan_set_name("pivy-tool");

	cvroot = scope_new_root();
	(void) scope_set(cvroot, "lifetime", "3650d");
	(void) scope_set(cvroot, "dn", "CN=%{cn}");
	(void) scope_set(cvroot, "cn", "%{slot}@%{guid}");

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'T':
			cvtpl_name = optarg;
			break;
		case 'D':
			ptr = strchr(optarg, '=');
			if (ptr == NULL) {
				errx(EXIT_BAD_ARGS, "invalid cert var: '%s'",
				    optarg);
			}
			*ptr = '\0';
			err = scope_set(cvroot, optarg, ptr+1);
			if (err != ERRF_OK) {
				errfx(EXIT_BAD_ARGS, err, "error while parsing "
				    "-D arg: %s", optarg);
			}
			break;
		case 'd':
			bunyan_set_level(BNY_TRACE);
			if (++d_level > 1)
				piv_full_apdu_debug = B_TRUE;
			break;
		case 'R':
			save_pinfo_admin = B_FALSE;
			break;
		case 'X':
			enum_all_retired = B_TRUE;
			break;
		case 'A':
			err = piv_alg_from_string(optarg, &key_alg);
			if (err != ERRF_OK)
				errfx(EXIT_BAD_ARGS, err, "failed to parse -A");
			key_length = len_for_admin_alg(key_alg);
			user_specified_alg = B_TRUE;
			break;
		case 'N':
			err = piv_alg_from_string(optarg, &key_new_alg);
			if (err != ERRF_OK)
				errfx(EXIT_BAD_ARGS, err, "failed to parse -N");
			break;
		case 'K':
			if (strcmp(optarg, "default") == 0) {
				admin_key = DEFAULT_ADMIN_KEY;
			} else if (optarg[0] == '@') {
				buf = read_key_file(&optarg[1], &len);
				if (len > key_length && sniff_hex(buf, len)) {
					admin_key = parse_hex(
					    (const char *)buf, &len);
				} else {
					admin_key = buf;
				}
			} else {
				admin_key = parse_hex(optarg, &len);
			}
			if (len != key_length) {
				errx(EXIT_BAD_ARGS, "admin key must be "
				    "%u bytes in length (%u given)",
				    key_length, len);
			}
			break;
		case 'u':
			err = scope_set(cvroot, "ad_upn", optarg);
			if (err != ERRF_OK) {
				errfx(EXIT_BAD_ARGS, err, "error while parsing "
				    "-u: %s", optarg);
			}
			break;
		case 'n':
			(void) scope_set(cvroot, "dn", "cn = %{cn}");
			err = scope_set(cvroot, "cn", optarg);
			if (err != ERRF_OK) {
				errfx(EXIT_BAD_ARGS, err, "error while parsing "
				    "-n: %s", optarg);
			}
			break;
		case 'r':
			err = scope_set(cvroot, "krb5_principal", optarg);
			if (err != ERRF_OK) {
				errfx(EXIT_BAD_ARGS, err, "error while parsing "
				    "-r: %s", optarg);
			}
			break;
		case 'f':
			min_retries = 0;
			break;
		case 't':
			if (strcasecmp(optarg, "never") == 0) {
				touchpolicy = YKPIV_TOUCH_NEVER;
			} else if (strcasecmp(optarg, "always") == 0) {
				touchpolicy = YKPIV_TOUCH_ALWAYS;
			} else if (strcasecmp(optarg, "cached") == 0) {
				touchpolicy = YKPIV_TOUCH_CACHED;
			}
			break;
		case 'i':
			if (strcasecmp(optarg, "never") == 0) {
				pinpolicy = YKPIV_PIN_NEVER;
			} else if (strcasecmp(optarg, "always") == 0) {
				pinpolicy = YKPIV_PIN_ALWAYS;
			} else if (strcasecmp(optarg, "once") == 0) {
				pinpolicy = YKPIV_PIN_ONCE;
			}
			break;
		case 'a':
			hasover = B_TRUE;
			err = piv_alg_from_string(optarg, &overalg);
			if (err != ERRF_OK)
				errfx(EXIT_BAD_ARGS, err, "failed to parse -a");
			/* ps_slot will be set after we've parsed the slot */
			break;
		case 'g':
			guid = parse_hex(optarg, &len);
			guid_len = len;
			if (len > 16) {
				errx(EXIT_BAD_ARGS, "GUID must be <=16 bytes "
				    "(%d given)", len);
			}
			break;
		case 'P':
			if (pin == NULL) {
				pin = optarg;
				break;
			}
			if (newpin == NULL) {
				newpin = optarg;
				break;
			}
			errx(EXIT_BAD_ARGS, "too many -P options given");
		case 'p':
			parseable = B_TRUE;
			break;
		case 'j':
			json = B_TRUE;
			break;
		case 'k':
			opubkey = sshkey_new(KEY_UNSPEC);
			assert(opubkey != NULL);
			ptr = optarg;
			rv = sshkey_read(opubkey, &ptr);
			if (rv != 0) {
				errfx(EXIT_BAD_ARGS, ssherrf("sshkey_read",
				    rv), "failed to parse public key in -k");
			}
			break;
		default:
			usage();
		}
	}

	if (optind >= argc) {
		warnx("operation required");
		usage();
	}

	const char *op = argv[optind++];

	piv_ctx = piv_open();
	VERIFY(piv_ctx != NULL);

	err = piv_establish_context(piv_ctx, SCARD_SCOPE_SYSTEM);
	if (err && errf_caused_by(err, "ServiceError")) {
		warnfx(err, "failed to create PCSC context");
		errf_free(err);
	} else if (err) {
		errfx(EXIT_IO_ERROR, err, "failed to initialise libpcsc");
	}

	if (strcmp(op, "list") == 0) {
		err = piv_enumerate(piv_ctx, &ks);
		if (err)
			errfx(1, err, "failed to enumerate PIV tokens");
		if (optind < argc)
			usage();
		err = cmd_list();

	} else if (strcmp(op, "init") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		check_select_key();
		err = cmd_init();

	} else if (strcmp(op, "change-pin") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		check_select_key();
		err = cmd_change_pin(piv_token_default_auth(selk));

	} else if (strcmp(op, "set-admin") == 0) {
		uint8_t *new_admin;

		if (optind >= argc)
			usage();

		check_select_key();
		if (key_new_alg == 0)
			key_new_alg = key_alg;

		if (strcmp(argv[optind], "default") == 0) {
			if (piv_token_is_ykpiv(selk) &&
			    ykpiv_version_compare(selk, 5, 7, 0) >= 0) {
				key_new_alg = PIV_ALG_AES192;
			}
			new_admin = (uint8_t *)DEFAULT_ADMIN_KEY;
			len = DEFAULT_KEY_LENGTH;
		} else if (strcmp(argv[optind], "random") == 0) {
			if (key_new_alg == 0 &&
			    piv_token_is_ykpiv(selk) &&
			    ykpiv_version_compare(selk, 5, 7, 0) >= 0) {
				key_new_alg = PIV_ALG_AES192;
			}
			len = len_for_admin_alg(key_new_alg);
			new_admin = malloc(len);
			VERIFY(new_admin != NULL);
			arc4random_buf(new_admin, len);
		} else if (argv[optind][0] == '@') {
			buf = read_key_file(&argv[optind][1], &len);
			if (len > 16 && sniff_hex(buf, len)) {
				new_admin = parse_hex(
				    (const char *)buf, &len);
			} else {
				new_admin = buf;
			}
		} else {
			new_admin = parse_hex(argv[optind], &len);
		}

		if (++optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		if (len != len_for_admin_alg(key_new_alg)) {
			errx(EXIT_BAD_ARGS, "admin key must be %zd bytes in "
			    "length (%d given)", len_for_admin_alg(key_new_alg),
			    len);
		}

		err = cmd_set_admin(new_admin, len);

	} else if (strcmp(op, "change-puk") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		check_select_key();
		err = cmd_change_pin(PIV_PUK);

	} else if (strcmp(op, "reset-pin") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		check_select_key();
		err = cmd_reset_pin();

	} else if (strcmp(op, "update-keyhist") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		check_select_key();
		err = cmd_update_keyhist();

	} else if (strcmp(op, "pinfo") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		check_select_key();
		err = cmd_pinfo();

	} else if (strcmp(op, "sign") == 0) {
		enum piv_slotid slotid;

		if (optind >= argc) {
			warnx("not enough arguments for %s", op);
			usage();
		}
		err = piv_slotid_from_string(argv[optind++], &slotid);
		if (err != ERRF_OK)
			errfx(EXIT_BAD_ARGS, err, "failed to parse slot id");

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		check_select_key();
		if (hasover)
			override = piv_force_slot(selk, slotid, overalg);
		err = cmd_sign(slotid);

	} else if (strcmp(op, "bench") == 0) {
		enum piv_slotid slotid;

		if (optind >= argc) {
			warnx("not enough arguments for %s", op);
			usage();
		}
		err = piv_slotid_from_string(argv[optind++], &slotid);
		if (err != ERRF_OK)
			errfx(EXIT_BAD_ARGS, err, "failed to parse slot id");

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		check_select_key();
		if (hasover)
			override = piv_force_slot(selk, slotid, overalg);
		err = cmd_bench(slotid);

	} else if (strcmp(op, "pubkey") == 0) {
		enum piv_slotid slotid;

		if (optind >= argc) {
			warnx("not enough arguments for %s (slot required)",
			    op);
			usage();
		}
		err = piv_slotid_from_string(argv[optind++], &slotid);
		if (err != ERRF_OK)
			errfx(EXIT_BAD_ARGS, err, "failed to parse slot id");

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		check_select_key();
		err = cmd_pubkey(slotid);

	} else if (strcmp(op, "attest") == 0) {
		enum piv_slotid slotid;

		if (optind >= argc) {
			warnx("not enough arguments for %s (slot required)",
			    op);
			usage();
		}
		err = piv_slotid_from_string(argv[optind++], &slotid);
		if (err != ERRF_OK)
			errfx(EXIT_BAD_ARGS, err, "failed to parse slot id");

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		check_select_key();
		err = cmd_attest(slotid);

	} else if (strcmp(op, "setup") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		check_select_key();
		err = cmd_setup();

	} else if (strcmp(op, "factory-reset") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		check_select_key();
		err = cmd_factory_reset();

	} else if (strcmp(op, "cert") == 0) {
		enum piv_slotid slotid;

		if (optind >= argc) {
			warnx("not enough arguments for %s (slot required)",
			    op);
			usage();
		}
		err = piv_slotid_from_string(argv[optind++], &slotid);
		if (err != ERRF_OK)
			errfx(EXIT_BAD_ARGS, err, "failed to parse slot id");

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		check_select_key();
		err = cmd_cert(slotid);

	} else if (strcmp(op, "ecdh") == 0) {
		enum piv_slotid slotid;

		if (optind >= argc) {
			warnx("not enough arguments for %s (slot required)",
			    op);
			usage();
		}
		err = piv_slotid_from_string(argv[optind++], &slotid);
		if (err != ERRF_OK)
			errfx(EXIT_BAD_ARGS, err, "failed to parse slot id");

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		check_select_key();
		if (hasover)
			override = piv_force_slot(selk, slotid, overalg);
		err = cmd_ecdh(slotid);

	} else if (strcmp(op, "auth") == 0) {
		enum piv_slotid slotid;

		if (optind >= argc) {
			warnx("not enough arguments for %s (slot required)",
			    op);
			usage();
		}
		err = piv_slotid_from_string(argv[optind++], &slotid);
		if (err != ERRF_OK)
			errfx(EXIT_BAD_ARGS, err, "failed to parse slot id");

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		check_select_key();
		if (hasover)
			override = piv_force_slot(selk, slotid, overalg);
		err = cmd_auth(slotid);

	} else if (strcmp(op, "box") == 0) {
		enum piv_slotid slotid;

		if (opubkey == NULL) {
			if (optind >= argc) {
				slotid = PIV_SLOT_KEY_MGMT;
			} else {
				err = piv_slotid_from_string(argv[optind++],
				    &slotid);
				if (err != ERRF_OK) {
					errfx(EXIT_BAD_ARGS, err,
					    "failed to parse slot id");
				}
			}
			check_select_key();
		} else {
			slotid = 0;
		}

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		err = cmd_box(slotid);

	} else if (strcmp(op, "unbox") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		err = cmd_unbox();

	} else if (strcmp(op, "box-info") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		err = cmd_box_info();

	} else if (strcmp(op, "sgdebug") == 0) {
		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}
		check_select_key();
		err = cmd_sgdebug();

	} else if (strcmp(op, "generate") == 0) {
		enum piv_slotid slotid;

		if (optind >= argc) {
			warnx("not enough arguments for %s (slot required)",
			    op);
			usage();
		}
		err = piv_slotid_from_string(argv[optind++], &slotid);
		if (err != ERRF_OK)
			errfx(EXIT_BAD_ARGS, err, "failed to parse slot id");

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		if (!hasover) {
			warnx("%s requires the -a (algorithm) option", op);
			usage();
		}

		check_select_key();
		if (hasover)
			override = piv_force_slot(selk, slotid, overalg);
		err = cmd_generate(slotid, overalg);

	} else if (strcmp(op, "import") == 0) {
		enum piv_slotid slotid;

		if (optind >= argc) {
			warnx("not enough arguments for %s (slot required)",
			    op);
			usage();
		}
		err = piv_slotid_from_string(argv[optind++], &slotid);
		if (err != ERRF_OK)
			errfx(EXIT_BAD_ARGS, err, "failed to parse slot id");

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		check_select_key();
		err = cmd_import(slotid);

	} else if (strcmp(op, "write-cert") == 0) {
		enum piv_slotid slotid;

		if (optind >= argc) {
			warnx("not enough arguments for %s (slot required)",
			    op);
			usage();
		}
		err = piv_slotid_from_string(argv[optind++], &slotid);
		if (err != ERRF_OK)
			errfx(EXIT_BAD_ARGS, err, "failed to parse slot id");

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		check_select_key();
		if (hasover)
			override = piv_force_slot(selk, slotid, overalg);
		err = cmd_write_cert(slotid);

	} else if (strcmp(op, "delete-cert") == 0) {
		enum piv_slotid slotid;

		if (optind >= argc) {
			warnx("not enough arguments for %s (slot required)",
			    op);
			usage();
		}
		err = piv_slotid_from_string(argv[optind++], &slotid);
		if (err != ERRF_OK)
			errfx(EXIT_BAD_ARGS, err, "failed to parse slot id");

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		check_select_key();
		if (hasover)
			override = piv_force_slot(selk, slotid, overalg);
		err = cmd_delete_cert(slotid);

	} else if (strcmp(op, "req-cert") == 0) {
		enum piv_slotid slotid;

		if (optind >= argc) {
			warnx("not enough arguments for %s (slot required)",
			    op);
			usage();
		}
		err = piv_slotid_from_string(argv[optind++], &slotid);
		if (err != ERRF_OK)
			errfx(EXIT_BAD_ARGS, err, "failed to parse slot id");

		if (optind < argc) {
			warnx("too many arguments for %s", op);
			usage();
		}

		check_select_key();
		if (hasover)
			override = piv_force_slot(selk, slotid, overalg);
		err = cmd_req_cert(slotid);

	} else if (strcmp(op, "version") == 0) {
		fprintf(stdout, "%s\n", PIVY_VERSION);

	} else {
		warnx("invalid operation '%s'", op);
		usage();
	}

	scope_free_root(cvroot);
	piv_close(piv_ctx);

	if (err)
		errfx(1, err, "error occurred while executing '%s'", op);

	return (0);
}

void
cleanup_exit(int i)
{
	exit(i);
}
