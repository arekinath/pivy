/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
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

#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <wintypes.h>
#include <winscard.h>
#endif

#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/types.h>
#include "debug.h"
#include <sys/ipc.h>
#include <sys/shm.h>

#include <zlib.h>

#include "libssh/ssherr.h"
#include "libssh/sshkey.h"
#include "libssh/sshbuf.h"
#include "libssh/digest.h"
#include "libssh/cipher.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "tlv.h"
#include "piv.h"
#include "bunyan.h"

#include "piv-internal.h"

#define	PIV_MAX_CERT_LEN		16384

const uint8_t AID_PIV[] = {
	0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00
};

boolean_t piv_full_apdu_debug = B_FALSE;

#define pcscerrf(call, rv)	\
    errf("PCSCError", NULL, call " failed: %d (%s)", \
    rv, pcsc_stringify_error(rv))

#define pcscrerrf(call, reader, rv)	\
    errf("PCSCError", NULL, call " failed on '%s': %d (%s)", \
    reader, rv, pcsc_stringify_error(rv))

#define swerrf(ins, sw, ...)	\
    errf("APDUError", NULL, "Card replied with SW=%04x (%s) to " ins, \
    (uint)sw, sw_to_name(sw), ##__VA_ARGS__)

#define tagerrf(ins, tag, ...)	\
    errf("PIVTagError", NULL, "Invalid tag 0x%x in PIV " ins " response", \
    (uint)tag, ##__VA_ARGS__)

#define ioerrf(cause, rdr)	\
    errf("IOError", cause, "Failed to communicate with PIV device '%s'", rdr)

#define invderrf(cause, rdr)	\
    errf("InvalidDataError", cause, "PIV device '%s' returned invalid or " \
    "unsupported payload", rdr)

/* smatch and similar don't support varargs macros */
#ifndef LINT

#define permerrf(cause, rdr, doing, ...)	\
    errf("PermissionError", cause, \
    "Permission denied " doing " on PIV device '%s'", ##__VA_ARGS__, rdr)

#define notsuperrf(cause, rdr, thing, ...) \
    errf("NotSupportedError", cause, \
    thing " not supported by PIV device '%s'", ##__VA_ARGS__, rdr)

#endif

#define boxderrf(cause) \
    errf("InvalidDataError", cause, \
    "PIVBox contained invalid or corrupted data")

#define boxverrf(cause) \
    errf("NotSupportedError", cause, \
    "PIVBox is not supported")

#define boxaerrf(cause) \
    errf("ArgumentError", cause, \
    "Supplied piv_ecdh_box argument is invalid")

#define VERIFYB(apdubuf)	\
	do { \
		VERIFY((apdubuf).b_data != NULL);	\
		VERIFY3U((apdubuf).b_size, >=, 0);	\
		VERIFY3U((apdubuf).b_size, >=, (apdubuf).b_len);	\
		VERIFY3U((apdubuf).b_offset + (apdubuf).b_len, <=,	\
		    (apdubuf).b_size);	\
	} while (0)

struct apdu {
	enum iso_class a_cls;
	enum iso_ins a_ins;
	uint8_t a_p1;
	uint8_t a_p2;
	uint8_t a_le;

	struct apdubuf a_cmd;
	uint16_t a_sw;
	struct apdubuf a_reply;
};

struct piv_slot {
	struct piv_slot *ps_next;
	enum piv_slotid ps_slot;
	enum piv_alg ps_alg;
	X509 *ps_x509;
	const char *ps_subj;
	struct sshkey *ps_pubkey;
};

struct piv_token {
	struct piv_token *pt_next;
	const char *pt_rdrname;
	SCARDHANDLE pt_cardhdl;
	DWORD pt_proto;
	SCARD_IO_REQUEST pt_sendpci;
	boolean_t pt_intxn;
	boolean_t pt_reset;

	uint8_t pt_fascn[26];
	size_t pt_fascn_len;

	uint8_t pt_guid[GUID_LEN];
	char *pt_guidhex;

	boolean_t pt_haschuuid;
	uint8_t pt_chuuid[GUID_LEN];
	uint8_t pt_expiry[8];
	enum piv_alg pt_algs[32];
	size_t pt_alg_count;
	uint pt_pinretries;
	boolean_t pt_ykpiv;
	boolean_t pt_nochuid;
	boolean_t pt_signedchuid;
	uint8_t pt_ykver[3];

	boolean_t pt_ykserial_valid;
	uint32_t pt_ykserial;

	uint8_t pt_hist_oncard;
	uint8_t pt_hist_offcard;
	char *pt_hist_url;

	enum piv_pin pt_auth;

	boolean_t pt_pin_global;
	boolean_t pt_pin_app;
	boolean_t pt_occ;
	boolean_t pt_vci;

	struct piv_slot *pt_slots;
	struct piv_slot *pt_last_slot;
};

static inline void
debug_dump(errf_t *err, struct apdu *apdu)
{
	bunyan_log(DEBUG, "APDU parsing error",
	    "data", BNY_BIN_HEX, apdu->a_reply.b_data + apdu->a_reply.b_offset,
	    apdu->a_reply.b_len,
	    "error", BNY_ERF, err, NULL);
}

static const char *
sw_to_name(enum iso_sw sw)
{
	switch (sw) {
	case SW_NO_ERROR:
		return ("NO_ERROR");
	case SW_FUNC_NOT_SUPPORTED:
		return ("FUNC_NOT_SUPPORTED");
	case SW_CONDITIONS_NOT_SATISFIED:
		return ("CONDITIONS_NOT_SATISFIED");
	case SW_SECURITY_STATUS_NOT_SATISFIED:
		return ("SECURITY_STATUS_NOT_SATISFIED");
	case SW_WARNING_EOF:
		return ("WARNING_EOF");
	case SW_FILE_NOT_FOUND:
		return ("FILE_NOT_FOUND");
	case SW_INCORRECT_P1P2:
		return ("INCORRECT_P1P2");
	case SW_WRONG_DATA:
		return ("WRONG_DATA");
	case SW_OUT_OF_MEMORY:
		return ("OUT_OF_MEMORY");
	case SW_WRONG_LENGTH:
		return ("WRONG_LENGTH");
	case SW_INS_NOT_SUP:
		return ("INS_NOT_SUPPORTED");
	default:
		/* FALL THROUGH */
		(void)0;
	}
	if ((sw & 0xFF00) == SW_BYTES_REMAINING_00)
		return ("BYTES_REMAINING");
	else if ((sw & 0xFFF0) == SW_INCORRECT_PIN)
		return ("INCORRECT_PIN");
	else if ((sw & 0xFF00) == SW_WARNING_NO_CHANGE_00)
		return ("WARNING_NO_CHANGE");
	else if ((sw & 0xFF00) == SW_WARNING_00)
		return ("WARNING_UNKNOWN");
	return ("UNKNOWN");
}

const char *
piv_token_rdrname(const struct piv_token *token)
{
	return (token->pt_rdrname);
}

boolean_t
piv_token_in_txn(const struct piv_token *token)
{
	return (token->pt_intxn);
}

const uint8_t *
piv_token_fascn(const struct piv_token *token, size_t *len)
{
	if (token->pt_fascn_len == 0) {
		*len = 0;
		return (NULL);
	}
	*len = token->pt_fascn_len;
	return (token->pt_fascn);
}

const uint8_t *
piv_token_guid(const struct piv_token *token)
{
	if (token->pt_nochuid)
		return (NULL);
	return (token->pt_guid);
}

/* from bunyan.c */
extern char *buf_to_hex(const uint8_t *buf, size_t len, boolean_t spaces);

const char *
piv_token_guid_hex(const struct piv_token *token)
{
	if (token->pt_nochuid)
		return (NULL);
	if (token->pt_guidhex == NULL) {
		struct piv_token *tkwrite = (struct piv_token *)token;
		tkwrite->pt_guidhex = buf_to_hex(token->pt_guid,
		    sizeof (token->pt_guid), B_FALSE);
	}
	return (token->pt_guidhex);
}

const uint8_t *
piv_token_chuuid(const struct piv_token *token)
{
	if (token->pt_nochuid || !token->pt_haschuuid)
		return (NULL);
	return (token->pt_chuuid);
}

const uint8_t *
piv_token_expiry(const struct piv_token *token, size_t *len)
{
	if (token->pt_nochuid) {
		*len = 0;
		return (NULL);
	}
	*len = sizeof (token->pt_expiry);
	return (token->pt_expiry);
}

size_t
piv_token_nalgs(const struct piv_token *token)
{
	return (token->pt_alg_count);
}

enum piv_alg
piv_token_alg(const struct piv_token *token, size_t idx)
{
	VERIFY3U(idx, <, token->pt_alg_count);
	return (token->pt_algs[idx]);
}

boolean_t
piv_token_has_chuid(const struct piv_token *token)
{
	return (!token->pt_nochuid);
}

boolean_t
piv_token_has_signed_chuid(const struct piv_token *token)
{
	return (token->pt_signedchuid);
}

enum piv_pin
piv_token_default_auth(const struct piv_token *token)
{
	return (token->pt_auth);
}

boolean_t
piv_token_has_auth(const struct piv_token *token, enum piv_pin auth)
{
	switch (auth) {
	case PIV_PIN:
		return (token->pt_pin_app);
	case PIV_GLOBAL_PIN:
		return (token->pt_pin_global);
	case PIV_PUK:
		return (B_TRUE);
	case PIV_OCC:
		return (token->pt_occ);
	default:
		return (B_FALSE);
	}
}

boolean_t
piv_token_has_vci(const struct piv_token *token)
{
	return (token->pt_vci);
}

uint
piv_token_keyhistory_oncard(const struct piv_token *token)
{
	return (token->pt_hist_oncard);
}

uint
piv_token_keyhistory_offcard(const struct piv_token *token)
{
	return (token->pt_hist_offcard);
}

const char *
piv_token_offcard_url(const struct piv_token *token)
{
	return (token->pt_hist_url);
}

boolean_t
piv_token_is_ykpiv(const struct piv_token *token)
{
	return (token->pt_ykpiv);
}

const uint8_t *
ykpiv_token_version(const struct piv_token *token)
{
	VERIFY(token->pt_ykpiv);
	return (token->pt_ykver);
}

int
ykpiv_version_compare(const struct piv_token *token, uint8_t major,
    uint8_t minor, uint8_t patch)
{
	VERIFY(token->pt_ykpiv);
	if (token->pt_ykver[0] < major)
		return (-1);
	if (token->pt_ykver[0] > major)
		return (1);
	if (token->pt_ykver[1] < minor)
		return (-1);
	if (token->pt_ykver[1] > minor)
		return (1);
	if (token->pt_ykver[2] < patch)
		return (-1);
	if (token->pt_ykver[2] > patch)
		return (1);
	return (0);
}

boolean_t
ykpiv_token_has_serial(const struct piv_token *token)
{
	VERIFY(token->pt_ykpiv);
	return (token->pt_ykserial_valid);
}

uint32_t
ykpiv_token_serial(const struct piv_token *token)
{
	VERIFY(token->pt_ykpiv);
	VERIFY(token->pt_ykserial_valid);
	return (token->pt_ykserial);
}

struct piv_token *
piv_token_next(struct piv_token *token)
{
	return (token->pt_next);
}

errf_t *
piv_auth_key(struct piv_token *tk, struct piv_slot *slot, struct sshkey *pubkey)
{
	errf_t *err;
	int rv;
	uint8_t *chal = NULL, *sig = NULL;
	size_t challen, siglen;
	enum sshdigest_types hashalg;
	struct sshbuf *b = NULL;

	VERIFY(tk->pt_intxn);

	if (sshkey_equal_public(pubkey, slot->ps_pubkey) == 0) {
		err = errf("KeysNotEqualError", NULL,
		    "Given public key and slot's public key do not match");
		return (errf("KeyAuthError", err, "Failed to authenticate key "
		    "in slot %02x of PIV device '%s'", slot->ps_slot,
		    tk->pt_rdrname));
	}

	challen = 64;
	chal = calloc(1, challen);
	VERIFY3P(chal, !=, NULL);
	arc4random_buf(chal, challen);

	hashalg = 0;
	err = piv_sign(tk, slot, chal, challen, &hashalg, &sig, &siglen);
	if (err)
		goto out;

	b = sshbuf_new();
	VERIFY3P(b, !=, NULL);

	rv = sshkey_sig_from_asn1(pubkey, hashalg, sig, siglen, b);
	if (rv != 0) {
		err = errf("NotSupportedError",
		    ssherrf("sshkey_sig_from_asn1", rv),
		    "PIV device '%s' returned an unsupported signature format",
		    tk->pt_rdrname);
		goto out;
	}

	rv = sshkey_verify(pubkey, sshbuf_ptr(b), sshbuf_len(b),
	    chal, challen, 0);
	if (rv != 0) {
		err = errf("KeyAuthError", ssherrf("sshkey_verify", rv),
		    "Failed to authenticate key in slot %02x of PIV "
		    "device '%s'", slot->ps_slot, tk->pt_rdrname);
		goto out;
	}

out:
	sshbuf_free(b);
	if (chal != NULL)
		explicit_bzero(chal, challen);
	free(chal);
	if (sig != NULL)
		explicit_bzero(sig, siglen);
	free(sig);

	return (err);
}

static errf_t *
piv_probe_ykpiv(struct piv_token *pk)
{
	errf_t *err;
	struct apdu *apdu;

	VERIFY(pk->pt_intxn == B_TRUE);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_VER, 0x00, 0x00);

	err = piv_apdu_transceive(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(WARN, "piv_probe_ykpiv.transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		piv_apdu_free(apdu);
		return (err);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		const uint8_t *reply =
		    &apdu->a_reply.b_data[apdu->a_reply.b_offset];
		if (apdu->a_reply.b_len < 3) {
			piv_apdu_free(apdu);
			err = notsuperrf(NULL, pk->pt_rdrname, "YubicoPIV");
			return (err);
		}
		pk->pt_ykpiv = B_TRUE;
		bcopy(reply, pk->pt_ykver, 3);
		err = NULL;
	} else {
		err = notsuperrf(swerrf("INS_YK_GET_VER", apdu->a_sw),
		    pk->pt_rdrname, "YubicoPIV");
	}

	piv_apdu_free(apdu);
	return (err);
}

static errf_t *
ykpiv_read_serial(struct piv_token *pt)
{
	errf_t *err;
	struct apdu *apdu;

	VERIFY(pt->pt_intxn);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_SERIAL, 0x00, 0x00);

	err = piv_apdu_transceive(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(WARN, "ykpiv_read_serial.transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		piv_apdu_free(apdu);
		return (err);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		const uint8_t *reply =
		    &apdu->a_reply.b_data[apdu->a_reply.b_offset];
		if (apdu->a_reply.b_len < 4) {
			piv_apdu_free(apdu);
			err = notsuperrf(NULL, pt->pt_rdrname, "YubicoPIV v5");
			return (err);
		}
		pt->pt_ykserial_valid = B_TRUE;
		pt->pt_ykserial = reply[3] | (reply[2] << 8) |
		    (reply[1] << 16) | (reply[0] << 24);
		err = NULL;
	} else {
		err = notsuperrf(swerrf("INS_YK_GET_SERIAL", apdu->a_sw),
		    pt->pt_rdrname, "YubicoPIV v5");
	}

	piv_apdu_free(apdu);
	return (err);
}

static errf_t *
piv_read_discov(struct piv_token *pk)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag, policy;

	VERIFY(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_uint(tlv, PIV_TAG_DISCOV);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(WARN, "piv_read_chuid.transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x7E) {
			err = invderrf(tagerrf("INS_GET_DATA(DISCOV)", tag),
			    pk->pt_rdrname);
			debug_dump(err, apdu);
			piv_apdu_free(apdu);
			return (err);
		}
		while (!tlv_at_end(tlv)) {
			tag = tlv_read_tag(tlv);
			bunyan_log(TRACE, "reading discov tlv tag",
			    "tag", BNY_UINT, (uint)tag, NULL);
			switch (tag) {
			case 0x4F:	/* AID */
				if (tlv_rem(tlv) > sizeof (AID_PIV) ||
				    bcmp(AID_PIV, tlv_ptr(tlv), tlv_rem(tlv)) != 0) {
					tlv_skip(tlv);
					tlv_skip(tlv);
					tlv_free(tlv);
					err = invderrf(errf("PIVDataError", NULL,
					    "PIV discovery AID tag contained "
					    "incorrect AID"), pk->pt_rdrname);
					debug_dump(err, apdu);
					piv_apdu_free(apdu);
					return (err);
				}
				tlv_skip(tlv);
				break;
			case 0x5F2F:	/* PIN and OCC policy */
				policy = tlv_read_uint(tlv);
				bunyan_log(TRACE, "policy in discov",
				    "policy", BNY_UINT, policy, NULL);
				if ((policy & 0x4000))
					pk->pt_pin_app = B_TRUE;
				if ((policy & 0x2000))
					pk->pt_pin_global = B_TRUE;
				if ((policy & 0x1000))
					pk->pt_occ = B_TRUE;
				if ((policy & 0x0800))
					pk->pt_vci = B_TRUE;

				if (pk->pt_pin_app)
					pk->pt_auth = PIV_PIN;
				else if (pk->pt_pin_global)
					pk->pt_auth = PIV_GLOBAL_PIN;
				else if (pk->pt_occ)
					pk->pt_auth = PIV_OCC;

				if ((policy & 0xFF) == 0x10) {
					pk->pt_auth = PIV_PIN;
				}
				if ((policy & 0xFF) == 0x20 &&
				    pk->pt_pin_global) {
					pk->pt_auth = PIV_GLOBAL_PIN;
				}
				tlv_end(tlv);
				break;
			default:
				tlv_skip(tlv);
				tlv_skip(tlv);
				tlv_free(tlv);
				piv_apdu_free(apdu);
				err = invderrf(tagerrf("INS_GET_DATA(DISCOV)",
				    tag), pk->pt_rdrname);
				return (err);
			}
		}
		tlv_end(tlv);
		tlv_free(tlv);
		err = NULL;

	} else if (apdu->a_sw == SW_FILE_NOT_FOUND ||
	    apdu->a_sw == SW_WRONG_DATA) {
		err = errf("NotFoundError", swerrf("INS_GET_DATA", apdu->a_sw),
		    "PIV discovery object was not found on device '%s'",
		    pk->pt_rdrname);

	} else if (apdu->a_sw == SW_FUNC_NOT_SUPPORTED) {
		err = notsuperrf(swerrf("INS_GET_DATA", apdu->a_sw),
		    pk->pt_rdrname, "PIV discovery object");

	} else {
		err = swerrf("INS_GET_DATA", apdu->a_sw);
		bunyan_log(DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

static errf_t *
piv_read_keyhist(struct piv_token *pk)
{
	errf_t *rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	size_t used;

	VERIFY(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_uint(tlv, PIV_TAG_KEYHIST);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = piv_apdu_transceive_chain(pk, apdu);
	if (rv) {
		rv = ioerrf(rv, pk->pt_rdrname);
		bunyan_log(WARN, "piv_read_chuid.transceive_apdu failed",
		    "error", BNY_ERF, rv, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (rv);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		if (apdu->a_reply.b_len < 1) {
			piv_apdu_free(apdu);
			rv = invderrf(errf("APDUError", NULL,
			    "Card replied with empty APDU to "
			    "INS_GET_DATA(KEYHIST)"), pk->pt_rdrname);
			return (rv);
		}
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x53) {
			rv = invderrf(tagerrf("INS_GET_DATA(KEYHIST)", tag),
			    pk->pt_rdrname);
			debug_dump(rv, apdu);
			piv_apdu_free(apdu);
			return (rv);
		}
		while (!tlv_at_end(tlv)) {
			tag = tlv_read_tag(tlv);
			bunyan_log(TRACE, "reading keyhist tlv tag",
			    "tag", BNY_UINT, (uint)tag, NULL);
			switch (tag) {
			case 0xC1:	/* # keys with on-card certs */
				pk->pt_hist_oncard = tlv_read_uint(tlv);
				tlv_end(tlv);
				break;
			case 0xC2:	/* # keys with off-card certs */
				pk->pt_hist_offcard = tlv_read_uint(tlv);
				tlv_end(tlv);
				break;
			case 0xF3:	/* URL for off-card certs */
				pk->pt_hist_url = malloc(tlv_rem(tlv) + 1);
				VERIFY(pk->pt_hist_url != NULL);
				used = tlv_read(tlv, (uint8_t *)pk->pt_hist_url,
				    0, tlv_rem(tlv));
				pk->pt_hist_url[used] = 0;
				tlv_end(tlv);
				break;
			case 0xFE:	/* CRC */
				tlv_skip(tlv);
				break;
			default:
				tlv_skip(tlv);
				tlv_skip(tlv);
				tlv_free(tlv);
				rv = invderrf(tagerrf("INS_GET_DATA(KEYHIST)",
				    tag), pk->pt_rdrname);
				debug_dump(rv, apdu);
				piv_apdu_free(apdu);
				return (rv);
			}
		}
		tlv_end(tlv);
		tlv_free(tlv);
		rv = 0;

	} else if (apdu->a_sw == SW_FILE_NOT_FOUND ||
	    apdu->a_sw == SW_WRONG_DATA) {
		rv = errf("NotFoundError", swerrf("INS_GET_DATA", apdu->a_sw),
		    "PIV key history object not found on device '%s'",
		    pk->pt_rdrname);

	} else if (apdu->a_sw == SW_FUNC_NOT_SUPPORTED) {
		rv = notsuperrf(swerrf("INS_GET_DATA", apdu->a_sw),
		    pk->pt_rdrname, "PIV key history object");

	} else {
		rv = swerrf("INS_GET_DATA", apdu->a_sw);
		bunyan_log(DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, rv, NULL);
	}

	piv_apdu_free(apdu);

	return (rv);
}

static errf_t *
piv_read_chuid(struct piv_token *pk)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag, i;
	size_t used;

	VERIFY(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_uint(tlv, PIV_TAG_CHUID);
	tlv_pop(tlv);

	bunyan_log(DEBUG, "reading CHUID file", NULL);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(WARN, "transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x53) {
			err = invderrf(tagerrf("INS_GET_DATA(CHUID)", tag),
			    pk->pt_rdrname);
			debug_dump(err, apdu);
			piv_apdu_free(apdu);
			return (err);
		}
		while (!tlv_at_end(tlv)) {
			tag = tlv_read_tag(tlv);
			bunyan_log(TRACE, "reading chuid tlv tag",
			    "tag", BNY_UINT, (uint)tag, NULL);
			switch (tag) {
			case 0x30:	/* FASC-N */
				pk->pt_fascn_len = tlv_read(tlv, pk->pt_fascn,
				    0, sizeof (pk->pt_fascn));
				tlv_end(tlv);
				break;
			case 0x32:	/* Org Ident */
			case 0xEE:	/* Buffer Length */
			case 0xFE:	/* CRC */
			case 0x33:	/* DUNS */
				tlv_skip(tlv);
				break;
			case 0x35:	/* Expiration date */
				used = tlv_read(tlv, pk->pt_expiry, 0,
				    sizeof (pk->pt_expiry));
				if (used < sizeof (pk->pt_expiry)) {
					bunyan_log(DEBUG, "card expiry date "
					    "is short", "len", BNY_UINT, used,
					    NULL);
				}
				tlv_end(tlv);
				break;
			case 0x36:	/* Cardholder UUID */
				pk->pt_haschuuid = B_TRUE;
				tlv_read(tlv, pk->pt_chuuid, 0,
				    sizeof (pk->pt_chuuid));
				tlv_end(tlv);
				break;
			case 0x3E:	/* Signature */
				if (tlv_rem(tlv) > 0)
					pk->pt_signedchuid = B_TRUE;
				tlv_skip(tlv);
				break;
			case 0x34:	/* Card GUID */
				VERIFY3U(tlv_read(tlv, pk->pt_guid, 0,
				    sizeof (pk->pt_guid)), ==,
				    sizeof (pk->pt_guid));
				bunyan_log(TRACE, "read guid",
				    "guid", BNY_BIN_HEX, pk->pt_guid,
				    sizeof (pk->pt_guid), NULL);
				tlv_end(tlv);
				break;
			default:
				tlv_skip(tlv);
				tlv_skip(tlv);
				tlv_free(tlv);
				err = invderrf(tagerrf("INS_GET_DATA(CHUID)",
				    tag), pk->pt_rdrname);
				debug_dump(err, apdu);
				piv_apdu_free(apdu);
				return (err);
			}
		}
		tlv_end(tlv);
		tlv_free(tlv);

		for (i = 0; i < sizeof (pk->pt_guid); ++i) {
			if (pk->pt_guid[i] != 0)
				break;
		}
		if (i == sizeof (pk->pt_guid)) {
			bcopy(pk->pt_chuuid, pk->pt_guid, sizeof (pk->pt_guid));
			for (i = 0; i < sizeof (pk->pt_guid); ++i) {
				if (pk->pt_guid[i] != 0)
					break;
			}
			if (i == sizeof (pk->pt_guid) && pk->pt_fascn_len > 0) {
				struct ssh_digest_ctx *hctx;
				uint8_t *buf = calloc(1, 32);
				VERIFY(buf != NULL);
				hctx = ssh_digest_start(SSH_DIGEST_SHA256);
				VERIFY(hctx != NULL);
				VERIFY0(ssh_digest_update(hctx, pk->pt_fascn,
				    pk->pt_fascn_len));
				VERIFY0(ssh_digest_final(hctx, buf, 32));
				bcopy(buf, pk->pt_guid, sizeof (pk->pt_guid));
				ssh_digest_free(hctx);
			}
		}
		err = ERRF_OK;

	} else if (apdu->a_sw == SW_FILE_NOT_FOUND) {
		err = errf("NotFoundError", swerrf("INS_GET_DATA", apdu->a_sw),
		    "PIV CHUID object was not found on device '%s'",
		    pk->pt_rdrname);

	} else {
		err = swerrf("INS_GET_DATA(CHUID)", apdu->a_sw);
		bunyan_log(DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

errf_t *
piv_enumerate(SCARDCONTEXT ctx, struct piv_token **tokens)
{
	DWORD rv, readersLen = 0;
	LPTSTR readers, thisrdr;
	struct piv_token *ks = NULL;
	errf_t *err;

	rv = SCardListReaders(ctx, NULL, NULL, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		return (pcscerrf("SCardListReaders", rv));
	}
	readers = calloc(1, readersLen);
	rv = SCardListReaders(ctx, NULL, readers, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		free(readers);
		return (pcscerrf("SCardListReaders", rv));
	}

	for (thisrdr = readers; *thisrdr != 0; thisrdr += strlen(thisrdr) + 1) {
		SCARDHANDLE card;
		struct piv_token *key;
		DWORD activeProtocol;

		rv = SCardConnect(ctx, thisrdr, SCARD_SHARE_SHARED,
		    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card,
		    &activeProtocol);
		if (rv != SCARD_S_SUCCESS) {
			err = pcscrerrf("SCardConnect", thisrdr, rv);
			bunyan_log(DEBUG, "SCardConnect failed",
			    "error", BNY_ERF, err, NULL);
			erfree(err);
			continue;
		}

		key = calloc(1, sizeof (struct piv_token));
		key->pt_cardhdl = card;
		key->pt_rdrname = strdup(thisrdr);
		key->pt_proto = activeProtocol;

		switch (activeProtocol) {
		case SCARD_PROTOCOL_T0:
			key->pt_sendpci = *SCARD_PCI_T0;
			break;
		case SCARD_PROTOCOL_T1:
			key->pt_sendpci = *SCARD_PCI_T1;
			break;
		default:
			VERIFY(0);
		}

		piv_txn_begin(key);
		err = piv_select(key);
		if (err == ERRF_OK) {
			err = piv_read_chuid(key);
			if (errf_caused_by(err, "NotFoundError")) {
				erfree(err);
				err = ERRF_OK;
				key->pt_nochuid = B_TRUE;
			}
		}
		if (err == ERRF_OK) {
			err = piv_read_discov(key);
			if (errf_caused_by(err, "NotFoundError") ||
			    errf_caused_by(err, "NotSupportedError")) {
				erfree(err);
				err = ERRF_OK;
				/*
				 * Default to preferring the application PIN if
				 * we have no discovery object.
				 */
				key->pt_pin_app = B_TRUE;
				key->pt_auth = PIV_PIN;
			}
		}
		if (err == ERRF_OK) {
			err = piv_read_keyhist(key);
			if (errf_caused_by(err, "NotFoundError") ||
			    errf_caused_by(err, "NotSupportedError")) {
				erfree(err);
				err = ERRF_OK;
			}
		}
		if (err == ERRF_OK) {
			err = piv_probe_ykpiv(key);
			if (err == ERRF_OK) {
				err = ykpiv_read_serial(key);
			}
			if (errf_caused_by(err, "NotSupportedError")) {
				erfree(err);
				err = ERRF_OK;
			}
		}
		piv_txn_end(key);

		if (err == ERRF_OK) {
			key->pt_next = ks;
			ks = key;
		} else {
			bunyan_log(DEBUG, "piv_enumerate() eliminated reader "
			    "due to error", "reader", BNY_STRING, thisrdr,
			    "error", BNY_ERF, err, NULL);
			erfree(err);
			(void) SCardDisconnect(card, SCARD_RESET_CARD);
		}
	}

	*tokens = ks;

	free(readers);
	return (ERRF_OK);
}

errf_t *
piv_find(SCARDCONTEXT ctx, const uint8_t *guid, size_t guidlen,
    struct piv_token **token)
{
	DWORD rv, readersLen = 0;
	LPTSTR readers, thisrdr;
	struct piv_token *found = NULL, *key;
	errf_t *err;

	rv = SCardListReaders(ctx, NULL, NULL, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		return (pcscerrf("SCardListReaders", rv));
	}
	readers = calloc(1, readersLen);
	rv = SCardListReaders(ctx, NULL, readers, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		free(readers);
		return (pcscerrf("SCardListReaders", rv));
	}

	key = calloc(1, sizeof (struct piv_token));
	VERIFY(key != NULL);

	for (thisrdr = readers; *thisrdr != 0; thisrdr += strlen(thisrdr) + 1) {
		SCARDHANDLE card;
		DWORD activeProtocol;

		rv = SCardConnect(ctx, thisrdr, SCARD_SHARE_SHARED,
		    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card,
		    &activeProtocol);
		if (rv != SCARD_S_SUCCESS) {
			err = pcscrerrf("SCardConnect", thisrdr, rv);
			bunyan_log(DEBUG, "SCardConnect failed",
			    "error", BNY_ERF, err, NULL);
			erfree(err);
			continue;
		}

		key->pt_cardhdl = card;
		key->pt_rdrname = strdup(thisrdr);
		VERIFY(key->pt_rdrname != NULL);
		key->pt_proto = activeProtocol;

		switch (activeProtocol) {
		case SCARD_PROTOCOL_T0:
			key->pt_sendpci = *SCARD_PCI_T0;
			break;
		case SCARD_PROTOCOL_T1:
			key->pt_sendpci = *SCARD_PCI_T1;
			break;
		default:
			VERIFY(0);
		}

		piv_txn_begin(key);
		err = piv_select(key);
		if (err) {
			erfree(err);
			goto nope;
		}
		err = piv_read_chuid(key);
		if (errf_caused_by(err, "NotFoundError") && guidlen == 0) {
			erfree(err);
			err = ERRF_OK;
			key->pt_nochuid = B_TRUE;
			if (found != NULL) {
				piv_txn_end(key);
				(void) SCardDisconnect(card, SCARD_RESET_CARD);
				free((char *)key->pt_rdrname);
				free(key);
				piv_txn_end(found);
				(void) SCardDisconnect(found->pt_cardhdl,
				    SCARD_RESET_CARD);
				free((char *)found->pt_rdrname);
				free(found);
				free(readers);
				return (errf("DuplicateError", NULL,
				    "More than one PIV token matched GUID"));
			}
			found = key;
			key = calloc(1, sizeof (struct piv_token));
			continue;
		} else if (err) {
			bunyan_log(DEBUG, "piv_find() eliminated reader "
			    "due to error", "reader", BNY_STRING, thisrdr,
			    "error", BNY_ERF, err, NULL);
			erfree(err);
			goto nope;
		}
		if (guidlen == 0 || bcmp(guid, key->pt_guid, guidlen) != 0)
			goto nope;

		if (found != NULL) {
			piv_txn_end(key);
			(void) SCardDisconnect(card, SCARD_RESET_CARD);
			free((char *)key->pt_rdrname);
			free(key);
			piv_txn_end(found);
			(void) SCardDisconnect(found->pt_cardhdl,
			    SCARD_RESET_CARD);
			free((char *)found->pt_rdrname);
			free(found);
			free(readers);
			return (errf("DuplicateError", NULL,
			    "More than one PIV token matched GUID"));
		}
		found = key;
		key = calloc(1, sizeof (struct piv_token));
		continue;

nope:
		piv_txn_end(key);
		(void) SCardDisconnect(card, SCARD_RESET_CARD);
		free((char *)key->pt_rdrname);
		bzero(key, sizeof (struct piv_token));
	}

	free(key);

	if (found == NULL) {
		free(readers);
		return (errf("NotFoundError", NULL,
		    "No PIV token found matching GUID"));
	}

	key = found;
	err = ERRF_OK;

	if (err == ERRF_OK) {
		err = piv_read_discov(key);
		if (errf_caused_by(err, "NotFoundError") ||
		    errf_caused_by(err, "NotSupportedError")) {
			erfree(err);
			err = ERRF_OK;
			/*
			 * Default to preferring the application PIN if
			 * we have no discovery object.
			 */
			key->pt_pin_app = B_TRUE;
			key->pt_auth = PIV_PIN;
		}
	}
	if (err == ERRF_OK) {
		err = piv_read_keyhist(key);
		if (errf_caused_by(err, "NotFoundError") ||
		    errf_caused_by(err, "NotSupportedError")) {
			erfree(err);
			err = ERRF_OK;
		}
	}
	if (err == ERRF_OK) {
		err = piv_probe_ykpiv(key);
		if (err == ERRF_OK) {
			err = ykpiv_read_serial(key);
		}
		if (errf_caused_by(err, "NotSupportedError")) {
			erfree(err);
			err = ERRF_OK;
		}
	}
	piv_txn_end(key);

	if (err) {
		bunyan_log(DEBUG, "piv_find() eliminated reader "
		    "due to error", "reader", BNY_STRING, thisrdr,
		    "error", BNY_ERF, err, NULL);
		erfree(err);
		(void) SCardDisconnect(key->pt_cardhdl, SCARD_RESET_CARD);
		free((char *)key->pt_rdrname);
		free(key);
	}

	*token = key;
	free(readers);
	return (ERRF_OK);
}

void
piv_release(struct piv_token *pk)
{
	struct piv_token *next;
	struct piv_slot *ps, *psnext;

	for (; pk != NULL; pk = next) {
		VERIFY(pk->pt_intxn == B_FALSE);
		(void) SCardDisconnect(pk->pt_cardhdl, SCARD_LEAVE_CARD);

		for (ps = pk->pt_slots; ps != NULL; ps = psnext) {
			OPENSSL_free((void *)ps->ps_subj);
			X509_free(ps->ps_x509);
			sshkey_free(ps->ps_pubkey);
			psnext = ps->ps_next;
			free(ps);
		}
		free(pk->pt_hist_url);
		free((char *)pk->pt_rdrname);

		next = pk->pt_next;
		free(pk);
	}
}

struct piv_slot *
piv_get_slot(struct piv_token *tk, enum piv_slotid slotid)
{
	struct piv_slot *s;
	for (s = tk->pt_slots; s != NULL; s = s->ps_next) {
		if (s->ps_slot == slotid)
			return (s);
	}
	return (NULL);
}

struct piv_slot *
piv_force_slot(struct piv_token *tk, enum piv_slotid slotid, enum piv_alg alg)
{
	struct piv_slot *s;
	for (s = tk->pt_slots; s != NULL; s = s->ps_next) {
		if (s->ps_slot == slotid)
			break;
	}
	if (s == NULL) {
		s = calloc(1, sizeof (struct piv_slot));
		VERIFY(s != NULL);
		if (tk->pt_last_slot == NULL) {
			tk->pt_slots = s;
		} else {
			tk->pt_last_slot->ps_next = s;
		}
		tk->pt_last_slot = s;
	}
	s->ps_slot = slotid;
	s->ps_alg = alg;
	return (s);
}

struct piv_slot *
piv_slot_next(struct piv_token *token, struct piv_slot *slot)
{
	if (slot == NULL)
		return (token->pt_slots);
	return (slot->ps_next);
}

enum piv_slotid
piv_slot_id(const struct piv_slot *slot)
{
	return (slot->ps_slot);
}

enum piv_alg
piv_slot_alg(const struct piv_slot *slot)
{
	return (slot->ps_alg);
}

X509 *
piv_slot_cert(const struct piv_slot *slot)
{
	return (slot->ps_x509);
}

const char *
piv_slot_subject(const struct piv_slot *slot)
{
	return (slot->ps_subj);
}

struct sshkey *
piv_slot_pubkey(const struct piv_slot *slot)
{
	return (slot->ps_pubkey);
}

struct apdu *
piv_apdu_make(enum iso_class cls, enum iso_ins ins, uint8_t p1, uint8_t p2)
{
	struct apdu *a = calloc(1, sizeof (struct apdu));
	a->a_cls = cls;
	a->a_ins = ins;
	a->a_p1 = p1;
	a->a_p2 = p2;
	return (a);
}

void
piv_apdu_free(struct apdu *a)
{
	if (a->a_reply.b_data != NULL) {
		explicit_bzero(a->a_reply.b_data, MAX_APDU_SIZE);
		free(a->a_reply.b_data);
	}
	free(a);
}

void
piv_apdu_set_cmd(struct apdu *apdu, const uint8_t *data, size_t len)
{
	apdu->a_cmd.b_offset = 0;
	apdu->a_cmd.b_len = len;
	apdu->a_cmd.b_size = len;
	apdu->a_cmd.b_data = (uint8_t *)data;
}

uint16_t
piv_apdu_sw(const struct apdu *apdu)
{
	return (apdu->a_sw);
}

const uint8_t *
piv_apdu_get_reply(const struct apdu *apdu, size_t *len)
{
	*len = apdu->a_reply.b_len;
	return (apdu->a_reply.b_data + apdu->a_reply.b_offset);
}

static uint8_t *
apdu_to_buffer(struct apdu *apdu, uint *outlen)
{
	struct apdubuf *d = &(apdu->a_cmd);
	uint8_t *buf = calloc(1, 6 + d->b_len);
	buf[0] = apdu->a_cls;
	buf[1] = apdu->a_ins;
	buf[2] = apdu->a_p1;
	buf[3] = apdu->a_p2;
	if (d->b_data == NULL) {
		buf[4] = apdu->a_le;
		*outlen = 5;
		return (buf);
	} else {
		/* TODO: maybe look at handling ext APDUs? */
		VERIFY(d->b_len < 256 && d->b_len > 0);
		buf[4] = d->b_len;
		bcopy(d->b_data + d->b_offset, buf + 5, d->b_len);
		buf[d->b_len + 5] = apdu->a_le;
		*outlen = d->b_len + 6;
		return (buf);
	}
}

static const char *
ins_to_name(enum iso_ins ins)
{
	switch (ins) {
	case INS_SELECT:
		return ("SELECT");
	case INS_GET_DATA:
		return ("GET_DATA");
	case INS_VERIFY:
		return ("VERIFY");
	case INS_CHANGE_PIN:
		return ("CHANGE_PIN");
	case INS_RESET_PIN:
		return ("RESET_PIN");
	case INS_GEN_AUTH:
		return ("GEN_AUTH");
	case INS_PUT_DATA:
		return ("PUT_DATA");
	case INS_GEN_ASYM:
		return ("GEN_ASYM");
	case INS_CONTINUE:
		return ("CONTINUE");
	case INS_SET_MGMT:
		return ("YKPIV_SET_MGMT");
	case INS_IMPORT_ASYM:
		return ("YKPIV_IMPORT_ASYM");
	case INS_GET_VER:
		return ("YKPIV_GET_VER");
	case INS_SET_PIN_RETRIES:
		return ("YKPIV_SET_PIN_RETRIES");
	case INS_ATTEST:
		return ("YKPIV_ATTEST");
	case INS_GET_SERIAL:
		return ("YKPIV_GET_SERIAL");
	default:
		return ("UNKNOWN");
	}
}

errf_t *
piv_apdu_transceive(struct piv_token *key, struct apdu *apdu)
{
	uint cmdLen = 0;
	int rv;
	errf_t *err;

	boolean_t freedata = B_FALSE;
	DWORD recvLength;
	uint8_t *cmd;
	struct apdubuf *r = &(apdu->a_reply);

	VERIFY(key->pt_intxn == B_TRUE);

	cmd = apdu_to_buffer(apdu, &cmdLen);
	VERIFY(cmd != NULL);
	if (cmd == NULL || cmdLen < 5)
		return (ERRF_NOMEM);

	if (r->b_data == NULL) {
		r->b_data = calloc(1, MAX_APDU_SIZE);
		r->b_size = MAX_APDU_SIZE;
		r->b_offset = 0;
		freedata = B_TRUE;
	}
	recvLength = r->b_size - r->b_offset;
	VERIFY(r->b_data != NULL);

	if (piv_full_apdu_debug) {
		bunyan_log(TRACE, "sending APDU",
		    "apdu", BNY_BIN_HEX, cmd, cmdLen,
		    NULL);
	}

	rv = SCardTransmit(key->pt_cardhdl, &key->pt_sendpci, cmd,
	    cmdLen, NULL, r->b_data + r->b_offset, &recvLength);
	explicit_bzero(cmd, cmdLen);
	free(cmd);

	if (piv_full_apdu_debug) {
		bunyan_log(TRACE, "received APDU",
		    "apdu", BNY_BIN_HEX, r->b_data + r->b_offset, (size_t)recvLength,
		    NULL);
	}

	if (rv != SCARD_S_SUCCESS) {
		err = pcscrerrf("SCardTransmit", key->pt_rdrname, rv);
		bunyan_log(DEBUG, "SCardTransmit failed",
		    "error", BNY_ERF, err, NULL);
		if (freedata) {
			free(r->b_data);
			bzero(r, sizeof (struct apdubuf));
		}
		return (err);
	}
	recvLength -= 2;

	r->b_len = recvLength;
	apdu->a_sw = (r->b_data[r->b_offset + recvLength] << 8) |
	    r->b_data[r->b_offset + recvLength + 1];

	bunyan_log(DEBUG, "APDU exchanged",
	    "class", BNY_UINT, (uint)apdu->a_cls,
	    "ins", BNY_UINT, (uint)apdu->a_ins,
	    "ins_name", BNY_STRING, ins_to_name(apdu->a_ins),
	    "p1", BNY_UINT, (uint)apdu->a_p1,
	    "p2", BNY_UINT, (uint)apdu->a_p2,
	    "lc", BNY_UINT, (uint)(cmdLen - 5),
	    "le", BNY_UINT, (uint)apdu->a_le,
	    "sw", BNY_UINT, (uint)apdu->a_sw,
	    "sw_name", BNY_STRING, sw_to_name(apdu->a_sw),
	    "lr", BNY_UINT, (uint)r->b_len,
	    NULL);

	return (ERRF_OK);
}

errf_t *
piv_apdu_transceive_chain(struct piv_token *pk, struct apdu *apdu)
{
	errf_t *rv;
	size_t offset;
	size_t rem;

	VERIFY(pk->pt_intxn == B_TRUE);

	/* First, send the command. */
	rem = apdu->a_cmd.b_len;
	do {
		/* Is there another block needed in the chain? */
		if (rem > 0xFF) {
			apdu->a_cls |= CLA_CHAIN;
			apdu->a_cmd.b_len = 0xFF;
		} else {
			apdu->a_cls &= ~CLA_CHAIN;
			apdu->a_cmd.b_len = rem;
		}
		rv = piv_apdu_transceive(pk, apdu);
		if (rv)
			return (rv);
		if ((apdu->a_sw & 0xFF00) == SW_NO_ERROR ||
		    (apdu->a_sw & 0xFF00) == SW_BYTES_REMAINING_00 ||
		    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
		    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
			apdu->a_cmd.b_offset += apdu->a_cmd.b_len;
			rem -= apdu->a_cmd.b_len;
		} else {
			/*
			 * Return any other error straight away -- we can
			 * only get response chaining on BYTES_REMAINING
			 */
			return (ERRF_OK);
		}
	} while (rem > 0);

	/*
	 * We keep the original reply offset so we can calculate how much
	 * data we actually received later.
	 */
	offset = apdu->a_reply.b_offset;

	while ((apdu->a_sw & 0xFF00) == SW_BYTES_REMAINING_00 ||
	    (apdu->a_sw == SW_NO_ERROR && apdu->a_reply.b_len >= 0xFF)) {
		apdu->a_cls = CLA_ISO;
		apdu->a_ins = INS_CONTINUE;
		apdu->a_p1 = 0;
		apdu->a_p2 = 0;
		if ((apdu->a_sw & 0xFF00) == SW_BYTES_REMAINING_00)
			apdu->a_le = apdu->a_sw & 0x00FF;
		apdu->a_cmd.b_data = NULL;
		apdu->a_reply.b_offset += apdu->a_reply.b_len;
		VERIFY(apdu->a_reply.b_offset < apdu->a_reply.b_size);

		rv = piv_apdu_transceive(pk, apdu);
		if (rv)
			return (rv);
	}

	/* Work out the total length of all the segments we recieved. */
	apdu->a_reply.b_len += apdu->a_reply.b_offset - offset;
	apdu->a_reply.b_offset = offset;

	return (ERRF_OK);
}

errf_t *
piv_txn_begin(struct piv_token *key)
{
	VERIFY(key->pt_intxn == B_FALSE);
	LONG rv;
	errf_t *err;
	DWORD activeProtocol = 0;
retry:
	rv = SCardBeginTransaction(key->pt_cardhdl);
	if (rv == SCARD_W_RESET_CARD) {
		rv = SCardReconnect(key->pt_cardhdl, SCARD_SHARE_SHARED,
		    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, SCARD_RESET_CARD,
		    &activeProtocol);
		if (rv == SCARD_S_SUCCESS) {
			goto retry;
		} else {
			err = ioerrf(pcscerrf("SCardReconnect", rv),
			    key->pt_rdrname);
			return (err);
		}
	}
	if (rv != SCARD_S_SUCCESS) {
		err = ioerrf(pcscerrf("SCardBeginTransaction", rv),
		    key->pt_rdrname);
		return (err);
	}
	key->pt_intxn = B_TRUE;
	return (0);
}

void
piv_txn_end(struct piv_token *key)
{
	VERIFY(key->pt_intxn == B_TRUE);
	LONG rv;
	rv = SCardEndTransaction(key->pt_cardhdl,
	    key->pt_reset ? SCARD_RESET_CARD : SCARD_LEAVE_CARD);
	if (rv != SCARD_S_SUCCESS) {
		bunyan_log(ERROR, "SCardEndTransaction failed",
		    "reader", BNY_STRING, key->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
	}
	key->pt_intxn = B_FALSE;
	key->pt_reset = B_FALSE;
}

errf_t *
piv_select(struct piv_token *tk)
{
	errf_t *rv = ERRF_OK;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag, idx;

	VERIFY(tk->pt_intxn == B_TRUE);

	apdu = piv_apdu_make(CLA_ISO, INS_SELECT, SEL_APP_AID, 0);
	apdu->a_cmd.b_data = (uint8_t *)AID_PIV;
	apdu->a_cmd.b_len = sizeof (AID_PIV);

	rv = piv_apdu_transceive_chain(tk, apdu);
	if (rv) {
		rv = ioerrf(rv, tk->pt_rdrname);
		bunyan_log(WARN, "piv_select.transceive_apdu failed",
		    "error", BNY_ERF, rv, NULL);
		piv_apdu_free(apdu);
		return (rv);
	}

	if (apdu->a_sw == SW_NO_ERROR || apdu->a_sw == SW_WARNING_EOF) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != PIV_TAG_APT) {
			rv = invderrf(tagerrf("INS_SELECT", tag), tk->pt_rdrname);
			debug_dump(rv, apdu);
			piv_apdu_free(apdu);
			return (rv);
		}
		while (!tlv_at_end(tlv)) {
			tag = tlv_read_tag(tlv);
			switch (tag) {
			case PIV_TAG_AID:
			case PIV_TAG_AUTHORITY:
			case PIV_TAG_APP_LABEL:
			case PIV_TAG_URI:
				/* TODO: validate/store these maybe? */
				tlv_skip(tlv);
				break;
			case PIV_TAG_ALGS:
				if (tk->pt_alg_count > 0) {
					tlv_skip(tlv);
					break;
				}
				while (!tlv_at_end(tlv)) {
					tag = tlv_read_tag(tlv);
					if (tag == 0x80) {
						idx = tk->pt_alg_count++;
						tk->pt_algs[idx] =
						    tlv_read_uint(tlv);
						tlv_end(tlv);
					} else if (tag == 0x06) {
						tlv_skip(tlv);
					} else {
						rv = invderrf(tagerrf("algo "
						    "list in INS_SELECT",
						    tag), tk->pt_rdrname);
						debug_dump(rv, apdu);
						tlv_skip(tlv);
						tlv_skip(tlv);
						tlv_free(tlv);
						piv_apdu_free(apdu);
						return (rv);
					}
				}
				tlv_end(tlv);
				break;
			default:
				rv = invderrf(tagerrf("INS_SELECT", tag),
				    tk->pt_rdrname);
				debug_dump(rv, apdu);
				tlv_skip(tlv);
				tlv_skip(tlv);
				tlv_free(tlv);
				piv_apdu_free(apdu);
				return (rv);
			}
		}
		tlv_end(tlv);
		tlv_free(tlv);
		rv = 0;
	} else {
		rv = errf("NotFoundError", swerrf("INS_SELECT", apdu->a_sw),
		    "PIV applet was not found on device '%s'", tk->pt_rdrname);
		bunyan_log(DEBUG, "card did not accept INS_SELECT for PIV",
		    "error", BNY_ERF, rv, NULL);
	}

	piv_apdu_free(apdu);

	return (rv);
}

errf_t *
piv_auth_admin(struct piv_token *pt, const uint8_t *key, size_t keylen)
{
	errf_t *err;
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	uint8_t *chal = NULL, *resp = NULL, *iv = NULL;
	size_t challen = 0, ivlen, resplen;
	const struct sshcipher *cipher;
	struct sshcipher_ctx *cctx;

	VERIFY(pt->pt_intxn == B_TRUE);

	cipher = cipher_by_name("3des-cbc");
	VERIFY(cipher != NULL);
	VERIFY(cipher_authlen(cipher) == 0);
	if (cipher_keylen(cipher) != keylen) {
		return (argerrf("key", "a buffer of length %u",
		    "%u bytes long", cipher_keylen(cipher), keylen));
	}

	tlv = tlv_init_write();
	tlv_push(tlv, 0x7C);
	tlv_push(tlv, GA_TAG_CHALLENGE);
	tlv_pop(tlv);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_AUTH, PIV_ALG_3DES,
	    PIV_SLOT_ADMIN);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(DEBUG, "piv_auth_admin.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_INCORRECT_P1P2) {
		err = errf("NotFoundError", swerrf("INS_GEN_AUTH(9b)",
		    apdu->a_sw), "PIV device '%s' has no admin key",
		    pt->pt_rdrname);
		piv_apdu_free(apdu);
		return (err);
	} else if (apdu->a_sw == SW_WRONG_DATA ||
	    apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GEN_AUTH(9b)", apdu->a_sw),
		    pt->pt_rdrname, "authenticating with 9B admin key");
		return (err);
	} else if (apdu->a_sw != SW_NO_ERROR) {
		err = notsuperrf(swerrf("INS_GEN_AUTH(9b)", apdu->a_sw),
		    pt->pt_rdrname, "Admin challenge-response authentication");
		piv_apdu_free(apdu);
		return (err);
	}

	tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
	    apdu->a_reply.b_len);
	tag = tlv_read_tag(tlv);
	if (tag != 0x7C) {
		err = invderrf(tagerrf("INS_GEN_AUTH(9b)", tag), pt->pt_rdrname);
		debug_dump(err, apdu);
		tlv_skip(tlv);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	while (!tlv_at_end(tlv)) {
		tag = tlv_read_tag(tlv);
		if (tag == GA_TAG_CHALLENGE) {
			challen = tlv_rem(tlv);
			chal = calloc(1, challen);
			challen = tlv_read(tlv, chal, 0, challen);
			tlv_end(tlv);
			continue;
		}
		tlv_skip(tlv);
	}
	tlv_end(tlv);

	VERIFY(chal != NULL);
	tlv_free(tlv);
	piv_apdu_free(apdu);

	resplen = challen;
	resp = calloc(1, resplen);
	VERIFY(resp != NULL);

	if (cipher_blocksize(cipher) != challen) {
		err = invderrf(errf("LengthError", NULL, "INS_GEN_AUTH(9b) "
		    "returned %d byte challenge but cipher blocks are %d bytes",
		    challen, cipher_blocksize(cipher)), pt->pt_rdrname);
		return (err);
	}

	ivlen = cipher_ivlen(cipher);
	iv = calloc(1, ivlen);
	VERIFY(iv != NULL);
	explicit_bzero(iv, ivlen);

	rv = cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 1);
	VERIFY(rv == 0);
	rv = cipher_crypt(cctx, 0, resp, chal, challen, 0, 0);
	VERIFY(rv == 0);
	cipher_free(cctx);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x7C);
	tlv_push(tlv, GA_TAG_RESPONSE);
	tlv_write(tlv, resp, 0, resplen);
	tlv_pop(tlv);
	tlv_pop(tlv);

	pt->pt_reset = B_TRUE;

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_AUTH, PIV_ALG_3DES,
	    PIV_SLOT_ADMIN);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	free(chal);
	explicit_bzero(resp, resplen);
	free(resp);

	err = piv_apdu_transceive(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(DEBUG, "piv_auth_admin.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
	} else if (apdu->a_sw == SW_INCORRECT_P1P2) {
		err = errf("NotFoundError", swerrf("INS_GEN_AUTH(9b)",
		    apdu->a_sw), "PIV device '%s' has no admin key",
		    pt->pt_rdrname);
		piv_apdu_free(apdu);
		return (err);
	} else if (apdu->a_sw == SW_WRONG_DATA ||
	    apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GEN_AUTH(9b)", apdu->a_sw),
		    pt->pt_rdrname, "authenticating with 9B admin key");
		return (err);
	} else {
		err = swerrf("INS_GEN_AUTH(9B)", apdu->a_sw);
		bunyan_log(DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);
	return (err);
}

errf_t *
piv_write_file(struct piv_token *pt, uint tag, const uint8_t *data, size_t len)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;

	VERIFY(pt->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_uint(tlv, tag);
	tlv_pop(tlv);
	tlv_pushl(tlv, 0x53, len + 8);
	tlv_write(tlv, (uint8_t *)data, 0, len);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_PUT_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(WARN, "piv_write_file.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
	} else if (apdu->a_sw == SW_OUT_OF_MEMORY) {
		err = errf("DeviceOutOfMemoryError", swerrf("INS_PUT_DATA(%x)",
		    apdu->a_sw, tag), "Out of memory to store file object on "
		    "PIV device '%s'", pt->pt_rdrname);
	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_PUT_DATA(%x)", apdu->a_sw, tag),
		    pt->pt_rdrname, "writing file object");
	} else if (apdu->a_sw == SW_FUNC_NOT_SUPPORTED) {
		err = notsuperrf(swerrf("INS_PUT_DATA(%x)", apdu->a_sw, tag),
		    pt->pt_rdrname, "File object %x", tag);
	} else {
		err = swerrf("INS_PUT_DATA(%x)", apdu->a_sw, tag);
	}

	piv_apdu_free(apdu);

	return (err);
}

static errf_t *
piv_generate_common(struct piv_token *pt, struct apdu *apdu,
    struct tlv_state *tlv, enum piv_alg alg, enum piv_slotid slotid,
    struct sshkey **pubkey)
{
	errf_t *err;
	int rv;
	uint tag;
	struct sshkey *k = NULL;

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(WARN, "piv_generate.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x7F49) {
			err = invderrf(tagerrf("INS_GEN_ASYM", tag),
			    pt->pt_rdrname);
			debug_dump(err, apdu);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (err);
		}
		if (alg == PIV_ALG_RSA1024 || alg == PIV_ALG_RSA2048) {
			k = sshkey_new(KEY_RSA);
			VERIFY(k != NULL);
		} else if (alg == PIV_ALG_ECCP256) {
			k = sshkey_new(KEY_ECDSA);
			VERIFY(k != NULL);
			k->ecdsa_nid = NID_X9_62_prime256v1;
			k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
			EC_KEY_set_asn1_flag(k->ecdsa, OPENSSL_EC_NAMED_CURVE);
		} else if (alg == PIV_ALG_ECCP384) {
			k = sshkey_new(KEY_ECDSA);
			VERIFY(k != NULL);
			k->ecdsa_nid = NID_secp384r1;
			k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
			EC_KEY_set_asn1_flag(k->ecdsa, OPENSSL_EC_NAMED_CURVE);
		} else {
			err = argerrf("alg", "a supported algorithm", "%d", alg);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (err);
		}
		while (!tlv_at_end(tlv)) {
			tag = tlv_read_tag(tlv);
			if (alg == PIV_ALG_RSA1024 || alg == PIV_ALG_RSA2048) {
				if (tag == 0x81) {		/* Modulus */
					VERIFY(BN_bin2bn(tlv_ptr(tlv),
					    tlv_rem(tlv), k->rsa->n) != NULL);
					tlv_skip(tlv);
					continue;
				} else if (tag == 0x82) {	/* Exponent */
					VERIFY(BN_bin2bn(tlv_ptr(tlv),
					    tlv_rem(tlv), k->rsa->e) != NULL);
					tlv_skip(tlv);
					continue;
				}
			} else if (alg == PIV_ALG_ECCP256 ||
			    alg == PIV_ALG_ECCP384) {
				if (tag == 0x86) {
					const EC_GROUP *g;
					EC_POINT *point;

					g = EC_KEY_get0_group(k->ecdsa);
					VERIFY(g != NULL);
					point = EC_POINT_new(g);
					VERIFY(point != NULL);
					rv = EC_POINT_oct2point(g, point,
					    tlv_ptr(tlv), tlv_rem(tlv), NULL);
					if (rv != 1) {
						make_sslerrf(err,
						    "EC_POINT_oct2point",
						    "parsing pubkey");
						err = invderrf(err,
						    pt->pt_rdrname);
						goto tlverr;
					}

					rv = sshkey_ec_validate_public(g,
					    point);
					if (rv) {
						err = invderrf(ssherrf(
						    "sshkey_ec_validate_public",
						    rv), pt->pt_rdrname);
						goto tlverr;
					}
					rv = EC_KEY_set_public_key(
					    k->ecdsa, point);
					if (rv != 1) {
						make_sslerrf(err,
						    "EC_KEY_set_public_key",
						    "parsing pubkey");
						err = invderrf(err,
						    pt->pt_rdrname);
						goto tlverr;
					}
					EC_POINT_free(point);

					tlv_skip(tlv);
					continue;
				}
			}
			err = invderrf(tagerrf("INS_GEN_ASYM", tag),
			    pt->pt_rdrname);
			debug_dump(err, apdu);
tlverr:
			tlv_skip(tlv);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (err);
		}
		tlv_end(tlv);
		tlv_free(tlv);

		*pubkey = k;

		err = ERRF_OK;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GEN_ASYM", apdu->a_sw), pt->pt_rdrname,
		    "generating new key in slot %02x", (uint)slotid);

	} else {
		err = swerrf("INS_GEN_ASYM", apdu->a_sw);
	}

	piv_apdu_free(apdu);
	return (err);
}

errf_t *
piv_generate(struct piv_token *pt, enum piv_slotid slotid, enum piv_alg alg,
    struct sshkey **pubkey)
{
	struct apdu *apdu;
	struct tlv_state *tlv;

	VERIFY(pt->pt_intxn);

	tlv = tlv_init_write();
	tlv_push(tlv, 0xAC);
	tlv_push(tlv, 0x80);
	tlv_write_uint(tlv, alg);
	tlv_pop(tlv);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_ASYM, 0x00, slotid);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	return (piv_generate_common(pt, apdu, tlv, alg, slotid, pubkey));
}

errf_t *
ykpiv_generate(struct piv_token *pt, enum piv_slotid slotid,
    enum piv_alg alg, enum ykpiv_pin_policy pinpolicy,
    enum ykpiv_touch_policy touchpolicy, struct sshkey **pubkey)
{
	struct apdu *apdu;
	struct tlv_state *tlv;

	VERIFY(pt->pt_intxn);

	/* Reject if this isn't a YubicoPIV card. */
	if (!pt->pt_ykpiv)
		return (argerrf("tk", "a YubicoPIV-compatible token", "not"));
	/* The TOUCH_CACHED option is only supported on versions >=4.3 */
	if (touchpolicy == YKPIV_TOUCH_CACHED &&
	    (pt->pt_ykver[0] < 4 ||
	    (pt->pt_ykver[0] == 4 && pt->pt_ykver[1] < 3))) {
		return (argerrf("touchpolicy", "TOUCH_CACHED only on YubicoPIV "
		    "version >=4.3", "not supported by this device (v%d.%d.%d)",
		    pt->pt_ykver[0], pt->pt_ykver[1], pt->pt_ykver[2]));
	}

	tlv = tlv_init_write();
	tlv_push(tlv, 0xAC);
	tlv_push(tlv, 0x80);
	tlv_write_uint(tlv, alg);
	tlv_pop(tlv);
	if (pinpolicy != YKPIV_PIN_DEFAULT) {
		tlv_push(tlv, 0xAA);
		tlv_write_uint(tlv, pinpolicy);
		tlv_pop(tlv);
	}
	if (touchpolicy != YKPIV_TOUCH_DEFAULT) {
		tlv_push(tlv, 0xAB);
		tlv_write_uint(tlv, touchpolicy);
		tlv_pop(tlv);
	}
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_ASYM, 0x00, slotid);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	return (piv_generate_common(pt, apdu, tlv, alg, slotid, pubkey));
}

errf_t *
piv_write_keyhistory(struct piv_token *pt, uint oncard, uint offcard,
    const char *offcard_url)
{
	struct tlv_state *tlv;
	errf_t *err;

	VERIFY(pt->pt_intxn);

	if (oncard > 20 || offcard > 20 || oncard + offcard > 20) {
		return (argerrf("oncard + offcard", "less than max keyhist "
		    "slots (%d)", "%d", 20, oncard + offcard));
	}

	if (offcard > 0 && offcard_url == NULL) {
		return (argerrf("offcard_url", "a valid URL string when "
		    "offcard > 0", "NULL"));
	}

	tlv = tlv_init_write();

	tlv_push(tlv, 0xC1);
	tlv_write_uint(tlv, oncard);
	tlv_pop(tlv);

	tlv_push(tlv, 0xC2);
	tlv_write_uint(tlv, offcard);
	tlv_pop(tlv);

	if (offcard_url != NULL) {
		tlv_push(tlv, 0xF3);
		tlv_write(tlv, (uint8_t *)offcard_url, 0,
		    strlen(offcard_url));
		tlv_pop(tlv);
	}

	err = piv_write_file(pt, PIV_TAG_KEYHIST, tlv_buf(tlv), tlv_len(tlv));

	if (err == ERRF_OK) {
		pt->pt_hist_oncard = oncard;
		pt->pt_hist_offcard = offcard;
		pt->pt_hist_url = strdup(offcard_url);
	}

	tlv_free(tlv);

	return (err);
}

errf_t *
piv_write_cert(struct piv_token *pk, enum piv_slotid slotid,
    const uint8_t *data, size_t datalen, uint flags)
{
	errf_t *err;
	struct tlv_state *tlv;
	uint tag;

	VERIFY(pk->pt_intxn == B_TRUE);

	switch (slotid) {
	case PIV_SLOT_9A:
		tag = PIV_TAG_CERT_9A;
		break;
	case PIV_SLOT_9C:
		tag = PIV_TAG_CERT_9C;
		break;
	case PIV_SLOT_9D:
		tag = PIV_TAG_CERT_9D;
		break;
	case PIV_SLOT_9E:
		tag = PIV_TAG_CERT_9E;
		break;
	default:
		if (slotid >= PIV_SLOT_RETIRED_1 &&
		    slotid <= PIV_SLOT_RETIRED_20) {
			tag = PIV_TAG_CERT_82 + (slotid - PIV_SLOT_82);
			break;
		}
		return (argerrf("slotid", "a supported slot number",
		    "%02x", slotid));
	}

	tlv = tlv_init_write();
	tlv_pushl(tlv, 0x70, datalen + 3);
	tlv_write(tlv, data, 0, datalen);
	tlv_pop(tlv);
	tlv_push(tlv, 0x71);
	tlv_write_byte(tlv, (uint8_t)flags);
	tlv_pop(tlv);

	err = piv_write_file(pk, tag, tlv_buf(tlv), tlv_len(tlv));

	tlv_free(tlv);

	return (err);
}

errf_t *
ykpiv_attest(struct piv_token *pt, struct piv_slot *slot, uint8_t **data,
    size_t *len)
{
	errf_t *err;
	struct apdu *apdu;

	VERIFY(pt->pt_intxn == B_TRUE);
	if (!pt->pt_ykpiv)
		return (argerrf("tk", "a YubicoPIV-compatible token", "not"));

	apdu = piv_apdu_make(CLA_ISO, INS_ATTEST, (uint8_t)slot->ps_slot, 0x00);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(WARN, "piv_read_file.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		piv_apdu_free(apdu);
		return (err);
	}

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		if (apdu->a_reply.b_len < 1) {
			err = notsuperrf(errf("InvalidDataError", NULL,
			    "No data payload returned to INS_ATTEST(%x)",
			    slot->ps_slot), pt->pt_rdrname,
			    "YubicoPIV attestation");
			piv_apdu_free(apdu);
			return (err);
		}
		*data = malloc(apdu->a_reply.b_len);
		VERIFY(*data != NULL);
		*len = apdu->a_reply.b_len;
		bcopy(apdu->a_reply.b_data + apdu->a_reply.b_offset,
		    *data, apdu->a_reply.b_len);
		err = ERRF_OK;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_ATTEST(%x)", apdu->a_sw,
		    slot->ps_slot), pt->pt_rdrname, "attesting slot %x",
		    slot->ps_slot);

	} else if (apdu->a_sw == SW_INS_NOT_SUP) {
		err = notsuperrf(swerrf("INS_ATTEST(%x)", apdu->a_sw,
		    slot->ps_slot), pt->pt_rdrname, "YubicoPIV attestation");

	} else {
		err = swerrf("INS_ATTEST(%x)", apdu->a_sw, slot->ps_slot);
		bunyan_log(DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

errf_t *
piv_read_file(struct piv_token *pt, uint tag, uint8_t **data, size_t *len)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint rtag;

	VERIFY(pt->pt_intxn);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_uint(tlv, tag);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(WARN, "piv_read_file.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		if (apdu->a_reply.b_len < 1) {
			err = invderrf(errf("APDUError", NULL,
			    "Card replied with empty APDU to "
			    "INS_GET_DATA(%x)", tag), pt->pt_rdrname);
			piv_apdu_free(apdu);
			return (err);
		}
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		rtag = tlv_read_tag(tlv);
		if (rtag != 0x53) {
			err = invderrf(tagerrf("INS_GET_DATA(%x)", rtag,
			    tag), pt->pt_rdrname);
			debug_dump(err, apdu);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (err);
		}
		*data = malloc(tlv_rem(tlv));
		VERIFY(*data != NULL);
		*len = tlv_read(tlv, *data, 0, tlv_rem(tlv));
		tlv_end(tlv);
		tlv_free(tlv);
		err = ERRF_OK;

	} else if (apdu->a_sw == SW_FILE_NOT_FOUND) {
		err = errf("NotFoundError", swerrf("INS_GET_DATA", apdu->a_sw),
		    "No PIV file object found at tag %x", tag);

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GET_DATA", apdu->a_sw),
		    pt->pt_rdrname, "reading PIV file object at tag %x", tag);

	} else {
		err = swerrf("INS_GET_DATA(%x)", apdu->a_sw, tag);
		bunyan_log(DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

void
piv_file_data_free(uint8_t *data, size_t len)
{
	explicit_bzero(data, len);
	free(data);
}

errf_t *
piv_read_cert(struct piv_token *pk, enum piv_slotid slotid)
{
	errf_t *err;
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	uint8_t *ptr, *buf = NULL;
	size_t len = 0;
	X509 *cert;
	struct piv_slot *pc;
	EVP_PKEY *pkey;
	uint8_t certinfo = 0;

	VERIFY(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	switch (slotid) {
	case PIV_SLOT_9A:
		tlv_write_uint(tlv, PIV_TAG_CERT_9A);
		break;
	case PIV_SLOT_9C:
		tlv_write_uint(tlv, PIV_TAG_CERT_9C);
		break;
	case PIV_SLOT_9D:
		tlv_write_uint(tlv, PIV_TAG_CERT_9D);
		break;
	case PIV_SLOT_9E:
		tlv_write_uint(tlv, PIV_TAG_CERT_9E);
		break;
	default:
		if (slotid >= PIV_SLOT_RETIRED_1 &&
		    slotid <= PIV_SLOT_RETIRED_20) {
			tlv_write_uint(tlv, PIV_TAG_CERT_82 +
			    (slotid - PIV_SLOT_82));
			break;
		}
		err = argerrf("slotid", "a supported PIV slot number",
		    "%02x", slotid);
		return (err);
	}
	tlv_pop(tlv);

	bunyan_log(DEBUG, "reading cert file",
	    "slot", BNY_UINT, (uint)slotid,
	    "cdata", BNY_BIN_HEX, tlv_buf(tlv), tlv_len(tlv),
	    NULL);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(WARN, "piv_read_cert.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		if (apdu->a_reply.b_len < 1) {
			err = invderrf(errf("APDUError", NULL,
			    "Card replied with empty APDU reading certificate "
			    "for slot %02x", slotid), pk->pt_rdrname);
			piv_apdu_free(apdu);
			return (err);
		}
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x53) {
			err = invderrf(tagerrf("INS_GET_DATA(%02x)", tag,
			    (uint)slotid), pk->pt_rdrname);
			debug_dump(err, apdu);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (err);
		}
		while (!tlv_at_end(tlv)) {
			tag = tlv_read_tag(tlv);
			if (tag == 0x71) {
				certinfo = tlv_read_byte(tlv);
				tlv_end(tlv);
				continue;
			}
			if (tag == 0x70) {
				ptr = tlv_ptr(tlv);
				len = tlv_rem(tlv);
			}
			tlv_skip(tlv);
		}
		tlv_end(tlv);

		/* See the NIST PIV spec. This bit should always be zero. */
		if ((certinfo & PIV_CI_X509) != 0) {
			err = errf("CertFlagError", NULL,
			    "Certificate for slot %02x has PIV_CI_X509 flag "
			    "set, not allowed by spec", (uint)slotid);
			err = invderrf(err, pk->pt_rdrname);
			debug_dump(err, apdu);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (err);
		}

		if ((certinfo & PIV_CI_COMPTYPE) == PIV_COMP_GZIP) {
			z_stream strm;
			buf = calloc(1, PIV_MAX_CERT_LEN);
			VERIFY(buf != NULL);

			bzero(&strm, sizeof (strm));
			VERIFY0(inflateInit2(&strm, 31));

			strm.avail_in = len;
			strm.next_in = ptr;
			strm.avail_out = PIV_MAX_CERT_LEN;
			strm.next_out = buf;

			if (inflate(&strm, Z_NO_FLUSH) != Z_STREAM_END ||
			    strm.avail_out <= 0) {
				err = errf("DecompressionError", NULL,
				    "Compressed cert in slot %02x failed "
				    "to decompress", slotid);
				err = invderrf(err, pk->pt_rdrname);
				tlv_free(tlv);
				piv_apdu_free(apdu);
				return (err);
			}
			if (strm.avail_out > PIV_MAX_CERT_LEN) {
				err = errf("DecompressionError", NULL,
				    "Compressed cert in slot %02x was "
				    "too big (%u bytes)", (uint)slotid,
				    strm.avail_out);
				err = invderrf(err, pk->pt_rdrname);
				tlv_free(tlv);
				piv_apdu_free(apdu);
				return (err);
			}

			bunyan_log(DEBUG, "decompressed cert",
			    "compressed_len", BNY_UINT, len,
			    "avail_out", BNY_UINT, strm.avail_out,
			    "uncompressed_len", BNY_UINT, PIV_MAX_CERT_LEN -
			    strm.avail_out, NULL);

			ptr = buf;
			len = PIV_MAX_CERT_LEN - strm.avail_out;

			VERIFY0(inflateEnd(&strm));

		} else if ((certinfo & PIV_CI_COMPTYPE) != PIV_COMP_NONE) {
			err = errf("CertFlagError", NULL,
			    "Certificate for slot %02x has unknown "
			    "compression type flag", (uint)slotid);
			err = invderrf(err, pk->pt_rdrname);
			bunyan_log(DEBUG, "card returned cert with unknown "
			    "compression type, assuming invalid",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)slotid, NULL);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (err);
		}

		cert = d2i_X509(NULL, (const uint8_t **)&ptr, len);
		if (cert == NULL) {
			make_sslerrf(err, "d2i_X509", "parsing cert %02x",
			    (uint)slotid);
			err = invderrf(err, pk->pt_rdrname);
			bunyan_log(WARN, "card returned invalid cert",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)slotid,
			    "error", BNY_ERF, err,
			    "data", BNY_BIN_HEX, ptr, len, NULL);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (err);
		}

		tlv_free(tlv);
		free(buf);

		for (pc = pk->pt_slots; pc != NULL; pc = pc->ps_next) {
			if (pc->ps_slot == slotid)
				break;
		}
		if (pc == NULL) {
			pc = calloc(1, sizeof (struct piv_slot));
			VERIFY(pc != NULL);
			if (pk->pt_last_slot == NULL) {
				pk->pt_slots = pc;
			} else {
				pk->pt_last_slot->ps_next = pc;
			}
			pk->pt_last_slot = pc;
		} else {
			OPENSSL_free((void *)pc->ps_subj);
			X509_free(pc->ps_x509);
			sshkey_free(pc->ps_pubkey);
		}
		pc->ps_slot = slotid;
		pc->ps_x509 = cert;
		pc->ps_subj = X509_NAME_oneline(
		    X509_get_subject_name(cert), NULL, 0);
		pkey = X509_get_pubkey(cert);
		VERIFY(pkey != NULL);
		rv = sshkey_from_evp_pkey(pkey, KEY_UNSPEC,
		    &pc->ps_pubkey);
		EVP_PKEY_free(pkey);
		if (rv != 0) {
			err = invderrf(ssherrf("sshkey_from_evp_pkey", rv),
			    pk->pt_rdrname);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (err);
		}

		err = NULL;

		switch (pc->ps_pubkey->type) {
		case KEY_ECDSA:
			switch (sshkey_size(pc->ps_pubkey)) {
			case 256:
				pc->ps_alg = PIV_ALG_ECCP256;
				break;
			case 384:
				pc->ps_alg = PIV_ALG_ECCP384;
				break;
			default:
				err = invderrf(errf("BadAlgorithmError", NULL,
				    "Cert subj is EC key of size %u, not "
				    "supported by PIV",
				    sshkey_size(pc->ps_pubkey)),
				    pk->pt_rdrname);
			}
			break;
		case KEY_RSA:
			switch (sshkey_size(pc->ps_pubkey)) {
			case 1024:
				pc->ps_alg = PIV_ALG_RSA1024;
				break;
			case 2048:
				pc->ps_alg = PIV_ALG_RSA2048;
				break;
			default:
				err = invderrf(errf("BadAlgorithmError", NULL,
				    "Cert subj is RSA key of size %u, not "
				    "supported by PIV",
				    sshkey_size(pc->ps_pubkey)),
				    pk->pt_rdrname);
			}
			break;
		default:
			err = invderrf(errf("BadAlgorithmError", NULL,
			    "Certificate subject key is of unsupported type: "
			    "%s", sshkey_type(pc->ps_pubkey)), pk->pt_rdrname);
		}

	} else if (apdu->a_sw == SW_FILE_NOT_FOUND) {
		err = errf("NotFoundError", swerrf("INS_GET_DATA", apdu->a_sw),
		    "No certificate found for slot %02x in device '%s'",
		    slotid, pk->pt_rdrname);

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GET_DATA", apdu->a_sw), pk->pt_rdrname,
		    "reading certificate for slot %02x", (uint)slotid);

	} else if (apdu->a_sw == SW_FUNC_NOT_SUPPORTED ||
	    apdu->a_sw == SW_WRONG_DATA) {
		err = notsuperrf(swerrf("INS_GET_DATA", apdu->a_sw),
		    pk->pt_rdrname, "Certificate slot %02x", slotid);

	} else {
		err = swerrf("INS_GET_DATA", apdu->a_sw);
		bunyan_log(DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

static inline int
read_all_aborts_on(errf_t *err)
{
	return (err &&
	    !errf_caused_by(err, "NotFoundError") &&
	    !errf_caused_by(err, "PermissionError") &&
	    !errf_caused_by(err, "NotSupportedError"));
}

errf_t *
piv_read_all_certs(struct piv_token *tk)
{
	errf_t *err;
	uint i;

	VERIFY(tk->pt_intxn == B_TRUE);

	err = piv_read_cert(tk, PIV_SLOT_9E);
	if (read_all_aborts_on(err))
		return (err);
	err = piv_read_cert(tk, PIV_SLOT_9A);
	if (read_all_aborts_on(err))
		return (err);
	err = piv_read_cert(tk, PIV_SLOT_9C);
	if (read_all_aborts_on(err))
		return (err);
	err = piv_read_cert(tk, PIV_SLOT_9D);
	if (read_all_aborts_on(err))
		return (err);

	for (i = 0; i < tk->pt_hist_oncard; ++i) {
		err = piv_read_cert(tk, PIV_SLOT_RETIRED_1 + i);
		if (read_all_aborts_on(err) && !errf_caused_by(err, "APDUError"))
			return (err);
	}

	return (ERRF_OK);
}

errf_t *
piv_change_pin(struct piv_token *pk, enum piv_pin type, const char *pin,
    const char *newpin)
{
	errf_t *err;
	struct apdu *apdu;
	uint8_t pinbuf[16];
	size_t i;

	VERIFY(pk->pt_intxn == B_TRUE);
	VERIFY(pin != NULL);
	VERIFY(newpin != NULL);
	if (strlen(pin) < 1 || strlen(pin) > 8) {
		return (argerrf("pin", "a string 1-8 chars in length",
		    "%d chars long", strlen(pin)));
	}
	if (strlen(newpin) < 1 || strlen(newpin) > 8) {
		return (argerrf("newpin", "a string 1-8 chars in length",
		    "%d chars long", strlen(newpin)));
	}

	memset(pinbuf, 0xFF, sizeof (pinbuf));
	for (i = 0; i < 8 && pin[i] != 0; ++i)
		pinbuf[i] = pin[i];
	VERIFY(pin[i] == 0);
	for (i = 8; i < 16 && newpin[i - 8] != 0; ++i)
		pinbuf[i] = newpin[i - 8];
	VERIFY(newpin[i - 8] == 0);

	apdu = piv_apdu_make(CLA_ISO, INS_CHANGE_PIN, 0x00, type);
	apdu->a_cmd.b_data = pinbuf;
	apdu->a_cmd.b_len = 16;

	err = piv_apdu_transceive(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(WARN, "piv_change_pin.transceive failed",
		    "error", BNY_ERF, err, NULL);
		piv_apdu_free(apdu);
		return (err);
	}

	explicit_bzero(pinbuf, sizeof (pinbuf));

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
		pk->pt_reset = B_TRUE;

	} else if ((apdu->a_sw & 0xFFF0) == SW_INCORRECT_PIN) {
		err = errf("PermissionError", swerrf("INS_CHANGE_PIN(%x)",
		    apdu->a_sw, type), "Incorrect PIN supplied");

	} else {
		err = swerrf("INS_CHANGE_PIN(%x)", apdu->a_sw, type);
		bunyan_log(DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

errf_t *
piv_reset_pin(struct piv_token *pk, enum piv_pin type, const char *puk,
    const char *newpin)
{
	errf_t *err;
	struct apdu *apdu;
	uint8_t pinbuf[16];
	size_t i;

	VERIFY(pk->pt_intxn);

	VERIFY(puk != NULL);
	VERIFY(newpin != NULL);
	if (strlen(puk) < 1 || strlen(puk) > 8) {
		return (argerrf("puk", "a string 1-8 chars in length",
		    "%d chars long", strlen(puk)));
	}
	if (strlen(newpin) < 1 || strlen(newpin) > 8) {
		return (argerrf("newpin", "a string 1-8 chars in length",
		    "%d chars long", strlen(newpin)));
	}

	memset(pinbuf, 0xFF, sizeof (pinbuf));
	for (i = 0; i < 8 && puk[i] != 0; ++i)
		pinbuf[i] = puk[i];
	VERIFY(puk[i] == 0);
	for (i = 8; i < 16 && newpin[i - 8] != 0; ++i)
		pinbuf[i] = newpin[i - 8];
	VERIFY(newpin[i - 8] == 0);

	apdu = piv_apdu_make(CLA_ISO, INS_RESET_PIN, 0x00, type);
	apdu->a_cmd.b_data = pinbuf;
	apdu->a_cmd.b_len = 16;

	err = piv_apdu_transceive(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(WARN, "piv_change_pin.transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		piv_apdu_free(apdu);
		return (err);
	}

	explicit_bzero(pinbuf, sizeof (pinbuf));

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
		pk->pt_reset = B_TRUE;

	} else if ((apdu->a_sw & 0xFFF0) == SW_INCORRECT_PIN) {
		err = errf("PermissionError", swerrf("INS_RESET_PIN(%x)",
		    apdu->a_sw, type), "Incorrect PUK supplied");

	} else {
		err = swerrf("INS_RESET_PIN(%x)", apdu->a_sw, type);
		bunyan_log(DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

errf_t *
ykpiv_set_pin_retries(struct piv_token *pk, uint pintries, uint puktries)
{
	errf_t *err;
	struct apdu *apdu;

	VERIFY(pk->pt_intxn);
	if (!pk->pt_ykpiv)
		return (argerrf("tk", "a YubicoPIV-compatible token", "not"));

	apdu = piv_apdu_make(CLA_ISO, INS_SET_PIN_RETRIES, pintries, puktries);

	err = piv_apdu_transceive(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(WARN,
		    "ykpiv_set_pin_retries.transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		piv_apdu_free(apdu);
		return (err);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
		pk->pt_reset = B_TRUE;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_SET_PIN_RETRIES", apdu->a_sw),
		    pk->pt_rdrname, "setting PIN retries");

	} else if (apdu->a_sw == SW_INS_NOT_SUP) {
		err = notsuperrf(swerrf("INS_SET_PIN_RETRIES", apdu->a_sw),
		    pk->pt_rdrname, "YubicoPIV extensions");

	} else {
		err = swerrf("INS_SET_PIN_RETRIES", apdu->a_sw);
		bunyan_log(DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

errf_t *
ykpiv_set_admin(struct piv_token *pk, const uint8_t *key, size_t keylen,
    enum ykpiv_touch_policy touchpolicy)
{
	errf_t *err;
	struct apdu *apdu;
	uint8_t *databuf;
	uint p2;

	VERIFY(pk->pt_intxn);
	if (!pk->pt_ykpiv) {
		return (argerrf("tk", "a YubicoPIV-compatible PIV token",
		    "not"));
	}

	if (touchpolicy == YKPIV_TOUCH_DEFAULT ||
	    touchpolicy == YKPIV_TOUCH_NEVER) {
		p2 = 0xFF;
	} else if (touchpolicy == YKPIV_TOUCH_ALWAYS) {
		p2 = 0xFE;
	} else {
		return (argerrf("touchpolicy", "an enum value", "%d",
		    touchpolicy));
	}

	databuf = calloc(1, 3 + keylen);
	VERIFY(databuf != NULL);
	databuf[0] = 0x03;
	databuf[1] = 0x9B;
	databuf[2] = keylen;
	bcopy(key, &databuf[3], keylen);

	apdu = piv_apdu_make(CLA_ISO, INS_SET_MGMT, 0xFF, p2);
	apdu->a_cmd.b_data = databuf;
	apdu->a_cmd.b_len = 3 + keylen;

	err = piv_apdu_transceive(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(WARN,
		    "ykpiv_set_admin.transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		piv_apdu_free(apdu);
		return (err);
	}

	explicit_bzero(databuf, 3 + keylen);
	free(databuf);

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
		pk->pt_reset = B_TRUE;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("YK_INS_SET_MGMT", apdu->a_sw),
		    pk->pt_rdrname, "changing 9B admin key");

	} else if (apdu->a_sw == SW_INS_NOT_SUP) {
		err = notsuperrf(swerrf("YK_INS_SET_MGMT", apdu->a_sw),
		    pk->pt_rdrname, "YubicoPIV extensions");

	} else {
		err = swerrf("INS_SET_MGMT", apdu->a_sw);
		bunyan_log(DEBUG, "card did not accept INS_SET_MGMT",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

errf_t *
piv_verify_pin(struct piv_token *pk, enum piv_pin type, const char *pin,
    uint *retries, boolean_t canskip)
{
	errf_t *err;
	struct apdu *apdu;
	uint8_t pinbuf[8];
	size_t i;

	VERIFY(pk->pt_intxn == B_TRUE);

	/*
	 * This gets a little confusing because there are several valid forms
	 * of this function:
	 *   1. piv_verify_pin(tk, type, NULL, NULL, ?);
	 *     => check if we are already authed and return ERRF_OK if so
	 *   2. piv_verify_pin(tk, type, NULL, &retries, ?);
	 *     => check how many retries are left without trying the PIN
	 *   3. piv_verify_pin(tk, type, pin, NULL, ?);
	 *     => try a PIN without any min retry cap
	 *   4. piv_verify_pin(tk, type, pin, &retries, ?);  (retries == 0)
	 *     => try a PIN without any min retry cap, if fail set *retries
	 *   5. piv_verify_pin(tk, type, pin, &retries, ?);  (retries > 0)
	 *     => try a PIN with a min retry cap and if we fail set *retries
	 *
	 * It's worth noting that the canskip argument is separate at least in
	 * part due to "PIN always" slots, which can't use the cached auth
	 * status and need a separate VERIFY command every time they're used.
	 */

	/*
	 * Decide if we want to do an initial empty VERIFY command to check
	 * the current auth status.
	 *
	 * We want to always do this for cases 1, 2 and 5 above, and on cases
	 * 3 and 4 we want to do it only if canskip is set.
	 */
	if (pin == NULL || canskip || (retries != NULL && *retries > 0)) {
		apdu = piv_apdu_make(CLA_ISO, INS_VERIFY, 0x00, type);

		err = piv_apdu_transceive(pk, apdu);
		if (err) {
			err = ioerrf(err, pk->pt_rdrname);
			bunyan_log(WARN, "piv_verify_pin.transceive failed",
			    "error", BNY_ERF, err, NULL);
			piv_apdu_free(apdu);
			return (err);
		}

		if ((apdu->a_sw & 0xFFF0) == SW_INCORRECT_PIN) {
			/* We're not authed. */

			if (pin != NULL && retries != NULL && *retries > 0 &&
			    (apdu->a_sw & 0x000F) <= *retries) {
				/* Case 5 */
				err = errf("MinRetriesError", NULL,
				    "Insufficient PIN retries remaining "
				    "(minimum %d, remaining %d)", *retries,
				    (apdu->a_sw & 0x000F));
				*retries = (apdu->a_sw & 0x000F);

			} else if (pin == NULL) {
				/* Cases 1, 2 */
				if (retries != NULL)
					*retries = (apdu->a_sw & 0x000F);
				piv_apdu_free(apdu);
				return (ERRF_OK);

			} else {
				/* Cases 3, 4 with canskip set */
				err = ERRF_OK;
			}
		} else if (apdu->a_sw == SW_WRONG_LENGTH ||
		    apdu->a_sw == SW_WRONG_DATA) {
			/*
			 * Probably this applet doesn't implement the empty
			 * VERIFY command properly (it's easy to miss it in
			 * the spec, and lots of them have had bugs here).
			 */
			if (pin == NULL) {
				/* Cases 1, 2 */
				piv_apdu_free(apdu);
				return (notsuperrf(swerrf("INS_VERIFY(%x)",
				    apdu->a_sw, type), pk->pt_rdrname,
				    "Reading PIN retry counter"));
			} else {
				/*
				 * In cases 3, 4 the canskip is best-effort
				 * anyway, so let's just continue.
				 *
				 * For case 5, maybe this is more questionable
				 * but we err on the side of continuing when
				 * faced with a card without empty VERIFY
				 * support.
				 */
				err = ERRF_OK;
			}
		} else if (apdu->a_sw == SW_NO_ERROR) {
			/* We are already authed! */
			if (pin == NULL) {
				/* Cases 1 and 2 just return here. */
				piv_apdu_free(apdu);
				return (ERRF_OK);

			} else if (canskip) {
				/* Cases 3 and 4 with canskip just ret too */
				piv_apdu_free(apdu);
				return (ERRF_OK);
			} else {

				/*
				 * Case 5, continue to try the PIN, we've
				 * met the retries constraint.
				 */
				err = ERRF_OK;
			}
		} else {
			err = swerrf("INS_VERIFY(%x)", apdu->a_sw, type);
			bunyan_log(DEBUG, "card did not accept INS_VERIFY"
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "error", BNY_ERF, err, NULL);
		}
		piv_apdu_free(apdu);
		if (err != ERRF_OK)
			return (err);
	}

	/* Cases 3-5 only past here. */
	VERIFY(pin != NULL);
#ifdef LINT
	if (pin == NULL)
		return (err);
#endif

	if (strlen(pin) < 1 || strlen(pin) > 8) {
		return (argerrf("pin", "a string 1-8 chars in length",
		    "%d chars long", strlen(pin)));
	}

	memset(pinbuf, 0xFF, sizeof (pinbuf));
	for (i = 0; i < 8 && pin[i] != 0; ++i)
		pinbuf[i] = pin[i];
	VERIFY(pin[i] == 0);

	apdu = piv_apdu_make(CLA_ISO, INS_VERIFY, 0x00, type);
	apdu->a_cmd.b_data = pinbuf;
	apdu->a_cmd.b_len = 8;

	err = piv_apdu_transceive(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(WARN, "piv_verify_pin.transceive failed",
		    "error", BNY_ERF, err, NULL);
		piv_apdu_free(apdu);
		return (err);
	}

	explicit_bzero(pinbuf, sizeof (pinbuf));

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
		pk->pt_reset = B_TRUE;

	} else if ((apdu->a_sw & 0xFFF0) == SW_INCORRECT_PIN) {
		if (retries != NULL)
			*retries = (apdu->a_sw & 0x000F);
		err = errf("PermissionError", swerrf("INS_VERIFY(%x)",
		    apdu->a_sw, type), "Incorrect PIN supplied");

	} else {
		err = swerrf("INS_VERIFY(%x)", apdu->a_sw, type);
		bunyan_log(DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

errf_t *
piv_sign(struct piv_token *tk, struct piv_slot *slot, const uint8_t *data,
    size_t datalen, enum sshdigest_types *hashalgo, uint8_t **signature,
    size_t *siglen)
{
	int i;
	errf_t *err;
	struct ssh_digest_ctx *hctx;
	uint8_t *buf;
	size_t nread, dglen, inplen;
	boolean_t cardhash = B_FALSE, ch_sha256 = B_FALSE;
	enum piv_alg oldalg;

	VERIFY(tk->pt_intxn);

	switch (slot->ps_alg) {
	case PIV_ALG_RSA1024:
		inplen = 128;
		if (*hashalgo == SSH_DIGEST_SHA1) {
			dglen = 20;
		} else {
			*hashalgo = SSH_DIGEST_SHA256;
			dglen = 32;
		}
		break;
	case PIV_ALG_RSA2048:
		inplen = 256;
		if (*hashalgo == SSH_DIGEST_SHA1) {
			dglen = 20;
		} else if (*hashalgo == SSH_DIGEST_SHA512) {
			dglen = 64;
		} else {
			*hashalgo = SSH_DIGEST_SHA256;
			dglen = 32;
		}
		break;
	case PIV_ALG_ECCP256:
		inplen = 32;
		for (i = 0; i < tk->pt_alg_count; ++i) {
			if (tk->pt_algs[i] == PIV_ALG_ECCP256_SHA256) {
				cardhash = B_TRUE;
				ch_sha256 = B_TRUE;
			} else if (tk->pt_algs[i] == PIV_ALG_ECCP256_SHA1) {
				cardhash = B_TRUE;
			}
		}
		if (*hashalgo == SSH_DIGEST_SHA1) {
			dglen = 20;
			if (cardhash) {
				oldalg = slot->ps_alg;
				slot->ps_alg = PIV_ALG_ECCP256_SHA1;
			}
		} else {
			*hashalgo = SSH_DIGEST_SHA256;
			dglen = 32;
			if (cardhash && ch_sha256) {
				oldalg = slot->ps_alg;
				slot->ps_alg = PIV_ALG_ECCP256_SHA256;
			} else if (cardhash) {
				*hashalgo = SSH_DIGEST_SHA1;
				dglen = 20;
				slot->ps_alg = PIV_ALG_ECCP256_SHA1;
			}
		}
		break;
	case PIV_ALG_ECCP384:
		inplen = 48;
		if (*hashalgo == SSH_DIGEST_SHA1) {
			dglen = 20;
		} else if (*hashalgo == SSH_DIGEST_SHA256) {
			dglen = 32;
		} else {
			*hashalgo = SSH_DIGEST_SHA384;
			dglen = 48;
		}
		break;
	default:
		return (errf("NotSupportedError", NULL, "Unsupported key "
		    "algorithm used in slot %x (%d) of PIV device '%s'",
		    slot->ps_slot, slot->ps_alg, tk->pt_rdrname));
	}

	if (!cardhash) {
		buf = calloc(1, inplen);
		VERIFY(buf != NULL);

		hctx = ssh_digest_start(*hashalgo);
		VERIFY(hctx != NULL);
		VERIFY0(ssh_digest_update(hctx, data, datalen));
		VERIFY0(ssh_digest_final(hctx, buf, dglen));
		ssh_digest_free(hctx);
	} else {
		bunyan_log(TRACE, "doing hash on card", NULL);
		buf = (uint8_t *)data;
		inplen = datalen;
	}

	/*
	 * If it's an RSA signature, we have to generate the PKCS#1 style
	 * padded signing blob around the hash.
	 *
	 * ECDSA is so much nicer than this. Why can't we just use it? Oh,
	 * because Java ruined everything. Right.
	 */
	if (slot->ps_alg == PIV_ALG_RSA1024 ||
	    slot->ps_alg == PIV_ALG_RSA2048) {
		int nid;
		/*
		 * Roll up your sleeves, folks, we're going in (to the dank
		 * and musty corners of OpenSSL where few dare tread)
		 */
		X509_SIG digestInfo;
		X509_ALGOR algor;
		ASN1_TYPE parameter;
		ASN1_OCTET_STRING digest;
		uint8_t *tmp, *out;

		tmp = calloc(1, inplen);
		VERIFY(tmp != NULL);
		out = NULL;

		/*
		 * XXX: I thought this should be sha256WithRSAEncryption (etc)
		 *      rather than just NID_sha256 but that doesn't work
		 */
		switch (*hashalgo) {
		case SSH_DIGEST_SHA1:
			nid = NID_sha1;
			break;
		case SSH_DIGEST_SHA256:
			nid = NID_sha256;
			break;
		case SSH_DIGEST_SHA512:
			nid = NID_sha512;
			break;
		default:
			VERIFY(0);
			nid = -1;
		}
		bcopy(buf, tmp, dglen);
		digestInfo.algor = &algor;
		digestInfo.algor->algorithm = OBJ_nid2obj(nid);
		digestInfo.algor->parameter = &parameter;
		digestInfo.algor->parameter->type = V_ASN1_NULL;
		digestInfo.algor->parameter->value.ptr = NULL;
		digestInfo.digest = &digest;
		digestInfo.digest->data = tmp;
		digestInfo.digest->length = (int)dglen;
		nread = i2d_X509_SIG(&digestInfo, &out);

		/*
		 * There is another undocumented openssl function that does
		 * this padding bit, but eh.
		 */
		memset(buf, 0xFF, inplen);
		buf[0] = 0x00;
		/* The second byte is the block type -- 0x01 here means 0xFF */
		buf[1] = 0x01;
		buf[inplen - nread - 1] = 0x00;
		bcopy(out, buf + (inplen - nread), nread);

		free(tmp);
		OPENSSL_free(out);
	}

	err = piv_sign_prehash(tk, slot, buf, inplen, signature, siglen);

	if (!cardhash)
		free(buf);

	if (cardhash)
		slot->ps_alg = oldalg;

	return (err);
}

errf_t *
piv_sign_prehash(struct piv_token *pk, struct piv_slot *pc,
    const uint8_t *hash, size_t hashlen, uint8_t **signature, size_t *siglen)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	uint8_t *buf;

	VERIFY(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_pushl(tlv, 0x7C, hashlen + 16);
	/* Push an empty RESPONSE tag to say that's what we're asking for. */
	tlv_push(tlv, GA_TAG_RESPONSE);
	tlv_pop(tlv);
	/* And now push the data we're providing (the CHALLENGE). */
	tlv_pushl(tlv, GA_TAG_CHALLENGE, hashlen);
	tlv_write(tlv, hash, 0, hashlen);
	tlv_pop(tlv);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_AUTH, pc->ps_alg, pc->ps_slot);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(WARN, "piv_sign_prehash.transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x7C) {
			err = invderrf(tagerrf("INS_GEN_AUTH(%x)", tag,
			    pc->ps_slot), pk->pt_rdrname);
			debug_dump(err, apdu);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (err);
		}
		tag = tlv_read_tag(tlv);
		if (tag != GA_TAG_RESPONSE) {
			err = invderrf(tagerrf("INS_GEN_AUTH(%x)", tag,
			    pc->ps_slot), pk->pt_rdrname);
			tlv_skip(tlv);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (err);
		}

		*siglen = tlv_rem(tlv);
		buf = calloc(1, *siglen);
		VERIFY(buf != NULL);
		*siglen = tlv_read(tlv, buf, 0, *siglen);
		*signature = buf;

		tlv_end(tlv);
		tlv_end(tlv);
		tlv_free(tlv);

		err = ERRF_OK;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GEN_AUTH(%x)", apdu->a_sw,
		    pc->ps_slot), pk->pt_rdrname,
		    "signing data with key in slot %02x", pc->ps_slot);

	} else if (apdu->a_sw == SW_WRONG_DATA ||
	    apdu->a_sw == SW_INCORRECT_P1P2) {
		err = errf("NotSupportedError", swerrf("INS_GEN_AUTH(%x)",
		    apdu->a_sw, pc->ps_slot), "Signature generation not "
		    "supported by key (or no key present) in slot %02x "
		    "of PIV device '%s'", pc->ps_slot, pk->pt_rdrname);

	} else {
		err = swerrf("INS_GEN_AUTH(%x)", apdu->a_sw, pc->ps_slot);
		bunyan_log(DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

errf_t *
piv_ecdh(struct piv_token *pk, struct piv_slot *slot, struct sshkey *pubkey,
    uint8_t **secret, size_t *seclen)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	uint8_t *buf;
	struct sshbuf *sbuf;
	size_t len;

	VERIFY(pk->pt_intxn);

	sbuf = sshbuf_new();
	VERIFY(sbuf != NULL);
	VERIFY3S(pubkey->type, ==, KEY_ECDSA);
	VERIFY0(sshbuf_put_eckey(sbuf, pubkey->ecdsa));
	/* The buffer has the 32-bit length prefixed */
	len = sshbuf_len(sbuf) - 4;
	buf = (uint8_t *)sshbuf_ptr(sbuf) + 4;
	VERIFY3U(*buf, ==, 0x04);

	tlv = tlv_init_write();
	tlv_pushl(tlv, 0x7C, len + 16);
	tlv_push(tlv, GA_TAG_RESPONSE);
	tlv_pop(tlv);
	tlv_pushl(tlv, GA_TAG_EXP, len);
	tlv_write(tlv, buf, 0, len);
	sshbuf_free(sbuf);
	tlv_pop(tlv);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_AUTH, slot->ps_alg,
	    slot->ps_slot);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(WARN, "piv_ecdh.transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x7C) {
			err = invderrf(tagerrf("INS_GEN_AUTH(%x)", tag,
			    slot->ps_slot), pk->pt_rdrname);
			debug_dump(err, apdu);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (err);
		}
		tag = tlv_read_tag(tlv);
		if (tag != GA_TAG_RESPONSE) {
			err = invderrf(tagerrf("INS_GEN_AUTH(%x)", tag,
			    slot->ps_slot), pk->pt_rdrname);
			debug_dump(err, apdu);
			tlv_skip(tlv);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (err);
		}

		*seclen = tlv_rem(tlv);
		buf = calloc(1, *seclen);
		VERIFY(buf != NULL);
		*seclen = tlv_read(tlv, buf, 0, *seclen);
		*secret = buf;

		tlv_end(tlv);
		tlv_end(tlv);
		tlv_free(tlv);

		err = ERRF_OK;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GEN_AUTH(%x)", apdu->a_sw,
		    slot->ps_slot), pk->pt_rdrname, "performing ECDH for "
		    "slot %x", slot->ps_slot);

	} else {
		err = swerrf("INS_GEN_AUTH(%x)", apdu->a_sw, slot->ps_slot);
		bunyan_log(DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

#define	BOX_DEFAULT_CIPHER	"chacha20-poly1305"
#define	BOX_DEFAULT_KDF		"sha512"

struct piv_ecdh_box *
piv_box_new(void)
{
	struct piv_ecdh_box *box;
	box = calloc(1, sizeof (struct piv_ecdh_box));
	return (box);
}

struct piv_ecdh_box *
piv_box_clone(const struct piv_ecdh_box *box)
{
	struct piv_ecdh_box *nbox;
	nbox = calloc(1, sizeof (struct piv_ecdh_box));
	if (nbox == NULL)
		goto err;
	nbox->pdb_guidslot_valid = box->pdb_guidslot_valid;
	if (box->pdb_guidslot_valid) {
		nbox->pdb_guidslot_valid = B_TRUE;
		nbox->pdb_slot = box->pdb_slot;
		bcopy(box->pdb_guid, nbox->pdb_guid, sizeof (nbox->pdb_guid));
	}
	if (sshkey_demote(box->pdb_ephem_pub, &nbox->pdb_ephem_pub))
		goto err;
	if (sshkey_demote(box->pdb_pub, &nbox->pdb_pub))
		goto err;
	if (box->pdb_free_str) {
		nbox->pdb_free_str = B_TRUE;
		nbox->pdb_cipher = strdup(box->pdb_cipher);
		nbox->pdb_kdf = strdup(box->pdb_kdf);
	} else {
		nbox->pdb_cipher = box->pdb_cipher;
		nbox->pdb_kdf = box->pdb_kdf;
	}
	if (box->pdb_iv.b_len > 0) {
		nbox->pdb_iv.b_data = malloc(box->pdb_iv.b_len);
		if (nbox->pdb_iv.b_data == NULL)
			goto err;
		nbox->pdb_iv.b_len = (nbox->pdb_iv.b_size = box->pdb_iv.b_len);
		bcopy(box->pdb_iv.b_data + box->pdb_iv.b_offset,
		    nbox->pdb_iv.b_data, box->pdb_iv.b_len);
	}
	if (box->pdb_enc.b_len > 0) {
		nbox->pdb_enc.b_data = malloc(box->pdb_enc.b_len);
		if (nbox->pdb_enc.b_data == NULL)
			goto err;
		nbox->pdb_enc.b_len =
		    (nbox->pdb_enc.b_size = box->pdb_enc.b_len);
		bcopy(box->pdb_enc.b_data + box->pdb_enc.b_offset,
		    nbox->pdb_enc.b_data, box->pdb_enc.b_len);
	}
	if (box->pdb_plain.b_len > 0) {
		nbox->pdb_plain.b_data = malloc(box->pdb_plain.b_len);
		if (nbox->pdb_plain.b_data == NULL)
			goto err;
		nbox->pdb_plain.b_len =
		    (nbox->pdb_plain.b_size = box->pdb_plain.b_len);
		bcopy(box->pdb_plain.b_data + box->pdb_plain.b_offset,
		    nbox->pdb_plain.b_data, box->pdb_plain.b_len);
	}

	return (nbox);
err:
	piv_box_free(nbox);
	return (NULL);
}

void
piv_box_free(struct piv_ecdh_box *box)
{
	if (box == NULL)
		return;
	sshkey_free(box->pdb_ephem_pub);
	sshkey_free(box->pdb_pub);
	if (box->pdb_free_str) {
		free((void *)box->pdb_cipher);
		free((void *)box->pdb_kdf);
	}
	free(box->pdb_iv.b_data);
	free(box->pdb_enc.b_data);
	if (box->pdb_plain.b_data != NULL) {
		explicit_bzero(box->pdb_plain.b_data, box->pdb_plain.b_size);
		free(box->pdb_plain.b_data);
	}
	free(box);
}

errf_t *
piv_box_set_data(struct piv_ecdh_box *box, const uint8_t *data, size_t len)
{
	uint8_t *buf;
	VERIFY3P(box->pdb_plain.b_data, ==, NULL);

	buf = calloc(1, len);
	if (buf == NULL)
		return (ERRF_NOMEM);
	box->pdb_plain.b_data = buf;
	box->pdb_plain.b_size = len;
	box->pdb_plain.b_len = len;
	box->pdb_plain.b_offset = 0;

	bcopy(data, buf, len);

	return (ERRF_OK);
}

errf_t *
piv_box_set_datab(struct piv_ecdh_box *box, struct sshbuf *buf)
{
	uint8_t *data;
	size_t len;
	VERIFY3P(box->pdb_plain.b_data, ==, NULL);

	len = sshbuf_len(buf);
	data = malloc(len);
	if (data == NULL)
		return (ERRF_NOMEM);
	VERIFY0(sshbuf_get(buf, data, len));
	box->pdb_plain.b_data = data;
	box->pdb_plain.b_size = len;
	box->pdb_plain.b_len = len;
	box->pdb_plain.b_offset = 0;

	return (ERRF_OK);
}

errf_t *
piv_box_take_data(struct piv_ecdh_box *box, uint8_t **data, size_t *len)
{
	if (box->pdb_plain.b_data == NULL) {
		return (errf("BoxSealed", NULL, "Box is sealed; data cannot "
		    "be taken (use piv_box_open first)"));
	}

	*data = calloc(1, box->pdb_plain.b_len);
	VERIFY(*data != NULL);
	*len = box->pdb_plain.b_len;
	bcopy(box->pdb_plain.b_data + box->pdb_plain.b_offset, *data, *len);

	explicit_bzero(box->pdb_plain.b_data, box->pdb_plain.b_size);
	free(box->pdb_plain.b_data);
	box->pdb_plain.b_data = NULL;
	box->pdb_plain.b_size = 0;
	box->pdb_plain.b_len = 0;
	box->pdb_plain.b_offset = 0;

	return (ERRF_OK);
}

errf_t *
piv_box_take_datab(struct piv_ecdh_box *box, struct sshbuf **pbuf)
{
	struct sshbuf *buf;

	if (box->pdb_plain.b_data == NULL) {
		return (errf("BoxSealed", NULL, "Box is sealed; data cannot "
		    "be taken (use piv_box_open first)"));
	}

	buf = sshbuf_new();
	sshbuf_put(buf, box->pdb_plain.b_data + box->pdb_plain.b_offset,
	    box->pdb_plain.b_len);

	explicit_bzero(box->pdb_plain.b_data, box->pdb_plain.b_size);
	free(box->pdb_plain.b_data);
	box->pdb_plain.b_data = NULL;
	box->pdb_plain.b_size = 0;
	box->pdb_plain.b_len = 0;
	box->pdb_plain.b_offset = 0;

	*pbuf = buf;

	return (ERRF_OK);
}

errf_t *
piv_box_open_offline(struct sshkey *privkey, struct piv_ecdh_box *box)
{
	const struct sshcipher *cipher;
	int dgalg;
	struct sshcipher_ctx *cctx;
	struct ssh_digest_ctx *dgctx;
	uint8_t *iv, *key, *sec, *enc, *plain;
	size_t ivlen, authlen, blocksz, keylen, dglen, seclen;
	size_t fieldsz, plainlen, enclen;
	size_t reallen, padding, i;
	errf_t *err;
	int rv;

	VERIFY3P(box->pdb_cipher, !=, NULL);
	VERIFY3P(box->pdb_kdf, !=, NULL);

	cipher = cipher_by_name(box->pdb_cipher);
	if (cipher == NULL) {
		err = boxverrf(errf("BadAlgorithmError", NULL,
		    "Cipher '%s' is not supported", box->pdb_cipher));
		return (err);
	}
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);

	dgalg = ssh_digest_alg_by_name(box->pdb_kdf);
	if (dgalg == -1) {
		err = boxverrf(errf("BadAlgorithmError", NULL,
		    "KDF digest '%s' is not supported", box->pdb_kdf));
		return (err);
	}
	dglen = ssh_digest_bytes(dgalg);
	if (dglen < keylen) {
		err = boxderrf(errf("BadAlgorithmError", NULL,
		    "KDF digest '%s' produces output too short for use as "
		    "key with cipher '%s'", box->pdb_kdf, box->pdb_cipher));
		return (err);
	}

	fieldsz = EC_GROUP_get_degree(EC_KEY_get0_group(privkey->ecdsa));
	seclen = (fieldsz + 7) / 8;
	sec = calloc(1, seclen);
	VERIFY(sec != NULL);
	seclen = ECDH_compute_key(sec, seclen,
	    EC_KEY_get0_public_key(box->pdb_ephem_pub->ecdsa), privkey->ecdsa,
	    NULL);
	if (seclen <= 0) {
		free(sec);
		make_sslerrf(err, "ECDH_compute_key", "performing ECDH");
		err = boxderrf(err);
		return (err);
	}

	dgctx = ssh_digest_start(dgalg);
	VERIFY3P(dgctx, !=, NULL);
	VERIFY0(ssh_digest_update(dgctx, sec, seclen));
	key = calloc(1, dglen);
	VERIFY3P(key, !=, NULL);
	VERIFY0(ssh_digest_final(dgctx, key, dglen));
	ssh_digest_free(dgctx);

	explicit_bzero(sec, seclen);
	free(sec);

	VERIFYB(box->pdb_iv);
	iv = box->pdb_iv.b_data + box->pdb_iv.b_offset;
	if (box->pdb_iv.b_len != ivlen) {
		err = boxderrf(errf("LengthError", NULL, "IV length (%d) is not "
		    "appropriate for cipher '%s'", ivlen, box->pdb_cipher));
		return (err);
	}

	VERIFYB(box->pdb_enc);
	enc = box->pdb_enc.b_data + box->pdb_enc.b_offset;
	enclen = box->pdb_enc.b_len;
	if (enclen < authlen + blocksz) {
		err = boxderrf(errf("LengthError", NULL, "Ciphertext length (%d) "
		    "is smaller than minimum length (auth tag + 1 block = %d)",
		    enclen, authlen + blocksz));
		return (err);
	}

	plainlen = enclen - authlen;
	plain = calloc(1, plainlen);
	VERIFY3P(plain, !=, NULL);

	VERIFY0(cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 0));
	rv = cipher_crypt(cctx, 0, plain, enc, enclen - authlen, 0,
	    authlen);
	cipher_free(cctx);

	explicit_bzero(key, dglen);
	free(key);

	if (rv != 0) {
		err = boxderrf(ssherrf("cipher_crypt", rv));
		return (err);
	}

	/* Strip off the pkcs#7 padding and verify it. */
	padding = plain[plainlen - 1];
	if (padding < 1 || padding > blocksz)
		goto paderr;
	reallen = plainlen - padding;
	for (i = reallen; i < plainlen; ++i) {
		if (plain[i] != padding) {
			goto paderr;
		}
	}

	if (box->pdb_plain.b_data != NULL) {
		explicit_bzero(box->pdb_plain.b_data, box->pdb_plain.b_size);
		free(box->pdb_plain.b_data);
	}
	box->pdb_plain.b_data = plain;
	box->pdb_plain.b_size = plainlen;
	box->pdb_plain.b_len = reallen;
	box->pdb_plain.b_offset = 0;

	return (ERRF_OK);

paderr:
	err = boxderrf(errf("PaddingError", NULL, "Padding failed validation"));
	explicit_bzero(plain, plainlen);
	free(plain);
	return (err);
}

errf_t *
piv_box_open(struct piv_token *tk, struct piv_slot *slot,
    struct piv_ecdh_box *box)
{
	const struct sshcipher *cipher;
	int rv;
	errf_t *err;
	int dgalg;
	struct sshcipher_ctx *cctx;
	struct ssh_digest_ctx *dgctx;
	uint8_t *iv, *key, *sec, *enc, *plain;
	size_t ivlen, authlen, blocksz, keylen, dglen, seclen;
	size_t plainlen, enclen;
	size_t reallen, padding, i;

	VERIFY3P(box->pdb_cipher, !=, NULL);
	VERIFY3P(box->pdb_kdf, !=, NULL);

	cipher = cipher_by_name(box->pdb_cipher);
	if (cipher == NULL) {
		err = boxverrf(errf("BadAlgorithmError", NULL,
		    "Cipher '%s' is not supported", box->pdb_cipher));
		return (err);
	}
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);

	dgalg = ssh_digest_alg_by_name(box->pdb_kdf);
	if (dgalg == -1) {
		err = boxverrf(errf("BadAlgorithmError", NULL,
		    "KDF digest '%s' is not supported", box->pdb_kdf));
		return (err);
	}
	dglen = ssh_digest_bytes(dgalg);
	if (dglen < keylen) {
		err = boxderrf(errf("BadAlgorithmError", NULL,
		    "KDF digest '%s' produces output too short for use as "
		    "key with cipher '%s'", box->pdb_kdf, box->pdb_cipher));
		return (err);
	}

	sec = NULL;
	VERIFY3P(box->pdb_ephem_pub, !=, NULL);
	err = piv_ecdh(tk, slot, box->pdb_ephem_pub, &sec, &seclen);
	if (err) {
		err = errf("BoxKeyError", err, "Failed to perform ECDH "
		    "operation needed to decrypt PIVBox");
		return (err);
	}
	VERIFY3P(sec, !=, NULL);
	VERIFY3U(seclen, >=, 0);

	dgctx = ssh_digest_start(dgalg);
	VERIFY3P(dgctx, !=, NULL);
	VERIFY0(ssh_digest_update(dgctx, sec, seclen));
	key = calloc(1, dglen);
	VERIFY3P(key, !=, NULL);
	VERIFY0(ssh_digest_final(dgctx, key, dglen));
	ssh_digest_free(dgctx);

	explicit_bzero(sec, seclen);
	free(sec);

	VERIFYB(box->pdb_iv);
	iv = box->pdb_iv.b_data + box->pdb_iv.b_offset;
	if (box->pdb_iv.b_len != ivlen) {
		err = boxderrf(errf("LengthError", NULL, "IV length (%d) is not "
		    "appropriate for cipher '%s'", ivlen, box->pdb_cipher));
		return (err);
	}

	VERIFYB(box->pdb_enc);
	enc = box->pdb_enc.b_data + box->pdb_enc.b_offset;
	enclen = box->pdb_enc.b_len;
	if (enclen < authlen + blocksz) {
		err = boxderrf(errf("LengthError", NULL, "Ciphertext length (%d) "
		    "is smaller than minimum length (auth tag + 1 block = %d)",
		    enclen, authlen + blocksz));
		return (err);
	}

	plainlen = enclen - authlen;
	plain = calloc(1, plainlen);
	VERIFY3P(plain, !=, NULL);

	VERIFY0(cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 0));
	rv = cipher_crypt(cctx, 0, plain, enc, enclen - authlen, 0,
	    authlen);
	cipher_free(cctx);

	explicit_bzero(key, dglen);
	free(key);

	if (rv != 0) {
		err = boxderrf(ssherrf("cipher_crypt", rv));
		return (err);
	}

	/* Strip off the pkcs#7 padding and verify it. */
	padding = plain[plainlen - 1];
	if (padding < 1 || padding > blocksz)
		goto paderr;
	reallen = plainlen - padding;
	for (i = reallen; i < plainlen; ++i) {
		if (plain[i] != padding) {
			goto paderr;
		}
	}

	if (box->pdb_plain.b_data != NULL) {
		explicit_bzero(box->pdb_plain.b_data, box->pdb_plain.b_size);
		free(box->pdb_plain.b_data);
	}
	box->pdb_plain.b_data = plain;
	box->pdb_plain.b_offset = 0;
	box->pdb_plain.b_size = plainlen;
	box->pdb_plain.b_len = reallen;

	return (ERRF_OK);

paderr:
	err = boxderrf(errf("PaddingError", NULL, "Padding failed validation"));
	explicit_bzero(plain, plainlen);
	free(plain);
	return (err);
}

errf_t *
piv_box_seal_offline(struct sshkey *pubk, struct piv_ecdh_box *box)
{
	const struct sshcipher *cipher;
	int rv;
	errf_t *err;
	int dgalg;
	struct sshkey *pkey;
	struct sshcipher_ctx *cctx;
	struct ssh_digest_ctx *dgctx;
	uint8_t *iv, *key, *sec, *enc, *plain;
	size_t ivlen, authlen, blocksz, keylen, dglen, seclen;
	size_t fieldsz, plainlen, enclen;
	size_t padding, i;

	if (pubk->type != KEY_ECDSA) {
		return (argerrf("pubkey", "an ECDSA public key",
		    "type %s", sshkey_type(pubk)));
	}

	rv = sshkey_generate(KEY_ECDSA, sshkey_size(pubk), &pkey);
	if (rv != 0) {
		err = boxaerrf(ssherrf("sshkey_generate", rv));
		return (err);
	}
	VERIFY0(sshkey_demote(pkey, &box->pdb_ephem_pub));

	if (box->pdb_cipher == NULL)
		box->pdb_cipher = BOX_DEFAULT_CIPHER;
	if (box->pdb_kdf == NULL)
		box->pdb_kdf = BOX_DEFAULT_KDF;

	cipher = cipher_by_name(box->pdb_cipher);
	if (cipher == NULL) {
		err = boxaerrf(errf("BadAlgorithmError", NULL,
		    "Cipher '%s' is not supported", box->pdb_cipher));
		return (err);
	}
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);

	dgalg = ssh_digest_alg_by_name(box->pdb_kdf);
	if (dgalg == -1) {
		err = boxaerrf(errf("BadAlgorithmError", NULL,
		    "KDF digest '%s' is not supported", box->pdb_kdf));
		return (err);
	}
	dglen = ssh_digest_bytes(dgalg);
	if (dglen < keylen) {
		err = boxaerrf(errf("BadAlgorithmError", NULL,
		    "KDF digest '%s' produces output too short for use as "
		    "key with cipher '%s'", box->pdb_kdf, box->pdb_cipher));
		return (err);
	}

	fieldsz = EC_GROUP_get_degree(EC_KEY_get0_group(pkey->ecdsa));
	seclen = (fieldsz + 7) / 8;
	sec = calloc(1, seclen);
	VERIFY(sec != NULL);
	seclen = ECDH_compute_key(sec, seclen,
	    EC_KEY_get0_public_key(pubk->ecdsa), pkey->ecdsa, NULL);
	if (seclen <= 0) {
		free(sec);
		make_sslerrf(err, "ECDH_compute_key", "performing ECDH");
		err = boxaerrf(err);
		return (err);
	}

	sshkey_free(pkey);

	dgctx = ssh_digest_start(dgalg);
	VERIFY3P(dgctx, !=, NULL);
	VERIFY0(ssh_digest_update(dgctx, sec, seclen));
	key = calloc(1, dglen);
	VERIFY3P(key, !=, NULL);
	VERIFY0(ssh_digest_final(dgctx, key, dglen));
	ssh_digest_free(dgctx);

	explicit_bzero(sec, seclen);
	free(sec);

	iv = calloc(1, ivlen);
	VERIFY3P(iv, !=, NULL);
	arc4random_buf(iv, ivlen);

	free(box->pdb_iv.b_data);
	box->pdb_iv.b_size = ivlen;
	box->pdb_iv.b_len = ivlen;
	box->pdb_iv.b_data = iv;
	box->pdb_iv.b_offset = 0;

	plainlen = box->pdb_plain.b_len;
	VERIFY3U(plainlen, >, 0);

	/*
	 * We add PKCS#7 style padding, consisting of up to a block of bytes,
	 * all set to the number of padding bytes added. This is easy to strip
	 * off after decryption and avoids the need to include and validate the
	 * real length of the payload separately.
	 */
	padding = blocksz - (plainlen % blocksz);
	VERIFY3U(padding, <=, blocksz);
	VERIFY3U(padding, >, 0);
	plainlen += padding;
	plain = calloc(1, plainlen);
	VERIFY3P(plain, !=, NULL);
	bcopy(box->pdb_plain.b_data + box->pdb_plain.b_offset, plain,
	    box->pdb_plain.b_len);
	for (i = box->pdb_plain.b_len; i < plainlen; ++i)
		plain[i] = padding;

	explicit_bzero(box->pdb_plain.b_data, box->pdb_plain.b_size);
	free(box->pdb_plain.b_data);
	box->pdb_plain.b_data = NULL;
	box->pdb_plain.b_size = 0;
	box->pdb_plain.b_len = 0;

	VERIFY0(cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 1));
	enclen = plainlen + authlen;
	enc = calloc(1, enclen);
	VERIFY3P(enc, !=, NULL);
	VERIFY0(cipher_crypt(cctx, 0, enc, plain, plainlen, 0, authlen));
	cipher_free(cctx);

	explicit_bzero(plain, plainlen);
	explicit_bzero(key, dglen);
	free(key);
	free(plain);

	VERIFY0(sshkey_demote(pubk, &box->pdb_pub));

	free(box->pdb_enc.b_data);
	box->pdb_enc.b_data = enc;
	box->pdb_enc.b_size = enclen;
	box->pdb_enc.b_len = enclen;
	box->pdb_enc.b_offset = 0;

	return (ERRF_OK);
}

errf_t *
piv_box_seal(struct piv_token *tk, struct piv_slot *slot,
    struct piv_ecdh_box *box)
{
	errf_t *err;

	err = piv_box_seal_offline(slot->ps_pubkey, box);
	if (err)
		return (err);

	box->pdb_guidslot_valid = B_TRUE;
	bcopy(tk->pt_guid, box->pdb_guid, sizeof (tk->pt_guid));
	box->pdb_slot = slot->ps_slot;

	return (ERRF_OK);
}

errf_t *
piv_box_find_token(struct piv_token *tks, struct piv_ecdh_box *box,
    struct piv_token **tk, struct piv_slot **slot)
{
	struct piv_token *pt;
	struct piv_slot *s;
	errf_t *err;
	enum piv_slotid slotid;

	for (pt = tks; pt != NULL; pt = pt->pt_next) {
		if (bcmp(pt->pt_guid, box->pdb_guid, sizeof (pt->pt_guid)) == 0)
			break;
	}
	if (pt == NULL) {
		slotid = box->pdb_slot;
		if (slotid == 0 || slotid == 0xFF)
			slotid = PIV_SLOT_KEY_MGMT;
		for (pt = tks; pt != NULL; pt = pt->pt_next) {
			s = piv_get_slot(pt, slotid);
			if (s == NULL) {
				if (piv_txn_begin(pt))
					continue;
				if (piv_select(pt) ||
				    piv_read_cert(pt, slotid)) {
					piv_txn_end(pt);
					continue;
				}
				piv_txn_end(pt);
				s = piv_get_slot(pt, slotid);
			}
			if (sshkey_equal_public(s->ps_pubkey, box->pdb_pub))
				goto out;

		}
		return (errf("NotFoundError", NULL, "No PIV token found on "
		    "system to unlock box"));
	}

	s = piv_get_slot(pt, box->pdb_slot);
	if (s == NULL) {
		if ((err = piv_txn_begin(pt)) != 0)
			return (err);
		if ((err = piv_select(pt)) != 0 ||
		    (err = piv_read_cert(pt, box->pdb_slot)) != 0) {
			piv_txn_end(pt);
			return (err);
		}
		piv_txn_end(pt);
		s = piv_get_slot(pt, box->pdb_slot);
	}

	if (!sshkey_equal_public(s->ps_pubkey, box->pdb_pub)) {
		return (errf("NotFoundError", NULL, "PIV token on system "
		    "with matching GUID for box has different keys"));
	}

out:
	*tk = pt;
	*slot = s;
	return (ERRF_OK);
}

errf_t *
sshbuf_put_piv_box(struct sshbuf *buf, struct piv_ecdh_box *box)
{
	int rc;
	const char *tname;

	if (box->pdb_pub->type != KEY_ECDSA ||
	    box->pdb_ephem_pub->type != KEY_ECDSA) {
		return (errf("ArgumentError", NULL,
		    "Box public key and ephemeral public key must both be "
		    "ECDSA keys (instead they are %s and %s)",
		    sshkey_type(box->pdb_pub),
		    sshkey_type(box->pdb_ephem_pub)));
	}
	if (box->pdb_pub->ecdsa_nid != box->pdb_ephem_pub->ecdsa_nid) {
		return (errf("ArgumentError", NULL,
		    "Box public and ephemeral key must be on the same "
		    "EC curve"));
	}

	if ((rc = sshbuf_put_u8(buf, 0xB0)) ||
	    (rc = sshbuf_put_u8(buf, 0xC5)))
		return (ssherrf("sshbuf_put_u8", rc));
	if ((rc = sshbuf_put_u8(buf, 0x01)))
		return (ssherrf("sshbuf_put_u8", rc));
	if (!box->pdb_guidslot_valid) {
		if ((rc = sshbuf_put_u8(buf, 0x00)) ||
		    (rc = sshbuf_put_u8(buf, 0x00)) ||
		    (rc = sshbuf_put_u8(buf, 0x00)))
			return (ssherrf("sshbuf_put_u8", rc));
	} else {
		if ((rc = sshbuf_put_u8(buf, 0x01)))
			return (ssherrf("sshbuf_put_u8", rc));
		rc = sshbuf_put_string8(buf, box->pdb_guid,
		    sizeof (box->pdb_guid));
		if (rc)
			return (ssherrf("sshbuf_put_string8(guid)", rc));
		if ((rc = sshbuf_put_u8(buf, box->pdb_slot)))
			return (ssherrf("sshbuf_put_u8", rc));
	}
	if ((rc = sshbuf_put_cstring8(buf, box->pdb_cipher)) ||
	    (rc = sshbuf_put_cstring8(buf, box->pdb_kdf)))
		return (ssherrf("sshbuf_put_cstring8", rc));

	tname = sshkey_curve_nid_to_name(box->pdb_pub->ecdsa_nid);
	VERIFY(tname != NULL);
	if ((rc = sshbuf_put_cstring8(buf, tname)))
		return (ssherrf("sshbuf_put_cstring8", rc));
	if ((rc = sshbuf_put_eckey8(buf, box->pdb_pub->ecdsa)) ||
	    (rc = sshbuf_put_eckey8(buf, box->pdb_ephem_pub->ecdsa)))
		return (ssherrf("sshbuf_put_eckey8", rc));

	if ((rc = sshbuf_put_string8(buf, box->pdb_iv.b_data,
	    box->pdb_iv.b_len)))
		return (ssherrf("sshbuf_put_string8", rc));

	if ((rc = sshbuf_put_string(buf, box->pdb_enc.b_data,
	    box->pdb_enc.b_len)))
		return (ssherrf("sshbuf_put_string", rc));

	return (0);
}

errf_t *
piv_box_to_binary(struct piv_ecdh_box *box, uint8_t **output, size_t *len)
{
	struct sshbuf *buf;
	errf_t *err;

	buf = sshbuf_new();
	VERIFY3P(buf, !=, NULL);

	if ((err = sshbuf_put_piv_box(buf, box))) {
		sshbuf_free(buf);
		return (err);
	}

	*len = sshbuf_len(buf);
	*output = calloc(1, *len);
	VERIFY3P(*output, !=, NULL);
	bcopy(sshbuf_ptr(buf), *output, *len);
	sshbuf_free(buf);

	return (ERRF_OK);
}

errf_t *
sshbuf_get_piv_box(struct sshbuf *buf, struct piv_ecdh_box **outbox)
{
	struct piv_ecdh_box *box = NULL;
	uint8_t ver, magic[2];
	errf_t *err = ERRF_OK;
	int rc = 0;
	uint8_t *tmpbuf = NULL;
	struct sshkey *k = NULL;
	size_t len;
	uint8_t temp;
	char *tname = NULL;

	box = piv_box_new();
	VERIFY(box != NULL);

	if ((rc = sshbuf_get_u8(buf, &magic[0])) ||
	    (rc = sshbuf_get_u8(buf, &magic[1]))) {
		err = boxderrf(ssherrf("sshbuf_get_u8", rc));
		goto out;
	}
	if (magic[0] != 0xB0 && magic[1] != 0xC5) {
		err = boxderrf(errf("MagicError", NULL,
		    "Bad magic number (0x%02x%02x)", (uint)magic[0],
		    (uint)magic[1]));
		goto out;
	}
	if ((rc = sshbuf_get_u8(buf, &ver))) {
		err = boxderrf(ssherrf("sshbuf_get_u8", rc));
		goto out;
	}
	if (ver != 0x01) {
		err = boxverrf(errf("VersionError", NULL,
		    "Unsupported version number 0x%02x", ver));
		goto out;
	}

	if ((rc = sshbuf_get_u8(buf, &temp))) {
		err = boxderrf(ssherrf("sshbuf_get_u8", rc));
		goto out;
	}
	box->pdb_guidslot_valid = (temp != 0x00);

	if ((rc = sshbuf_get_string8(buf, &tmpbuf, &len))) {
		err = boxderrf(ssherrf("sshbuf_get_string8", rc));
		goto out;
	}
	if (box->pdb_guidslot_valid && len != sizeof (box->pdb_guid)) {
		err = boxderrf(errf("LengthError", NULL,
		    "Box is marked guidslot_valid but GUID length is only %d",
		    len));
		goto out;
	} else if (box->pdb_guidslot_valid) {
		bcopy(tmpbuf, box->pdb_guid, len);
	}
	free(tmpbuf);
	tmpbuf = NULL;
	if ((rc = sshbuf_get_u8(buf, &temp))) {
		err = boxderrf(ssherrf("sshbuf_get_u8", rc));
		goto out;
	}
	if (box->pdb_guidslot_valid)
		box->pdb_slot = temp;

	box->pdb_free_str = B_TRUE;
	if ((rc = sshbuf_get_cstring8(buf, (char **)&box->pdb_cipher, NULL)) ||
	    (rc = sshbuf_get_cstring8(buf, (char **)&box->pdb_kdf, NULL))) {
		err = boxderrf(ssherrf("sshbuf_get_cstring8", rc));
		goto out;
	}

	if ((rc = sshbuf_get_cstring8(buf, &tname, NULL))) {
		err = boxderrf(ssherrf("sshbuf_get_cstring8", rc));
		goto out;
	}
	k = sshkey_new(KEY_ECDSA);
	k->ecdsa_nid = sshkey_curve_name_to_nid(tname);
	if (k->ecdsa_nid == -1) {
		err = boxverrf(errf("CurveError", NULL, "EC curve '%s' not "
		    "supported", tname));
		goto out;
	}

	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY(k->ecdsa != NULL);

	if ((rc = sshbuf_get_eckey8(buf, k->ecdsa))) {
		err = boxderrf(ssherrf("sshbuf_get_eckey8", rc));
		goto out;
	}
	if ((rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa)))) {
		err = boxderrf(ssherrf("sshkey_ec_validate_public", rc));
		goto out;
	}
	box->pdb_pub = k;
	k = NULL;

	k = sshkey_new(KEY_ECDSA);
	k->ecdsa_nid = box->pdb_pub->ecdsa_nid;

	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY(k->ecdsa != NULL);

	if ((rc = sshbuf_get_eckey8(buf, k->ecdsa))) {
		err = boxderrf(ssherrf("sshbuf_get_eckey8", rc));
		goto out;
	}
	if ((rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa)))) {
		err = boxderrf(ssherrf("sshkey_ec_validate_public", rc));
		goto out;
	}
	box->pdb_ephem_pub = k;
	k = NULL;

	if ((rc = sshbuf_get_string8(buf, &box->pdb_iv.b_data,
	    &box->pdb_iv.b_size))) {
		err = boxderrf(ssherrf("sshbuf_get_string8", rc));
		goto out;
	}
	box->pdb_iv.b_len = box->pdb_iv.b_size;
	if ((rc = sshbuf_get_string(buf, &box->pdb_enc.b_data,
	    &box->pdb_enc.b_size))) {
		err = boxderrf(ssherrf("sshbuf_get_string", rc));
		goto out;
	}
	box->pdb_enc.b_len = box->pdb_enc.b_size;

	*outbox = box;
	box = NULL;

out:
	piv_box_free(box);
	if (k != NULL)
		sshkey_free(k);
	free(tname);
	free(tmpbuf);
	return (err);
}

const uint8_t *
piv_box_guid(const struct piv_ecdh_box *box)
{
	VERIFY(box->pdb_guidslot_valid);
	return (box->pdb_guid);
}

boolean_t
piv_box_has_guidslot(const struct piv_ecdh_box *box)
{
	return (box->pdb_guidslot_valid);
}

enum piv_slotid
piv_box_slot(const struct piv_ecdh_box *box)
{
	VERIFY(box->pdb_guidslot_valid);
	return (box->pdb_slot);
}

struct sshkey *
piv_box_pubkey(const struct piv_ecdh_box *box)
{
	return (box->pdb_pub);
}

struct sshkey *
piv_box_ephem_pubkey(const struct piv_ecdh_box *box)
{
	return (box->pdb_ephem_pub);
}

errf_t *
piv_box_copy_pubkey(const struct piv_ecdh_box *box, struct sshkey **tgt)
{
	int rc;
	if ((rc = sshkey_demote(box->pdb_pub, tgt)))
		return (ssherrf("sshkey_demote", rc));
	return (ERRF_OK);
}

size_t
piv_box_encsize(const struct piv_ecdh_box *box)
{
	return (box->pdb_enc.b_len);
}

boolean_t
piv_box_sealed(const struct piv_ecdh_box *box)
{
	return (box->pdb_plain.b_data == NULL);
}

const char *
piv_box_cipher(const struct piv_ecdh_box *box)
{
	if (box->pdb_cipher == NULL)
		return (BOX_DEFAULT_CIPHER);
	return (box->pdb_cipher);
}

const char *
piv_box_kdf(const struct piv_ecdh_box *box)
{
	if (box->pdb_kdf == NULL)
		return (BOX_DEFAULT_KDF);
	return (box->pdb_kdf);
}

void
piv_box_set_guid(struct piv_ecdh_box *box, const uint8_t *guid, size_t len)
{
	VERIFY3U(len, ==, sizeof (box->pdb_guid));
	bcopy(guid, box->pdb_guid, len);
	box->pdb_guidslot_valid = B_TRUE;
}

void
piv_box_set_slot(struct piv_ecdh_box *box, enum piv_slotid slot)
{
	box->pdb_slot = slot;
	box->pdb_guidslot_valid = B_TRUE;
}

static int piv_box_read_old_v1(struct sshbuf *buf, struct piv_ecdh_box **pbox);

errf_t *
piv_box_from_binary(const uint8_t *input, size_t inplen,
    struct piv_ecdh_box **pbox)
{
	errf_t *err = ERRF_OK;
	struct sshbuf *buf;

	buf = sshbuf_from(input, inplen);
	VERIFY3P(buf, !=, NULL);

	if (inplen > 1 && *input == 0x01) {
		int rv;
		rv = piv_box_read_old_v1(buf, pbox);
		if (rv != 0)
			err = boxderrf(errfno("piv_box_read_old_v1", rv, ""));
		return (err);
	}

	err = sshbuf_get_piv_box(buf, pbox);

	sshbuf_free(buf);

	return (err);
}

static int
piv_box_read_old_v1(struct sshbuf *buf, struct piv_ecdh_box **pbox)
{
	struct sshbuf *kbuf;
	int rv;
	uint8_t ver;
	uint8_t *tmp;
	size_t len;
	struct piv_ecdh_box *box;

	box = calloc(1, sizeof (struct piv_ecdh_box));
	VERIFY3P(box, !=, NULL);

	kbuf = sshbuf_new();
	VERIFY3P(kbuf, !=, NULL);

	if (sshbuf_get_u8(buf, &ver)) {
		bunyan_log(TRACE, "failed to read box version", NULL);
		rv = EINVAL;
		goto out;
	}
	if (ver != 1) {
		bunyan_log(TRACE, "bad piv box version",
		    "version", BNY_UINT, (uint)ver, NULL);
		rv = ENOTSUP;
		goto out;
	}

	if (sshbuf_get_string(buf, &tmp, &len)) {
		bunyan_log(TRACE, "failed to read box guid", NULL);
		rv = EINVAL;
		goto out;
	}
	if (len != sizeof (box->pdb_guid)) {
		bunyan_log(TRACE, "bad piv box guid: short",
		    "len", BNY_UINT, (uint)len, NULL);
		free(tmp);
		rv = EINVAL;
		goto out;
	}
	bcopy(tmp, box->pdb_guid, len);
	free(tmp);

	if (sshbuf_get_u8(buf, &ver)) {
		bunyan_log(TRACE, "failed to read box slot", NULL);
		rv = EINVAL;
		goto out;
	}
	box->pdb_slot = ver;

	if (sshbuf_get_stringb(buf, kbuf)) {
		bunyan_log(TRACE, "failed to read ephem_pub buf", NULL);
		rv = EINVAL;
		goto out;
	}
	if (sshkey_fromb(kbuf, &box->pdb_ephem_pub)) {
		bunyan_log(TRACE, "failed to read ephem_pub", NULL);
		rv = EINVAL;
		goto out;
	}
	sshbuf_reset(kbuf);
	if (sshbuf_get_stringb(buf, kbuf)) {
		bunyan_log(TRACE, "failed to read pub buf", NULL);
		rv = EINVAL;
		goto out;
	}
	if (sshkey_fromb(kbuf, &box->pdb_pub)) {
		bunyan_log(TRACE, "failed to read pub", NULL);
		rv = EINVAL;
		goto out;
	}

	box->pdb_free_str = B_TRUE;
	if (sshbuf_get_cstring(buf, (char **)&box->pdb_cipher, &len) ||
	    sshbuf_get_cstring(buf, (char **)&box->pdb_kdf, &len) ||
	    sshbuf_get_string(buf, &box->pdb_iv.b_data, &box->pdb_iv.b_size) ||
	    sshbuf_get_string(buf, &box->pdb_enc.b_data,
	    &box->pdb_enc.b_size)) {
		bunyan_log(TRACE, "failed to read box other fields", NULL);
		rv = EINVAL;
		goto out;
	}

	box->pdb_iv.b_len = box->pdb_iv.b_size;
	box->pdb_enc.b_len = box->pdb_enc.b_size;
	box->pdb_iv.b_offset = 0;
	box->pdb_enc.b_offset = 0;

	*pbox = box;
	sshbuf_free(buf);
	sshbuf_free(kbuf);
	return (0);

out:
	sshbuf_free(buf);
	sshbuf_free(kbuf);
	sshkey_free(box->pdb_ephem_pub);
	sshkey_free(box->pdb_pub);
	free((void *)box->pdb_cipher);
	free((void *)box->pdb_kdf);
	free(box->pdb_iv.b_data);
	free(box->pdb_enc.b_data);
	free(box);
	return (rv);
}
