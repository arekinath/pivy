/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

/*
 * Documentation references used below:
 * [piv]: https://csrc.nist.gov/publications/detail/sp/800-73/4/final
 * [yubico-piv]: https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
 * [iso7816]: (you'll need an ISO membership, or try a university library)
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

#include "debug.h"

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
#include <sys/ipc.h>
#include <sys/shm.h>

#include <zlib.h>

#include "openssh/config.h"
#include "openssh/ssherr.h"
#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
#include "openssh/digest.h"
#include "openssh/cipher.h"
#include "openssh/authfd.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>

#include "utils.h"
#include "tlv.h"
#include "piv.h"
#include "bunyan.h"
#include "utils.h"

/* Contains structs apdubuf, piv_ecdh_box, and enum piv_box_version */
#include "piv-internal.h"

#define	PIV_MAX_CERT_LEN		16384

const uint8_t AID_PIV[] = {
	0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00
};

boolean_t piv_full_apdu_debug = B_FALSE;

struct apdu {
	enum iso_class a_cls;
	enum iso_ins a_ins;
	uint8_t a_p1;
	uint8_t a_p2;
	size_t a_le;
	boolean_t a_xlen;

	struct apdubuf a_cmd;
	uint16_t a_sw;
	struct apdubuf a_reply;
};

/* Tags used in the GENERAL AUTHENTICATE command. */
enum gen_auth_tag {
	GA_TAG_WITNESS = 0x80,
	GA_TAG_CHALLENGE = 0x81,
	GA_TAG_RESPONSE = 0x82,
	GA_TAG_EXP = 0x85,
};

struct piv_slot {
	/*
	 * Links to the next member of the slot list hanging off a token at
	 * ->pt_slots. There's only one slots list per token.
	 */
	struct piv_slot *ps_next;

	enum piv_slotid ps_slot;
	enum piv_alg ps_alg;
	X509 *ps_x509;
	const char *ps_subj;
	const char *ps_issuer;
	const char *ps_cert_ser_hex;
	struct sshkey *ps_pubkey;
	enum piv_slot_auth ps_auth;

	boolean_t ps_got_metadata;
};

enum piv_token_xapdu_state {
	XLEN_UNKNOWN = 0,
	XLEN_YES,
	XLEN_NO,
};

struct piv_token {
	struct piv_ctx *pt_ctx;

	/* piv_ctx list of all tokens created. */
	struct piv_token *pt_lib_prev;
	struct piv_token *pt_lib_next;

	/*
	 * Next in the enumeration. If this token was returned by piv_find()
	 * then this will always be NULL. piv_enumerate() can return a linked
	 * list of piv_tokens though.
	 */
	struct piv_token *pt_next;

	/* PCSC parameters */
	const char *pt_rdrname;
	SCARDHANDLE pt_cardhdl;
	DWORD pt_proto;
	SCARD_IO_REQUEST pt_sendpci;

	/*
	 * Are we in a transaction right now?
	 */
	boolean_t pt_intxn;
	/*
	 * Do we need to reset at the end of this txn?
	 */
	boolean_t pt_reset;
	/*
	 * Do we have an auth'd PIN that we should try to reset at the end of
	 * this txn?
	 */
	enum piv_pin pt_used_pin;

	/*
	 * Are extended length APDUs working?
	 */
	enum piv_token_xapdu_state pt_xselect;
	enum piv_token_xapdu_state pt_xapdu;
	/* Max length of extended length APDUs */
	size_t pt_xapdu_cmd_max;
	size_t pt_xapdu_resp_max;

	/*
	 * Our GUID. This can either be the GUID from our CHUID file, or if
	 * we don't have one, we can synthesise this from other data.
	 */
	uint8_t pt_guid[GUID_LEN];
	/* We use this to cache a cstring hex version of pt_guid */
	char *pt_guidhex;

	/* Contents of the CHUID file. */
	struct piv_chuid *pt_chuid;

	/*
	 * Array of supported algorithms, if we got any in the answer to
	 * SELECT. Lots of PIV cards don't supply these.
	 */
	enum piv_alg pt_algs[PIV_RTS_MAX_ALGS];
	size_t pt_alg_count;

	/*
	 * If we are using any of the retired key history slots (82-95), then
	 * these should be set (they're from the Key History Object). The
	 * number of slots in use is oncard + offcard.
	 */
	uint8_t pt_hist_oncard;
	uint8_t pt_hist_offcard;
	char *pt_hist_url;

	/* Extra into in response to SELECT */
	char *pt_app_label;
	char *pt_app_uri;

	/* Our preferred authentication method */
	enum piv_pin pt_auth;

	/* Supported authentication methods */
	boolean_t pt_pin_global;
	boolean_t pt_pin_app;
	boolean_t pt_occ;
	boolean_t pt_vci;

	struct piv_slot *pt_slots;
	struct piv_slot *pt_last_slot;
	boolean_t pt_did_read_all;

	/* YubicoPIV specific stuff */
	boolean_t pt_ykpiv;			/* Supports YubicoPIV? */
	uint8_t pt_ykver[3];			/* YK FW version number */

	boolean_t pt_ykserial_valid;	/* YubiKey serial # only on YK5 */
	uint32_t pt_ykserial;
};

enum piv_pinfo_kv_type {
	PIV_PINFO_KV_UINT,
	PIV_PINFO_KV_STRING,
	PIV_PINFO_KV_BOOL,
	PIV_PINFO_KV_DATA
};

struct piv_pinfo_kv {
	struct piv_pinfo_kv 	*ppk_next;
	struct piv_pinfo_kv 	*ppk_prev;
	char			*ppk_name;
	enum piv_pinfo_kv_type	 ppk_type;
	union {
		uint		 ppk_uint;
		char		*ppk_string;
		struct {
			uint8_t	*ppk_data;
			size_t	 ppk_len;
		};
	};
};

struct piv_pinfo {
	char			*pp_name;
	char			*pp_affiliation;
	char			*pp_expiry;
	char			*pp_serial;
	char			*pp_issuer;
	char			*pp_org_1;
	char			*pp_org_2;

	uint8_t			*pp_yk_admin;
	size_t			 pp_yk_admin_len;

	struct piv_pinfo_kv	*pp_kv;
};

struct piv_ctx {
	boolean_t		 pc_scard_init;
	boolean_t		 pc_scard_owned;
	boolean_t		 pc_scard_nordr;
	DWORD			 pc_scard_scope;
	SCARDCONTEXT		 pc_scard;
	struct piv_token	*pc_tokens;
};

struct piv_ctx *
piv_open(void)
{
	struct piv_ctx *ctx;
	ctx = calloc(1, sizeof (*ctx));
	return (ctx);
}

static void piv_release_one(struct piv_token *pk);

void
piv_close(struct piv_ctx *ctx)
{
	struct piv_token *pt, *npt;
	if (ctx == NULL)
		return;
	if (ctx->pc_scard_owned)
		SCardReleaseContext(ctx->pc_scard);
	for (pt = ctx->pc_tokens; pt != NULL; pt = npt) {
		npt = pt->pt_lib_next;
		piv_release_one(pt);
	}
	free(ctx);
}

void
piv_set_context(struct piv_ctx *ctx, SCARDCONTEXT sctx)
{
	VERIFY(!ctx->pc_scard_init);
	ctx->pc_scard_init = B_TRUE;
	ctx->pc_scard_owned = B_FALSE;
	ctx->pc_scard_nordr = B_FALSE;
	ctx->pc_scard = sctx;
}

errf_t *
piv_establish_context(struct piv_ctx *ctx, DWORD scope)
{
	DWORD rv;
	VERIFY(!ctx->pc_scard_init);
	rv = SCardEstablishContext(scope, NULL, NULL, &ctx->pc_scard);
	switch (rv) {
	case SCARD_S_SUCCESS:
		ctx->pc_scard_init = B_TRUE;
		ctx->pc_scard_owned = B_TRUE;
		ctx->pc_scard_nordr = B_FALSE;
		return (ERRF_OK);
	case SCARD_E_NO_READERS_AVAILABLE:
		ctx->pc_scard_scope = scope;
		ctx->pc_scard_nordr = B_TRUE;
		return (ERRF_OK);
	case SCARD_E_NO_SERVICE:
#if defined(SCARD_E_SERVICE_STOPPED)
	case SCARD_E_SERVICE_STOPPED:	/* This is a pcsclite-ism */
#endif
		return (errf("ServiceError",
		    pcscerrf("SCardEstablishContext", rv),
		    "PC/SC system service/daemon not available"));
	default:
		return (pcscerrf("SCardEstablishContext", rv));
	}
}

/* Helper to dump out APDU data */
static inline void
debug_dump(errf_t *err, struct apdu *apdu)
{
	bunyan_log(BNY_DEBUG, "APDU parsing error",
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
	case SW_FILE_INVALID:
		return ("FILE_INVALID");
	case SW_INVALID_KEY_REF:
		return ("INVALID_KEY_REF");
	default:
		/* FALL THROUGH */
		(void)0;
	}
	if ((sw & 0xFF00) == SW_BYTES_REMAINING_00)
		return ("BYTES_REMAINING");
	else if ((sw & 0xFF00) == SW_CORRECT_LE_00)
		return ("CORRECT_LE");
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

const struct piv_fascn *
piv_token_fascn(const struct piv_token *token)
{
	if (token->pt_chuid == NULL)
		return (NULL);
	return (piv_chuid_get_fascn(token->pt_chuid));
}

const uint8_t *
piv_token_guid(const struct piv_token *token)
{
	return (token->pt_guid);
}

const char *
piv_token_guid_hex(const struct piv_token *token)
{
	if (token->pt_guidhex == NULL) {
		struct piv_token *tkwrite = (struct piv_token *)token;
		tkwrite->pt_guidhex = buf_to_hex(token->pt_guid,
		    sizeof (token->pt_guid), B_FALSE);
	}
	return (token->pt_guidhex);
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
	return (token->pt_chuid != NULL);
}

boolean_t
piv_token_has_signed_chuid(const struct piv_token *token)
{
	if (token->pt_chuid == NULL)
		return (B_FALSE);
	return (piv_chuid_is_signed(token->pt_chuid));
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

boolean_t
piv_token_has_xlen_apdu(const struct piv_token *token)
{
	return (token->pt_xapdu == XLEN_YES ||
	    token->pt_xselect == XLEN_YES);
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

const char *
piv_token_app_label(const struct piv_token *token)
{
	return (token->pt_app_label);
}

const char *
piv_token_app_uri(const struct piv_token *token)
{
	return (token->pt_app_uri);
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
	if (!token->pt_ykpiv)
		return (B_FALSE);
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

	/*
	 * First check that the key on the slot is at least claiming to be
	 * the same
	 */
	if (sshkey_equal_public(pubkey, slot->ps_pubkey) == 0) {
		err = errf("KeysNotEqualError", NULL,
		    "Given public key and slot's public key do not match");
		return (errf("KeyAuthError", err, "Failed to authenticate key "
		    "in slot %02x of PIV device '%s'", slot->ps_slot,
		    tk->pt_rdrname));
	}

	/*
	 * Now we generate a random challenge value and have the card sign it.
	 * 64 bytes is probably overkill, but more doesn't hurt (we normally
	 * are just sending a hash anyway).
	 */
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

	/* Convert it to SSH signature format so we can use sshkey_verify */
	rv = sshkey_sig_from_asn1(pubkey, hashalg, sig, siglen, b);
	if (rv != 0) {
		err = errf("NotSupportedError",
		    ssherrf("sshkey_sig_from_asn1", rv),
		    "PIV device '%s' returned an unsupported signature format",
		    tk->pt_rdrname);
		goto out;
	}

	rv = sshkey_verify(pubkey, sshbuf_ptr(b), sshbuf_len(b),
	    chal, challen, NULL, 0, NULL);
	if (rv != 0) {
		err = errf("KeyAuthError", ssherrf("sshkey_verify", rv),
		    "Failed to authenticate key in slot %02x of PIV "
		    "device '%s'", slot->ps_slot, tk->pt_rdrname);
		goto out;
	}

out:
	sshbuf_free(b);
	freezero(chal, challen);
	freezero(sig, siglen);
	return (err);
}

/*
 * Reads the PIV applet version from a YubiKey, or YubiKey-compatible device
 * (like one running PivApplet).
 *
 * We use the fact that a device responds to this version command to indicate
 * whether we should bother trying to use any other Yubico extensions to the
 * PIV interface. If the device doesn't respond to "GET VERSION" we assume it
 * supports no other extensions.
 *
 * This command is documented in [yubico-piv]
 */
static errf_t *
ykpiv_get_version(struct piv_token *pk)
{
	errf_t *err;
	struct apdu *apdu;

	VERIFY(pk->pt_intxn == B_TRUE);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_VER, 0x00, 0x00);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN, "ykpiv_get_version.transceive_apdu failed",
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

#if !defined(__APPLE__)
		if (ykpiv_version_compare(pk, 5, 0, 0) >= 0 &&
		    pk->pt_app_label == NULL &&
		    pk->pt_xapdu == XLEN_YES &&
		    pk->pt_xapdu_cmd_max < 0xB00) {
			/*
			 * YubiKeys on 5.x or later lack the xlen APDU info
			 * in RTS, but they support larger than the
			 * conservative defaults we set in piv_select().
			 */
			pk->pt_xapdu_cmd_max = 0xB00;
			pk->pt_xapdu_resp_max = 0x10000;
		}
#endif

		err = NULL;
	} else {
		err = notsuperrf(swerrf("INS_YK_GET_VER", apdu->a_sw),
		    pk->pt_rdrname, "YubicoPIV");
	}

	piv_apdu_free(apdu);
	return (err);
}

/*
 * Reads the serial number from a YubiKey. This is only available in YubicoPIV
 * applet version 5.0.0 or later.
 *
 * This command is undocumented at present, but can be found used by the
 * official yubico tools (which are open source). The official clients use
 * require a response to this command in some circumstances before they will
 * operate on a device.
 */
static errf_t *
ykpiv_read_serial(struct piv_token *pt)
{
	errf_t *err;
	struct apdu *apdu;

	VERIFY(pt->pt_intxn);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_SERIAL, 0x00, 0x00);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(BNY_WARN, "ykpiv_read_serial.transceive_apdu failed",
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

/*
 * Reads and parses the PIV Discovery Object.
 * [piv] 800-73-4 part 1 appendix A (table 18)
 */
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
	tlv_write_u8to32(tlv, PIV_TAG_DISCOV);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_read_chuid.transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		goto out;
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		if ((err = tlv_read_tag(tlv, &tag)))
			goto invdata;
		if (tag != 0x7E) {
			err = tagerrf("INS_GET_DATA(DISCOV)", tag);
			goto invdata;
		}
		while (!tlv_at_end(tlv)) {
			if ((err = tlv_read_tag(tlv, &tag)))
				goto invdata;
			bunyan_log(BNY_TRACE, "reading discov tlv tag",
			    "tag", BNY_UINT, (uint)tag, NULL);
			switch (tag) {
			case 0x4F:	/* AID */
				if (tlv_rem(tlv) > sizeof (AID_PIV) ||
				    bcmp(AID_PIV, tlv_ptr(tlv), tlv_rem(tlv)) != 0) {
					err = invderrf(errf("PIVDataError", NULL,
					    "PIV discovery AID tag contained "
					    "incorrect AID"), pk->pt_rdrname);
					goto invdata;
				}
				tlv_skip(tlv);
				break;
			case 0x5F2F:	/* PIN and OCC policy */
				/* See [piv] 800-73-4 part 1, section 3.3.2 */
				if ((err = tlv_read_u8to32(tlv, &policy)))
					goto invdata;
				bunyan_log(BNY_TRACE, "policy in discov",
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
				if ((err = tlv_end(tlv)))
					goto invdata;
				break;
			default:
				err = tagerrf("INS_GET_DATA(DISCOV)", tag);
				goto invdata;
			}
		}
		if ((err = tlv_end(tlv)))
			goto invdata;
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
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

out:
	tlv_free(tlv);
	piv_apdu_free(apdu);
	return (err);

invdata:
	tlv_abort(tlv);
	err = invderrf(err, pk->pt_rdrname);
	debug_dump(err, apdu);
	goto out;
}

/*
 * Reads and parses the PIV Key History Object.
 * [piv] 800-73-4 part 1 section 3.3.3
 * [piv] 800-73-4 part 1 appendix A (table 19)
 */
static errf_t *
piv_read_keyhist(struct piv_token *pk)
{
	errf_t *rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag, uval;

	VERIFY(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_u8to32(tlv, PIV_TAG_KEYHIST);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = piv_apdu_transceive_chain(pk, apdu);
	if (rv) {
		rv = ioerrf(rv, pk->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_read_chuid.transceive_apdu failed",
		    "error", BNY_ERF, rv, NULL);
		goto out;
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		if (apdu->a_reply.b_len < 1) {
			rv = errf("EmptyDataError", NULL,
			    "Card replied with empty APDU to "
			    "INS_GET_DATA(KEYHIST)");
			goto invdata;
		}
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		if ((rv = tlv_read_tag(tlv, &tag)))
			goto invdata;
		if (tag != 0x53) {
			rv = tagerrf("INS_GET_DATA(KEYHIST)", tag);
			goto invdata;
		}
		while (!tlv_at_end(tlv)) {
			if ((rv = tlv_read_tag(tlv, &tag)))
				goto invdata;
			bunyan_log(BNY_TRACE, "reading keyhist tlv tag",
			    "tag", BNY_UINT, (uint)tag, NULL);
			switch (tag) {
			case 0xC1:	/* # keys with on-card certs */
				if ((rv = tlv_read_u8to32(tlv, &uval)))
					goto invdata;
				pk->pt_hist_oncard = uval;
				if ((rv = tlv_end(tlv)))
					goto invdata;
				break;
			case 0xC2:	/* # keys with off-card certs */
				if ((rv = tlv_read_u8to32(tlv, &uval)))
					goto invdata;
				pk->pt_hist_offcard = uval;
				if ((rv = tlv_end(tlv)))
					goto invdata;
				break;
			case 0xF3:	/* URL for off-card certs */
				rv = tlv_read_string(tlv, &pk->pt_hist_url);
				if (rv != NULL)
					goto invdata;
				if ((rv = tlv_end(tlv)))
					goto invdata;
				break;
			case 0xFE:	/* CRC */
				tlv_skip(tlv);
				break;
			default:
				rv = tagerrf("INS_GET_DATA(KEYHIST)", tag);
				goto invdata;
			}
		}
		if ((rv = tlv_end(tlv)))
			goto invdata;
		rv = NULL;

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
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, rv, NULL);
	}

out:
	tlv_free(tlv);
	piv_apdu_free(apdu);
	return (rv);

invdata:
	if (tlv != NULL)
		tlv_abort(tlv);
	rv = invderrf(rv, pk->pt_rdrname);
	debug_dump(rv, apdu);
	goto out;
}

/*
 * Reads and parses the PIV Card Holder Unique Identifier Object.
 * [piv] 800-73-4 part 1 section 3.1.2
 * [piv] 800-73-4 part 1 appendix A (table 9)
 */
static errf_t *
piv_read_chuid(struct piv_token *pk)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag, i;

	VERIFY(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_u8to32(tlv, PIV_TAG_CHUID);
	tlv_pop(tlv);

	bunyan_log(BNY_DEBUG, "reading CHUID file", NULL);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN, "transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		goto out;
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		const uint8_t *guid;

		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		if ((err = tlv_read_tag(tlv, &tag)))
			goto invdata;
		if (tag != 0x53) {
			err = tagerrf("INS_GET_DATA(CHUID)", tag);
			goto invdata;
		}
		if (pk->pt_chuid != NULL)
			piv_chuid_free(pk->pt_chuid);
		pk->pt_chuid = NULL;
		err = piv_chuid_decode(tlv_ptr(tlv), tlv_rem(tlv),
		    &pk->pt_chuid);
		if (err != ERRF_OK)
			goto invdata;
		tlv_skip(tlv);

		guid = piv_chuid_get_guid(pk->pt_chuid);
		for (i = 0; i < GUID_LEN; ++i) {
			if (guid != 0)
				break;
		}
		if (i == GUID_LEN) {
			const uint8_t *chuuid;
			const struct piv_fascn *pf;
			chuuid = piv_chuid_get_chuuid(pk->pt_chuid);
			pf = piv_chuid_get_fascn(pk->pt_chuid);

			if (chuuid != NULL) {
				bcopy(chuuid, pk->pt_guid, GUID_LEN);
			} else if (pf != NULL) {
				struct ssh_digest_ctx *hctx;
				uint8_t *buf = calloc(1, 32);
				VERIFY(buf != NULL);
				hctx = ssh_digest_start(SSH_DIGEST_SHA256);
				VERIFY(hctx != NULL);
				VERIFY0(ssh_digest_update(hctx, pf->pf_agency,
				    strlen(pf->pf_agency)));
				VERIFY0(ssh_digest_update(hctx, pf->pf_system,
				    strlen(pf->pf_system)));
				VERIFY0(ssh_digest_update(hctx, pf->pf_crednum,
				    strlen(pf->pf_crednum)));
				VERIFY0(ssh_digest_update(hctx, pf->pf_cs,
				    strlen(pf->pf_cs)));
				VERIFY0(ssh_digest_update(hctx, pf->pf_ici,
				    strlen(pf->pf_ici)));
				VERIFY0(ssh_digest_final(hctx, buf, 32));
				bcopy(buf, pk->pt_guid, sizeof (pk->pt_guid));
				ssh_digest_free(hctx);
			}
		} else {
			bcopy(guid, pk->pt_guid, sizeof (pk->pt_guid));
		}

		err = ERRF_OK;

	} else if (apdu->a_sw == SW_FILE_NOT_FOUND ||
	    apdu->a_sw == SW_WRONG_DATA) {
		err = errf("NotFoundError", swerrf("INS_GET_DATA", apdu->a_sw),
		    "PIV CHUID object was not found on device '%s'",
		    pk->pt_rdrname);

	} else {
		err = swerrf("INS_GET_DATA(CHUID)", apdu->a_sw);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

out:
	tlv_free(tlv);
	piv_apdu_free(apdu);
	return (err);

invdata:
	tlv_abort(tlv);
	err = invderrf(err, pk->pt_rdrname);
	debug_dump(err, apdu);
	goto out;
}

errf_t *
piv_enumerate(struct piv_ctx *ctx, struct piv_token **tokens)
{
	DWORD rv, readersLen = 0;
	LPTSTR readers, thisrdr;
	struct piv_token *ks = NULL;
	errf_t *err;
	struct piv_token *key;
	SCARDHANDLE card;
	DWORD activeProtocol;

	if (!ctx->pc_scard_init && ctx->pc_scard_nordr) {
		/* Previous attempt got "no readers" error */
		err = piv_establish_context(ctx, ctx->pc_scard_scope);
		if (err) {
			err = errf("PCSCContextError", err,
			    "PCSC context is not functional");
			return (err);
		}
		if (!ctx->pc_scard_init) {
			*tokens = NULL;
			return (ERRF_OK);
		}
	}

	if (!ctx->pc_scard_init) {
		return (errf("PCSCContextError", NULL,
		    "PCSC context has not been initialised"));
	}

	for (key = ctx->pc_tokens; key != NULL; key = key->pt_lib_next) {
		if (key->pt_intxn) {
			return (errf("TransactionError", NULL,
			    "Another token belonging to this context is "
			    "currently in a transaction, can't use "
			    "piv_enumerate"));
		}
		(void) SCardDisconnect(key->pt_cardhdl, SCARD_RESET_CARD);
	}

	rv = SCardListReaders(ctx->pc_scard, NULL, NULL, &readersLen);
	switch (rv) {
	case SCARD_S_SUCCESS:
		break;
	case SCARD_E_INVALID_HANDLE:
	case SCARD_E_NO_SERVICE:
#if defined(SCARD_E_SERVICE_STOPPED)
	case SCARD_E_SERVICE_STOPPED:	/* This is a pcsclite-ism */
#endif
		return (errf("PCSCContextError",
		    pcscerrf("SCardListReaders", rv),
		    "PCSC context is not functional"));
	case SCARD_E_NO_READERS_AVAILABLE:
		/* Pretend this isn't an error: we just didn't find any rdrs */
		*tokens = NULL;
		return (ERRF_OK);
	default:
		return (pcscerrf("SCardListReaders", rv));
	}
	readers = calloc(1, readersLen);
	rv = SCardListReaders(ctx->pc_scard, NULL, readers, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		free(readers);
		return (pcscerrf("SCardListReaders", rv));
	}

	for (thisrdr = readers; *thisrdr != 0; thisrdr += strlen(thisrdr) + 1) {
		rv = SCardConnect(ctx->pc_scard, thisrdr, SCARD_SHARE_SHARED,
		    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card,
		    &activeProtocol);
		if (rv != SCARD_S_SUCCESS) {
			err = pcscrerrf("SCardConnect", thisrdr, rv);
			bunyan_log(BNY_DEBUG, "SCardConnect failed",
			    "error", BNY_ERF, err, NULL);
			errf_free(err);
			continue;
		}

		key = calloc(1, sizeof (struct piv_token));
		key->pt_xapdu_cmd_max = 0xFF;
		key->pt_xapdu_resp_max = 0x100;
		key->pt_ctx = ctx;
		key->pt_lib_next = ctx->pc_tokens;
		if (ctx->pc_tokens != NULL)
			ctx->pc_tokens->pt_lib_prev = key;
		ctx->pc_tokens = key;
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

		if ((err = piv_txn_begin(key))) {
			bunyan_log(BNY_DEBUG, "piv_txn_begin failed",
			    "error", BNY_ERF, err, NULL);
			errf_free(err);
			(void) SCardDisconnect(card, SCARD_RESET_CARD);
			continue;
		}
		err = piv_select(key);
		if (err == ERRF_OK) {
			err = piv_read_chuid(key);
			if (errf_caused_by(err, "NotFoundError")) {
				errf_free(err);
				err = ERRF_OK;
			}
		}
		if (err == ERRF_OK) {
			err = piv_read_discov(key);
			if (errf_caused_by(err, "NotFoundError") ||
			    errf_caused_by(err, "NotSupportedError")) {
				errf_free(err);
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
			    errf_caused_by(err, "NotSupportedError") ||
			    errf_caused_by(err, "EmptyDataError")) {
				errf_free(err);
				err = ERRF_OK;
			}
		}
		if (err == ERRF_OK) {
			err = ykpiv_get_version(key);
			if (err == ERRF_OK) {
				err = ykpiv_read_serial(key);
			}
			if (errf_caused_by(err, "NotSupportedError")) {
				errf_free(err);
				err = ERRF_OK;
			}
		}
		piv_txn_end(key);

		if (err == ERRF_OK) {
			key->pt_next = ks;
			ks = key;
		} else {
			bunyan_log(BNY_DEBUG, "piv_enumerate() eliminated reader "
			    "due to error", "reader", BNY_STRING, thisrdr,
			    "error", BNY_ERF, err, NULL);
			errf_free(err);
			(void) SCardDisconnect(card, SCARD_RESET_CARD);
		}
	}

	*tokens = ks;

	free(readers);
	return (ERRF_OK);
}

errf_t *
piv_find(struct piv_ctx *ctx, const uint8_t *guid, size_t guidlen,
    struct piv_token **token)
{
	DWORD rv, readersLen = 0;
	LPTSTR readers, thisrdr;
	struct piv_token *found = NULL, *key;
	errf_t *err;

	if (!ctx->pc_scard_init && ctx->pc_scard_nordr) {
		/* Previous attempt got "no readers" error */
		err = piv_establish_context(ctx, ctx->pc_scard_scope);
		if (err) {
			err = errf("PCSCContextError", err,
			    "PCSC context is not functional");
			return (err);
		}
		if (!ctx->pc_scard_init) {
			return (errf("NotFoundError", NULL,
			    "No PIV token found matching GUID"));
		}
	}

	if (!ctx->pc_scard_init) {
		return (errf("PCSCContextError", NULL,
		    "PCSC context has not been initialised"));
	}

	rv = SCardListReaders(ctx->pc_scard, NULL, NULL, &readersLen);
	switch (rv) {
	case SCARD_S_SUCCESS:
		break;
	case SCARD_E_INVALID_HANDLE:
	case SCARD_E_NO_SERVICE:
#if defined(SCARD_E_SERVICE_STOPPED)
	case SCARD_E_SERVICE_STOPPED:	/* This is a pcsclite-ism */
#endif
		return (errf("PCSCContextError",
		    pcscerrf("SCardListReaders", rv),
		    "PCSC context is not functional"));
	case SCARD_E_NO_READERS_AVAILABLE:
		return (errf("NotFoundError", NULL,
		    "No PIV token found matching GUID"));
	default:
		return (pcscerrf("SCardListReaders", rv));
	}
	readers = calloc(1, readersLen);
	rv = SCardListReaders(ctx->pc_scard, NULL, readers, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		free(readers);
		return (pcscerrf("SCardListReaders", rv));
	}

	key = calloc(1, sizeof (struct piv_token));
	VERIFY(key != NULL);

	for (thisrdr = readers; *thisrdr != 0; thisrdr += strlen(thisrdr) + 1) {
		SCARDHANDLE card;
		DWORD activeProtocol;

		rv = SCardConnect(ctx->pc_scard, thisrdr, SCARD_SHARE_SHARED,
		    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card,
		    &activeProtocol);
		if (rv != SCARD_S_SUCCESS) {
			err = pcscrerrf("SCardConnect", thisrdr, rv);
			bunyan_log(BNY_DEBUG, "SCardConnect failed",
			    "error", BNY_ERF, err, NULL);
			errf_free(err);
			continue;
		}

		key->pt_xapdu_cmd_max = 0xFF;
		key->pt_xapdu_resp_max = 0x100;
		key->pt_ctx = ctx;
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

		if ((err = piv_txn_begin(key))) {
			errf_free(err);
			goto nopenotxn;
		}
		err = piv_select(key);
		if (err) {
			errf_free(err);
			goto nope;
		}
		err = piv_read_chuid(key);
		if (errf_caused_by(err, "NotFoundError") && guidlen == 0) {
			errf_free(err);
			err = ERRF_OK;
			if (found != NULL) {
				piv_txn_end(key);
				(void) SCardDisconnect(card, SCARD_RESET_CARD);
				free((char *)key->pt_rdrname);
				piv_chuid_free(key->pt_chuid);
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
			bunyan_log(BNY_DEBUG, "piv_find() eliminated reader "
			    "due to error", "reader", BNY_STRING, thisrdr,
			    "error", BNY_ERF, err, NULL);
			errf_free(err);
			goto nope;
		}
		if (guidlen == 0 || bcmp(guid, key->pt_guid, guidlen) != 0)
			goto nope;

		if (found != NULL) {
			piv_txn_end(key);
			(void) SCardDisconnect(card, SCARD_RESET_CARD);
			free((char *)key->pt_rdrname);
			piv_chuid_free(key->pt_chuid);
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
nopenotxn:
		(void) SCardDisconnect(card, SCARD_RESET_CARD);
		free((char *)key->pt_rdrname);
		piv_chuid_free(key->pt_chuid);
		bzero(key, sizeof (struct piv_token));
	}

	free((char *)key->pt_rdrname);
	piv_chuid_free(key->pt_chuid);
	free(key);

	if (found == NULL) {
		free(readers);
		return (errf("NotFoundError", NULL,
		    "No PIV token found matching GUID"));
	}

	key = found;
	key->pt_lib_next = ctx->pc_tokens;
	if (ctx->pc_tokens != NULL)
		ctx->pc_tokens->pt_lib_prev = key;
	ctx->pc_tokens = key;
	err = ERRF_OK;

	if (err == ERRF_OK) {
		err = piv_read_discov(key);
		if (errf_caused_by(err, "NotFoundError") ||
		    errf_caused_by(err, "NotSupportedError")) {
			errf_free(err);
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
		    errf_caused_by(err, "NotSupportedError") ||
		    errf_caused_by(err, "EmptyDataError")) {
			errf_free(err);
			err = ERRF_OK;
		}
	}
	if (err == ERRF_OK) {
		err = ykpiv_get_version(key);
		if (err == ERRF_OK) {
			err = ykpiv_read_serial(key);
		}
		if (errf_caused_by(err, "NotSupportedError")) {
			errf_free(err);
			err = ERRF_OK;
		}
	}
	piv_txn_end(key);

	if (err) {
		bunyan_log(BNY_DEBUG, "piv_find() eliminated reader "
		    "due to error", "reader", BNY_STRING, thisrdr,
		    "error", BNY_ERF, err, NULL);
		errf_free(err);
		(void) SCardDisconnect(key->pt_cardhdl, SCARD_RESET_CARD);
		free((char *)key->pt_rdrname);
		free(key);
	}

	*token = key;
	free(readers);
	return (ERRF_OK);
}

static void
piv_release_one(struct piv_token *pk)
{
	struct piv_slot *ps, *psnext;
	VERIFY(pk->pt_intxn == B_FALSE);
	(void) SCardDisconnect(pk->pt_cardhdl, SCARD_LEAVE_CARD);

	for (ps = pk->pt_slots; ps != NULL; ps = psnext) {
		OPENSSL_free((void *)ps->ps_subj);
		OPENSSL_free((void *)ps->ps_issuer);
		OPENSSL_free((void *)ps->ps_cert_ser_hex);
		X509_free(ps->ps_x509);
		sshkey_free(ps->ps_pubkey);
		psnext = ps->ps_next;
		free(ps);
	}
	free(pk->pt_hist_url);
	free(pk->pt_app_label);
	free(pk->pt_app_uri);
	free((char *)pk->pt_rdrname);
	free(pk->pt_guidhex);
	piv_chuid_free(pk->pt_chuid);

	if (pk->pt_lib_prev != NULL)
		pk->pt_lib_prev->pt_lib_next = pk->pt_lib_next;
	if (pk->pt_lib_next != NULL)
		pk->pt_lib_next->pt_lib_prev = pk->pt_lib_prev;
	if (pk->pt_lib_prev == NULL)
		pk->pt_ctx->pc_tokens = pk->pt_lib_next;

	free(pk);
}

void
piv_release(struct piv_token *pk)
{
	struct piv_token *next;
	for (; pk != NULL; pk = next) {
		next = pk->pt_next;
		piv_release_one(pk);
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

const char *
piv_slot_issuer(const struct piv_slot *slot)
{
	return (slot->ps_issuer);
}

const char *
piv_slot_serial_hex(const struct piv_slot *slot)
{
	return (slot->ps_cert_ser_hex);
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
		freezero(a->a_reply.b_data, a->a_reply.b_size);
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
	uint8_t *buf = calloc(1, 10 + d->b_len);
	buf[0] = apdu->a_cls;
	buf[1] = apdu->a_ins;
	buf[2] = apdu->a_p1;
	buf[3] = apdu->a_p2;
	if (d->b_data == NULL && apdu->a_xlen) {
		buf[4] = 0;
		if (apdu->a_le >= 0xFFFF) {
			buf[5] = 0;
			buf[6] = 0;
		} else {
			buf[5] = (apdu->a_le & 0xFF00) >> 8;
			buf[6] = apdu->a_le & 0xFF;
		}
		*outlen = 7;
		return (buf);
	} else if (d->b_data == NULL) {
		buf[4] = (apdu->a_le > 0xFF) ? 0x00 : apdu->a_le;
		*outlen = 5;
		return (buf);
	} else if (d->b_len > 256 || (apdu->a_xlen && d->b_len > 0)) {
		VERIFY(d->b_len <= 0x10000 && d->b_len > 0);
		buf[4] = 0;
		buf[5] = (d->b_len & 0xFF00) >> 8;
		buf[6] = d->b_len & 0xFF;
		bcopy(d->b_data + d->b_offset, buf + 7, d->b_len);
		if (apdu->a_cls & CLA_CHAIN) {
			*outlen = d->b_len + 7;
		} else {
			buf[d->b_len + 7] = (apdu->a_le & 0xFF00) >> 8;
			buf[d->b_len + 8] = apdu->a_le & 0xFF;
			*outlen = d->b_len + 9;
		}
		return (buf);
	} else {
		VERIFY(d->b_len < 256 && d->b_len > 0);
		buf[4] = d->b_len;
		bcopy(d->b_data + d->b_offset, buf + 5, d->b_len);
		if (apdu->a_cls & CLA_CHAIN) {
			*outlen = d->b_len + 5;
		} else {
			buf[d->b_len + 5] = (apdu->a_le > 0xFF) ? 0x00 :
			    apdu->a_le;
			*outlen = d->b_len + 6;
		}
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
	case INS_RESET:
		return ("YKPIV_RESET");
	case INS_GET_METADATA:
		return ("YKPIV_GET_METADATA");
	default:
		return ("UNKNOWN");
	}
}

/*
 * The basic APDU transceiver function. Doesn't handle any chaining or length
 * correction logic at all.
 */
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
		bunyan_log(BNY_TRACE, "sending APDU",
		    "apdu", BNY_BIN_HEX, cmd, cmdLen,
		    NULL);
	}

	rv = SCardTransmit(key->pt_cardhdl, &key->pt_sendpci, cmd,
	    cmdLen, NULL, r->b_data + r->b_offset, &recvLength);
	freezero(cmd, cmdLen);

	if (piv_full_apdu_debug) {
		bunyan_log(BNY_TRACE, "received APDU",
		    "apdu", BNY_BIN_HEX, r->b_data + r->b_offset,
		    (size_t)recvLength, NULL);
	}

	if (rv != SCARD_S_SUCCESS) {
		err = pcscrerrf("SCardTransmit", key->pt_rdrname, rv);
		bunyan_log(BNY_DEBUG, "SCardTransmit failed",
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

	bunyan_log(BNY_DEBUG, "APDU exchanged",
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
	    "xlen", BNY_STRING, apdu->a_xlen ? "true" : "false",
	    NULL);

	return (ERRF_OK);
}

/*
 * This function sends and receives chains of commands so that the data length
 * can be arbitrarily long on either side.
 */
errf_t *
piv_apdu_transceive_chain(struct piv_token *pk, struct apdu *apdu)
{
	errf_t *rv;
	size_t offset;
	size_t rem;
	boolean_t gotok = B_FALSE;
	size_t max = pk->pt_xapdu_cmd_max;

	VERIFY(pk->pt_intxn == B_TRUE);

	apdu->a_xlen = (pk->pt_xapdu == XLEN_YES);

	/* First, send the command. */
	rem = apdu->a_cmd.b_len;
	do {
rebuild:
		/* Is there another block needed in the chain? */
		if (rem > max) {
			apdu->a_cls |= CLA_CHAIN;
			apdu->a_cmd.b_len = max;
		} else {
			apdu->a_cls &= ~CLA_CHAIN;
			apdu->a_cmd.b_len = rem;
			max = pk->pt_xapdu_resp_max;
			apdu->a_le = 0;
		}
again:
		rv = piv_apdu_transceive(pk, apdu);
		if (errf_caused_by(rv, "PCSCError") &&
		    apdu->a_xlen && max > 256) {
			max >>= 1;
			pk->pt_xapdu_cmd_max = max;
			bunyan_log(BNY_DEBUG, "got an error on a large xlen"
			    "apdu, shrinking max cmd apdu len",
			    "new_max", BNY_SIZE_T, max, NULL);
			goto rebuild;
		} else if (rv) {
			return (rv);
		}
		if ((apdu->a_sw & 0xFF00) == SW_CORRECT_LE_00) {
			apdu->a_le = apdu->a_sw & 0x00FF;
			/*
			 * We have to explicitly jump here because this case
			 * can happen even on zero-length commands (where rem
			 * would be 0 too and we would leave this loop)
			 */
			goto again;
		} else if ((apdu->a_sw & 0xFF00) == SW_NO_ERROR ||
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

	/*
	 * Now we send CONTINUE commands until we've received all the data that
	 * the other side has to send to us.
	 *
	 * Note the case where we got SW_NO_ERROR but max length data -- we try
	 * a CONTINUE just in case -- there are a few cards which are buggy
	 * and don't always give us SW_BYTES_REMAINING.
	 */
	while ((apdu->a_sw & 0xFF00) == SW_BYTES_REMAINING_00 ||
	    (apdu->a_sw == SW_NO_ERROR && apdu->a_reply.b_len >= max)) {
		if (apdu->a_sw == SW_NO_ERROR)
			gotok = B_TRUE;
		apdu->a_cls = CLA_ISO;
		apdu->a_ins = INS_CONTINUE;
		apdu->a_p1 = 0;
		apdu->a_p2 = 0;
		if ((apdu->a_sw & 0xFF00) == SW_BYTES_REMAINING_00 ||
		    (apdu->a_sw & 0xFF00) == SW_CORRECT_LE_00) {
			apdu->a_le = apdu->a_sw & 0x00FF;
		}
		apdu->a_cmd.b_data = NULL;
		apdu->a_reply.b_offset += apdu->a_reply.b_len;
		VERIFY(apdu->a_reply.b_offset < apdu->a_reply.b_size);

		rv = piv_apdu_transceive(pk, apdu);
		if (rv)
			return (rv);
	}

	if (gotok && apdu->a_sw == SW_WRONG_DATA)
		apdu->a_sw = SW_NO_ERROR;

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
	DWORD disp = SCARD_LEAVE_CARD;
	errf_t *err;

	if (!key->pt_reset && key->pt_used_pin != PIV_NO_PIN) {
		/* Attempt to clear the PIN's security status if we can. */
		err = piv_clear_pin(key, key->pt_used_pin);
		if (err != ERRF_OK)
			errf_free(err);
	}
	if (key->pt_reset)
		disp = SCARD_RESET_CARD;
	if (key->pt_used_pin != PIV_NO_PIN)
		disp = SCARD_RESET_CARD;

	rv = SCardEndTransaction(key->pt_cardhdl, disp);
	if (rv != SCARD_S_SUCCESS) {
		bunyan_log(BNY_ERROR, "SCardEndTransaction failed",
		    "reader", BNY_STRING, key->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
	}
	key->pt_intxn = B_FALSE;
	key->pt_reset = B_FALSE;
	key->pt_used_pin = PIV_NO_PIN;
}

errf_t *
piv_clear_pin(struct piv_token *pk, enum piv_pin type)
{
	errf_t *err = ERRF_OK;
	struct apdu *apdu;

	VERIFY(pk->pt_intxn == B_TRUE);

	apdu = piv_apdu_make(CLA_ISO, INS_VERIFY, 0xFF, type);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_clear_pin.transceive failed",
		    "error", BNY_ERF, err, NULL);
		piv_apdu_free(apdu);
		return (err);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
		if (pk->pt_used_pin == type)
			pk->pt_used_pin = PIV_NO_PIN;

	} else if (apdu->a_sw == SW_FILE_INVALID) {
		err = errf("PermissionError", swerrf("INS_VERIFY(%x)",
		    apdu->a_sw, type), "PIN is blocked (has run out of "
		    "retry attempts) and cannot be used");

	} else if (apdu->a_sw == SW_INVALID_KEY_REF) {
		err = errf("NotSupportedError", swerrf("INS_VERIFY(%x)",
		    apdu->a_sw, type), "PIN type %x not supported", type);

	} else {
		err = swerrf("INS_VERIFY(%x)", apdu->a_sw, type);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

errf_t *
piv_select(struct piv_token *tk)
{
	errf_t *rv = ERRF_OK;
	struct apdu *apdu;
	enum piv_token_xapdu_state xapdu;

	VERIFY(tk->pt_intxn == B_TRUE);

	apdu = piv_apdu_make(CLA_ISO, INS_SELECT, SEL_APP_AID, 0);

#if !defined(__APPLE__)
	/*
	 * If this is a T=1 card, and this is the first time we've talked to it,
	 * try an ext-len SELECT APDU and see if it works.
	 */
	xapdu = tk->pt_xapdu;
	if (tk->pt_xselect == XLEN_UNKNOWN &&
	    tk->pt_proto == SCARD_PROTOCOL_T1) {
		bunyan_log(BNY_DEBUG,
		    "probing card for xlen SELECT apdu support",
		    "reader", BNY_STRING, tk->pt_rdrname, NULL);
		tk->pt_xapdu = XLEN_YES;
	} else if (tk->pt_xselect == XLEN_NO) {
		tk->pt_xapdu = XLEN_NO;
	}
#endif

again:
	/*
	 * Set this up each time, because apdu_transceive_chain can alter
	 * the cmd buf offset and NULL its data.
	 */
	apdu->a_cmd.b_offset = 0;
	apdu->a_cmd.b_data = (uint8_t *)AID_PIV;
	apdu->a_cmd.b_len = sizeof (AID_PIV);

	rv = piv_apdu_transceive_chain(tk, apdu);
	if (rv) {
		rv = ioerrf(rv, tk->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_select.transceive_apdu failed",
		    "error", BNY_ERF, rv, NULL);
		goto out;
	}

	if (apdu->a_sw == SW_NO_ERROR || apdu->a_sw == SW_WARNING_EOF) {
		struct piv_rts rts;
		bzero(&rts, sizeof (rts));
		rv = piv_decode_rts(&rts, &apdu->a_reply);
		/*
		 * Some cards will interpret the ext-len SELECT as a zero-length
		 * SELECT and return an interindustry DO instead (e.g. the 6F
		 * tagged FCI template).
		 *
		 * If we get something strange, reset and try again without xlen.
		 */
		if (rv && errf_caused_by(rv, "PIVTagError") &&
		    tk->pt_xselect != XLEN_NO) {
			errf_free(rv);
			tk->pt_xselect = XLEN_NO;
			tk->pt_xapdu = XLEN_NO;
			xapdu = XLEN_UNKNOWN;
			goto again;
		}
		if (rv)
			goto invdata;
		tk->pt_app_label = rts.pr_app_label;
		tk->pt_app_uri = rts.pr_app_uri;
		tk->pt_alg_count = rts.pr_alg_count;
		bcopy(rts.pr_algs, tk->pt_algs, sizeof (tk->pt_algs));

		if (tk->pt_xapdu == XLEN_YES &&
		    tk->pt_xselect == XLEN_UNKNOWN) {
			tk->pt_xselect = XLEN_YES;
			xapdu = XLEN_YES;
			/*
			 * Defaults, chosen to be safe for most JavaCard
			 * implementations. If a card supports more than this
			 * they should probably include an ext-len info tag
			 * in their RTS.
			 */
			tk->pt_xapdu_cmd_max = 0x7FF;
			tk->pt_xapdu_resp_max = 0x800;
		}

		if (tk->pt_proto != SCARD_PROTOCOL_T1 &&
		    rts.pr_has_xlen_info) {
			bunyan_log(BNY_WARN, "piv_select: card advertises "
			    "extended-length APDU support but we aren't "
			    "connected with T=1, ignoring",
			    "reader", BNY_STRING, tk->pt_rdrname, NULL);
		} else if (tk->pt_proto == SCARD_PROTOCOL_T1 &&
		    rts.pr_has_xlen_info &&
		    rts.pr_max_cmd_apdu > 256 &&
		    rts.pr_max_resp_apdu > 256) {
			bunyan_log(BNY_DEBUG, "got ext-len apdu info from RTS",
			    "reader", BNY_STRING, tk->pt_rdrname,
			    "cmd_max", BNY_SIZE_T, rts.pr_max_cmd_apdu,
			    "resp_max", BNY_SIZE_T, rts.pr_max_resp_apdu,
			    NULL);
			tk->pt_xapdu = (xapdu = XLEN_YES);
			tk->pt_xapdu_cmd_max = rts.pr_max_cmd_apdu;
			tk->pt_xapdu_resp_max = rts.pr_max_resp_apdu;
		}
		rv = ERRF_OK;

	} else if (tk->pt_xselect != XLEN_NO &&
	    (apdu->a_sw == SW_WRONG_LENGTH || apdu->a_sw == SW_INS_NOT_SUP)) {
		bunyan_log(BNY_DEBUG, "card does not seem to support extended"
		    " length select APDUs, trying normal",
		    "reader", BNY_STRING, tk->pt_rdrname, NULL);
		tk->pt_xselect = XLEN_NO;
		tk->pt_xapdu = XLEN_NO;
		goto again;

	} else {
		rv = errf("NotFoundError", swerrf("INS_SELECT", apdu->a_sw),
		    "PIV applet was not found on device '%s'", tk->pt_rdrname);
		bunyan_log(BNY_DEBUG, "card did not accept INS_SELECT for PIV",
		    "error", BNY_ERF, rv, NULL);
	}

out:
	piv_apdu_free(apdu);
	tk->pt_xapdu = xapdu;
	return (rv);

invdata:
	rv = invderrf(rv, tk->pt_rdrname);
	debug_dump(rv, apdu);
	goto out;
}

/*
 * see [piv] 800-73-4 part 2 appendix A.1
 */
errf_t *
piv_auth_admin(struct piv_token *pt, const uint8_t *key, size_t keylen,
    enum piv_alg keyalg)
{
	errf_t *err;
	int rv;
	struct apdu *apdu = NULL;
	struct tlv_state *tlv;
	uint tag;
	uint8_t *chal = NULL, *resp = NULL, *iv = NULL;
	size_t challen = 0, ivlen, resplen = 0;
	const struct sshcipher *cipher;
	struct sshcipher_ctx *cctx;

	VERIFY(pt->pt_intxn == B_TRUE);

	switch (keyalg) {
		case PIV_ALG_3DES:
			cipher = cipher_by_name("3des-cbc");
			break;
		case PIV_ALG_AES128:
			cipher = cipher_by_name("aes128-cbc");
			break;
		case PIV_ALG_AES256:
			cipher = cipher_by_name("aes256-cbc");
			break;
		case PIV_ALG_AES192:
			cipher = cipher_by_name("aes192-cbc");
			break;
		default:
			return (argerrf("key", "a supported key algorithm",
			    "%u", keyalg));
	}

	VERIFY(cipher != NULL);
	VERIFY(cipher_authlen(cipher) == 0);
	if (cipher_keylen(cipher) != keylen) {
		return (argerrf("key", "a buffer of length %u",
		    "%u bytes long", cipher_keylen(cipher), keylen));
	}

	/*
	 * We only do single-step challenge-response auth at the moment, not
	 * the two-step mutual auth using a witness value.
	 */
	tlv = tlv_init_write();
	tlv_push(tlv, 0x7C);
	tlv_push(tlv, GA_TAG_CHALLENGE);
	tlv_pop(tlv);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_AUTH, keyalg,
	    PIV_SLOT_ADMIN);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(BNY_DEBUG, "piv_auth_admin.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);
	tlv = NULL;

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
	if ((err = tlv_read_tag(tlv, &tag)))
		goto invdata;
	if (tag != 0x7C) {
		err = tagerrf("INS_GEN_AUTH(9b)", tag);
		goto invdata;
	}

	while (!tlv_at_end(tlv)) {
		if ((err = tlv_read_tag(tlv, &tag)))
			goto invdata;
		if (tag == GA_TAG_CHALLENGE) {
			err = tlv_read_alloc(tlv, &chal, &challen);
			if (err)
				goto invdata;
			if ((err = tlv_end(tlv)))
				goto invdata;
			continue;
		}
		tlv_skip(tlv);
	}
	if ((err = tlv_end(tlv)))
		goto invdata;

	VERIFY(chal != NULL);
	tlv_free(tlv);
	tlv = NULL;
	piv_apdu_free(apdu);
	apdu = NULL;

	resplen = challen;
	resp = calloc_conceal(1, resplen);
	VERIFY(resp != NULL);

	if (cipher_blocksize(cipher) != challen) {
		err = invderrf(errf("LengthError", NULL, "INS_GEN_AUTH(9b) "
		    "returned %d byte challenge but cipher blocks are %d bytes",
		    challen, cipher_blocksize(cipher)), pt->pt_rdrname);
		goto out;
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
	tlv_write(tlv, resp, resplen);
	tlv_pop(tlv);
	tlv_pop(tlv);

	pt->pt_reset = B_TRUE;

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_AUTH, keyalg,
	    PIV_SLOT_ADMIN);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	free(chal);
	chal = NULL;
	freezero(resp, resplen);
	resp = NULL;

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(BNY_DEBUG, "piv_auth_admin.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		goto out;
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
	} else if (apdu->a_sw == SW_INCORRECT_P1P2) {
		err = errf("NotFoundError", swerrf("INS_GEN_AUTH(9b)",
		    apdu->a_sw), "PIV device '%s' has no admin key",
		    pt->pt_rdrname);
	} else if (apdu->a_sw == SW_WRONG_DATA ||
	    apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GEN_AUTH(9b)", apdu->a_sw),
		    pt->pt_rdrname, "authenticating with 9B admin key");
	} else {
		err = swerrf("INS_GEN_AUTH(9B)", apdu->a_sw);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

out:
	freezero(resp, resplen);
	free(chal);
	free(iv);
	tlv_free(tlv);
	piv_apdu_free(apdu);
	return (err);

invdata:
	err = invderrf(err, pt->pt_rdrname);
	debug_dump(err, apdu);
	tlv_abort(tlv);
	goto out;
}

errf_t *
piv_write_pinfo(struct piv_token *pt, const struct piv_pinfo *pinfo)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint8_t *data;
	size_t len;

	VERIFY(pt->pt_intxn == B_TRUE);

	err = piv_pinfo_encode(pinfo, &data, &len);
	if (err)
		return (err);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_u8to32(tlv, PIV_TAG_PRINTINFO);
	tlv_pop(tlv);
	tlv_push(tlv, 0x53);
	tlv_write(tlv, (uint8_t *)data, len);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_PUT_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_write_pinfo.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
	} else if (apdu->a_sw == SW_OUT_OF_MEMORY) {
		err = errf("DeviceOutOfMemoryError", swerrf("INS_PUT_DATA(PINFO)",
		    apdu->a_sw), "Out of memory to store file object on "
		    "PIV device '%s'", pt->pt_rdrname);
	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_PUT_DATA(PINFO)", apdu->a_sw),
		    pt->pt_rdrname, "writing PINFO object");
	} else if (apdu->a_sw == SW_FUNC_NOT_SUPPORTED) {
		err = notsuperrf(swerrf("INS_PUT_DATA(PINFO)", apdu->a_sw),
		    pt->pt_rdrname, "PINFO object");
	} else {
		err = swerrf("INS_PUT_DATA(PINFO)", apdu->a_sw);
	}

	piv_apdu_free(apdu);

	return (err);
}

errf_t *
piv_write_chuid(struct piv_token *pt, const struct piv_chuid *chuid)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint8_t *data;
	size_t len;

	VERIFY(pt->pt_intxn == B_TRUE);

	err = piv_chuid_encode(chuid, &data, &len);
	if (err)
		return (err);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_u8to32(tlv, PIV_TAG_CHUID);
	tlv_pop(tlv);
	tlv_push(tlv, 0x53);
	tlv_write(tlv, (uint8_t *)data, len);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_PUT_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_write_pinfo.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR) {
		const uint8_t *nguid;

		piv_chuid_free(pt->pt_chuid);
		if ((err = piv_chuid_clone(chuid, &pt->pt_chuid))) {
			piv_apdu_free(apdu);
			return (err);
		}
		nguid = piv_chuid_get_guid(chuid);
		bcopy(nguid, pt->pt_guid, sizeof (pt->pt_guid));

		free(pt->pt_guidhex);
		pt->pt_guidhex = NULL;

	} else if (apdu->a_sw == SW_OUT_OF_MEMORY) {
		err = errf("DeviceOutOfMemoryError", swerrf("INS_PUT_DATA(PINFO)",
		    apdu->a_sw), "Out of memory to store file object on "
		    "PIV device '%s'", pt->pt_rdrname);
	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_PUT_DATA(PINFO)", apdu->a_sw),
		    pt->pt_rdrname, "writing PINFO object");
	} else if (apdu->a_sw == SW_FUNC_NOT_SUPPORTED) {
		err = notsuperrf(swerrf("INS_PUT_DATA(PINFO)", apdu->a_sw),
		    pt->pt_rdrname, "PINFO object");
	} else {
		err = swerrf("INS_PUT_DATA(PINFO)", apdu->a_sw);
	}

	piv_apdu_free(apdu);

	return (err);
}

/*
 * see [piv] 800-73-4 part 2 section 3.3.1
 */
errf_t *
piv_write_file(struct piv_token *pt, uint tag, const uint8_t *data, size_t len)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;

	VERIFY(pt->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_u8to32(tlv, tag);
	tlv_pop(tlv);
	tlv_push(tlv, 0x53);
	tlv_write(tlv, (uint8_t *)data, len);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_PUT_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_write_file.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);
	tlv = NULL;

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

/*
 * see [piv] 800-73-4 part 2 section 3.3.2
 */
static errf_t *
piv_generate_common(struct piv_token *pt, struct apdu *apdu,
    struct tlv_state *tlv, enum piv_alg alg, enum piv_slotid slotid,
    struct sshkey **pubkey)
{
	errf_t *err;
	int rv;
	uint tag;
	struct sshkey *k = NULL;
	BIGNUM *mod = NULL, *exp = NULL;
	EC_POINT *point = NULL;
	EC_KEY *eck = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_generate.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		goto out;
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		if ((err = tlv_read_tag(tlv, &tag)))
			goto invdata;
		if (tag != 0x7F49) {
			err = tagerrf("INS_GEN_ASYM", tag);
			goto invdata;
		}
		if (alg == PIV_ALG_RSA1024 || alg == PIV_ALG_RSA2048 ||
		    alg == PIV_ALG_RSA3072 || alg == PIV_ALG_RSA4096) {
			k = sshkey_new(KEY_RSA);
			VERIFY(k != NULL);

		} else if (alg == PIV_ALG_ECCP256) {
			k = sshkey_new(KEY_ECDSA);
			VERIFY(k != NULL);
			k->ecdsa_nid = NID_X9_62_prime256v1;

		} else if (alg == PIV_ALG_ECCP384) {
			k = sshkey_new(KEY_ECDSA);
			VERIFY(k != NULL);
			k->ecdsa_nid = NID_secp384r1;

		} else if (alg == PIV_ALG_ED25519) {
			k = sshkey_new(KEY_ED25519);
			VERIFY(k != NULL);

		} else {
			err = argerrf("alg", "a supported algorithm", "%d", alg);
			tlv_abort(tlv);
			goto out;
		}
		while (!tlv_at_end(tlv)) {
			if ((err = tlv_read_tag(tlv, &tag)))
				goto invdata;
			if (alg == PIV_ALG_RSA1024 || alg == PIV_ALG_RSA2048 ||
			    alg == PIV_ALG_RSA3072 || alg == PIV_ALG_RSA4096) {
				if (tag == 0x81) {		/* Modulus */
					mod = BN_bin2bn(tlv_ptr(tlv),
					    tlv_rem(tlv), NULL);
					if (mod == NULL) {
						make_sslerrf(err, "BN_bin2bn",
						    "parsing RSA key");
						goto invdata;
					}
				} else if (tag == 0x82) {	/* Exponent */
					exp = BN_bin2bn(tlv_ptr(tlv),
					    tlv_rem(tlv), NULL);
					if (exp == NULL) {
						make_sslerrf(err, "BN_bin2bn",
						    "parsing RSA key");
						goto invdata;
					}
				} else {
					err = tagerrf("INS_GEN_ASYM", tag);
					goto invdata;
				}
				if (mod == NULL || exp == NULL) {
					tlv_skip(tlv);
					continue;
				}

				rsa = RSA_new();
				VERIFY(rsa != NULL);
				rv = RSA_set0_key(rsa, mod, exp, NULL);
				if (rv != 1) {
					make_sslerrf(err, "RSA_set0_key",
					    "parsing RSA key");
					goto invdata;
				}
				mod = NULL;
				exp = NULL;

				pkey = EVP_PKEY_new();
				VERIFY(pkey != NULL);
				EVP_PKEY_assign_RSA(pkey, rsa);
				rsa = NULL;

				EVP_PKEY_free(k->pkey);
				k->pkey = pkey;
				pkey = NULL;

				tlv_skip(tlv);
				continue;
			} else if (alg == PIV_ALG_ECCP256 ||
			    alg == PIV_ALG_ECCP384) {
				if (tag == 0x86) {
					const EC_GROUP *g;

					pkey = EVP_PKEY_new();
					VERIFY(pkey != NULL);

					eck = EC_KEY_new_by_curve_name(
					    k->ecdsa_nid);
					VERIFY(eck != NULL);
					EC_KEY_set_asn1_flag(eck,
					    OPENSSL_EC_NAMED_CURVE);

					g = EC_KEY_get0_group(eck);
					VERIFY(g != NULL);
					point = EC_POINT_new(g);
					VERIFY(point != NULL);
					rv = EC_POINT_oct2point(g, point,
					    tlv_ptr(tlv), tlv_rem(tlv), NULL);
					if (rv != 1) {
						make_sslerrf(err,
						    "EC_POINT_oct2point",
						    "parsing pubkey");
						goto invdata;
					}

					rv = sshkey_ec_validate_public(g,
					    point);
					if (rv) {
						err = ssherrf(
						    "sshkey_ec_validate_public",
						    rv);
						goto invdata;
					}
					rv = EC_KEY_set_public_key(
					    eck, point);
					if (rv != 1) {
						make_sslerrf(err,
						    "EC_KEY_set_public_key",
						    "parsing pubkey");
						goto invdata;
					}

					EVP_PKEY_assign_EC_KEY(pkey, eck);
					eck = NULL;

					EVP_PKEY_free(k->pkey);
					k->pkey = pkey;
					pkey = NULL;

					tlv_skip(tlv);
					continue;
				} else {
					err = tagerrf("INS_GEN_ASYM", tag);
					goto invdata;
				}
			} else if (alg == PIV_ALG_ED25519 ||
			    alg == PIV_ALG_X25519) {
				if (tag == 0x86) {
					uint8_t *buf;
					size_t len;

					err = tlv_read_alloc(tlv, &buf, &len);
					if (err)
						goto invdata;
					if (len != 32) {
						free(buf);
						err = errf("LengthError", NULL,
						    "ed25519/x25519 key wrong"
						    "length: %lld", len);
						goto invdata;
					}
					k->ed25519_pk = buf;

					if ((err = tlv_end(tlv)))
						goto invdata;

					continue;
				} else {
					err = tagerrf("INS_GEN_ASYM", tag);
					goto invdata;
				}
			}
			err = tagerrf("INS_GEN_ASYM", tag);
			goto invdata;
		}
		if ((err = tlv_end(tlv)))
			goto invdata;

		*pubkey = k;

		err = ERRF_OK;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GEN_ASYM", apdu->a_sw), pt->pt_rdrname,
		    "generating new key in slot %02x", (uint)slotid);

	} else {
		err = swerrf("INS_GEN_ASYM", apdu->a_sw);
	}

out:
	BN_free(mod);
	BN_free(exp);
	EC_POINT_free(point);
	EC_KEY_free(eck);
	RSA_free(rsa);
	EVP_PKEY_free(pkey);
	tlv_free(tlv);
	piv_apdu_free(apdu);
	return (err);

invdata:
	err = invderrf(err, pt->pt_rdrname);
	debug_dump(err, apdu);
	tlv_abort(tlv);
	goto out;
}

/*
 * see [piv] 800-73-4 part 2 section 3.3.2
 */
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
	tlv_write_u8to32(tlv, alg);
	tlv_pop(tlv);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_ASYM, 0x00, slotid);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	return (piv_generate_common(pt, apdu, tlv, alg, slotid, pubkey));
}

errf_t *
ykpiv_move_key(struct piv_token *pt, struct piv_slot *src,
    enum piv_slotid dest)
{
	struct apdu *apdu;
	errf_t *err;

	VERIFY(pt->pt_intxn);

	/* Reject if this isn't a YubicoPIV card. */
	if (!pt->pt_ykpiv)
		return (argerrf("pt", "a YubicoPIV-compatible token", "not"));
	if (ykpiv_version_compare(pt, 5, 7, 0) == -1) {
		return (argerrf("pt", "MANAGE_KEY only on YubicoPIV "
		    "version >=5.7", "not supported by this device (v%d.%d.%d)",
		    pt->pt_ykver[0], pt->pt_ykver[1], pt->pt_ykver[2]));
	}

	apdu = piv_apdu_make(CLA_ISO, INS_MANAGE_KEY, dest, src->ps_slot);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		goto out;
	}

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		err = ERRF_OK;

	} else if (apdu->a_sw == SW_FUNC_NOT_SUPPORTED) {
		err = notsuperrf(swerrf("YK_INS_MANAGE_KEY", apdu->a_sw),
		    pt->pt_rdrname, "key slot 0x%02X", src->ps_slot);

	} else {
		err = swerrf("YK_INS_MANAGE_KEY", apdu->a_sw);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

out:
	piv_apdu_free(apdu);
	return (err);
}

errf_t *
ykpiv_delete_key(struct piv_token *pt, struct piv_slot *slot)
{
	struct apdu *apdu;
	errf_t *err;

	VERIFY(pt->pt_intxn);

	/* Reject if this isn't a YubicoPIV card. */
	if (!pt->pt_ykpiv)
		return (argerrf("pt", "a YubicoPIV-compatible token", "not"));
	if (ykpiv_version_compare(pt, 5, 7, 0) == -1) {
		return (argerrf("pt", "MANAGE_KEY only on YubicoPIV "
		    "version >=5.7", "not supported by this device (v%d.%d.%d)",
		    pt->pt_ykver[0], pt->pt_ykver[1], pt->pt_ykver[2]));
	}

	apdu = piv_apdu_make(CLA_ISO, INS_MANAGE_KEY, 0xFF, slot->ps_slot);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		goto out;
	}

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		err = ERRF_OK;

	} else if (apdu->a_sw == SW_FUNC_NOT_SUPPORTED) {
		err = notsuperrf(swerrf("YK_INS_MANAGE_KEY", apdu->a_sw),
		    pt->pt_rdrname, "key slot 0x%02X", slot->ps_slot);

	} else {
		err = swerrf("YK_INS_MANAGE_KEY", apdu->a_sw);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

out:
	piv_apdu_free(apdu);
	return (err);
}

errf_t *
ykpiv_admin_auth_info(struct piv_token *pt, enum piv_alg *palg,
    boolean_t *pis_default, enum ykpiv_touch_policy *ptouchpol)
{
	struct apdu *apdu;
	struct tlv_state *tlv = NULL;
	errf_t *err;
	uint tag;
	enum piv_alg alg = PIV_ALG_3DES;
	enum ykpiv_touch_policy touchpol = YKPIV_TOUCH_DEFAULT;
	boolean_t is_default = B_FALSE;
	uint8_t v;

	VERIFY(pt->pt_intxn);

	/* Reject if this isn't a YubicoPIV card. */
	if (!pt->pt_ykpiv)
		return (argerrf("pt", "a YubicoPIV-compatible token", "not"));
	if (ykpiv_version_compare(pt, 5, 3, 0) == -1) {
		return (argerrf("pt", "GET_METADATA only on YubicoPIV "
		    "version >=5.3", "not supported by this device (v%d.%d.%d)",
		    pt->pt_ykver[0], pt->pt_ykver[1], pt->pt_ykver[2]));
	}

	apdu = piv_apdu_make(CLA_ISO, INS_GET_METADATA, 0x00, PIV_SLOT_ADMIN);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		goto out;
	}

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		while (!tlv_at_end(tlv)) {
			if ((err = tlv_read_tag(tlv, &tag)))
				goto invdata;
			switch (tag) {
			case 0x01:
				if (tlv_rem(tlv) != 1) {
					err = errf("LengthError", NULL,
					    "ykpiv metadata tag 0x%02x has "
					    "incorrect length: %d", tag,
					    tlv_rem(tlv));
					goto invdata;
				}
				if ((err = tlv_read_u8(tlv, &v)))
					goto invdata;
				alg = v;
				if ((err = tlv_end(tlv)))
					goto invdata;
				break;
			case 0x02:
				if (tlv_rem(tlv) != 2) {
					err = errf("LengthError", NULL,
					    "ykpiv metadata tag 0x%02x has "
					    "incorrect length: %d", tag,
					    tlv_rem(tlv));
					goto invdata;
				}
				if ((err = tlv_read_u8(tlv, &v)))
					goto invdata;
				if ((err = tlv_read_u8(tlv, &v)))
					goto invdata;
				touchpol = v;
				if ((err = tlv_end(tlv)))
					goto invdata;
				break;
			case 0x05:
				if (tlv_rem(tlv) != 1) {
					err = errf("LengthError", NULL,
					    "ykpiv metadata tag 0x%02x has "
					    "incorrect length: %d", tag,
					    tlv_rem(tlv));
					goto invdata;
				}
				if ((err = tlv_read_u8(tlv, &v)))
					goto invdata;
				if (v != 0 && v != 1) {
					err = errf("ValueError", NULL,
					    "ykpiv metadata tag 0x%02x has "
					    "invalid value: %d", tag, v);
					goto invdata;
				}
				is_default = v;
				if ((err = tlv_end(tlv)))
					goto invdata;
				break;
			default:
				tlv_skip(tlv);
			}
		}
		err = NULL;

	} else if (apdu->a_sw == SW_FUNC_NOT_SUPPORTED) {
		err = notsuperrf(swerrf("YK_INS_GET_METADATA", apdu->a_sw),
		    pt->pt_rdrname, "key slot 0x9B");

	} else {
		err = swerrf("YK_INS_GET_METADATA", apdu->a_sw);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	if (palg != NULL)
		*palg = alg;
	if (pis_default != NULL)
		*pis_default = is_default;
	if (ptouchpol != NULL)
		*ptouchpol = touchpol;

out:
	tlv_free(tlv);
	piv_apdu_free(apdu);
	return (err);

invdata:
	tlv_abort(tlv);
	err = invderrf(err, pt->pt_rdrname);
	debug_dump(err, apdu);
	goto out;
}

/*
 * Documented at
 * https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
 * under "GET METADATA". Some of the details (like format of policy field) had
 * to be learned by reading the code in libykcs11.
 */
errf_t *
ykpiv_get_metadata(struct piv_token *pt, struct piv_slot *slot)
{
	struct apdu *apdu;
	struct tlv_state *tlv = NULL;
	errf_t *err;
	uint tag;
	enum ykpiv_pin_policy pinpol;
	enum ykpiv_touch_policy touchpol;
	uint8_t v;

	VERIFY(pt->pt_intxn);

	/* Reject if this isn't a YubicoPIV card. */
	if (!pt->pt_ykpiv)
		return (argerrf("tk", "a YubicoPIV-compatible token", "not"));
	if (ykpiv_version_compare(pt, 5, 3, 0) == -1) {
		return (argerrf("touchpolicy", "GET_METADATA only on YubicoPIV "
		    "version >=5.3", "not supported by this device (v%d.%d.%d)",
		    pt->pt_ykver[0], pt->pt_ykver[1], pt->pt_ykver[2]));
	}

	apdu = piv_apdu_make(CLA_ISO, INS_GET_METADATA, 0x00, slot->ps_slot);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		goto out;
	}

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		while (!tlv_at_end(tlv)) {
			if ((err = tlv_read_tag(tlv, &tag)))
				goto invdata;
			switch (tag) {
			case 0x01:
				if (tlv_rem(tlv) != 1) {
					err = errf("LengthError", NULL,
					    "ykpiv metadata tag 0x%02x has "
					    "incorrect length: %d", tag,
					    tlv_rem(tlv));
					goto invdata;
				}
				if ((err = tlv_read_u8(tlv, &v)))
					goto invdata;
				if ((err = tlv_end(tlv)))
					goto invdata;
				slot->ps_alg = v;
				break;
			case 0x02:
				if (tlv_rem(tlv) != 2) {
					err = errf("LengthError", NULL,
					    "ykpiv metadata tag 0x%02x has "
					    "incorrect length: %d", tag,
					    tlv_rem(tlv));
					goto invdata;
				}
				if ((err = tlv_read_u8(tlv, &v)))
					goto invdata;
				pinpol = v;
				if ((err = tlv_read_u8(tlv, &v)))
					goto invdata;
				touchpol = v;
				if ((err = tlv_end(tlv)))
					goto invdata;
				if (pinpol == YKPIV_PIN_ONCE ||
				    pinpol == YKPIV_PIN_ALWAYS) {
					slot->ps_auth |= PIV_SLOT_AUTH_PIN;
				}
				if (pinpol == YKPIV_PIN_NEVER) {
					slot->ps_auth &= ~PIV_SLOT_AUTH_PIN;
				}
				if (touchpol == YKPIV_TOUCH_ALWAYS ||
				    touchpol == YKPIV_TOUCH_CACHED) {
					slot->ps_auth |= PIV_SLOT_AUTH_TOUCH;
				}
				if (touchpol == YKPIV_TOUCH_NEVER) {
					slot->ps_auth &= ~PIV_SLOT_AUTH_TOUCH;
				}
				break;
			default:
				tlv_skip(tlv);
			}
		}
		err = NULL;

	} else if (apdu->a_sw == SW_FUNC_NOT_SUPPORTED) {
		err = notsuperrf(swerrf("YK_INS_GET_METADATA", apdu->a_sw),
		    pt->pt_rdrname, "key slot 0x%02x", slot->ps_slot);

	} else {
		err = swerrf("YK_INS_GET_METADATA", apdu->a_sw);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

out:
	tlv_free(tlv);
	piv_apdu_free(apdu);
	return (err);

invdata:
	tlv_abort(tlv);
	err = invderrf(err, pt->pt_rdrname);
	debug_dump(err, apdu);
	goto out;
}

static errf_t *
ykpiv_attest_metadata(struct piv_token *pt, struct piv_slot *slot)
{
	uint8_t *ptr, *buf = NULL;
	size_t len = 0;
	X509 *cert;
	errf_t *err;
	int nid, idx;
	X509_EXTENSION *ext;
	ASN1_OCTET_STRING *octstr;
	const uint8_t *data;
	enum ykpiv_pin_policy pinpol;
	enum ykpiv_touch_policy touchpol;

	err = ykpiv_attest(pt, slot, &buf, &len);
	if (err != ERRF_OK)
		return (err);

	nid = OBJ_txt2nid("1.3.6.1.4.1.41482.3.8");
	if (nid == NID_undef) {
		nid = OBJ_create("1.3.6.1.4.1.41482.3.8", "ykAttestationPolicy",
		    "Yubico PIV attestation policy extension");
	}

	ptr = buf;
	cert = d2i_X509(NULL, (const uint8_t **)&ptr, len);
	if (cert == NULL) {
		make_sslerrf(err, "d2i_X509", "parsing attestation cert %02x",
		    (uint)slot->ps_slot);
		return (err);
	}
	free(buf);
	buf = NULL;

	idx = X509_get_ext_by_NID(cert, nid, -1);
	if (idx == -1) {
		err = errf("ExtensionMissing", NULL, "YubicoPIV attestation "
		    "extension for policy not present in attestation cert");
		return (invderrf(err, pt->pt_rdrname));
	}
	ext = X509_get_ext(cert, idx);
	if (ext == NULL) {
		err = errf("ExtensionMissing", NULL, "YubicoPIV attestation "
		    "extension for policy not present in attestation cert");
		return (invderrf(err, pt->pt_rdrname));
	}

	octstr = X509_EXTENSION_get_data(ext);
	if (octstr == NULL || ASN1_STRING_length(octstr) != 2) {
		err = errf("ExtensionInvalid", NULL, "YubicoPIV attestation "
		    "extension for policy does not contain valid data");
		return (invderrf(err, pt->pt_rdrname));
	}

	data = ASN1_STRING_data(octstr);
	pinpol = data[0];
	touchpol = data[1];
	bunyan_log(BNY_TRACE, "got policy bytes from attestation cert",
	    "pinpol", BNY_UINT, (uint)pinpol,
	    "touchpol", BNY_UINT, (uint)touchpol,
	    NULL);

	if (pinpol == YKPIV_PIN_ONCE ||
	    pinpol == YKPIV_PIN_ALWAYS) {
		slot->ps_auth |= PIV_SLOT_AUTH_PIN;
	}
	if (pinpol == YKPIV_PIN_NEVER) {
		slot->ps_auth &= ~PIV_SLOT_AUTH_PIN;
	}
	if (touchpol == YKPIV_TOUCH_ALWAYS ||
	    touchpol == YKPIV_TOUCH_CACHED) {
		slot->ps_auth |= PIV_SLOT_AUTH_TOUCH;
	}
	if (touchpol == YKPIV_TOUCH_NEVER) {
		slot->ps_auth &= ~PIV_SLOT_AUTH_TOUCH;
	}

	X509_free(cert);

	return (ERRF_OK);
}

/*
 * The yubico extensions for generate are documented in [yubico-piv]. They're
 * all extra tags which can be included underneath the 'AC' top-level template.
 */
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
	    ykpiv_version_compare(pt, 4, 3, 0) == -1) {
		return (argerrf("touchpolicy", "TOUCH_CACHED only on YubicoPIV "
		    "version >=4.3", "not supported by this device (v%d.%d.%d)",
		    pt->pt_ykver[0], pt->pt_ykver[1], pt->pt_ykver[2]));
	}

	tlv = tlv_init_write();
	tlv_push(tlv, 0xAC);
	tlv_push(tlv, 0x80);
	tlv_write_u8to32(tlv, alg);
	tlv_pop(tlv);
	if (pinpolicy != YKPIV_PIN_DEFAULT) {
		tlv_push(tlv, 0xAA);
		tlv_write_u8to32(tlv, pinpolicy);
		tlv_pop(tlv);
	}
	if (touchpolicy != YKPIV_TOUCH_DEFAULT) {
		tlv_push(tlv, 0xAB);
		tlv_write_u8to32(tlv, touchpolicy);
		tlv_pop(tlv);
	}
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_ASYM, 0x00, slotid);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	return (piv_generate_common(pt, apdu, tlv, alg, slotid, pubkey));
}

errf_t *
tlv_write_bignum(struct tlv_state *tlv, uint tag, const BIGNUM *v)
{
	u_char *d = NULL;
	errf_t *err = NULL;
	size_t len;

	d = malloc(SSHBUF_MAX_BIGNUM);
	if (d == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	len = BN_num_bytes(v);
	if (BN_bn2bin(v, d) != len) {
		make_sslerrf(err, "BN_bn2bin", "bignum too long");
		goto out;
	}
	tlv_push(tlv, tag);
	tlv_write(tlv, d, len);
	tlv_pop(tlv);

out:
	free(d);
	return (err);
}

/*
 * Documented under [yubico-piv]
 */
errf_t *
ykpiv_import(struct piv_token *pt, enum piv_slotid slotid, struct sshkey *key,
    enum ykpiv_pin_policy pinpolicy, enum ykpiv_touch_policy touchpolicy)
{
	struct tlv_state *tlv;
	errf_t *err;
	enum piv_alg alg;
	struct apdu *apdu = NULL;
	RSA *rsa;
	EC_KEY *eck;

	VERIFY(pt->pt_intxn);

	tlv = tlv_init_write();

	switch (key->type) {
	case KEY_RSA:
		switch (sshkey_size(key)) {
		case 1024:
			alg = PIV_ALG_RSA1024;
			break;
		case 2048:
			alg = PIV_ALG_RSA2048;
			break;
		case 3072:
			alg = PIV_ALG_RSA3072;
			break;
		case 4096:
			alg = PIV_ALG_RSA4096;
			break;
		default:
			err = argerrf("privkey", "an RSA private key of "
			    "a supported size", "a %u-bit RSA key",
			    sshkey_size(key));
			goto out;
		}
		rsa = EVP_PKEY_get1_RSA(key->pkey);
		tlv_write_bignum(tlv, 0x01, RSA_get0_p(rsa));
		tlv_write_bignum(tlv, 0x02, RSA_get0_q(rsa));
		tlv_write_bignum(tlv, 0x03, RSA_get0_dmp1(rsa));
		tlv_write_bignum(tlv, 0x04, RSA_get0_dmq1(rsa));
		tlv_write_bignum(tlv, 0x05, RSA_get0_iqmp(rsa));
		break;
	case KEY_ECDSA:
		switch (sshkey_size(key)) {
		case 256:
			alg = PIV_ALG_ECCP256;
			break;
		case 384:
			alg = PIV_ALG_ECCP384;
			break;
		default:
			err = argerrf("privkey", "an ECDSA private key on "
			    "a supported curve", "on a %u-bit curve",
			    sshkey_size(key));
			goto out;
		}
		eck = EVP_PKEY_get1_EC_KEY(key->pkey);
		tlv_write_bignum(tlv, 0x06, EC_KEY_get0_private_key(eck));
		break;
	default:
		err = argerrf("privkey", "an RSA or ECDSA private key",
		    "%s key", sshkey_type(key));
		goto out;
	}

	apdu = piv_apdu_make(CLA_ISO, INS_IMPORT_ASYM, alg, slotid);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		goto out;
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
	} else if (apdu->a_sw == SW_OUT_OF_MEMORY) {
		err = errf("DeviceOutOfMemoryError",
		    swerrf("INS_IMPORT_ASYM(%x)", apdu->a_sw, slotid),
		    "Out of memory to store asym key object on "
		    "PIV device '%s'", pt->pt_rdrname);
	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_IMPORT_ASYM(%x)", apdu->a_sw,
		    slotid), pt->pt_rdrname, "importing private key");
	} else if (apdu->a_sw == SW_FUNC_NOT_SUPPORTED) {
		err = notsuperrf(swerrf("INS_IMPORT_ASYM(%x)", apdu->a_sw,
		    slotid), pt->pt_rdrname, "Importing private keys");
	} else {
		err = swerrf("INS_IMPORT_ASYM(%x)", apdu->a_sw, slotid);
	}

out:
	piv_apdu_free(apdu);
	tlv_free(tlv);
	return (err);
}

/*
 * [piv] 800-73-4 part 1 section 3.3.3
 * [piv] 800-73-4 part 1 appendix A (table 19)
 */
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
	tlv_write_u8to32(tlv, oncard);
	tlv_pop(tlv);

	tlv_push(tlv, 0xC2);
	tlv_write_u8to32(tlv, offcard);
	tlv_pop(tlv);

	if (offcard_url != NULL) {
		tlv_push(tlv, 0xF3);
		tlv_write(tlv, (uint8_t *)offcard_url, strlen(offcard_url));
		tlv_pop(tlv);
	}

	err = piv_write_file(pt, PIV_TAG_KEYHIST, tlv_buf(tlv), tlv_len(tlv));

	if (err == ERRF_OK) {
		pt->pt_hist_oncard = oncard;
		pt->pt_hist_offcard = offcard;
		free(pt->pt_hist_url);
		if (offcard_url != NULL)
			pt->pt_hist_url = strdup(offcard_url);
		else
			pt->pt_hist_url = NULL;
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

	if (data != NULL && datalen > 0) {
		tlv = tlv_init_write();
		tlv_push(tlv, 0x70);
		tlv_write(tlv, data, datalen);
		tlv_pop(tlv);
		tlv_push(tlv, 0x71);
		tlv_write_byte(tlv, (uint8_t)flags);
		tlv_pop(tlv);

		err = piv_write_file(pk, tag, tlv_buf(tlv), tlv_len(tlv));

		tlv_free(tlv);
	} else {
		err = piv_write_file(pk, tag, NULL, 0);
	}

	return (err);
}

/*
 * Attestation is documented under [yubico-piv] and also in the pages at
 * https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
 * and
 * https://developers.yubico.com/yubico-piv-tool/Attestation.html
 */
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
		bunyan_log(BNY_WARN, "piv_read_file.transceive_chain failed",
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
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

/*
 * see [piv] 800-73-4 part 2 section 3.1.2
 */
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
	tlv_write_u8to32(tlv, tag);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_read_file.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		if (apdu->a_reply.b_len < 1) {
			err = invderrf(errf("APDUError", NULL,
			    "Card replied with empty APDU to "
			    "INS_GET_DATA(%x)", tag), pt->pt_rdrname);
			goto out;
		}
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		if ((err = tlv_read_tag(tlv, &rtag)))
			goto invdata;
		if (rtag != 0x53) {
			err = tagerrf("INS_GET_DATA(%x)", rtag, tag);
			goto invdata;
		}
		err = tlv_read_alloc(tlv, data, len);
		if (err)
			goto invdata;
		if ((err = tlv_end(tlv)))
			goto invdata;
		err = ERRF_OK;

	} else if (apdu->a_sw == SW_FILE_NOT_FOUND) {
		err = errf("NotFoundError", swerrf("INS_GET_DATA", apdu->a_sw),
		    "No PIV file object found at tag %x", tag);

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GET_DATA", apdu->a_sw),
		    pt->pt_rdrname, "reading PIV file object at tag %x", tag);

	} else {
		err = swerrf("INS_GET_DATA(%x)", apdu->a_sw, tag);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

out:
	tlv_free(tlv);
	piv_apdu_free(apdu);
	return (err);

invdata:
	err = invderrf(err, pt->pt_rdrname);
	debug_dump(err, apdu);
	tlv_abort(tlv);
	goto out;
}

void
piv_file_data_free(uint8_t *data, size_t len)
{
	freezero(data, len);
}

/*
 * The structure inside the certificate objects is documented in
 * [piv] 800-73-4 part 2 appendix A, in tables 15 and onwards
 *
 * Towards the end of Appendix A (after table 39 or so) there is some
 * additional text explaining how CertInfo works and compression.
 */
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
	ASN1_INTEGER *serialasn1;
	BIGNUM *serial = NULL;

	VERIFY(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	switch (slotid) {
	case PIV_SLOT_9A:
		tlv_write_u8to32(tlv, PIV_TAG_CERT_9A);
		break;
	case PIV_SLOT_9C:
		tlv_write_u8to32(tlv, PIV_TAG_CERT_9C);
		break;
	case PIV_SLOT_9D:
		tlv_write_u8to32(tlv, PIV_TAG_CERT_9D);
		break;
	case PIV_SLOT_9E:
		tlv_write_u8to32(tlv, PIV_TAG_CERT_9E);
		break;
	default:
		if (slotid >= PIV_SLOT_RETIRED_1 &&
		    slotid <= PIV_SLOT_RETIRED_20) {
			tlv_write_u8to32(tlv, PIV_TAG_CERT_82 +
			    (slotid - PIV_SLOT_82));
			break;
		}
		err = argerrf("slotid", "a supported PIV slot number",
		    "%02x", slotid);
		tlv_pop(tlv);
		tlv_free(tlv);
		return (err);
	}
	tlv_pop(tlv);

	bunyan_log(BNY_DEBUG, "reading cert file",
	    "slot", BNY_UINT, (uint)slotid,
	    "cdata", BNY_BIN_HEX, tlv_buf(tlv), tlv_len(tlv),
	    NULL);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_read_cert.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		goto out;
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		if (apdu->a_reply.b_len < 1) {
			err = invderrf(errf("APDUError", NULL,
			    "Card replied with empty APDU reading certificate "
			    "for slot %02x", slotid), pk->pt_rdrname);
			goto out;
		}
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		if ((err = tlv_read_tag(tlv, &tag)))
			goto invdata;
		if (tag != 0x53) {
			err = tagerrf("INS_GET_DATA(%02x)", tag, (uint)slotid);
			goto invdata;
		}
		while (!tlv_at_end(tlv)) {
			if ((err = tlv_read_tag(tlv, &tag)))
				goto invdata;
			if (tag == 0x71) {
				if ((err = tlv_read_u8(tlv, &certinfo)) ||
				    (err = tlv_end(tlv))) {
					goto invdata;
				}
				continue;
			}
			if (tag == 0x70) {
				ptr = tlv_ptr(tlv);
				len = tlv_rem(tlv);
			}
			tlv_skip(tlv);
		}
		if ((err = tlv_end(tlv)))
			goto invdata;

		/* See the NIST PIV spec. This bit should always be zero. */
		if ((certinfo & PIV_CI_X509) != 0) {
			err = errf("CertFlagError", NULL,
			    "Certificate for slot %02x has PIV_CI_X509 flag "
			    "set, not allowed by spec", (uint)slotid);
			goto invdata;
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
				goto invdata;
			}
			if (strm.avail_out > PIV_MAX_CERT_LEN) {
				err = errf("DecompressionError", NULL,
				    "Compressed cert in slot %02x was "
				    "too big (%u bytes)", (uint)slotid,
				    strm.avail_out);
				goto invdata;
			}

			bunyan_log(BNY_DEBUG, "decompressed cert",
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
			goto invdata;
		}

		cert = d2i_X509(NULL, (const uint8_t **)&ptr, len);
		if (cert == NULL) {
			make_sslerrf(err, "d2i_X509", "parsing cert %02x",
			    (uint)slotid);
			goto invdata;
		}

		free(buf);
		buf = NULL;

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
			OPENSSL_free((void *)pc->ps_issuer);
			OPENSSL_free((void *)pc->ps_cert_ser_hex);
			X509_free(pc->ps_x509);
			sshkey_free(pc->ps_pubkey);
		}
		switch (pc->ps_slot) {
		case PIV_SLOT_CARD_AUTH:
		case PIV_SLOT_YK_ATTESTATION:
			break;
		default:
			pc->ps_auth |= PIV_SLOT_AUTH_PIN;
			break;
		}
		pc->ps_slot = slotid;
		pc->ps_x509 = cert;
		pc->ps_subj = X509_NAME_oneline(
		    X509_get_subject_name(cert), NULL, 0);
		pc->ps_issuer = X509_NAME_oneline(
		    X509_get_issuer_name(cert), NULL, 0);

		serialasn1 = X509_get_serialNumber(cert);
		serial = ASN1_INTEGER_to_BN(serialasn1, NULL);
		pc->ps_cert_ser_hex = BN_bn2hex(serial);
		BN_free(serial);

		pkey = X509_get_pubkey(cert);
		VERIFY(pkey != NULL);
		rv = sshkey_from_evp_pkey(pkey, KEY_UNSPEC,
		    &pc->ps_pubkey);
		EVP_PKEY_free(pkey);
		if (rv != 0) {
			err = ssherrf("sshkey_from_evp_pkey", rv);
			goto invdata;
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
			case 3072:
				pc->ps_alg = PIV_ALG_RSA3072;
				break;
			case 4096:
				pc->ps_alg = PIV_ALG_RSA4096;
				break;
			default:
				err = invderrf(errf("BadAlgorithmError", NULL,
				    "Cert subj is RSA key of size %u, not "
				    "supported by PIV",
				    sshkey_size(pc->ps_pubkey)),
				    pk->pt_rdrname);
			}
			break;
		case KEY_ED25519:
			pc->ps_alg = PIV_ALG_ED25519;
			break;
		default:
			err = invderrf(errf("BadAlgorithmError", NULL,
			    "Certificate subject key is of unsupported type: "
			    "%s", sshkey_type(pc->ps_pubkey)), pk->pt_rdrname);
		}

		if (err == NULL && pk->pt_ykpiv &&
		    ykpiv_version_compare(pk, 5, 3, 0) >= 0) {
			err = ykpiv_get_metadata(pk, pc);
			if (err == ERRF_OK) {
				pc->ps_got_metadata = B_TRUE;
			} else {
				/* Ignore it if it fails. */
				errf_free(err);
				err = NULL;
			}
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
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

out:
	free(buf);
	tlv_free(tlv);
	piv_apdu_free(apdu);
	return (err);

invdata:
	err = invderrf(err, pk->pt_rdrname);
	debug_dump(err, apdu);
	tlv_abort(tlv);
	goto out;
}

enum piv_slot_auth
piv_slot_get_auth(struct piv_token *pt, struct piv_slot *slot)
{
	errf_t *err;

	if (slot->ps_got_metadata)
		return (slot->ps_auth);

	if (pt->pt_ykpiv && ykpiv_version_compare(pt, 5, 3, 0) >= 0) {
		err = ykpiv_get_metadata(pt, slot);
		if (err == ERRF_OK) {
			slot->ps_got_metadata = B_TRUE;
			return (slot->ps_auth);
		} else {
			/* Ignore it if it fails. */
			bunyan_log(BNY_DEBUG, "getting metadata failed",
			    "error", BNY_ERF, err, NULL);
			errf_free(err);
		}
	}

	if (pt->pt_ykpiv && ykpiv_version_compare(pt, 4, 0, 0) >= 0) {
		err = ykpiv_attest_metadata(pt, slot);
		if (err == ERRF_OK) {
			slot->ps_got_metadata = B_TRUE;
			return (slot->ps_auth);
		} else {
			/* Ignore it if it fails. */
			bunyan_log(BNY_DEBUG, "getting metadata from "
			    "attestation cert failed",
			    "error", BNY_ERF, err, NULL);
			errf_free(err);
		}
	}

	/* Don't bother trying again if everything failed. */
	slot->ps_got_metadata = B_TRUE;

	return (slot->ps_auth);
}

static inline int
read_all_aborts_on(errf_t *err)
{
	return (err &&
	    !errf_caused_by(err, "NotFoundError") &&
	    !errf_caused_by(err, "PermissionError") &&
	    !errf_caused_by(err, "NotSupportedError") &&
	    !errf_caused_by(err, "InvalidDataError"));
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
	else if (err)
		errf_free(err);
	err = piv_read_cert(tk, PIV_SLOT_9A);
	if (read_all_aborts_on(err))
		return (err);
	else if (err)
		errf_free(err);
	err = piv_read_cert(tk, PIV_SLOT_9C);
	if (read_all_aborts_on(err))
		return (err);
	else if (err)
		errf_free(err);
	err = piv_read_cert(tk, PIV_SLOT_9D);
	if (read_all_aborts_on(err))
		return (err);
	else if (err)
		errf_free(err);

	for (i = 0; i < tk->pt_hist_oncard; ++i) {
		err = piv_read_cert(tk, PIV_SLOT_RETIRED_1 + i);
		if (read_all_aborts_on(err) && !errf_caused_by(err, "APDUError"))
			return (err);
		else if (err)
			errf_free(err);
	}

	tk->pt_did_read_all = B_TRUE;

	return (ERRF_OK);
}

/*
 * see [piv] 800-83-4 part 2 section 3.2.2
 */
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

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_change_pin.transceive failed",
		    "error", BNY_ERF, err, NULL);
		piv_apdu_free(apdu);
		return (err);
	}

	explicit_bzero(pinbuf, sizeof (pinbuf));

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
		if (pk->pt_used_pin == PIV_NO_PIN || pk->pt_used_pin == type)
			pk->pt_used_pin = type;
		else
			pk->pt_reset = B_TRUE;

	} else if ((apdu->a_sw & 0xFFF0) == SW_INCORRECT_PIN) {
		err = errf("PermissionError", swerrf("INS_CHANGE_PIN(%x)",
		    apdu->a_sw, type), "Incorrect PIN supplied");

	} else if (apdu->a_sw == SW_INVALID_KEY_REF) {
		err = errf("NotSupportedError", swerrf("INS_CHANGE_PIN(%x)",
		    apdu->a_sw, type), "PIN type %x not supported", type);

	} else {
		err = swerrf("INS_CHANGE_PIN(%x)", apdu->a_sw, type);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}
/*
 * see [piv] 800-83-4 part 2 section 3.2.3
 */

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

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_change_pin.transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		piv_apdu_free(apdu);
		return (err);
	}

	explicit_bzero(pinbuf, sizeof (pinbuf));

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
		if (pk->pt_used_pin == PIV_NO_PIN || pk->pt_used_pin == type)
			pk->pt_used_pin = type;
		else
			pk->pt_reset = B_TRUE;

	} else if ((apdu->a_sw & 0xFFF0) == SW_INCORRECT_PIN) {
		err = errf("PermissionError", swerrf("INS_RESET_PIN(%x)",
		    apdu->a_sw, type), "Incorrect PUK supplied");

	} else if (apdu->a_sw == SW_FILE_INVALID) {
		err = errf("PermissionError", swerrf("INS_RESET_PIN(%x)",
		    apdu->a_sw, type), "PUK is blocked due to too many "
		    "incorrect attempts");

	} else if (apdu->a_sw == SW_INVALID_KEY_REF) {
		err = errf("NotSupportedError", swerrf("INS_RESET_PIN(%x)",
		    apdu->a_sw, type), "PIN type %x not supported", type);

	} else {
		err = swerrf("INS_RESET_PIN(%x)", apdu->a_sw, type);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

errf_t *
ykpiv_reset(struct piv_token *pt)
{
	errf_t *err;
	struct apdu *apdu;

	VERIFY(pt->pt_intxn);
	if (!pt->pt_ykpiv)
		return (argerrf("tk", "a YubicoPIV-compatible token", "not"));

	apdu = piv_apdu_make(CLA_ISO, INS_RESET, 0, 0);

	err = piv_apdu_transceive(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		piv_apdu_free(apdu);
		return (err);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
		pt->pt_reset = B_TRUE;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_RESET", apdu->a_sw),
		    pt->pt_rdrname, "resetting YubicoPIV");

	} else if (apdu->a_sw == SW_CONDITIONS_NOT_SATISFIED) {
		err = errf("ResetConditionsError", swerrf("INS_RESET",
		    apdu->a_sw), "Conditions for use of INS_RESET "
		    "not met (all PINs and PUK must be blocked)");

	} else if (apdu->a_sw == SW_INS_NOT_SUP) {
		err = notsuperrf(swerrf("INS_RESET", apdu->a_sw),
		    pt->pt_rdrname, "YubicoPIV extensions");

	} else {
		err = swerrf("INS_RESET", apdu->a_sw);
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

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN,
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
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

	piv_apdu_free(apdu);

	return (err);
}

errf_t *
ykpiv_set_admin(struct piv_token *pk, const uint8_t *key, size_t keylen,
    enum piv_alg alg, enum ykpiv_touch_policy touchpolicy)
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
	databuf[0] = alg;
	databuf[1] = 0x9B;
	databuf[2] = keylen;
	bcopy(key, &databuf[3], keylen);

	apdu = piv_apdu_make(CLA_ISO, INS_SET_MGMT, 0xFF, p2);
	apdu->a_cmd.b_data = databuf;
	apdu->a_cmd.b_len = 3 + keylen;

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN,
		    "ykpiv_set_admin.transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		piv_apdu_free(apdu);
		return (err);
	}

	freezero(databuf, 3 + keylen);

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
		bunyan_log(BNY_DEBUG, "card did not accept INS_SET_MGMT",
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

		err = piv_apdu_transceive_chain(pk, apdu);
		if (err) {
			err = ioerrf(err, pk->pt_rdrname);
			bunyan_log(BNY_WARN, "piv_verify_pin.transceive failed",
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
			bunyan_log(BNY_DEBUG, "card did not accept INS_VERIFY"
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

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_verify_pin.transceive failed",
		    "error", BNY_ERF, err, NULL);
		piv_apdu_free(apdu);
		return (err);
	}

	explicit_bzero(pinbuf, sizeof (pinbuf));

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
		if (pk->pt_used_pin == PIV_NO_PIN || pk->pt_used_pin == type)
			pk->pt_used_pin = type;
		else
			pk->pt_reset = B_TRUE;

	} else if (apdu->a_sw == SW_FILE_INVALID) {
		if (retries != NULL)
			*retries = 0;
		err = errf("PermissionError", swerrf("INS_VERIFY(%x)",
		    apdu->a_sw, type), "PIN is blocked (has run out of "
		    "retry attempts) and cannot be used");

	} else if ((apdu->a_sw & 0xFFF0) == SW_INCORRECT_PIN) {
		if (retries != NULL)
			*retries = (apdu->a_sw & 0x000F);
		err = errf("PermissionError", swerrf("INS_VERIFY(%x)",
		    apdu->a_sw, type), "Incorrect PIN supplied");

	} else if (apdu->a_sw == SW_INVALID_KEY_REF) {
		err = errf("NotSupportedError", swerrf("INS_VERIFY(%x)",
		    apdu->a_sw, type), "PIN type %x not supported", type);

	} else {
		err = swerrf("INS_VERIFY(%x)", apdu->a_sw, type);
		bunyan_log(BNY_DEBUG, "unexpected card error",
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
	int i, rc;
	errf_t *err;
	struct ssh_digest_ctx *hctx;
	uint8_t *buf;
	size_t nread, dglen, inplen;
	boolean_t cardhash = B_FALSE, ch_sha256 = B_FALSE, ch_sha384 = B_FALSE;
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
	case PIV_ALG_RSA3072:
		inplen = 384;
		if (*hashalgo == SSH_DIGEST_SHA1) {
			dglen = 20;
		} else if (*hashalgo == SSH_DIGEST_SHA512) {
			dglen = 64;
		} else {
			*hashalgo = SSH_DIGEST_SHA256;
			dglen = 32;
		}
		break;
	case PIV_ALG_RSA4096:
		inplen = 512;
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
		/*
		 * JC22x cards running PivApplet have proprietary algorithm IDs
		 * for hash-on-card ECDSA since they can't sign a precomputed
		 * hash value from the host like they're supposed to.
		 *
		 * If it's one of these cards, it advertises
		 * PIV_ALG_ECCP256_SHA* in the pt_algs list. If we have this,
		 * try to use it (since regular ECCP256 won't work).
		 */
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
				/*
				 * In sign_prehash we just send ps_alg as the
				 * alg ID to the card. So stash the old one here
				 * and replace it with the _SHA* variant.
				 */
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
				oldalg = slot->ps_alg;
				slot->ps_alg = PIV_ALG_ECCP256_SHA1;
			}
		}
		break;
	case PIV_ALG_ECCP384:
		inplen = 48;
		/*
		 * JC22x cards running PivApplet have proprietary algorithm IDs
		 * for hash-on-card ECDSA since they can't sign a precomputed
		 * hash value from the host like they're supposed to.
		 *
		 * If it's one of these cards, it advertises
		 * PIV_ALG_ECCP384_SHA* in the pt_algs list. If we have this,
		 * try to use it (since regular ECCP384 won't work).
		 */
		for (i = 0; i < tk->pt_alg_count; ++i) {
			if (tk->pt_algs[i] == PIV_ALG_ECCP384_SHA384) {
				cardhash = B_TRUE;
				ch_sha384 = B_TRUE;
			} else if (tk->pt_algs[i] == PIV_ALG_ECCP384_SHA256) {
				cardhash = B_TRUE;
				ch_sha256 = B_TRUE;
			} else if (tk->pt_algs[i] == PIV_ALG_ECCP384_SHA1) {
				cardhash = B_TRUE;
			}
		}
		if (*hashalgo == SSH_DIGEST_SHA1) {
			dglen = 20;
			if (cardhash) {
				oldalg = slot->ps_alg;
				slot->ps_alg = PIV_ALG_ECCP384_SHA1;
			}
		} else if (*hashalgo == SSH_DIGEST_SHA256) {
			dglen = 32;
			if (cardhash && ch_sha256) {
				oldalg = slot->ps_alg;
				slot->ps_alg = PIV_ALG_ECCP384_SHA256;
			} else if (cardhash) {
				*hashalgo = SSH_DIGEST_SHA1;
				dglen = 20;
				oldalg = slot->ps_alg;
				slot->ps_alg = PIV_ALG_ECCP384_SHA1;
			}
		} else {
			*hashalgo = SSH_DIGEST_SHA384;
			dglen = 48;
			if (cardhash && ch_sha384) {
				oldalg = slot->ps_alg;
				slot->ps_alg = PIV_ALG_ECCP384_SHA384;
			} else if (cardhash && ch_sha256) {
				*hashalgo = SSH_DIGEST_SHA256;
				dglen = 32;
				oldalg = slot->ps_alg;
				slot->ps_alg = PIV_ALG_ECCP384_SHA256;
			} else if (cardhash) {
				*hashalgo = SSH_DIGEST_SHA1;
				dglen = 20;
				oldalg = slot->ps_alg;
				slot->ps_alg = PIV_ALG_ECCP384_SHA1;
			}
		}
		break;
	case PIV_ALG_ED25519:
		inplen = 32;
		dglen = 64;
		cardhash = B_TRUE;
		*hashalgo = SSH_DIGEST_SHA512;
		oldalg = slot->ps_alg;
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
		if ((rc = ssh_digest_update(hctx, data, datalen)) ||
		    (rc = ssh_digest_final(hctx, buf, dglen))) {
			ssh_digest_free(hctx);
			err = ssherrf("ssh_digest_update/final", rc);
			return (err);
		}
		ssh_digest_free(hctx);
	} else {
		bunyan_log(BNY_TRACE, "doing hash on card", NULL);
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
	    slot->ps_alg == PIV_ALG_RSA2048 ||
	    slot->ps_alg == PIV_ALG_RSA3072 ||
	    slot->ps_alg == PIV_ALG_RSA4096) {
		int nid;
		/*
		 * Roll up your sleeves, folks, we're going in (to the dank
		 * and musty corners of OpenSSL where few dare tread)
		 */
		X509_SIG *digestInfo;
		X509_ALGOR *algor;
		ASN1_OCTET_STRING *digest;
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

		digestInfo = X509_SIG_new();
		VERIFY(digestInfo != NULL);

		X509_SIG_getm(digestInfo, &algor, &digest);

		VERIFY(X509_ALGOR_set0(algor, OBJ_nid2obj(nid), V_ASN1_NULL,
		    NULL) == 1);
		VERIFY(ASN1_OCTET_STRING_set(digest, tmp, (int)dglen) == 1);

		nread = i2d_X509_SIG(digestInfo, &out);

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
		X509_SIG_free(digestInfo);
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
	uint8_t *buf = NULL;

	VERIFY(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x7C);
	/* Push an empty RESPONSE tag to say that's what we're asking for. */
	tlv_push(tlv, GA_TAG_RESPONSE);
	tlv_pop(tlv);
	/* And now push the data we're providing (the CHALLENGE). */
	tlv_push(tlv, GA_TAG_CHALLENGE);
	tlv_write(tlv, hash, hashlen);
	tlv_pop(tlv);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_AUTH, pc->ps_alg, pc->ps_slot);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_sign_prehash.transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		goto out;
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		if ((err = tlv_read_tag(tlv, &tag)))
			goto invdata;
		if (tag != 0x7C) {
			err = tagerrf("INS_GEN_AUTH(%x)", tag, pc->ps_slot);
			goto invdata;
		}
		if ((err = tlv_read_tag(tlv, &tag)))
			goto invdata;
		if (tag != GA_TAG_RESPONSE) {
			err = tagerrf("INS_GEN_AUTH(%x)", tag, pc->ps_slot);
			goto invdata;
		}

		err = tlv_read_alloc(tlv, &buf, siglen);
		if (err)
			goto invdata;
		if ((err = tlv_end(tlv)) ||
		    (err = tlv_end(tlv))) {
			goto invdata;
		}

		*signature = buf;
		buf = NULL;
		err = ERRF_OK;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GEN_AUTH(%x)", apdu->a_sw,
		    pc->ps_slot), pk->pt_rdrname,
		    "signing data with key in slot %02x", pc->ps_slot);
		/* We probably needed a PIN for this. */
		pc->ps_auth |= PIV_SLOT_AUTH_PIN;

	} else if (apdu->a_sw == SW_WRONG_DATA ||
	    apdu->a_sw == SW_INCORRECT_P1P2) {
		err = errf("NotSupportedError", swerrf("INS_GEN_AUTH(%x)",
		    apdu->a_sw, pc->ps_slot), "Signature generation not "
		    "supported by key (or no key present) in slot %02x "
		    "of PIV device '%s'", pc->ps_slot, pk->pt_rdrname);

	} else {
		err = swerrf("INS_GEN_AUTH(%x)", apdu->a_sw, pc->ps_slot);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

out:
	free(buf);
	tlv_free(tlv);
	piv_apdu_free(apdu);
	return (err);

invdata:
	err = invderrf(err, pk->pt_rdrname);
	tlv_abort(tlv);
	goto out;
}

errf_t *
piv_ecdh(struct piv_token *pk, struct piv_slot *slot, struct sshkey *pubkey,
    uint8_t **secret, size_t *seclen)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	uint8_t *buf = NULL;
	struct sshbuf *sbuf;
	size_t len;

	VERIFY(pk->pt_intxn);

	sbuf = sshbuf_new();
	VERIFY(sbuf != NULL);
	VERIFY3S(pubkey->type, ==, KEY_ECDSA);
	VERIFY0(sshbuf_put_eckey(sbuf, EVP_PKEY_get1_EC_KEY(pubkey->pkey)));
	/* The buffer has the 32-bit length prefixed */
	len = sshbuf_len(sbuf) - 4;
	buf = (uint8_t *)sshbuf_ptr(sbuf) + 4;
	VERIFY3U(*buf, ==, 0x04);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x7C);
	tlv_push(tlv, GA_TAG_RESPONSE);
	tlv_pop(tlv);
	tlv_push(tlv, GA_TAG_EXP);
	tlv_write(tlv, buf, len);
	sshbuf_free(sbuf);
	tlv_pop(tlv);
	tlv_pop(tlv);

	buf = NULL;

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_AUTH, slot->ps_alg,
	    slot->ps_slot);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_ecdh.transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		goto out;
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		if ((err = tlv_read_tag(tlv, &tag)))
			goto invdata;
		if (tag != 0x7C) {
			err = tagerrf("INS_GEN_AUTH(%x)", tag, slot->ps_slot);
			goto invdata;
		}
		if ((err = tlv_read_tag(tlv, &tag)))
			goto invdata;
		if (tag != GA_TAG_RESPONSE) {
			err = tagerrf("INS_GEN_AUTH(%x)", tag, slot->ps_slot);
			goto invdata;
		}

		if ((err = tlv_read_alloc(tlv, &buf, seclen)) ||
		    (err = tlv_end(tlv)) ||
		    (err = tlv_end(tlv))) {
			goto invdata;
		}

		*secret = buf;
		buf = NULL;
		err = ERRF_OK;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GEN_AUTH(%x)", apdu->a_sw,
		    slot->ps_slot), pk->pt_rdrname, "performing ECDH for "
		    "slot %x", slot->ps_slot);
		/* We probably needed a PIN for this. */
		slot->ps_auth |= PIV_SLOT_AUTH_PIN;

	} else {
		err = swerrf("INS_GEN_AUTH(%x)", apdu->a_sw, slot->ps_slot);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

out:
	free(buf);
	tlv_free(tlv);
	piv_apdu_free(apdu);
	return (err);

invdata:
	err = invderrf(err, pk->pt_rdrname);
	debug_dump(err, apdu);
	tlv_abort(tlv);
	goto out;
}

#define	BOX_DEFAULT_CIPHER	"chacha20-poly1305"
#define	BOX_DEFAULT_KDF		"sha512"

struct piv_ecdh_box *
piv_box_new(void)
{
	struct piv_ecdh_box *box;
	box = calloc(1, sizeof (struct piv_ecdh_box));
	box->pdb_version = PIV_BOX_VNEXT - 1;
	return (box);
}

struct piv_ecdh_box *
piv_box_clone(const struct piv_ecdh_box *box)
{
	struct piv_ecdh_box *nbox;
	nbox = calloc(1, sizeof (struct piv_ecdh_box));
	if (nbox == NULL)
		goto err;
	nbox->pdb_version = box->pdb_version;
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
	if (box->pdb_nonce.b_len > 0) {
		nbox->pdb_nonce.b_data = malloc(box->pdb_nonce.b_len);
		if (nbox->pdb_nonce.b_data == NULL)
			goto err;
		nbox->pdb_nonce.b_len = (nbox->pdb_nonce.b_size =
		    box->pdb_nonce.b_len);
		bcopy(box->pdb_nonce.b_data + box->pdb_nonce.b_offset,
		    nbox->pdb_nonce.b_data, box->pdb_nonce.b_len);
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
	free(box->pdb_nonce.b_data);
	free(box->pdb_guidhex);
	if (box->pdb_plain.b_data != NULL) {
		freezero(box->pdb_plain.b_data, box->pdb_plain.b_size);
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

	*data = calloc_conceal(1, box->pdb_plain.b_len);
	VERIFY(*data != NULL);
	*len = box->pdb_plain.b_len;
	bcopy(box->pdb_plain.b_data + box->pdb_plain.b_offset, *data, *len);

	freezero(box->pdb_plain.b_data, box->pdb_plain.b_size);
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

	freezero(box->pdb_plain.b_data, box->pdb_plain.b_size);
	box->pdb_plain.b_data = NULL;
	box->pdb_plain.b_size = 0;
	box->pdb_plain.b_len = 0;
	box->pdb_plain.b_offset = 0;

	*pbuf = buf;

	return (ERRF_OK);
}

static errf_t *
piv_box_open_common(uint8_t *sec, size_t seclen, struct piv_ecdh_box *box)
{
	const struct sshcipher *cipher;
	int dgalg;
	struct sshcipher_ctx *cctx;
	struct ssh_digest_ctx *dgctx;
	uint8_t *iv, *key, *enc, *plain;
	size_t ivlen, authlen, blocksz, keylen, dglen;
	size_t plainlen, enclen;
	size_t reallen, padding, i;
	errf_t *err;
	int rv;

	VERIFY3P(box->pdb_cipher, !=, NULL);
	VERIFY3P(box->pdb_kdf, !=, NULL);

	VERIFY3P(sec, !=, NULL);
	VERIFY3U(seclen, >=, 0);

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
	/* TODO: support non-authenticated ciphers by adding an HMAC */
	VERIFY3U(authlen, >, 0);

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

	dgctx = ssh_digest_start(dgalg);
	VERIFY3P(dgctx, !=, NULL);
	VERIFY0(ssh_digest_update(dgctx, sec, seclen));
	if (box->pdb_nonce.b_len > 0) {
		/*
		 * In the original libnacl/libsodium box primitive, the nonce
		 * is combined with the ECDH output in a more complex way than
		 * this. Based on reading the RFCs for systems like OpenSSH,
		 * though, this method (simply concat'ing them and hashing)
		 * seems to be acceptable.
		 *
		 * We never publish this hash value (it's the symmetric key!)
		 * so we don't need to worry about length extension attacks and
		 * similar.
		 */
		VERIFY0(ssh_digest_update(dgctx, box->pdb_nonce.b_data +
		    box->pdb_nonce.b_offset, box->pdb_nonce.b_len));
	}
	key = calloc_conceal(1, dglen);
	VERIFY3P(key, !=, NULL);
	VERIFY0(ssh_digest_final(dgctx, key, dglen));
	ssh_digest_free(dgctx);

	freezero(sec, seclen);

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
	plain = calloc_conceal(1, plainlen);
	VERIFY3P(plain, !=, NULL);

	VERIFY0(cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 0));
	rv = cipher_crypt(cctx, 0, plain, enc, enclen - authlen, 0,
	    authlen);
	cipher_free(cctx);

	freezero(key, dglen);

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
		freezero(box->pdb_plain.b_data, box->pdb_plain.b_size);
	}
	box->pdb_plain.b_data = plain;
	box->pdb_plain.b_size = plainlen;
	box->pdb_plain.b_len = reallen;
	box->pdb_plain.b_offset = 0;

	return (ERRF_OK);

paderr:
	err = boxderrf(errf("PaddingError", NULL, "Padding failed validation"));
	freezero(plain, plainlen);
	return (err);
}

errf_t *
piv_box_open_offline(struct sshkey *privkey, struct piv_ecdh_box *box)
{
	EC_KEY *eck, *epheck;
	uint8_t *sec;
	size_t seclen;
	size_t fieldsz;
	errf_t *err;
	int rv;

	eck = EVP_PKEY_get1_EC_KEY(privkey->pkey);
	fieldsz = EC_GROUP_get_degree(EC_KEY_get0_group(eck));
	seclen = (fieldsz + 7) / 8;
	sec = calloc_conceal(1, seclen);
	VERIFY(sec != NULL);
	epheck = EVP_PKEY_get1_EC_KEY(box->pdb_ephem_pub->pkey);
	rv = ECDH_compute_key(sec, seclen,
	    EC_KEY_get0_public_key(epheck), eck, NULL);
	if (rv <= 0) {
		free(sec);
		make_sslerrf(err, "ECDH_compute_key", "performing ECDH");
		err = boxderrf(err);
		return (err);
	}
	seclen = (size_t)rv;

	return (piv_box_open_common(sec, seclen, box));
}

errf_t *
piv_box_open(struct piv_token *tk, struct piv_slot *slot,
    struct piv_ecdh_box *box)
{
	errf_t *err;
	uint8_t *sec = NULL;
	size_t seclen;

	VERIFY3P(box->pdb_ephem_pub, !=, NULL);
	err = piv_ecdh(tk, slot, box->pdb_ephem_pub, &sec, &seclen);
	if (err) {
		err = errf("BoxKeyError", err, "Failed to perform ECDH "
		    "operation needed to decrypt PIVBox");
		return (err);
	}

	return (piv_box_open_common(sec, seclen, box));
}

errf_t *
piv_box_seal_offline(struct sshkey *pubk, struct piv_ecdh_box *box)
{
	const struct sshcipher *cipher;
	int rv;
	errf_t *err;
	int dgalg;
	struct sshkey *pkey;
	EC_KEY *eck, *epheck;
	struct sshcipher_ctx *cctx;
	struct ssh_digest_ctx *dgctx;
	uint8_t *iv, *key, *sec, *enc, *plain, *nonce;
	size_t ivlen, authlen, blocksz, keylen, dglen, seclen, noncelen;
	size_t fieldsz, plainlen, enclen;
	size_t padding, i;

	if (pubk->type != KEY_ECDSA) {
		return (argerrf("pubkey", "an ECDSA public key",
		    "type %s", sshkey_type(pubk)));
	}

	if (box->pdb_ephem == NULL) {
		rv = sshkey_generate(KEY_ECDSA, sshkey_size(pubk), &pkey);
		if (rv != 0) {
			err = boxaerrf(ssherrf("sshkey_generate", rv));
			return (err);
		}
	} else {
		pkey = box->pdb_ephem;
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
	/* TODO: support non-authenticated ciphers by adding an HMAC */
	VERIFY3U(authlen, >, 0);

	if (box->pdb_version >= PIV_BOX_V2 && (
	    box->pdb_nonce.b_data == NULL || box->pdb_nonce.b_len == 0)) {
		noncelen = 16;
		nonce = calloc(1, noncelen);
		VERIFY3P(nonce, !=, NULL);
		arc4random_buf(nonce, noncelen);

		free(box->pdb_nonce.b_data);
		box->pdb_nonce.b_data = nonce;
		box->pdb_nonce.b_offset = 0;
		box->pdb_nonce.b_size = noncelen;
		box->pdb_nonce.b_len = noncelen;
	}

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

	eck = EVP_PKEY_get1_EC_KEY(pkey->pkey);
	epheck = EVP_PKEY_get1_EC_KEY(pubk->pkey);
	fieldsz = EC_GROUP_get_degree(EC_KEY_get0_group(eck));
	seclen = (fieldsz + 7) / 8;
	sec = calloc(1, seclen);
	VERIFY(sec != NULL);
	rv = ECDH_compute_key(sec, seclen,
	    EC_KEY_get0_public_key(epheck), eck, NULL);
	if (rv <= 0) {
		free(sec);
		make_sslerrf(err, "ECDH_compute_key", "performing ECDH");
		err = boxaerrf(err);
		return (err);
	}
	seclen = (size_t)rv;

	if (box->pdb_ephem == NULL)
		sshkey_free(pkey);

	dgctx = ssh_digest_start(dgalg);
	VERIFY3P(dgctx, !=, NULL);
	VERIFY0(ssh_digest_update(dgctx, sec, seclen));
	if (box->pdb_nonce.b_len > 0) {
		/* See comment in piv_box_open_offline */
		VERIFY0(ssh_digest_update(dgctx, box->pdb_nonce.b_data +
		    box->pdb_nonce.b_offset, box->pdb_nonce.b_len));
	}
	key = calloc(1, dglen);
	VERIFY3P(key, !=, NULL);
	VERIFY0(ssh_digest_final(dgctx, key, dglen));
	ssh_digest_free(dgctx);

	freezero(sec, seclen);

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

	freezero(box->pdb_plain.b_data, box->pdb_plain.b_size);
	box->pdb_plain.b_data = NULL;
	box->pdb_plain.b_size = 0;
	box->pdb_plain.b_len = 0;

	VERIFY0(cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 1));
	enclen = plainlen + authlen;
	enc = calloc(1, enclen);
	VERIFY3P(enc, !=, NULL);
	VERIFY0(cipher_crypt(cctx, 0, enc, plain, plainlen, 0, authlen));
	cipher_free(cctx);

	freezero(plain, plainlen);
	freezero(key, dglen);

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

	if (!box->pdb_guidslot_valid)
		goto allslots;

	/* First, try for an exact match on the GUID */
	for (pt = tks; pt != NULL; pt = pt->pt_next) {
		if (bcmp(pt->pt_guid, box->pdb_guid,
		    sizeof (pt->pt_guid)) == 0) {
			s = piv_get_slot(pt, box->pdb_slot);
			if (s == NULL && !pt->pt_did_read_all) {
				if ((err = piv_txn_begin(pt)))
					return (err);
				if ((err = piv_select(pt)) ||
				    (err = piv_read_cert(pt, box->pdb_slot))) {
					piv_txn_end(pt);
					return (err);
				}
				piv_txn_end(pt);
				s = piv_get_slot(pt, box->pdb_slot);
			}
			if (s == NULL)
				continue;
			if (!sshkey_equal_public(s->ps_pubkey, box->pdb_pub)) {
				return (errf("NotFoundError", NULL,
				    "PIV token on system with matching "
				    "GUID for box has different key"));
			}
			goto found;
		}
	}
	/*
	 * If no GUID matches, try probing the relevant slot (or 9D) on all
	 * the cards we can see to see if the key matches.
	 */
	slotid = box->pdb_slot;
	if (slotid == 0 || slotid == 0xFF)
		slotid = PIV_SLOT_KEY_MGMT;
	for (pt = tks; pt != NULL; pt = pt->pt_next) {
		s = piv_get_slot(pt, slotid);
		if (s == NULL && !pt->pt_did_read_all) {
			if ((err = piv_txn_begin(pt))) {
				errf_free(err);
				continue;
			}
			if ((err = piv_select(pt)) ||
			    (err = piv_read_cert(pt, slotid))) {
				errf_free(err);
				piv_txn_end(pt);
				continue;
			}
			piv_txn_end(pt);
			s = piv_get_slot(pt, slotid);
		}
		if (s == NULL)
			continue;
		if (sshkey_equal_public(s->ps_pubkey, box->pdb_pub))
			goto found;
	}

allslots:
	/*
	 * Finally, if all else fails, exhaustively check every slot on every
	 * token available.
	 */
	for (pt = tks; pt != NULL; pt = pt->pt_next) {
		if (!pt->pt_did_read_all) {
			if (piv_txn_begin(pt))
				continue;
			if (piv_select(pt) || piv_read_all_certs(pt)) {
				piv_txn_end(pt);
				continue;
			}
			piv_txn_end(pt);
		}

		s = NULL;
		while ((s = piv_slot_next(pt, s)) != NULL) {
			if (sshkey_equal_public(s->ps_pubkey, box->pdb_pub))
				goto found;
		}
	}

	return (errf("NotFoundError", NULL, "No PIV token found on "
		"system to unlock box"));

found:
	*tk = pt;
	*slot = s;
	return (ERRF_OK);
}

errf_t *
sshbuf_put_piv_box(struct sshbuf *buf, struct piv_ecdh_box *box)
{
	int rc;
	const char *tname;
	uint8_t ver;
	EC_KEY *eck, *epheck;

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
	ver = box->pdb_version;
	if ((rc = sshbuf_put_u8(buf, ver)))
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

	if (ver >= PIV_BOX_V2) {
		if ((rc = sshbuf_put_string8(buf, box->pdb_nonce.b_data,
		    box->pdb_nonce.b_len)))
			return (ssherrf("sshbuf_put_string8", rc));
	} else {
		VERIFY3U(box->pdb_nonce.b_len, ==, 0);
		VERIFY3P(box->pdb_nonce.b_data, ==, NULL);
	}

	tname = sshkey_curve_nid_to_name(box->pdb_pub->ecdsa_nid);
	VERIFY(tname != NULL);
	if ((rc = sshbuf_put_cstring8(buf, tname)))
		return (ssherrf("sshbuf_put_cstring8", rc));
	eck = EVP_PKEY_get1_EC_KEY(box->pdb_pub->pkey);
	epheck = EVP_PKEY_get1_EC_KEY(box->pdb_ephem_pub->pkey);
	if ((rc = sshbuf_put_eckey8(buf, eck)) ||
	    (rc = sshbuf_put_eckey8(buf, epheck)))
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
	EC_KEY *eck = NULL;

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
	if (ver < PIV_BOX_V1 || ver >= PIV_BOX_VNEXT) {
		err = boxverrf(errf("VersionError", NULL,
		    "Unsupported version number 0x%02x", ver));
		goto out;
	}
	box->pdb_version = ver;

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

	if (ver >= PIV_BOX_V2) {
		if ((rc = sshbuf_get_string8(buf, &box->pdb_nonce.b_data,
		    &box->pdb_nonce.b_size))) {
			err = boxderrf(ssherrf("sshbuf_get_string8", rc));
			goto out;
		}
		box->pdb_nonce.b_len = box->pdb_nonce.b_size;
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

	eck = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY(eck != NULL);

	if ((rc = sshbuf_get_eckey8(buf, eck))) {
		err = boxderrf(ssherrf("sshbuf_get_eckey8", rc));
		goto out;
	}
	if ((rc = sshkey_ec_validate_public(EC_KEY_get0_group(eck),
	    EC_KEY_get0_public_key(eck)))) {
		err = boxderrf(ssherrf("sshkey_ec_validate_public", rc));
		goto out;
	}
	EVP_PKEY_free(k->pkey);
	k->pkey = EVP_PKEY_new();
	VERIFY(k->pkey != NULL);
	EVP_PKEY_assign_EC_KEY(k->pkey, eck);
	eck = NULL;

	box->pdb_pub = k;
	k = NULL;

	k = sshkey_new(KEY_ECDSA);
	k->ecdsa_nid = box->pdb_pub->ecdsa_nid;

	eck = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY(eck != NULL);

	if ((rc = sshbuf_get_eckey8(buf, eck))) {
		err = boxderrf(ssherrf("sshbuf_get_eckey8", rc));
		goto out;
	}
	if ((rc = sshkey_ec_validate_public(EC_KEY_get0_group(eck),
	    EC_KEY_get0_public_key(eck)))) {
		err = boxderrf(ssherrf("sshkey_ec_validate_public", rc));
		goto out;
	}

	EVP_PKEY_free(k->pkey);
	k->pkey = EVP_PKEY_new();
	VERIFY(k->pkey != NULL);
	EVP_PKEY_assign_EC_KEY(k->pkey, eck);
	eck = NULL;

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
	EC_KEY_free(eck);
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

const char *
piv_box_guid_hex(const struct piv_ecdh_box *box)
{
	VERIFY(box->pdb_guidslot_valid);
	if (box->pdb_guidhex == NULL) {
		struct piv_ecdh_box *boxwr = (struct piv_ecdh_box *)box;
		boxwr->pdb_guidhex = buf_to_hex(box->pdb_guid,
		    sizeof (box->pdb_guid), B_FALSE);
	}
	return (box->pdb_guidhex);
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

size_t
piv_box_nonce_size(const struct piv_ecdh_box *box)
{
	return (box->pdb_nonce.b_len);
}

uint
piv_box_version(const struct piv_ecdh_box *box)
{
	return (box->pdb_version);
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
		bunyan_log(BNY_TRACE, "failed to read box version", NULL);
		rv = EINVAL;
		goto out;
	}
	if (ver != 1) {
		bunyan_log(BNY_TRACE, "bad piv box version",
		    "version", BNY_UINT, (uint)ver, NULL);
		rv = ENOTSUP;
		goto out;
	}

	if (sshbuf_get_string(buf, &tmp, &len)) {
		bunyan_log(BNY_TRACE, "failed to read box guid", NULL);
		rv = EINVAL;
		goto out;
	}
	if (len != sizeof (box->pdb_guid)) {
		bunyan_log(BNY_TRACE, "bad piv box guid: short",
		    "len", BNY_UINT, (uint)len, NULL);
		free(tmp);
		rv = EINVAL;
		goto out;
	}
	bcopy(tmp, box->pdb_guid, len);
	free(tmp);

	if (sshbuf_get_u8(buf, &ver)) {
		bunyan_log(BNY_TRACE, "failed to read box slot", NULL);
		rv = EINVAL;
		goto out;
	}
	box->pdb_slot = ver;

	if (sshbuf_get_stringb(buf, kbuf)) {
		bunyan_log(BNY_TRACE, "failed to read ephem_pub buf", NULL);
		rv = EINVAL;
		goto out;
	}
	if (sshkey_fromb(kbuf, &box->pdb_ephem_pub)) {
		bunyan_log(BNY_TRACE, "failed to read ephem_pub", NULL);
		rv = EINVAL;
		goto out;
	}
	sshbuf_reset(kbuf);
	if (sshbuf_get_stringb(buf, kbuf)) {
		bunyan_log(BNY_TRACE, "failed to read pub buf", NULL);
		rv = EINVAL;
		goto out;
	}
	if (sshkey_fromb(kbuf, &box->pdb_pub)) {
		bunyan_log(BNY_TRACE, "failed to read pub", NULL);
		rv = EINVAL;
		goto out;
	}

	box->pdb_free_str = B_TRUE;
	if (sshbuf_get_cstring(buf, (char **)&box->pdb_cipher, &len) ||
	    sshbuf_get_cstring(buf, (char **)&box->pdb_kdf, &len) ||
	    sshbuf_get_string(buf, &box->pdb_iv.b_data, &box->pdb_iv.b_size) ||
	    sshbuf_get_string(buf, &box->pdb_enc.b_data,
	    &box->pdb_enc.b_size)) {
		bunyan_log(BNY_TRACE, "failed to read box other fields", NULL);
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

errf_t *
piv_alg_from_string(const char *str, enum piv_alg *out)
{
	if (strcasecmp(str, "3des") == 0) {
		*out = PIV_ALG_3DES;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "aes128") == 0) {
		*out = PIV_ALG_AES128;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "aes192") == 0) {
		*out = PIV_ALG_AES192;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "aes256") == 0) {
		*out = PIV_ALG_AES256;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "rsa1024") == 0) {
		*out = PIV_ALG_RSA1024;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "rsa2048") == 0) {
		*out = PIV_ALG_RSA2048;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "rsa3072") == 0) {
		*out = PIV_ALG_RSA3072;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "rsa4096") == 0) {
		*out = PIV_ALG_RSA4096;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "eccp256") == 0) {
		*out = PIV_ALG_ECCP256;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "eccp384") == 0) {
		*out = PIV_ALG_ECCP384;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "sm-eccp256") == 0 ||
	    strcasecmp(str, "sm-cs2-eccp256") == 0) {
		*out = PIV_ALG_SM_ECCP256;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "sm-eccp384") == 0 ||
	    strcasecmp(str, "sm-cs7-eccp384") == 0) {
		*out = PIV_ALG_SM_ECCP384;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "ed25519") == 0) {
		*out = PIV_ALG_ED25519;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "x25519") == 0) {
		*out = PIV_ALG_X25519;
		return (ERRF_OK);
	}
	return (errf("InvalidAlgorithm", NULL, "Invalid/unknown algorithm "
	    "name: '%s'", str));
}

const char *
piv_alg_to_string(enum piv_alg alg)
{
	switch (alg) {
	case PIV_ALG_3DES:
		return ("3DES");
	case PIV_ALG_RSA1024:
		return ("RSA1024");
	case PIV_ALG_RSA2048:
		return ("RSA2048");
	case PIV_ALG_RSA3072:
		return ("RSA3072");
	case PIV_ALG_RSA4096:
		return ("RSA4096");
	case PIV_ALG_AES128:
		return ("AES128");
	case PIV_ALG_AES192:
		return ("AES192");
	case PIV_ALG_AES256:
		return ("AES256");
	case PIV_ALG_ECCP256:
		return ("ECCP256");
	case PIV_ALG_ECCP384:
		return ("ECCP384");
	case PIV_ALG_ECCP256_SHA1:
		return ("ECCP256-SHA1");
	case PIV_ALG_ECCP256_SHA256:
		return ("ECCP256-SHA256");
	case PIV_ALG_ECCP384_SHA1:
		return ("ECCP384-SHA1");
	case PIV_ALG_ECCP384_SHA256:
		return ("ECCP384-SHA256");
	case PIV_ALG_ECCP384_SHA384:
		return ("ECCP384-SHA384");
	case PIV_ALG_SM_ECCP256:
		return ("SM-CS2-ECCP256");
	case PIV_ALG_SM_ECCP384:
		return ("SM-CS7-ECCP384");
	case PIV_ALG_ED25519:
		return ("ED25519");
	case PIV_ALG_X25519:
		return ("X25519");
	default:
		return (NULL);
	}
}

char *
piv_slotid_to_string(enum piv_slotid slotid)
{
	char name[64];

	switch (slotid) {
	case 0x9A:
		strlcpy(name, "piv-auth", sizeof (name));
		break;
	case 0x9C:
		strlcpy(name, "piv-sign", sizeof (name));
		break;
	case 0x9D:
		strlcpy(name, "key-mgmt", sizeof (name));
		break;
	case 0x9E:
		strlcpy(name, "card-auth", sizeof (name));
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
		snprintf(name, sizeof (name), "retired-%u",
		    slotid - 0x81);
		break;
	default:
		snprintf(name, sizeof (name), "0x%02x", slotid);
	}

	return (strdup(name));
}

errf_t *
piv_slotid_from_string(const char *str, enum piv_slotid *out)
{
	if (strcasecmp(str, "piv-auth") == 0 ||
	    strcasecmp(str, "auth") == 0) {
		*out = PIV_SLOT_PIV_AUTH;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "piv-sign") == 0 ||
	    strcasecmp(str, "sign") == 0 ||
	    strcasecmp(str, "signature") == 0) {
		*out = PIV_SLOT_SIGNATURE;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "piv-key-mgmt") == 0 ||
	    strcasecmp(str, "key-mgmt") == 0) {
		*out = PIV_SLOT_KEY_MGMT;
		return (ERRF_OK);
	}
	if (strcasecmp(str, "piv-card-auth") == 0 ||
	    strcasecmp(str, "card-auth") == 0) {
		*out = PIV_SLOT_CARD_AUTH;
		return (ERRF_OK);
	}
	if (strncasecmp(str, "retired-", 8) == 0) {
		uint n;
		char *p = (char *)str + 8;
		errno = 0;
		n = strtoul(str + 8, &p, 10);
		if (errno != 0 || *p != '\0') {
			return (errf("InvalidSlotID", NULL, "Failed to parse "
			    "retired slot id '%s'", str));
		}
		n = PIV_SLOT_RETIRED_1 + (n - 1);
		if (n > PIV_SLOT_RETIRED_20) {
			return (errf("InvalidSlotID", NULL, "Retired slot "
			    "index too large: '%s'", str));
		}
		*out = n;
		return (ERRF_OK);
	}
	if (strncasecmp(str, "piv-retired-", 12) == 0) {
		uint n;
		char *p = (char *)str + 12;
		errno = 0;
		n = strtoul(str + 12, &p, 10);
		if (errno != 0 || *p != '\0') {
			return (errf("InvalidSlotID", NULL, "Failed to parse "
			    "retired slot id '%s'", str));
		}
		n = PIV_SLOT_RETIRED_1 + (n - 1);
		if (n > PIV_SLOT_RETIRED_20) {
			return (errf("InvalidSlotID", NULL, "Retired slot "
			    "index too large: '%s'", str));
		}
		*out = n;
		return (ERRF_OK);
	}
	if (strncmp(str, "0x", 2) == 0) {
		uint n;
		char *p = (char *)str + 2;
		errno = 0;
		n = strtoul(str + 2, &p, 16);
		if (errno != 0 || *p != '\0') {
			return (errf("InvalidSlotID", NULL, "Failed to parse "
			    "hex slot id '%s'", str));
		}
		if (n < 0x82 ||
		    (n > 0x95 && n < 0x9A) ||
		    (n > 0x9E && n != 0xF9)) {
			return (errf("InvalidSlotID", NULL, "Slot ID "
			    "out of range: '%s'", str));
		}
		*out = n;
		return (ERRF_OK);
	}
	if (strlen(str) == 2) {
		uint n;
		char *p = (char *)str;
		errno = 0;
		n = strtoul(str, &p, 16);
		if (errno != 0 || *p != '\0') {
			return (errf("InvalidSlotID", NULL, "Failed to parse "
			    "hex slot id '%s'", str));
		}
		if (n < 0x82 ||
		    (n > 0x95 && n < 0x9A) ||
		    (n > 0x9E && n != 0xF9)) {
			return (errf("InvalidSlotID", NULL, "Slot ID "
			    "out of range: '%s'", str));
		}
		*out = n;
		return (ERRF_OK);
	}
	return (errf("InvalidSlotID", NULL, "Invalid or unsupported PIV "
	    "slot ID: '%s'", str));
}

const struct piv_chuid *
piv_token_chuid(struct piv_token *pk)
{
	return (pk->pt_chuid);
}

errf_t *
piv_read_pinfo(struct piv_token *pk, struct piv_pinfo **outp)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;

	VERIFY(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_u8to32(tlv, PIV_TAG_PRINTINFO);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN, "transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		goto out;
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
	    	tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
	    	if ((err = tlv_read_tag(tlv, &tag)))
			goto invdata;
		if (tag != 0x53) {
			err = tagerrf("INS_GET_DATA(PINFO)", tag);
			goto invdata;
		}
	    	err = piv_pinfo_decode(tlv_ptr(tlv), tlv_rem(tlv), outp);
	    	if (err != ERRF_OK)
	    		goto invdata;
	    	tlv_skip(tlv);

		err = ERRF_OK;

	} else if (apdu->a_sw == SW_FILE_NOT_FOUND ||
	    apdu->a_sw == SW_WRONG_DATA) {
		err = errf("NotFoundError", swerrf("INS_GET_DATA", apdu->a_sw),
		    "PIV PINFO object was not found on device '%s'",
		    pk->pt_rdrname);

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GET_DATA", apdu->a_sw),
		    pk->pt_rdrname, "reading PIV PINFO object");

	} else {
		err = swerrf("INS_GET_DATA(PINFO)", apdu->a_sw);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

out:
	tlv_free(tlv);
	piv_apdu_free(apdu);
	return (err);

invdata:
	tlv_abort(tlv);
	err = invderrf(err, pk->pt_rdrname);
	debug_dump(err, apdu);
	goto out;
}

void
pinfo_kv_free(struct piv_pinfo_kv *kv)
{
	if (kv == NULL)
		return;
	VERIFY(kv->ppk_next == NULL);
	VERIFY(kv->ppk_prev == NULL);
	free(kv->ppk_name);
	switch (kv->ppk_type) {
	case PIV_PINFO_KV_STRING:
		free(kv->ppk_string);
		break;
	case PIV_PINFO_KV_DATA:
		freezero(kv->ppk_data, kv->ppk_len);
		break;
	default:
		break;
	}
	free(kv);
}

errf_t *
piv_pinfo_encode(const struct piv_pinfo *pp, uint8_t **out, size_t *outlen)
{
	struct tlv_state *tlv = NULL;
	errf_t *err;
	uint8_t *buf = NULL;
	size_t buflen = 0;
	struct piv_pinfo_kv *kv;

	tlv = tlv_init_write();

	if (pp->pp_name != NULL) {
		tlv_push(tlv, 0x01);
		tlv_write(tlv, (uint8_t *)pp->pp_name, strlen(pp->pp_name));
		tlv_pop(tlv);
	}
	if (pp->pp_affiliation != NULL) {
		tlv_push(tlv, 0x02);
		tlv_write(tlv, (uint8_t *)pp->pp_affiliation,
		    strlen(pp->pp_affiliation));
		tlv_pop(tlv);
	}
	if (pp->pp_expiry != NULL) {
		tlv_push(tlv, 0x04);
		tlv_write(tlv, (uint8_t *)pp->pp_expiry, strlen(pp->pp_expiry));
		tlv_pop(tlv);
	}
	if (pp->pp_serial != NULL) {
		tlv_push(tlv, 0x05);
		tlv_write(tlv, (uint8_t *)pp->pp_serial, strlen(pp->pp_serial));
		tlv_pop(tlv);
	}
	if (pp->pp_issuer != NULL) {
		tlv_push(tlv, 0x06);
		tlv_write(tlv, (uint8_t *)pp->pp_issuer, strlen(pp->pp_issuer));
		tlv_pop(tlv);
	}
	if (pp->pp_org_1 != NULL) {
		tlv_push(tlv, 0x07);
		tlv_write(tlv, (uint8_t *)pp->pp_org_1, strlen(pp->pp_org_1));
		tlv_pop(tlv);
	}
	if (pp->pp_org_2 != NULL) {
		tlv_push(tlv, 0x08);
		tlv_write(tlv, (uint8_t *)pp->pp_org_2, strlen(pp->pp_org_2));
		tlv_pop(tlv);
	}

	if (pp->pp_yk_admin != NULL && pp->pp_yk_admin_len > 0) {
		tlv_push(tlv, 0x88);
		tlv_push(tlv, 0x89);
		tlv_write(tlv, pp->pp_yk_admin, pp->pp_yk_admin_len);
		tlv_pop(tlv);
		tlv_pop(tlv);
	}

	for (kv = pp->pp_kv; kv != NULL; kv = kv->ppk_next) {
		tlv_push(tlv, 0x90);

		tlv_push(tlv, 0x01);
		tlv_write(tlv, (uint8_t *)kv->ppk_name, strlen(kv->ppk_name));
		tlv_pop(tlv);

		switch (kv->ppk_type) {
		case PIV_PINFO_KV_BOOL:
			tlv_push(tlv, 0x02);
			tlv_pop(tlv);
			break;
		case PIV_PINFO_KV_UINT:
			tlv_push(tlv, 0x03);
			tlv_write_u8to32(tlv, kv->ppk_uint);
			tlv_pop(tlv);
			break;
		case PIV_PINFO_KV_STRING:
			tlv_push(tlv, 0x04);
			tlv_write(tlv, (uint8_t *)kv->ppk_string,
			    strlen(kv->ppk_string));
			tlv_pop(tlv);
			break;
		case PIV_PINFO_KV_DATA:
			tlv_push(tlv, 0x05);
			tlv_write(tlv, kv->ppk_data, kv->ppk_len);
			tlv_pop(tlv);
			break;
		}

		tlv_pop(tlv);
	}

	buflen = tlv_len(tlv);
	buf = malloc(buflen);
	if (buf == NULL) {
		err = errfno("malloc", errno, NULL);
		goto out;
	}
	bcopy(tlv_buf(tlv), buf, buflen);

	*outlen = buflen;
	*out = buf;
	buf = NULL;
	buflen = 0;
	err = ERRF_OK;

out:
	freezero(buf, buflen);
	tlv_free(tlv);
	return (err);
}

errf_t *
piv_pinfo_decode(const uint8_t *data, size_t len, struct piv_pinfo **out)
{
	struct tlv_state *tlv = NULL;
	uint tag;
	errf_t *err;
	struct piv_pinfo *pi = NULL;
	struct piv_pinfo_kv *kv = NULL;

	pi = calloc(1, sizeof (struct piv_pinfo));
	if (pi == NULL) {
		err = errfno("calloc", errno, NULL);
		goto out;
	}

	tlv = tlv_init(data, 0, len);
	if (tlv == NULL) {
		err = errfno("tlv_init", errno, NULL);
		goto out;
	}

	while (!tlv_at_end(tlv)) {
		if ((err = tlv_read_tag(tlv, &tag)))
			goto out;
		switch (tag) {
		case 0x01:	/* Name */
			if ((err = tlv_read_string(tlv, &pi->pp_name)))
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0x02:	/* Employee Affiliation */
			if ((err = tlv_read_string(tlv, &pi->pp_affiliation)))
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0x04:	/* Expiration date */
			if ((err = tlv_read_string(tlv, &pi->pp_expiry)))
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0x05:	/* Agency Card Serial Number */
			if ((err = tlv_read_string(tlv, &pi->pp_serial)))
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0x06:	/* Issuer Identification */
			if ((err = tlv_read_string(tlv, &pi->pp_issuer)))
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0x07:	/* Org. Affiliation (Line 1) */
			if ((err = tlv_read_string(tlv, &pi->pp_org_1)))
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0x08:	/* Org. Affiliation (Line 2) */
			if ((err = tlv_read_string(tlv, &pi->pp_org_2)))
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0x88:	/* Yubico Extensions */
			if ((err = tlv_read_tag(tlv, &tag)))
				goto out;
			switch (tag) {
			case 0x89:
				err = tlv_read_alloc(tlv, &pi->pp_yk_admin,
				    &pi->pp_yk_admin_len);
				if (err)
					goto out;
				if ((err = tlv_end(tlv)))
					goto out;
				break;
			default:
				err = tagerrf("PINFO YK ext", tag);
				goto out;
			}
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0x90:	/* KV extension */
			kv = calloc(1, sizeof (struct piv_pinfo_kv));
			if (kv == NULL) {
				err = errfno("calloc", errno, NULL);
				goto out;
			}

			if ((err = tlv_read_tag(tlv, &tag)))
				goto out;
			if (tag != 0x01) {
				err = tagerrf("PINFO KV ext", tag);
				goto out;
			}
			if ((err = tlv_read_string(tlv, &kv->ppk_name)))
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;

			if ((err = tlv_read_tag(tlv, &tag)))
				goto out;

			switch (tag) {
			case 0x02:
				kv->ppk_type = PIV_PINFO_KV_BOOL;
				if ((err = tlv_end(tlv)))
					goto out;
				break;
			case 0x03:
				kv->ppk_type = PIV_PINFO_KV_UINT;
				if ((err = tlv_read_u8to32(tlv, &kv->ppk_uint)))
					goto out;
				if ((err = tlv_end(tlv)))
					goto out;
				break;
			case 0x04:
				kv->ppk_type = PIV_PINFO_KV_STRING;
				if ((err = tlv_read_string(tlv, &kv->ppk_string)))
					goto out;
				if ((err = tlv_end(tlv)))
					goto out;
				break;
			case 0x05:
				kv->ppk_type = PIV_PINFO_KV_DATA;
				err = tlv_read_alloc(tlv, &kv->ppk_data,
				    &kv->ppk_len);
				if (err)
					goto out;
				if ((err = tlv_end(tlv)))
					goto out;
				break;
			default:
				err = tagerrf("PINFO KV ext", tag);
				goto out;
			}
			if ((err = tlv_end(tlv)))
				goto out;

			kv->ppk_next = pi->pp_kv;
			if (pi->pp_kv != NULL)
				pi->pp_kv->ppk_prev = kv;
			pi->pp_kv = kv;
			kv = NULL;

			break;
		case 0xFE:	/* LRC */
			tlv_skip(tlv);
			break;
		default:
			err = tagerrf("PINFO", tag);
			goto out;
		}
	}

	*out = pi;
	pi = NULL;
	err = ERRF_OK;
out:
	if (err != ERRF_OK)
		tlv_abort(tlv);
	else
		tlv_free(tlv);
	piv_pinfo_free(pi);
	pinfo_kv_free(kv);
	return (err);
}

struct piv_pinfo *
piv_pinfo_new(void)
{
	struct piv_pinfo *pp;

	pp = calloc(1, sizeof (struct piv_pinfo));
	if (pp == NULL)
		return (NULL);

	return (pp);
}

void
piv_pinfo_free(struct piv_pinfo *pp)
{
	struct piv_pinfo_kv *kv, *nkv;

	if (pp == NULL)
		return;

	for (kv = pp->pp_kv; kv != NULL; kv = nkv) {
		nkv = kv->ppk_next;
		kv->ppk_next = NULL;
		kv->ppk_prev = NULL;
		pinfo_kv_free(kv);
	}

	free(pp->pp_name);
	free(pp->pp_affiliation);
	free(pp->pp_expiry);
	free(pp->pp_serial);
	free(pp->pp_issuer);
	free(pp->pp_org_1);
	free(pp->pp_org_2);

	freezero(pp->pp_yk_admin, pp->pp_yk_admin_len);

	free(pp);
}

void
piv_pinfo_set_name(struct piv_pinfo *pp, const char *v)
{
	free(pp->pp_name);
	pp->pp_name = nstrdup(v);
}

void
piv_pinfo_set_affiliation(struct piv_pinfo *pp, const char *v)
{
	free(pp->pp_affiliation);
	pp->pp_affiliation = nstrdup(v);
}

void
piv_pinfo_set_expiry(struct piv_pinfo *pp, const char *v)
{
	free(pp->pp_expiry);
	pp->pp_expiry = nstrdup(v);
}

const char *pinfo_months[] = {
	"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT",
	"NOV", "DEC"
};

void
piv_pinfo_set_expiry_rel(struct piv_pinfo *pp, uint sec)
{
	char buf[12] = {0};
	time_t now;
	struct tm *tm;

	now = time(NULL);
	now += sec;
	tm = gmtime(&now);

	snprintf(buf, sizeof (buf), "%04d%s%02d", tm->tm_year + 1900,
	    pinfo_months[tm->tm_mon], tm->tm_mday);

	piv_pinfo_set_expiry(pp, buf);
}

void
piv_pinfo_set_serial(struct piv_pinfo *pp, const char *v)
{
	free(pp->pp_serial);
	pp->pp_serial = nstrdup(v);
}

void
piv_pinfo_set_issuer(struct piv_pinfo *pp, const char *v)
{
	free(pp->pp_issuer);
	pp->pp_issuer = nstrdup(v);
}

void
piv_pinfo_set_org_line_1(struct piv_pinfo *pp, const char *v)
{
	free(pp->pp_org_1);
	pp->pp_org_1 = nstrdup(v);
}

void
piv_pinfo_set_org_line_2(struct piv_pinfo *pp, const char *v)
{
	free(pp->pp_org_2);
	pp->pp_org_2 = nstrdup(v);
}

void
ykpiv_pinfo_set_admin_key(struct piv_pinfo *pp, const uint8_t *key, size_t len)
{
	freezero(pp->pp_yk_admin, pp->pp_yk_admin_len);
	pp->pp_yk_admin = malloc(len);
	VERIFY(pp->pp_yk_admin != NULL);
	bcopy(key, pp->pp_yk_admin, len);
	pp->pp_yk_admin_len = len;
}

struct piv_pinfo_kv *
set_pinfo_kv(struct piv_pinfo *pp, const char *key, enum piv_pinfo_kv_type type)
{
	struct piv_pinfo_kv *kv;
	for (kv = pp->pp_kv; kv != NULL; kv = kv->ppk_next) {
		if (strcmp(key, kv->ppk_name) == 0 &&
		    kv->ppk_type == type) {
			return (kv);
		}
	}
	kv = calloc(1, sizeof (struct piv_pinfo_kv));
	kv->ppk_name = nstrdup(key);
	kv->ppk_type = type;
	kv->ppk_next = pp->pp_kv;
	if (pp->pp_kv != NULL)
		pp->pp_kv->ppk_prev = kv;
	pp->pp_kv = kv;
	return (kv);
}

void
piv_pinfo_set_kv(struct piv_pinfo *pp, const char *key, const uint8_t *val,
    size_t len)
{
	struct piv_pinfo_kv *kv;
	kv = set_pinfo_kv(pp, key, PIV_PINFO_KV_DATA);
	if (kv == NULL)
		return;
	free(kv->ppk_data);
	kv->ppk_data = malloc(len);
	bcopy(val, kv->ppk_data, len);
	kv->ppk_len = len;
}

void
piv_pinfo_set_kv_uint(struct piv_pinfo *pp, const char *key, uint val)
{
	struct piv_pinfo_kv *kv;
	kv = set_pinfo_kv(pp, key, PIV_PINFO_KV_UINT);
	if (kv == NULL)
		return;
	kv->ppk_uint = val;
}

void
piv_pinfo_set_kv_bool(struct piv_pinfo *pp, const char *key)
{
	(void) set_pinfo_kv(pp, key, PIV_PINFO_KV_BOOL);
}

void
piv_pinfo_unset_kv(struct piv_pinfo *pp, const char *key)
{
	struct piv_pinfo_kv *kv, *nkv;
	for (kv = pp->pp_kv; kv != NULL; kv = nkv) {
		nkv = kv->ppk_next;
		if (strcmp(key, kv->ppk_name) == 0) {
			if (kv->ppk_prev == NULL)
				pp->pp_kv = kv->ppk_next;
			else
				kv->ppk_prev->ppk_next = kv->ppk_next;
			if (kv->ppk_next != NULL)
				kv->ppk_next->ppk_prev = kv->ppk_prev;
			kv->ppk_prev = NULL;
			kv->ppk_next = NULL;
			pinfo_kv_free(kv);
		}
	}
}

void
piv_pinfo_set_kv_string(struct piv_pinfo *pp, const char *key, const char *val)
{
	struct piv_pinfo_kv *kv;
	kv = set_pinfo_kv(pp, key, PIV_PINFO_KV_STRING);
	if (kv == NULL)
		return;
	free(kv->ppk_string);
	kv->ppk_string = nstrdup(val);
}

const char *
piv_pinfo_get_name(const struct piv_pinfo *pp)
{
	return (pp->pp_name);
}

const char *
piv_pinfo_get_affiliation(const struct piv_pinfo *pp)
{
	return (pp->pp_affiliation);
}

const char *
piv_pinfo_get_expiry(const struct piv_pinfo *pp)
{
	return (pp->pp_expiry);
}

const char *
piv_pinfo_get_serial(const struct piv_pinfo *pp)
{
	return (pp->pp_serial);
}

const char *
piv_pinfo_get_issuer(const struct piv_pinfo *pp)
{
	return (pp->pp_issuer);
}

const char *
piv_pinfo_get_org_line_1(const struct piv_pinfo *pp)
{
	return (pp->pp_org_1);
}

const char *
piv_pinfo_get_org_line_2(const struct piv_pinfo *pp)
{
	return (pp->pp_org_2);
}

const uint8_t *
ykpiv_pinfo_get_admin_key(const struct piv_pinfo *pp, size_t *len)
{
	*len = pp->pp_yk_admin_len;
	return (pp->pp_yk_admin);
}

const struct piv_pinfo_kv *
get_pinfo_kv(const struct piv_pinfo *pp, const char *key,
    enum piv_pinfo_kv_type type)
{
	const struct piv_pinfo_kv *kv;
	for (kv = pp->pp_kv; kv != NULL; kv = kv->ppk_next) {
		if (strcmp(key, kv->ppk_name) == 0 &&
		    kv->ppk_type == type) {
			return (kv);
		}
	}
	return (NULL);
}

boolean_t
piv_pinfo_get_kv_uint(const struct piv_pinfo *pp, const char *key, uint *out)
{
	const struct piv_pinfo_kv *kv;
	kv = get_pinfo_kv(pp, key, PIV_PINFO_KV_UINT);
	if (kv == NULL)
		return (B_FALSE);
	*out = kv->ppk_uint;
	return (B_TRUE);
}

boolean_t
piv_pinfo_get_kv_bool(const struct piv_pinfo *pp, const char *key)
{
	const struct piv_pinfo_kv *kv;
	kv = get_pinfo_kv(pp, key, PIV_PINFO_KV_BOOL);
	if (kv == NULL)
		return (B_FALSE);
	return (B_TRUE);
}

const char *
piv_pinfo_get_kv_string(const struct piv_pinfo *pp, const char *key)
{
	const struct piv_pinfo_kv *kv;
	kv = get_pinfo_kv(pp, key, PIV_PINFO_KV_STRING);
	if (kv == NULL)
		return (NULL);
	return (kv->ppk_string);
}

const uint8_t *
piv_pinfo_get_kv(const struct piv_pinfo *pp, const char *key, size_t *len)
{
	const struct piv_pinfo_kv *kv;
	kv = get_pinfo_kv(pp, key, PIV_PINFO_KV_DATA);
	if (kv == NULL) {
		*len = 0;
		return (NULL);
	}
	*len = kv->ppk_len;
	return (kv->ppk_data);
}

errf_t *
piv_box_open_agent(int fd, struct piv_ecdh_box *box)
{
	struct piv_ecdh_box *rebox = NULL;
	struct sshkey *pubkey, *temp = NULL, *temppub = NULL;
	errf_t *err;
	int rc;
	uint i;
	size_t len;
	uint8_t code;
	uint32_t nexts;
	char *extname;
	int has_rebox = 0, has_ecdh = 0;
	struct ssh_identitylist *idl = NULL;
	struct sshbuf *req = NULL, *buf = NULL, *boxbuf = NULL, *reply = NULL;
	struct sshbuf *datab = NULL;
	uint8_t *sec = NULL;
	size_t seclen;
	boolean_t found = B_FALSE;

	pubkey = piv_box_pubkey(box);

	rc = ssh_fetch_identitylist(fd, &idl);
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
		    "SSH agent");
		goto out;
	}

	req = sshbuf_new();
	reply = sshbuf_new();
	if (req == NULL || reply == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	if ((rc = sshbuf_put_u8(req, SSH_AGENTC_EXTENSION))) {
		err = ssherrf("sshbuf_put_u8", rc);
		goto out;
	}
	if ((rc = sshbuf_put_cstring(req, "query"))) {
		err = ssherrf("sshbuf_put_cstring", rc);
		goto out;
	}
	if ((rc = sshbuf_put_u32(req, 0))) {
		err = ssherrf("sshbuf_put_u32", rc);
		goto out;
	}
	rc = ssh_request_reply(fd, req, reply);
	if (rc) {
		err = ssherrf("ssh_request_reply", rc);
		goto out;
	}

	if ((rc = sshbuf_get_u8(reply, &code))) {
		err = ssherrf("sshbuf_get_u8", rc);
		goto out;
	}
	if (code != SSH_AGENT_SUCCESS) {
		err = errf("NotSupportedError", NULL, "SSH agent does not "
		    "support 'query' extension (returned code %d)", (int)code);
		goto out;
	}
	if ((rc = sshbuf_get_u32(reply, &nexts))) {
		err = ssherrf("sshbuf_get_u32", rc);
		goto out;
	}
	for (i = 0; i < nexts; ++i) {
		if ((rc = sshbuf_get_cstring(reply, &extname, &len))) {
			err = ssherrf("sshbuf_get_cstring", rc);
			goto out;
		}
		if (strcmp("ecdh-rebox@joyent.com", extname) == 0)
			has_rebox = 1;
		else if (strcmp("ecdh@joyent.com", extname) == 0)
			has_ecdh = 1;
		free(extname);
		extname = NULL;
	}

	sshbuf_reset(req);
	sshbuf_reset(reply);
	buf = sshbuf_new();
	boxbuf = sshbuf_new();
	if (buf == NULL || boxbuf == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	if (has_rebox) {
		rc = sshkey_generate(KEY_ECDSA, sshkey_size(pubkey), &temp);
		if (rc) {
			err = ssherrf("sshkey_generate", rc);
			goto out;
		}
		if ((rc = sshkey_demote(temp, &temppub))) {
			err = ssherrf("sshkey_demote", rc);
			goto out;
		}

		if ((rc = sshbuf_put_u8(req, SSH_AGENTC_EXTENSION))) {
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

		rc = ssh_request_reply(fd, req, reply);
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
		goto out;
	}

	if (has_ecdh) {
		if ((rc = sshkey_putb(pubkey, boxbuf))) {
			err = ssherrf("sshkey_putb", rc);
			goto out;
		}
		if ((rc = sshbuf_put_stringb(buf, boxbuf))) {
			err = ssherrf("sshbuf_put_stringb", rc);
			goto out;
		}
		sshbuf_reset(boxbuf);
		if ((rc = sshkey_putb(box->pdb_ephem_pub, boxbuf))) {
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

		if ((rc = sshbuf_put_u8(req, SSH_AGENTC_EXTENSION))) {
			err = ssherrf("sshbuf_put_u8", rc);
			goto out;
		}
		if ((rc = sshbuf_put_cstring(req, "ecdh@joyent.com"))) {
			err = ssherrf("sshbuf_put_cstring", rc);
			goto out;
		}
		if ((rc = sshbuf_put_stringb(req, buf))) {
			err = ssherrf("sshbuf_put_stringb", rc);
			goto out;
		}

		rc = ssh_request_reply(fd, req, reply);
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
			    "message code %d to ECDH request", (int)code);
			goto out;
		}
		if ((rc = sshbuf_get_string(reply, &sec, &seclen))) {
			err = ssherrf("sshbuf_get_string", rc);
			goto out;
		}

		err = piv_box_open_common(sec, seclen, box);
		goto out;
	}

	err = errf("NotSupportedError", NULL, "SSH agent does not support "
	    "ECDH extensions");

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


errf_t *
piv_read_cardcap(struct piv_token *pk, struct piv_cardcap **outp)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;

	VERIFY(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_u8to32(tlv, PIV_TAG_CARDCAP);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pk, apdu);
	if (err) {
		err = ioerrf(err, pk->pt_rdrname);
		bunyan_log(BNY_WARN, "transceive_apdu failed",
		    "error", BNY_ERF, err, NULL);
		goto out;
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		if ((err = tlv_read_tag(tlv, &tag)))
			goto invdata;
		if (tag != 0x53) {
			err = tagerrf("INS_GET_DATA(PINFO)", tag);
			goto invdata;
		}
		err = piv_cardcap_decode(tlv_ptr(tlv), tlv_rem(tlv), outp);
		if (err != ERRF_OK)
			goto invdata;
		tlv_skip(tlv);

		err = ERRF_OK;

	} else if (apdu->a_sw == SW_FILE_NOT_FOUND ||
	    apdu->a_sw == SW_WRONG_DATA) {
		err = errf("NotFoundError", swerrf("INS_GET_DATA", apdu->a_sw),
		    "PIV CARDCAP object was not found on device '%s'",
		    pk->pt_rdrname);

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_GET_DATA", apdu->a_sw),
		    pk->pt_rdrname, "reading PIV CARDCAP object");

	} else {
		err = swerrf("INS_GET_DATA(CARDCAP)", apdu->a_sw);
		bunyan_log(BNY_DEBUG, "unexpected card error",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "error", BNY_ERF, err, NULL);
	}

out:
	tlv_free(tlv);
	piv_apdu_free(apdu);
	return (err);

invdata:
	tlv_abort(tlv);
	err = invderrf(err, pk->pt_rdrname);
	debug_dump(err, apdu);
	goto out;
}

errf_t *
piv_write_cardcap(struct piv_token *pt, const struct piv_cardcap *pinfo)
{
	errf_t *err;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint8_t *data;
	size_t len;

	VERIFY(pt->pt_intxn == B_TRUE);

	err = piv_cardcap_encode(pinfo, &data, &len);
	if (err)
		return (err);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_u8to32(tlv, PIV_TAG_CARDCAP);
	tlv_pop(tlv);
	tlv_push(tlv, 0x53);
	tlv_write(tlv, (uint8_t *)data, len);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_PUT_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	err = piv_apdu_transceive_chain(pt, apdu);
	if (err) {
		err = ioerrf(err, pt->pt_rdrname);
		bunyan_log(BNY_WARN, "piv_write_cardcap.transceive_chain failed",
		    "error", BNY_ERF, err, NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (err);
	}

	tlv_free(tlv);
	tlv = NULL;

	if (apdu->a_sw == SW_NO_ERROR) {
		err = ERRF_OK;
	} else if (apdu->a_sw == SW_OUT_OF_MEMORY) {
		err = errf("DeviceOutOfMemoryError", swerrf("INS_PUT_DATA(CARDCAP)",
		    apdu->a_sw), "Out of memory to store file object on "
		    "PIV device '%s'", pt->pt_rdrname);
	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		err = permerrf(swerrf("INS_PUT_DATA(CARDCAP)", apdu->a_sw),
		    pt->pt_rdrname, "writing CARDCAP object");
	} else if (apdu->a_sw == SW_FUNC_NOT_SUPPORTED) {
		err = notsuperrf(swerrf("INS_PUT_DATA(CARDCAP)", apdu->a_sw),
		    pt->pt_rdrname, "CARDCAP object");
	} else {
		err = swerrf("INS_PUT_DATA(CARDCAP)", apdu->a_sw);
	}

	piv_apdu_free(apdu);

	return (err);
}
