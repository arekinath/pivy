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

#define	PIV_MAX_CERT_LEN		16384

const uint8_t AID_PIV[] = {
	0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00
};

boolean_t piv_full_apdu_debug = B_FALSE;

int
piv_auth_key(struct piv_token *tk, struct piv_slot *slot, struct sshkey *pubkey)
{
	int rv;
	uint8_t *chal = NULL, *sig = NULL;
	size_t challen, siglen;
	enum sshdigest_types hashalg;
	struct sshbuf *b = NULL;

	assert(tk->pt_intxn == B_TRUE);

	if (!sshkey_equal_public(pubkey, slot->ps_pubkey))
		return (ESRCH);

	challen = 64;
	chal = calloc(1, challen);
	VERIFY3P(chal, !=, NULL);
	arc4random_buf(chal, challen);

	hashalg = 0;
	rv = piv_sign(tk, slot, chal, challen, &hashalg, &sig, &siglen);
	if (rv != 0)
		goto out;

	b = sshbuf_new();
	VERIFY3P(b, !=, NULL);

	rv = sshkey_sig_from_asn1(pubkey, hashalg, sig, siglen, b);
	if (rv != 0) {
		rv = ENOTSUP;
		goto out;
	}

	rv = sshkey_verify(pubkey, sshbuf_ptr(b), sshbuf_len(b),
	    chal, challen, 0);
	if (rv != 0) {
		rv = ESRCH;
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

	return (rv);
}

static int
piv_probe_ykpiv(struct piv_token *pk)
{
	int rv;
	struct apdu *apdu;

	assert(pk->pt_intxn == B_TRUE);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_VER, 0x00, 0x00);

	rv = piv_apdu_transceive(pk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_probe_ykpiv.transceive_apdu failed",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		piv_apdu_free(apdu);
		return (EIO);
	}

	if (apdu->a_sw == SW_NO_ERROR) {
		const uint8_t *reply =
		    &apdu->a_reply.b_data[apdu->a_reply.b_offset];
		if (apdu->a_reply.b_len < 3) {
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}
		pk->pt_ykpiv = B_TRUE;
		bcopy(reply, pk->pt_ykver, 3);
		rv = 0;
	} else {
		rv = ENOTSUP;
	}

	piv_apdu_free(apdu);
	return (rv);
}

static int
piv_read_chuid(struct piv_token *pk)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	size_t used;

	assert(pk->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x5C);
	tlv_write_uint(tlv, PIV_TAG_CHUID);
	tlv_pop(tlv);

	bunyan_log(DEBUG, "reading CHUID file", NULL);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = piv_apdu_transceive_chain(pk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_read_chuid.transceive_apdu failed",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x53) {
			bunyan_log(DEBUG, "card returned invalid tag in "
			    "PIV INS_GET_DATA(CHUID) response payload",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "tag", BNY_UINT, tag,
			    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
			    apdu->a_reply.b_offset, apdu->a_reply.b_len, NULL);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}
		while (!tlv_at_end(tlv)) {
			tag = tlv_read_tag(tlv);
			bunyan_log(TRACE, "reading chuid tlv tag", "tag", BNY_UINT, (uint)tag, NULL);
			switch (tag) {
			case 0xEE:	/* Buffer Length */
			case 0xFE:	/* CRC */
			case 0x30:	/* FASC-N */
			case 0x32:	/* Org Ident */
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
				bunyan_log(TRACE, "read guid", "guid", BNY_BIN_HEX, pk->pt_guid, sizeof (pk->pt_guid), NULL);
				tlv_end(tlv);
				break;
			default:
				tlv_skip(tlv);
				tlv_skip(tlv);
				tlv_free(tlv);
				piv_apdu_free(apdu);
				return (ENOTSUP);
			}
		}
		tlv_end(tlv);
		tlv_free(tlv);
		rv = 0;

	} else if (apdu->a_sw == SW_FILE_NOT_FOUND) {
		rv = ENOENT;

	} else {
		bunyan_log(DEBUG, "card did not accept INS_GET_DATA for "
		    "PIV CHUID file",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		rv = EINVAL;
	}

	piv_apdu_free(apdu);

	return (rv);
}

struct piv_token *
piv_enumerate(SCARDCONTEXT ctx)
{
	DWORD rv, readersLen;
	LPTSTR readers, thisrdr;
	struct piv_token *ks = NULL;

	rv = SCardListReaders(ctx, NULL, NULL, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		bunyan_log(ERROR, "SCardListReaders failed",
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		return (NULL);
	}
	readers = calloc(1, readersLen);
	rv = SCardListReaders(ctx, NULL, readers, &readersLen);
	if (rv != SCARD_S_SUCCESS) {
		bunyan_log(ERROR, "SCardListReaders failed",
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		return (NULL);
	}

	for (thisrdr = readers; *thisrdr != 0; thisrdr += strlen(thisrdr) + 1) {
		SCARDHANDLE card;
		struct piv_token *key;
		DWORD activeProtocol;

		rv = SCardConnect(ctx, thisrdr, SCARD_SHARE_SHARED,
		    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card,
		    &activeProtocol);
		if (rv != SCARD_S_SUCCESS) {
			bunyan_log(DEBUG, "SCardConnect failed",
			    "reader", BNY_STRING, thisrdr,
			    "err", BNY_STRING, pcsc_stringify_error(rv),
			    NULL);
			continue;
		}

		key = calloc(1, sizeof (struct piv_token));
		key->pt_cardhdl = card;
		key->pt_rdrname = thisrdr;
		key->pt_proto = activeProtocol;

		switch (activeProtocol) {
		case SCARD_PROTOCOL_T0:
			key->pt_sendpci = *SCARD_PCI_T0;
			break;
		case SCARD_PROTOCOL_T1:
			key->pt_sendpci = *SCARD_PCI_T1;
			break;
		default:
			assert(0);
		}

		piv_txn_begin(key);
		rv = piv_select(key);
		if (rv == 0) {
			rv = piv_read_chuid(key);
			if (rv == ENOENT) {
				rv = 0;
				key->pt_nochuid = B_TRUE;
			}
		}
		if (rv == 0) {
			rv = piv_probe_ykpiv(key);
			if (rv == ENOTSUP)
				rv = 0;
		}
		piv_txn_end(key);

		if (rv == 0) {
			key->pt_next = ks;
			ks = key;
		} else {
			(void) SCardDisconnect(card, SCARD_RESET_CARD);
		}
	}

	return (ks);
}

void
piv_release(struct piv_token *pk)
{
	struct piv_token *next;
	struct piv_slot *ps, *psnext;

	while (pk != NULL) {
		assert(pk->pt_intxn == B_FALSE);
		(void) SCardDisconnect(pk->pt_cardhdl, SCARD_LEAVE_CARD);

		ps = pk->pt_slots;
		while (ps != NULL) {
			OPENSSL_free((void *)ps->ps_subj);
			X509_free(ps->ps_x509);
			sshkey_free(ps->ps_pubkey);
			psnext = ps->ps_next;
			free(ps);
			ps = psnext;
		}

		next = pk->pt_next;
		free(pk);
		pk = next;
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
		buf[5] = apdu->a_le;
		*outlen = 5;
		return (buf);
	} else {
		/* TODO: maybe look at handling ext APDUs? */
		assert(d->b_len < 256 && d->b_len > 0);
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
	default:
		return ("UNKNOWN");
	}
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
	case SW_INCORRECT_PIN:
		return ("INCORRECT_PIN");
	case SW_INCORRECT_P1P2:
		return ("INCORRECT_P1P2");
	case SW_WRONG_DATA:
		return ("WRONG_DATA");
	case SW_OUT_OF_MEMORY:
		return ("OUT_OF_MEMORY");
	case SW_WRONG_LENGTH:
		return ("WRONG_LENGTH");
	default:
		/* FALL THROUGH */
		(void)0;
	}
	if ((sw & 0xFF00) == SW_BYTES_REMAINING_00)
		return ("BYTES_REMAINING");
	else if ((sw & 0xFF00) == SW_WARNING_NO_CHANGE_00)
		return ("WARNING_NO_CHANGE");
	else if ((sw & 0xFF00) == SW_WARNING_00)
		return ("WARNING_UNKNOWN");
	return ("UNKNOWN");
}

int
piv_apdu_transceive(struct piv_token *key, struct apdu *apdu)
{
	uint cmdLen = 0;
	int rv;

	boolean_t freedata = B_FALSE;
	DWORD recvLength;
	uint8_t *cmd;
	struct apdubuf *r = &(apdu->a_reply);

	assert(key->pt_intxn == B_TRUE);

	cmd = apdu_to_buffer(apdu, &cmdLen);
	assert(cmd != NULL);
	if (cmd == NULL || cmdLen < 5)
		return (ENOMEM);

	if (r->b_data == NULL) {
		r->b_data = calloc(1, MAX_APDU_SIZE);
		r->b_size = MAX_APDU_SIZE;
		r->b_offset = 0;
		freedata = B_TRUE;
	}
	recvLength = r->b_size - r->b_offset;
	assert(r->b_data != NULL);

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
		bunyan_log(DEBUG, "SCardTransmit failed",
		    "reader", BNY_STRING, key->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		if (freedata) {
			free(r->b_data);
			bzero(r, sizeof (struct apdubuf));
		}
		return (rv);
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
	    "lc", BNY_UINT, (uint)cmdLen,
	    "sw", BNY_UINT, (uint)apdu->a_sw,
	    "sw_name", BNY_STRING, sw_to_name(apdu->a_sw),
	    "le", BNY_UINT, (uint)r->b_len,
	    NULL);

	return (0);
}

int
piv_apdu_transceive_chain(struct piv_token *pk, struct apdu *apdu)
{
	int rv;
	size_t offset;
	size_t rem;

	VERIFY(pk->pt_intxn == B_TRUE);

	/* First, send the command. */
	rem = apdu->a_cmd.b_len;
	while (rem > 0) {
		/* Is there another block needed in the chain? */
		if (rem > 0xFF) {
			apdu->a_cls |= CLA_CHAIN;
			apdu->a_cmd.b_len = 0xFF;
		} else {
			apdu->a_cls &= ~CLA_CHAIN;
			apdu->a_cmd.b_len = rem;
		}
		rv = piv_apdu_transceive(pk, apdu);
		if (rv != 0)
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
			return (0);
		}
	}

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
		if (rv != 0)
			return (rv);
	}

	/* Work out the total length of all the segments we recieved. */
	apdu->a_reply.b_len += apdu->a_reply.b_offset - offset;
	apdu->a_reply.b_offset = offset;

	return (0);
}

int
piv_txn_begin(struct piv_token *key)
{
	VERIFY(key->pt_intxn == B_FALSE);
	LONG rv;
	DWORD activeProtocol;
retry:
	rv = SCardBeginTransaction(key->pt_cardhdl);
	if (rv == SCARD_W_RESET_CARD) {
		rv = SCardReconnect(key->pt_cardhdl, SCARD_SHARE_SHARED,
		    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, SCARD_RESET_CARD,
		    &activeProtocol);
		if (rv == SCARD_S_SUCCESS) {
			goto retry;
		} else {
			bunyan_log(ERROR, "SCardBeginTransaction failed, and "
			    "attempt to ack reset failed",
			    "reader", BNY_STRING, key->pt_rdrname,
			    "err", BNY_STRING, pcsc_stringify_error(rv),
			    NULL);
			return (EIO);
		}
	}
	if (rv != SCARD_S_SUCCESS) {
		bunyan_log(ERROR, "SCardBeginTransaction failed",
		    "reader", BNY_STRING, key->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		return (EIO);
	}
	key->pt_intxn = B_TRUE;
	return (0);
}

void
piv_txn_end(struct piv_token *key)
{
	assert(key->pt_intxn == B_TRUE);
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

int
piv_select(struct piv_token *tk)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag, idx;

	assert(tk->pt_intxn == B_TRUE);

	apdu = piv_apdu_make(CLA_ISO, INS_SELECT, SEL_APP_AID, 0);
	apdu->a_cmd.b_data = (uint8_t *)AID_PIV;
	apdu->a_cmd.b_len = sizeof (AID_PIV);

	rv = piv_apdu_transceive_chain(tk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_select.transceive_apdu failed",
		    "reader", BNY_STRING, tk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		piv_apdu_free(apdu);
		return (EIO);
	}

	if (apdu->a_sw == SW_NO_ERROR || apdu->a_sw == SW_WARNING_EOF) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != PIV_TAG_APT) {
			bunyan_log(DEBUG, "card returned invalid tag in "
			    "PIV INS_SELECT response payload",
			    "reader", BNY_STRING, tk->pt_rdrname,
			    "tag", BNY_UINT, tag,
			    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
			    apdu->a_reply.b_offset, apdu->a_reply.b_len, NULL);
			piv_apdu_free(apdu);
			return (ENOTSUP);
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
						assert(0);
					}
				}
				tlv_end(tlv);
				break;
			default:
				bunyan_log(DEBUG, "card returned unknown tag "
				    "in PIV INS_SELECT response payload",
				    "reader", BNY_STRING, tk->pt_rdrname,
				    "tag", BNY_UINT, tag,
				    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
				    apdu->a_reply.b_offset, apdu->a_reply.b_len,
				    NULL);
				tlv_skip(tlv);
				tlv_skip(tlv);
				tlv_free(tlv);
				piv_apdu_free(apdu);
				return (ENOTSUP);
			}
		}
		tlv_end(tlv);
		tlv_free(tlv);
		rv = 0;
	} else {
		bunyan_log(DEBUG, "card did not accept INS_SELECT for PIV",
		    "reader", BNY_STRING, tk->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		rv = ENOENT;
	}

	piv_apdu_free(apdu);

	return (rv);
}

int
piv_auth_admin(struct piv_token *pt, const uint8_t *key, size_t keylen)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	uint8_t *chal = NULL, *resp = NULL, *iv = NULL;
	size_t challen, ivlen, resplen;
	const struct sshcipher *cipher;
	struct sshcipher_ctx *cctx;

	assert(pt->pt_intxn == B_TRUE);

	cipher = cipher_by_name("3des-cbc");
	assert(cipher != NULL);

	assert(cipher_keylen(cipher) == keylen);
	assert(cipher_authlen(cipher) == 0);

	tlv = tlv_init_write();
	tlv_push(tlv, 0x7C);
	tlv_push(tlv, GA_TAG_CHALLENGE);
	tlv_pop(tlv);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_AUTH, PIV_ALG_3DES,
	    PIV_SLOT_ADMIN);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = piv_apdu_transceive(pt, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_auth_admin.transceive_chain failed",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw != SW_NO_ERROR) {
		bunyan_log(DEBUG, "card did not return challenge to "
		    "INS_GEN_AUTH",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		piv_apdu_free(apdu);
		return (EINVAL);
	}

	tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
	    apdu->a_reply.b_len);
	tag = tlv_read_tag(tlv);
	if (tag != 0x7C) {
		bunyan_log(DEBUG, "card returned invalid tag in PIV "
		    "INS_GEN_AUTH response payload",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "slotid", BNY_UINT, (uint)0x9B,
		    "tag", BNY_UINT, tag,
		    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
		    apdu->a_reply.b_offset, apdu->a_reply.b_len, NULL);
		tlv_skip(tlv);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (ENOTSUP);
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

	assert(chal != NULL);
	tlv_free(tlv);
	piv_apdu_free(apdu);

	resplen = challen;
	resp = calloc(1, resplen);
	assert(resp != NULL);

	assert(cipher_blocksize(cipher) == challen);

	ivlen = cipher_ivlen(cipher);
	iv = calloc(1, ivlen);
	assert(iv != NULL);
	explicit_bzero(iv, ivlen);

	rv = cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 1);
	assert(rv == 0);
	rv = cipher_crypt(cctx, 0, resp, chal, challen, 0, 0);
	assert(rv == 0);
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

	rv = piv_apdu_transceive(pt, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_auth_admin.transceive_chain failed",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR) {
		rv = 0;
	} else if (apdu->a_sw == SW_INCORRECT_P1P2) {
		rv = ENOENT;
	} else if (apdu->a_sw == SW_WRONG_DATA) {
		rv = EACCES;
	} else {
		rv = EINVAL;
	}

	piv_apdu_free(apdu);
	return (rv);
}

int
piv_write_file(struct piv_token *pt, uint tag, const uint8_t *data, size_t len)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;

	assert(pt->pt_intxn == B_TRUE);

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

	rv = piv_apdu_transceive_chain(pt, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_write_file.transceive_chain failed",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR) {
		rv = 0;
	} else if (apdu->a_sw == SW_OUT_OF_MEMORY) {
		rv = ENOMEM;
	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		rv = EPERM;
	} else if (apdu->a_sw == SW_FUNC_NOT_SUPPORTED) {
		rv = ENOENT;
	} else {
		rv = EINVAL;
	}

	piv_apdu_free(apdu);

	return (rv);
}

int
piv_generate(struct piv_token *pt, enum piv_slotid slotid, enum piv_alg alg,
    struct sshkey **pubkey)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	struct sshkey *k = NULL;

	assert(pt->pt_intxn == B_TRUE);

	tlv = tlv_init_write();
	tlv_push(tlv, 0xAC);
	tlv_push(tlv, 0x80);
	tlv_write_uint(tlv, alg);
	tlv_pop(tlv);
	tlv_pop(tlv);

	apdu = piv_apdu_make(CLA_ISO, INS_GEN_ASYM, 0x00, slotid);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = piv_apdu_transceive_chain(pt, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_generate.transceive_chain failed",
		    "reader", BNY_STRING, pt->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x7F49) {
			bunyan_log(DEBUG, "card returned invalid tag in "
			    "PIV INS_GEN_ASYM response payload",
			    "reader", BNY_STRING, pt->pt_rdrname,
			    "slotid", BNY_UINT, (uint)slotid,
			    "tag", BNY_UINT, tag,
			    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
			    apdu->a_reply.b_offset, apdu->a_reply.b_len, NULL);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}
		if (alg == PIV_ALG_RSA1024 || alg == PIV_ALG_RSA2048) {
			k = sshkey_new(KEY_RSA);
			assert(k != NULL);
		} else if (alg == PIV_ALG_ECCP256) {
			k = sshkey_new(KEY_ECDSA);
			assert(k != NULL);
			k->ecdsa_nid = NID_X9_62_prime256v1;
			k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
			EC_KEY_set_asn1_flag(k->ecdsa, OPENSSL_EC_NAMED_CURVE);
		} else if (alg == PIV_ALG_ECCP384) {
			k = sshkey_new(KEY_ECDSA);
			assert(k != NULL);
			k->ecdsa_nid = NID_secp384r1;
			k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
			EC_KEY_set_asn1_flag(k->ecdsa, OPENSSL_EC_NAMED_CURVE);
		}
		while (!tlv_at_end(tlv)) {
			tag = tlv_read_tag(tlv);
			if (alg == PIV_ALG_RSA1024 || alg == PIV_ALG_RSA2048) {
				if (tag == 0x81) {		/* Modulus */
					assert(BN_bin2bn(tlv_ptr(tlv),
					    tlv_rem(tlv), k->rsa->n) != NULL);
					tlv_skip(tlv);
					continue;
				} else if (tag == 0x82) {	/* Exponent */
					assert(BN_bin2bn(tlv_ptr(tlv),
					    tlv_rem(tlv), k->rsa->e) != NULL);
					tlv_skip(tlv);
					continue;
				}
			} else if (alg == PIV_ALG_ECCP256 ||
			    alg == PIV_ALG_ECCP384) {
				if (tag == 0x86) {
					const EC_GROUP *g;
					EC_POINT *pt;

					g = EC_KEY_get0_group(k->ecdsa);
					pt = EC_POINT_new(g);
					rv = EC_POINT_oct2point(g, pt,
					    tlv_ptr(tlv), tlv_rem(tlv), NULL);
					assert(rv == 1);

					rv = sshkey_ec_validate_public(g, pt);
					assert(rv == 0);
					rv = EC_KEY_set_public_key(
					    k->ecdsa, pt);
					assert(rv == 1);
					EC_POINT_free(pt);

					tlv_skip(tlv);
					continue;
				}
			}
			tlv_skip(tlv);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}
		tlv_end(tlv);
		tlv_free(tlv);

		*pubkey = k;

		rv = 0;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		rv = EPERM;

	} else {
		rv = EINVAL;
	}

	piv_apdu_free(apdu);
	return (rv);
}

int
piv_write_cert(struct piv_token *pk, enum piv_slotid slotid,
    const uint8_t *data, size_t datalen, uint flags)
{
	int rv;
	struct tlv_state *tlv;
	uint tag;

	assert(pk->pt_intxn == B_TRUE);

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
		assert(0);
	}

	tlv = tlv_init_write();
	tlv_pushl(tlv, 0x70, datalen + 3);
	tlv_write(tlv, data, 0, datalen);
	tlv_pop(tlv);
	tlv_push(tlv, 0x71);
	tlv_write_byte(tlv, (uint8_t)flags);
	tlv_pop(tlv);

	rv = piv_write_file(pk, tag, tlv_buf(tlv), tlv_len(tlv));

	tlv_free(tlv);

	return (rv);
}

int
piv_read_cert(struct piv_token *pk, enum piv_slotid slotid)
{
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

	assert(pk->pt_intxn == B_TRUE);

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
		assert(0);
	}
	tlv_pop(tlv);

	bunyan_log(DEBUG, "reading cert file",
	    "slot", BNY_UINT, (uint)slotid,
	    "cdata", BNY_BIN_HEX, tlv_buf(tlv), tlv_len(tlv),
	    NULL);

	apdu = piv_apdu_make(CLA_ISO, INS_GET_DATA, 0x3F, 0xFF);
	apdu->a_cmd.b_data = tlv_buf(tlv);
	apdu->a_cmd.b_len = tlv_len(tlv);

	rv = piv_apdu_transceive_chain(pk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_read_cert.transceive_chain failed",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		if (apdu->a_reply.b_offset + 1 > apdu->a_reply.b_len) {
			piv_apdu_free(apdu);
			return (ENOENT);
		}
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x53) {
			bunyan_log(DEBUG, "card returned invalid tag in "
			    "PIV INS_GET_DATA response payload",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)slotid,
			    "tag", BNY_UINT, tag,
			    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
			    apdu->a_reply.b_offset, apdu->a_reply.b_len, NULL);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
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
			bunyan_log(DEBUG, "card returned cert with PIV_CI_X509 "
			    "flag set, assuming invalid",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)slotid, NULL);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
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

			VERIFY3S(inflate(&strm, Z_NO_FLUSH), ==, Z_STREAM_END);

			VERIFY3U(strm.avail_out, >, 0);
			VERIFY3U(strm.avail_out, <, PIV_MAX_CERT_LEN);

			bunyan_log(DEBUG, "decompressed cert",
			    "compressed_len", BNY_UINT, len,
			    "avail_out", BNY_UINT, strm.avail_out,
			    "uncompressed_len", BNY_UINT, PIV_MAX_CERT_LEN -
			    strm.avail_out, NULL);

			ptr = buf;
			len = PIV_MAX_CERT_LEN - strm.avail_out;

			VERIFY0(inflateEnd(&strm));

		} else if ((certinfo & PIV_CI_COMPTYPE) != PIV_COMP_NONE) {
			bunyan_log(DEBUG, "card returned cert with unknown "
			    "compression type, assuming invalid",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)slotid, NULL);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}

		cert = d2i_X509(NULL, (const uint8_t **)&ptr, len);
		if (cert == NULL) {
			/* Getting error codes out of OpenSSL is weird. */
			char errbuf[128];
			unsigned long err = ERR_peek_last_error();
			ERR_load_crypto_strings();
			ERR_error_string(err, errbuf);
			bunyan_log(WARN, "card returned invalid cert",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)slotid,
			    "openssl_err", BNY_STRING, errbuf,
			    "data", BNY_BIN_HEX, ptr, len, NULL);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (EINVAL);
		}

		tlv_free(tlv);
		free(buf);

		for (pc = pk->pt_slots; pc != NULL; pc = pc->ps_next) {
			if (pc->ps_slot == slotid)
				break;
		}
		if (pc == NULL) {
			pc = calloc(1, sizeof (struct piv_slot));
			assert(pc != NULL);
			pc->ps_next = pk->pt_slots;
			pk->pt_slots = pc;
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
		assert(pkey != NULL);
		assert(sshkey_from_evp_pkey(pkey, KEY_UNSPEC,
		    &pc->ps_pubkey) == 0);

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
				assert(0);
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
				assert(0);
			}
			break;
		default:
			assert(0);
		}

		rv = 0;

	} else if (apdu->a_sw == SW_FILE_NOT_FOUND) {
		rv = ENOENT;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		rv = EPERM;

	} else {
		bunyan_log(DEBUG, "card did not accept INS_GET_DATA for PIV",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		rv = EINVAL;
	}

	piv_apdu_free(apdu);

	return (rv);
}

int
piv_read_all_certs(struct piv_token *tk)
{
	int rv;

	assert(tk->pt_intxn == B_TRUE);

	rv = piv_read_cert(tk, PIV_SLOT_9E);
	if (rv != 0 && rv != ENOENT && rv != ENOTSUP && rv != EPERM)
		return (rv);
	rv = piv_read_cert(tk, PIV_SLOT_9A);
	if (rv != 0 && rv != ENOENT && rv != ENOTSUP && rv != EPERM)
		return (rv);
	rv = piv_read_cert(tk, PIV_SLOT_9C);
	if (rv != 0 && rv != ENOENT && rv != ENOTSUP && rv != EPERM)
		return (rv);
	rv = piv_read_cert(tk, PIV_SLOT_9D);
	if (rv != 0 && rv != ENOENT && rv != ENOTSUP && rv != EPERM)
		return (rv);

	return (rv);
}

int
piv_change_pin(struct piv_token *pk, const char *pin, const char *newpin)
{
	int rv;
	struct apdu *apdu;
	uint8_t pinbuf[16];
	size_t i;

	assert(pk->pt_intxn == B_TRUE);

	memset(pinbuf, 0xFF, sizeof (pinbuf));
	for (i = 0; i < 8 && pin[i] != 0; ++i)
		pinbuf[i] = pin[i];
	assert(pin[i] == 0);
	for (i = 8; i < 16 && newpin[i - 8] != 0; ++i)
		pinbuf[i] = newpin[i - 8];
	assert(newpin[i - 8] == 0);

	apdu = piv_apdu_make(CLA_ISO, INS_CHANGE_PIN, 0x00, 0x80);
	apdu->a_cmd.b_data = pinbuf;
	apdu->a_cmd.b_len = 16;

	rv = piv_apdu_transceive(pk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_change_pin.transceive_apdu failed",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		piv_apdu_free(apdu);
		return (EIO);
	}

	explicit_bzero(pinbuf, sizeof (pinbuf));

	if (apdu->a_sw == SW_NO_ERROR) {
		rv = 0;
		pk->pt_reset = B_TRUE;

	} else if ((apdu->a_sw & 0xFFF0) == SW_INCORRECT_PIN) {
		rv = EACCES;

	} else {
		bunyan_log(DEBUG, "card did not accept INS_CHANGE_PIN for PIV",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		rv = EINVAL;
	}

	piv_apdu_free(apdu);

	return (rv);
}

int
piv_verify_pin(struct piv_token *pk, const char *pin, uint *retries)
{
	int rv;
	struct apdu *apdu;
	uint8_t pinbuf[8];
	size_t i;

	assert(pk->pt_intxn == B_TRUE);

	if (pin == NULL || (retries != NULL && *retries > 0)) {
		VERIFY3P(retries, !=, NULL);

		apdu = piv_apdu_make(CLA_ISO, INS_VERIFY, 0x00, 0x80);

		rv = piv_apdu_transceive(pk, apdu);
		if (rv != 0) {
			bunyan_log(WARN, "piv_verify_pin.transceive failed",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "err", BNY_STRING, pcsc_stringify_error(rv),
			    NULL);
			piv_apdu_free(apdu);
			return (EIO);
		}

		if ((apdu->a_sw & 0xFFF0) == SW_INCORRECT_PIN) {
			if ((apdu->a_sw & 0x000F) <= *retries) {
				*retries = (apdu->a_sw & 0x000F);
				rv = EAGAIN;
			} else if (pin == NULL) {
				*retries = (apdu->a_sw & 0x000F);
				piv_apdu_free(apdu);
				return (0);
			} else {
				rv = 0;
			}
		} else if (apdu->a_sw == SW_WRONG_LENGTH ||
		    apdu->a_sw == SW_WRONG_DATA) {
			if (pin == NULL) {
				piv_apdu_free(apdu);
				return (ENOTSUP);
			} else {
				/*
				 * We can't seem to check the number of retries
				 * remaining, so just proceed through.
				 */
				rv = 0;
			}
		} else if (apdu->a_sw == SW_NO_ERROR && pk->pt_ykpiv) {
			/*
			 * YubicoPIV pre-4.x returns sw=9000 on all PIN
			 * operations if the PIN is already "unlocked". We
			 * normally get here because of a bug -- YubicoPIV uses
			 * a single global flag to indicate whether the PIN is
			 * unlocked, and operations on a key just either reset
			 * or don't reset that global flag based on whether the
			 * key is reuseable.
			 *
			 * This means that if we have a txn where we do, e.g.:
			 * VERIFY, GEN_AUTH(9a), GEN_AUTH(9c)
			 * then the GEN_AUTH(9c) will be accepted, even though
			 * it shouldn't be by the PIV spec (9c is supposed to
			 * require a PIN entry with every operation).
			 */
			if (pk->pt_ykver[0] >= 4) {
				/*
				 * YubicoPIV >4.x returns 9000 here but we
				 * still need to re-enter the PIN (they fixed
				 * the bug... ish).
				 */
				rv = 0;
			} else {
				/*
				 * YubicoPIV 1.x (Yubikey NEO) doesn't need the
				 * PIN re-entered.
				 */
				piv_apdu_free(apdu);
				return (0);
			}
		} else {
			bunyan_log(DEBUG, "card did not accept INS_VERIFY"
			    " for PIV",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
			rv = EINVAL;
		}
		piv_apdu_free(apdu);
		if (rv != 0)
			return (rv);
	}

	memset(pinbuf, 0xFF, sizeof (pinbuf));
	for (i = 0; i < 8 && pin[i] != 0; ++i)
		pinbuf[i] = pin[i];
	assert(pin[i] == 0);

	apdu = piv_apdu_make(CLA_ISO, INS_VERIFY, 0x00, 0x80);
	apdu->a_cmd.b_data = pinbuf;
	apdu->a_cmd.b_len = 8;

	rv = piv_apdu_transceive(pk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_verify_pin.transceive_apdu failed",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		piv_apdu_free(apdu);
		return (EIO);
	}

	explicit_bzero(pinbuf, sizeof (pinbuf));

	if (apdu->a_sw == SW_NO_ERROR) {
		rv = 0;
		pk->pt_reset = B_TRUE;

	} else if ((apdu->a_sw & 0xFFF0) == SW_INCORRECT_PIN) {
		if (retries != NULL)
			*retries = (apdu->a_sw & 0x000F);
		rv = EACCES;

	} else {
		bunyan_log(DEBUG, "card did not accept INS_VERIFY for PIV",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		rv = EINVAL;
	}

	piv_apdu_free(apdu);

	return (rv);
}

int
piv_sign(struct piv_token *tk, struct piv_slot *slot, const uint8_t *data,
    size_t datalen, enum sshdigest_types *hashalgo, uint8_t **signature,
    size_t *siglen)
{
	int rv, i;
	struct ssh_digest_ctx *hctx;
	uint8_t *buf;
	size_t nread, dglen, inplen;
	boolean_t cardhash = B_FALSE;
	enum piv_alg oldalg;

	assert(tk->pt_intxn == B_TRUE);

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
		} else {
			*hashalgo = SSH_DIGEST_SHA256;
			dglen = 32;
		}
		break;
	case PIV_ALG_ECCP256:
		inplen = 32;
		if (*hashalgo == SSH_DIGEST_SHA1) {
			dglen = 20;
		} else {
			*hashalgo = SSH_DIGEST_SHA256;
			dglen = 32;
		}
		for (i = 0; i < tk->pt_alg_count; ++i) {
			if (tk->pt_algs[i] == PIV_ALG_ECCP256_SHA1 &&
			    *hashalgo == SSH_DIGEST_SHA1) {
				cardhash = B_TRUE;
				oldalg = slot->ps_alg;
				slot->ps_alg = PIV_ALG_ECCP256_SHA1;
			} else if (tk->pt_algs[i] == PIV_ALG_ECCP256_SHA256 &&
			    *hashalgo == SSH_DIGEST_SHA256) {
				cardhash = B_TRUE;
				oldalg = slot->ps_alg;
				slot->ps_alg = PIV_ALG_ECCP256_SHA256;
			}
		}
		break;
	case PIV_ALG_ECCP384:
		*hashalgo = SSH_DIGEST_SHA384;
		inplen = (dglen = 48);
		break;
	default:
		assert(0);
	}

	if (!cardhash) {
		buf = calloc(1, inplen);
		assert(buf != NULL);

		hctx = ssh_digest_start(*hashalgo);
		assert(hctx != NULL);
		assert(ssh_digest_update(hctx, data, datalen) == 0);
		assert(ssh_digest_final(hctx, buf, dglen) == 0);
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
		assert(tmp != NULL);
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

	rv = piv_sign_prehash(tk, slot, buf, inplen, signature, siglen);

	if (!cardhash)
		free(buf);

	if (cardhash)
		slot->ps_alg = oldalg;

	return (rv);
}

int
piv_sign_prehash(struct piv_token *pk, struct piv_slot *pc,
    const uint8_t *hash, size_t hashlen, uint8_t **signature, size_t *siglen)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	uint8_t *buf;

	assert(pk->pt_intxn == B_TRUE);

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

	rv = piv_apdu_transceive_chain(pk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_sign_prehash.transceive_apdu failed",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x7C) {
			bunyan_log(DEBUG, "card returned invalid tag in "
			    "PIV INS_GEN_AUTH response payload",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)pc->ps_slot,
			    "tag", BNY_UINT, tag,
			    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
			    apdu->a_reply.b_offset, apdu->a_reply.b_len, NULL);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}
		tag = tlv_read_tag(tlv);
		if (tag != GA_TAG_RESPONSE) {
			tlv_skip(tlv);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}

		*siglen = tlv_rem(tlv);
		buf = calloc(1, *siglen);
		assert(buf != NULL);
		*siglen = tlv_read(tlv, buf, 0, *siglen);
		*signature = buf;

		tlv_end(tlv);
		tlv_end(tlv);
		tlv_free(tlv);

		rv = 0;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		rv = EPERM;

	} else {
		bunyan_log(DEBUG, "card did not accept INS_GET_AUTH for PIV",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		rv = EINVAL;
	}

	piv_apdu_free(apdu);

	return (rv);
}

int
piv_ecdh(struct piv_token *pk, struct piv_slot *slot, struct sshkey *pubkey,
    uint8_t **secret, size_t *seclen)
{
	int rv;
	struct apdu *apdu;
	struct tlv_state *tlv;
	uint tag;
	uint8_t *buf;
	struct sshbuf *sbuf;
	size_t len;

	assert(pk->pt_intxn == B_TRUE);

	sbuf = sshbuf_new();
	assert(sbuf != NULL);
	assert(pubkey->type == KEY_ECDSA);
	rv = sshbuf_put_eckey(sbuf, pubkey->ecdsa);
	assert(rv == 0);
	/* The buffer has the 32-bit length prefixed */
	len = sshbuf_len(sbuf) - 4;
	buf = (uint8_t *)sshbuf_ptr(sbuf) + 4;
	assert(*buf == 0x04);

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

	rv = piv_apdu_transceive_chain(pk, apdu);
	if (rv != 0) {
		bunyan_log(WARN, "piv_ecdh.transceive_apdu failed",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "err", BNY_STRING, pcsc_stringify_error(rv),
		    NULL);
		tlv_free(tlv);
		piv_apdu_free(apdu);
		return (EIO);
	}

	tlv_free(tlv);

	if (apdu->a_sw == SW_NO_ERROR ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_NO_CHANGE_00 ||
	    (apdu->a_sw & 0xFF00) == SW_WARNING_00) {
		tlv = tlv_init(apdu->a_reply.b_data, apdu->a_reply.b_offset,
		    apdu->a_reply.b_len);
		tag = tlv_read_tag(tlv);
		if (tag != 0x7C) {
			bunyan_log(DEBUG, "card returned invalid tag in "
			    "PIV INS_GEN_AUTH response payload",
			    "reader", BNY_STRING, pk->pt_rdrname,
			    "slotid", BNY_UINT, (uint)slot->ps_slot,
			    "tag", BNY_UINT, tag,
			    "reply", BNY_BIN_HEX, apdu->a_reply.b_data +
			    apdu->a_reply.b_offset, apdu->a_reply.b_len, NULL);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}
		tag = tlv_read_tag(tlv);
		if (tag != GA_TAG_RESPONSE) {
			tlv_skip(tlv);
			tlv_skip(tlv);
			tlv_free(tlv);
			piv_apdu_free(apdu);
			return (ENOTSUP);
		}

		*seclen = tlv_rem(tlv);
		buf = calloc(1, *seclen);
		assert(buf != NULL);
		*seclen = tlv_read(tlv, buf, 0, *seclen);
		*secret = buf;

		tlv_end(tlv);
		tlv_end(tlv);
		tlv_free(tlv);

		rv = 0;

	} else if (apdu->a_sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
		rv = EPERM;

	} else {
		bunyan_log(DEBUG, "card did not accept INS_GET_AUTH for PIV",
		    "reader", BNY_STRING, pk->pt_rdrname,
		    "sw", BNY_UINT, (uint)apdu->a_sw, NULL);
		rv = EINVAL;
	}

	piv_apdu_free(apdu);

	return (rv);
}

struct piv_ecdh_box *
piv_box_new(void)
{
	struct piv_ecdh_box *box;
	box = calloc(1, sizeof (struct piv_ecdh_box));
	return (box);
}

void
piv_box_free(struct piv_ecdh_box *box)
{
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

int
piv_box_set_data(struct piv_ecdh_box *box, const uint8_t *data, size_t len)
{
	uint8_t *buf;
	VERIFY3P(box->pdb_plain.b_data, ==, NULL);

	buf = calloc(1, len);
	if (buf == NULL)
		return (ENOMEM);
	box->pdb_plain.b_data = buf;
	box->pdb_plain.b_size = len;
	box->pdb_plain.b_len = len;
	box->pdb_plain.b_offset = 0;

	bcopy(data, buf, len);

	return (0);
}

int
piv_box_take_data(struct piv_ecdh_box *box, uint8_t **data, size_t *len)
{
	if (box->pdb_plain.b_data == NULL)
		return (EINVAL);

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

	return (0);
}

int
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

	VERIFY3P(box->pdb_cipher, !=, NULL);
	VERIFY3P(box->pdb_kdf, !=, NULL);

	cipher = cipher_by_name(box->pdb_cipher);
	VERIFY3P(cipher, !=, NULL);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);

	dgalg = ssh_digest_alg_by_name(box->pdb_kdf);
	dglen = ssh_digest_bytes(dgalg);
	VERIFY3U(dglen, >=, keylen);

	fieldsz = EC_GROUP_get_degree(EC_KEY_get0_group(privkey->ecdsa));
	seclen = (fieldsz + 7) / 8;
	sec = calloc(1, seclen);
	assert(sec != NULL);
	seclen = ECDH_compute_key(sec, seclen,
	    EC_KEY_get0_public_key(box->pdb_ephem_pub->ecdsa), privkey->ecdsa,
	    NULL);
	VERIFY3U(seclen, >, 0);

	dgctx = ssh_digest_start(dgalg);
	VERIFY3P(dgctx, !=, NULL);
	VERIFY0(ssh_digest_update(dgctx, sec, seclen));
	key = calloc(1, dglen);
	VERIFY3P(key, !=, NULL);
	VERIFY0(ssh_digest_final(dgctx, key, dglen));
	ssh_digest_free(dgctx);

	explicit_bzero(sec, seclen);
	free(sec);

	iv = box->pdb_iv.b_data;
	VERIFY3U(box->pdb_iv.b_len, ==, ivlen);
	VERIFY3U(box->pdb_iv.b_offset, ==, 0);
	VERIFY3P(iv, !=, NULL);

	enc = box->pdb_enc.b_data + box->pdb_enc.b_offset;
	VERIFY3P(box->pdb_enc.b_data, !=, NULL);
	enclen = box->pdb_enc.b_len;
	VERIFY3U(enclen, >=, authlen + blocksz);

	plainlen = enclen - authlen;
	plain = calloc(1, plainlen);
	VERIFY3P(plain, !=, NULL);

	VERIFY0(cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 0));
	VERIFY0(cipher_crypt(cctx, 0, plain, enc, enclen - authlen, 0,
	    authlen));
	cipher_free(cctx);

	explicit_bzero(key, dglen);
	free(key);

	/* Strip off the pkcs#7 padding and verify it. */
	padding = plain[plainlen - 1];
	VERIFY3U(padding, <=, blocksz);
	VERIFY3U(padding, >, 0);
	reallen = plainlen - padding;
	for (i = reallen; i < plainlen; ++i)
		VERIFY3U(plain[i], ==, padding);

	free(box->pdb_plain.b_data);
	box->pdb_plain.b_data = plain;
	box->pdb_plain.b_size = plainlen;
	box->pdb_plain.b_len = reallen;
	box->pdb_plain.b_offset = 0;

	return (0);
}

int
piv_box_open(struct piv_token *tk, struct piv_slot *slot,
    struct piv_ecdh_box *box)
{
	const struct sshcipher *cipher;
	int rv;
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
	if (cipher == NULL)
		return (EINVAL);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);

	dgalg = ssh_digest_alg_by_name(box->pdb_kdf);
	dglen = ssh_digest_bytes(dgalg);
	VERIFY3U(dglen, >=, keylen);

	sec = NULL;
	VERIFY3P(box->pdb_ephem_pub, !=, NULL);
	rv = piv_ecdh(tk, slot, box->pdb_ephem_pub, &sec, &seclen);
	if (rv != 0)
		return (rv);
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

	iv = box->pdb_iv.b_data;
	VERIFY3U(box->pdb_iv.b_size, ==, ivlen);
	VERIFY3P(iv, !=, NULL);

	enc = box->pdb_enc.b_data;
	VERIFY3P(enc, !=, NULL);
	enclen = box->pdb_enc.b_size;
	VERIFY3U(enclen, >=, authlen + blocksz);

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
		return (EBADMSG);
	}

	/* Strip off the pkcs#7 padding and verify it. */
	padding = plain[plainlen - 1];
	VERIFY3U(padding, <=, blocksz);
	VERIFY3U(padding, >, 0);
	reallen = plainlen - padding;
	for (i = reallen; i < plainlen; ++i)
		VERIFY3U(plain[i], ==, padding);

	free(box->pdb_plain.b_data);
	box->pdb_plain.b_data = plain;
	box->pdb_plain.b_offset = 0;
	box->pdb_plain.b_size = plainlen;
	box->pdb_plain.b_len = reallen;

	return (0);
}

int
piv_box_seal_offline(struct sshkey *pubk, struct piv_ecdh_box *box)
{
	const struct sshcipher *cipher;
	int rv;
	int dgalg;
	struct sshkey *pkey;
	struct sshcipher_ctx *cctx;
	struct ssh_digest_ctx *dgctx;
	uint8_t *iv, *key, *sec, *enc, *plain;
	size_t ivlen, authlen, blocksz, keylen, dglen, seclen;
	size_t fieldsz, plainlen, enclen;
	size_t padding, i;

	rv = sshkey_generate(KEY_ECDSA, 256, &pkey);
	VERIFY0(rv);
	VERIFY0(sshkey_demote(pkey, &box->pdb_ephem_pub));

	if (box->pdb_cipher == NULL)
		box->pdb_cipher = "chacha20-poly1305";
	if (box->pdb_kdf == NULL)
		box->pdb_kdf = "sha512";

	cipher = cipher_by_name(box->pdb_cipher);
	VERIFY3P(cipher, !=, NULL);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);

	dgalg = ssh_digest_alg_by_name(box->pdb_kdf);
	dglen = ssh_digest_bytes(dgalg);
	VERIFY3U(dglen, >=, keylen);

	fieldsz = EC_GROUP_get_degree(EC_KEY_get0_group(pkey->ecdsa));
	seclen = (fieldsz + 7) / 8;
	sec = calloc(1, seclen);
	assert(sec != NULL);
	seclen = ECDH_compute_key(sec, seclen,
	    EC_KEY_get0_public_key(pubk->ecdsa), pkey->ecdsa, NULL);
	VERIFY3U(seclen, >, 0);

	bunyan_log(TRACE, "derived symmetric key",
	    "secret", BNY_BIN_HEX, sec, seclen, NULL);

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

	plainlen = box->pdb_plain.b_size;
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
	bcopy(box->pdb_plain.b_data, plain, box->pdb_plain.b_len);
	for (i = box->pdb_plain.b_size; i < plainlen; ++i)
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

	return (0);
}

int
piv_box_seal(struct piv_token *tk, struct piv_slot *slot,
    struct piv_ecdh_box *box)
{
	int rv;

	rv = piv_box_seal_offline(slot->ps_pubkey, box);
	if (rv != 0)
		return (rv);

	box->pdb_guidslot_valid = B_TRUE;
	bcopy(tk->pt_guid, box->pdb_guid, sizeof (tk->pt_guid));
	box->pdb_slot = slot->ps_slot;

	return (0);
}

int
piv_box_find_token(struct piv_token *tks, struct piv_ecdh_box *box,
    struct piv_token **tk, struct piv_slot **slot)
{
	struct piv_token *pt;
	struct piv_slot *s;
	int rv;
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
				if (piv_txn_begin(pt) != 0)
					continue;
				if (piv_select(pt) != 0 ||
				    piv_read_cert(pt, slotid) != 0) {
					piv_txn_end(pt);
					continue;
				}
				piv_txn_end(pt);
				s = piv_get_slot(pt, slotid);
			}
			if (sshkey_equal_public(s->ps_pubkey, box->pdb_pub))
				goto out;

		}
		return (ENOENT);
	}

	s = piv_get_slot(pt, box->pdb_slot);
	if (s == NULL) {
		if ((rv = piv_txn_begin(pt)) != 0)
			return (rv);
		if ((rv = piv_select(pt)) != 0 ||
		    (rv = piv_read_cert(pt, box->pdb_slot)) != 0) {
		    	piv_txn_end(pt);
			return (rv);
		}
		piv_txn_end(pt);
		s = piv_get_slot(pt, box->pdb_slot);
	}

	if (!sshkey_equal_public(s->ps_pubkey, box->pdb_pub))
		return (ENOENT);

out:
	*tk = pt;
	*slot = s;
	return (0);
}

int
sshbuf_put_piv_box(struct sshbuf *buf, struct piv_ecdh_box *box)
{
	int rc;
	const char *tname;

	if (box->pdb_pub->type != KEY_ECDSA ||
	    box->pdb_ephem_pub->type != KEY_ECDSA)
		return (EINVAL);
	if (box->pdb_pub->ecdsa_nid != box->pdb_ephem_pub->ecdsa_nid)
		return (EINVAL);

	if ((rc = sshbuf_put_u8(buf, 0xB0)) ||
	    (rc = sshbuf_put_u8(buf, 0xC5)))
		return (rc);
	if ((rc = sshbuf_put_u8(buf, 0x01)))
		return (rc);
	if (!box->pdb_guidslot_valid) {
		if ((rc = sshbuf_put_u8(buf, 0x00)) ||
		    (rc = sshbuf_put_u8(buf, 0x00)) ||
		    (rc = sshbuf_put_u8(buf, 0x00)))
			return (rc);
	} else {
		if ((rc = sshbuf_put_u8(buf, 0x01)))
			return (rc);
		rc = sshbuf_put_string8(buf, box->pdb_guid,
		    sizeof (box->pdb_guid));
		if (rc)
			return (rc);
		if ((rc = sshbuf_put_u8(buf, box->pdb_slot)))
			return (rc);
	}
	if ((rc = sshbuf_put_cstring8(buf, box->pdb_cipher)) ||
	    (rc = sshbuf_put_cstring8(buf, box->pdb_kdf)))
		return (rc);

	tname = sshkey_curve_nid_to_name(box->pdb_pub->ecdsa_nid);
	VERIFY(tname != NULL);
	if ((rc = sshbuf_put_cstring8(buf, tname)) ||
	    (rc = sshbuf_put_eckey8(buf, box->pdb_pub->ecdsa)) ||
	    (rc = sshbuf_put_eckey8(buf, box->pdb_ephem_pub->ecdsa)))
		return (rc);

	if ((rc = sshbuf_put_string8(buf, box->pdb_iv.b_data,
	    box->pdb_iv.b_len)))
		return (rc);

	if ((rc = sshbuf_put_string(buf, box->pdb_enc.b_data,
	    box->pdb_enc.b_len)))
		return (rc);

	return (0);
}

int
piv_box_to_binary(struct piv_ecdh_box *box, uint8_t **output, size_t *len)
{
	struct sshbuf *buf;
	int rc;

	buf = sshbuf_new();
	VERIFY3P(buf, !=, NULL);

	if ((rc = sshbuf_put_piv_box(buf, box))) {
		sshbuf_free(buf);
		return (rc);
	}

	*len = sshbuf_len(buf);
	*output = calloc(1, *len);
	VERIFY3P(*output, !=, NULL);
	bcopy(sshbuf_ptr(buf), *output, *len);
	sshbuf_free(buf);

	return (0);
}

int
sshbuf_get_piv_box(struct sshbuf *buf, struct piv_ecdh_box **outbox)
{
	struct piv_ecdh_box *box = NULL;
	uint8_t ver, magic[2];
	int rc;
	uint8_t *tmpbuf = NULL;
	struct sshkey *k = NULL;
	size_t len;
	uint8_t temp;
	char *tname = NULL;

	box = piv_box_new();
	VERIFY(box != NULL);

	if ((rc = sshbuf_get_u8(buf, &magic[0])) ||
	    (rc = sshbuf_get_u8(buf, &magic[1])))
		goto out;
	if (magic[0] != 0xB0 && magic[1] != 0xC5) {
		bunyan_log(TRACE, "bad piv box magic",
		    "magic[0]", BNY_UINT, (uint)magic[0],
		    "magic[1]", BNY_UINT, (uint)magic[1], NULL);
		rc = ENOTSUP;
		goto out;
	}
	if ((rc = sshbuf_get_u8(buf, &ver)))
		goto out;
	if (ver != 0x01) {
		bunyan_log(TRACE, "bad piv box version (supported = v1)",
		    "version", BNY_UINT, (uint)ver, NULL);
		rc = ENOTSUP;
		goto out;
	}

	if ((rc = sshbuf_get_u8(buf, &temp)))
		goto out;
	box->pdb_guidslot_valid = (temp != 0x00);

	if ((rc = sshbuf_get_string8(buf, &tmpbuf, &len)))
		goto out;
	if (box->pdb_guidslot_valid && len != sizeof (box->pdb_guid)) {
		rc = EINVAL;
		goto out;
	} else if (box->pdb_guidslot_valid) {
		bcopy(tmpbuf, box->pdb_guid, len);
	}
	free(tmpbuf);
	tmpbuf = NULL;
	if ((rc = sshbuf_get_u8(buf, &temp)))
		goto out;
	if (box->pdb_guidslot_valid)
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

	if ((rc = sshbuf_get_eckey8(buf, k->ecdsa)) ||
	    (rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa))))
		goto out;
	box->pdb_pub = k;
	k = NULL;

	k = sshkey_new(KEY_ECDSA);
	k->ecdsa_nid = box->pdb_pub->ecdsa_nid;

	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY(k->ecdsa != NULL);

	if ((rc = sshbuf_get_eckey8(buf, k->ecdsa)) ||
	    (rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa)))) {
		goto out;
	}
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

static int piv_box_read_old_v1(struct sshbuf *buf, struct piv_ecdh_box **pbox);

int
piv_box_from_binary(const uint8_t *input, size_t inplen,
    struct piv_ecdh_box **pbox)
{
	int rv;
	struct sshbuf *buf;

	buf = sshbuf_from(input, inplen);
	VERIFY3P(buf, !=, NULL);

	if (inplen > 1 && *input == 0x01)
		return (piv_box_read_old_v1(buf, pbox));

	rv = sshbuf_get_piv_box(buf, pbox);

	sshbuf_free(buf);

	return (rv);
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
