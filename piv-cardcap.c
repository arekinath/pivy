/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 * Copyright 2024 The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
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

#include "utils.h"
#include "tlv.h"
#include "piv.h"
#include "bunyan.h"
#include "utils.h"

/* Contains structs apdubuf, piv_ecdh_box, and enum piv_box_version */
#include "piv-internal.h"

enum piv_cardcap_flags {
	PIV_CARDCAP_HAS_APDUS	= (1<<0),
	PIV_CARDCAP_HAS_LRC	= (1<<1)
};

struct piv_cardcap {
	enum piv_cardcap_flags	 pcc_flags;
	uint8_t			 pcc_card_id[21];
	size_t			 pcc_card_id_len;
	uint8_t			 pcc_container_ver;
	uint8_t			 pcc_grammar_ver;
	uint8_t			*pcc_app_cardurl;
	size_t			 pcc_app_cardurl_len;
	uint8_t			 pcc_pkcs15;
	uint8_t			 pcc_data_model;
	uint8_t			*pcc_acl_rules;
	size_t			 pcc_acl_rules_len;
	uint8_t			 pcc_card_apdus[6];
	uint8_t			*pcc_redir;
	size_t			 pcc_redir_len;
	uint8_t			*pcc_cts;
	size_t			 pcc_cts_len;
	uint8_t			*pcc_sts;
	size_t			 pcc_sts_len;
	uint8_t			*pcc_next_ccc;
	size_t			 pcc_next_ccc_len;
	uint8_t			 pcc_lrc;
	char			*pcc_id_hex;
};

struct piv_cardcap *
piv_cardcap_new(void)
{
	struct piv_cardcap *cc;
	uint8_t default_id[] = {
		/* GSC-RID: GSC-IS data model */
		0xa0, 0x00, 0x00, 0x01, 0x16,
		0xFF,			/* Manufacturer */
		PIV_CARDCAP_JAVACARD,	/* Card Type */
	};
	cc = calloc(1, sizeof (*cc));
	cc->pcc_card_id_len = sizeof (default_id);
	bcopy(default_id, cc->pcc_card_id, sizeof (default_id));
	cc->pcc_data_model = PIV_CARDCAP_MODEL_PIV;
	cc->pcc_container_ver = 0x21;
	cc->pcc_grammar_ver = 0x21;
	return (cc);
}

void
piv_cardcap_free(struct piv_cardcap *cc)
{
	if (cc == NULL)
		return;
	free(cc->pcc_app_cardurl);
	free(cc->pcc_acl_rules);
	free(cc->pcc_redir);
	free(cc->pcc_cts);
	free(cc->pcc_sts);
	free(cc->pcc_next_ccc);
	free(cc->pcc_id_hex);
	free(cc);
}

enum cardcap_type
piv_cardcap_type(const struct piv_cardcap *cc)
{
	return (cc->pcc_card_id[6]);
}

void
piv_cardcap_set_type(struct piv_cardcap *cc, enum cardcap_type type)
{
	cc->pcc_card_id[6] = type;
}

uint
piv_cardcap_manufacturer(const struct piv_cardcap *cc)
{
	return (cc->pcc_card_id[5]);
}

void
piv_cardcap_set_manufacturer(struct piv_cardcap *cc, uint id)
{
	cc->pcc_card_id[5] = id;
}

/* should be at most 15 bytes */
const uint8_t *
piv_cardcap_id(const struct piv_cardcap *cc, size_t *plen)
{
	if (cc->pcc_card_id_len < 7) {
		*plen = 0;
		return (NULL);
	}
	*plen = cc->pcc_card_id_len - 7;
	return (&cc->pcc_card_id[7]);
}

const char *
piv_cardcap_id_hex(const struct piv_cardcap *cc)
{
	if (cc->pcc_card_id_len < 7)
		return (NULL);
	if (cc->pcc_id_hex == NULL) {
		struct piv_cardcap *ccwrite = (struct piv_cardcap *)cc;
		ccwrite->pcc_id_hex = buf_to_hex(&cc->pcc_card_id[7],
		    cc->pcc_card_id_len - 7, B_FALSE);
	}
	return (cc->pcc_id_hex);
}

void
piv_cardcap_set_id(struct piv_cardcap *cc, const uint8_t *id, size_t len)
{
	VERIFY(len + 7 <= sizeof (cc->pcc_card_id));
	cc->pcc_card_id_len = len + 7;
	bcopy(id, &cc->pcc_card_id[7], len);
	free(cc->pcc_id_hex);
	cc->pcc_id_hex = NULL;
}

void
piv_cardcap_set_random_id(struct piv_cardcap *cc)
{
	cc->pcc_card_id_len = sizeof (cc->pcc_card_id);
	arc4random_buf(&cc->pcc_card_id[7], cc->pcc_card_id_len - 7);
	free(cc->pcc_id_hex);
	cc->pcc_id_hex = NULL;
}

boolean_t
piv_cardcap_has_pkcs15(const struct piv_cardcap *cc)
{
	return (cc->pcc_pkcs15 == 1);
}

void
piv_cardcap_set_pkcs15(struct piv_cardcap *cc, boolean_t ena)
{
	if (ena)
		cc->pcc_pkcs15 = 1;
	else
		cc->pcc_pkcs15 = 0;
}

enum cardcap_data_model
piv_cardcap_data_model(const struct piv_cardcap *cc)
{
	return (cc->pcc_data_model);
}

void
piv_cardcap_set_data_model(struct piv_cardcap *cc, enum cardcap_data_model dmid)
{
	cc->pcc_data_model = dmid;
}

errf_t *
piv_cardcap_encode(const struct piv_cardcap *cc, uint8_t **out, size_t *len)
{
	struct tlv_state *tlv = NULL;
	uint8_t *buf = NULL;
	errf_t *err;

	tlv = tlv_init_write();
	if (tlv == NULL) {
		err = errfno("tlv_init_write", errno, NULL);
		goto out;
	}

	tlv_push(tlv, 0xF0);	/* Card ID */
	tlv_write(tlv, cc->pcc_card_id, cc->pcc_card_id_len);
	tlv_pop(tlv);

	tlv_push(tlv, 0xF1); 	/* Container version */
	tlv_write_byte(tlv, cc->pcc_container_ver);
	tlv_pop(tlv);

	tlv_push(tlv, 0xF2);	/* Grammar version */
	tlv_write_byte(tlv, cc->pcc_grammar_ver);
	tlv_pop(tlv);

	tlv_push(tlv, 0xF3);	/* Applications CardURL */
	tlv_write(tlv, cc->pcc_app_cardurl, cc->pcc_app_cardurl_len);
	tlv_pop(tlv);

	tlv_push(tlv, 0xF4);	/* PKCS#15 */
	tlv_write_byte(tlv, cc->pcc_pkcs15);
	tlv_pop(tlv);

	tlv_push(tlv, 0xF5);	/* Registered Data Model number */
	tlv_write_byte(tlv, cc->pcc_data_model);
	tlv_pop(tlv);

	tlv_push(tlv, 0xF6); 	/* Access Control Rule Table */
	tlv_write(tlv, cc->pcc_acl_rules, cc->pcc_acl_rules_len);
	tlv_pop(tlv);

	tlv_push(tlv, 0xF7);	/* CARD APDUs */
	if (cc->pcc_flags & PIV_CARDCAP_HAS_APDUS)
		tlv_write(tlv, cc->pcc_card_apdus, sizeof (cc->pcc_card_apdus));
	tlv_pop(tlv);

	tlv_push(tlv, 0xFA);	/* Redirection Tag */
	tlv_write(tlv, cc->pcc_redir, cc->pcc_redir_len);
	tlv_pop(tlv);

	tlv_push(tlv, 0xFB);	/* Capability Tuples (CTs) */
	tlv_write(tlv, cc->pcc_cts, cc->pcc_cts_len);
	tlv_pop(tlv);

	tlv_push(tlv, 0xFC);	/* Status Tuples (STs) */
	tlv_write(tlv, cc->pcc_sts, cc->pcc_sts_len);
	tlv_pop(tlv);

	tlv_push(tlv, 0xFD);	/* Next CCC */
	tlv_write(tlv, cc->pcc_next_ccc, cc->pcc_next_ccc_len);
	tlv_pop(tlv);

	tlv_push(tlv, 0xFE);	/* LRC */
	if (cc->pcc_flags & PIV_CARDCAP_HAS_LRC)
		tlv_write_byte(tlv, cc->pcc_lrc);
	tlv_pop(tlv);

	*len = tlv_len(tlv);
	*out = malloc(*len);
	if (*out == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	bcopy(tlv_buf(tlv), *out, *len);

	err = ERRF_OK;

out:
	tlv_free(tlv);
	free(buf);
	return (err);
}

errf_t *
piv_cardcap_decode(const uint8_t *data, size_t len, struct piv_cardcap **out)
{
	struct tlv_state *tlv = NULL;
	uint tag;
	errf_t *err;
	struct piv_cardcap *cc;
	uint8_t v;
	boolean_t got_cver = B_FALSE, got_gver = B_FALSE;

	cc = calloc(1, sizeof (*cc));
	if (cc == NULL) {
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
		case 0xF0:	/* Card ID */
			if (tlv_at_end(tlv)) {
				tlv_skip(tlv);
				break;
			}
			err = tlv_read_upto(tlv, cc->pcc_card_id,
			    sizeof (cc->pcc_card_id), &cc->pcc_card_id_len);
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0xF1:	/* Container version */
			if (tlv_at_end(tlv)) {
				tlv_skip(tlv);
				break;
			}
			if ((err = tlv_read_u8(tlv, &cc->pcc_container_ver)))
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			got_cver = B_TRUE;
			break;
		case 0xF2:	/* Grammar version */
			if (tlv_at_end(tlv)) {
				tlv_skip(tlv);
				break;
			}
			if ((err = tlv_read_u8(tlv, &cc->pcc_grammar_ver)))
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			got_gver = B_TRUE;
			break;
		case 0xF3:	/* Applications CardURL */
			err = tlv_read_alloc(tlv, &cc->pcc_app_cardurl,
			    &cc->pcc_app_cardurl_len);
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0xF4:	/* PKCS#15 */
			if (tlv_at_end(tlv)) {
				tlv_skip(tlv);
				break;
			}
			if ((err = tlv_read_u8(tlv, &cc->pcc_pkcs15)))
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0xF5:	/* Registered Data Model number */
			if ((err = tlv_read_u8(tlv, &cc->pcc_data_model)))
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0xF6:	/* Access Control Rule Table */
			err = tlv_read_alloc(tlv, &cc->pcc_acl_rules,
			    &cc->pcc_acl_rules_len);
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0xF7:	/* CARD APDUs */
			if (tlv_at_end(tlv)) {
				tlv_skip(tlv);
				break;
			}
			err = tlv_read(tlv, cc->pcc_card_apdus,
			    sizeof (cc->pcc_card_apdus));
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			cc->pcc_flags |= PIV_CARDCAP_HAS_APDUS;
			break;
		case 0xFA:	/* Redirection Tag */
			err = tlv_read_alloc(tlv, &cc->pcc_redir,
			    &cc->pcc_redir_len);
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0xFB:	/* Capability Tuples (CTs) */
			err = tlv_read_alloc(tlv, &cc->pcc_cts,
			    &cc->pcc_cts_len);
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0xFC:	/* Status Tuples (STs) */
			err = tlv_read_alloc(tlv, &cc->pcc_sts,
			    &cc->pcc_sts_len);
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0xFD:	/* Next CCC */
			err = tlv_read_alloc(tlv, &cc->pcc_next_ccc,
			    &cc->pcc_next_ccc_len);
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0xFE:	/* LRC */
			if (tlv_at_end(tlv)) {
				tlv_skip(tlv);
				break;
			}
			err = tlv_read_u8(tlv, &cc->pcc_lrc);
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			cc->pcc_flags |= PIV_CARDCAP_HAS_LRC;
			break;
		default:
			err = tagerrf("CARDCAP", tag);
			goto out;
		}
	}

	if (!got_gver || !got_cver) {
		err = errf("NotSupportedError", NULL, "CARDCAP "
		    "object is missing container and grammar version fields");
		goto out;
	}
	v = (cc->pcc_container_ver >> 4) & 0xF;
	if (v > 2) {
		err = errf("NotSupportedError", NULL, "CARDCAP "
		    "object has wrong major container version (%u)",
		    v);
		goto out;
	}
	v = (cc->pcc_grammar_ver >> 4) & 0xF;
	if (v > 2) {
		err = errf("NotSupportedError", NULL, "CARDCAP "
		    "object has wrong major grammar version (%u)",
		    v);
		goto out;
	}

	*out = cc;
	cc = NULL;
	err = ERRF_OK;

out:
	if (err != ERRF_OK)
		tlv_abort(tlv);
	tlv_free(tlv);
	piv_cardcap_free(cc);
	return (err);
}

#if defined(__CPROVER) && __CPROVER_MAIN == __FILE_piv_cardcap_c

uint8_t *
genbinstr(size_t minlen, size_t maxlen, size_t *plen)
{
	size_t len, i;
	uint8_t *buf;
	__CPROVER_assume(len >= minlen);
	__CPROVER_assume(len <= maxlen);
	buf = malloc(len);
	__CPROVER_assume(buf != NULL);
	for (i = 0; i < len; ++i) {
		uint8_t c;
		buf[i] = c;
	}
	*plen = len;
	return (buf);
}

void
cardcap_write_proof(void)
{
	struct piv_cardcap *ccap;
	errf_t *err;
	enum cardcap_type ctype;
	enum cardcap_data_model dmodel;
	uint8_t *buf;
	size_t len;

	ccap = piv_cardcap_new();
	piv_cardcap_set_type(ccap, ctype);
	piv_cardcap_set_data_model(ccap, dmodel);

	buf = genbinstr(2, 3, &len);
	piv_cardcap_set_id(ccap, buf, len);

	buf = NULL;
	len = 0;

	err = piv_cardcap_encode(ccap, &buf, &len);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);
	assert(buf != NULL);
	assert(len > 0);

	piv_cardcap_free(ccap);
}

void
cardcap_read_proof(void)
{
	struct piv_cardcap *ccap;
	errf_t *err;
	uint8_t *buf, *nbuf;
	size_t len, i;

	uint8_t *buf0 = genbinstr(1, 5, &len);
	err = piv_cardcap_decode(buf0, len, &ccap);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err != ERRF_OK);

	uint8_t *buf1 = genbinstr(8, 10, &len);
	err = piv_cardcap_decode(buf1, len, &ccap);
	__CPROVER_assume(err == ERRF_OK);
	assert(ccap != NULL);

	const char *idhex = piv_cardcap_id_hex(ccap);
	assert(idhex == NULL || strlen(idhex) > 0);

	piv_cardcap_free(ccap);
}

int
main(int argc, char *argv[])
{
	__CPROVER_assume(ERRF_NOMEM != NULL);
	cardcap_read_proof();
	cardcap_write_proof();
	return (0);
}

#endif
