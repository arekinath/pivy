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
#include <limits.h>

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

enum piv_chuid_flags {
	PIV_CHUID_HAS_CHUUID 	= (1<<0),
	PIV_CHUID_HAS_BUFLEN	= (1<<1),
};

struct piv_chuid {
	enum piv_chuid_flags	 pc_flags;
	uint16_t		 pc_buflen;
	struct piv_fascn	*pc_fascn;
	uint8_t			 pc_guid[GUID_LEN];
	uint8_t			 pc_chuuid[GUID_LEN];
	uint8_t			*pc_expiry;
	size_t			 pc_expiry_len;
	uint8_t			*pc_orgid;
	size_t			 pc_orgid_len;
	uint8_t			*pc_duns;
	size_t			 pc_duns_len;
	CMS_ContentInfo		*pc_sig;
	char			*pc_guidhex;
};

void
piv_chuid_free(struct piv_chuid *chuid)
{
	if (chuid == NULL)
		return;
	piv_fascn_free(chuid->pc_fascn);
	free(chuid->pc_expiry);
	free(chuid->pc_orgid);
	free(chuid->pc_duns);
	CMS_ContentInfo_free(chuid->pc_sig);
	free(chuid->pc_guidhex);
	free(chuid);
}

struct piv_chuid *
piv_chuid_new(void)
{
	struct piv_chuid *chuid;

	chuid = calloc(1, sizeof (struct piv_chuid));
	if (chuid == NULL)
		return (NULL);

	return (chuid);
}

errf_t *
piv_chuid_clone(const struct piv_chuid *other, struct piv_chuid **out)
{
	struct piv_chuid *chuid = NULL;
	uint8_t *buf = NULL;
	const uint8_t *p;
	size_t len;
	errf_t *err;

	chuid = calloc(1, sizeof (struct piv_chuid));
	if (chuid == NULL)
		return (NULL);

	chuid->pc_flags = other->pc_flags;

	chuid->pc_buflen = other->pc_buflen;

	bcopy(other->pc_guid, chuid->pc_guid, sizeof (chuid->pc_guid));
	bcopy(other->pc_chuuid, chuid->pc_chuuid, sizeof (chuid->pc_chuuid));

	if (other->pc_fascn != NULL) {
		chuid->pc_fascn = piv_fascn_clone(other->pc_fascn);
		if (chuid->pc_fascn == NULL) {
			err = ERRF_NOMEM;
			goto out;
		}
	}

	if (other->pc_expiry_len > 0) {
		chuid->pc_expiry = malloc(other->pc_expiry_len);
		if (chuid->pc_expiry == NULL) {
			err = ERRF_NOMEM;
			goto out;
		}
		bcopy(other->pc_expiry, chuid->pc_expiry, other->pc_expiry_len);
		chuid->pc_expiry_len = other->pc_expiry_len;
	}

	if (other->pc_orgid_len > 0) {
		chuid->pc_orgid = malloc(other->pc_orgid_len);
		if (chuid->pc_orgid == NULL) {
			err = ERRF_NOMEM;
			goto out;
		}
		bcopy(other->pc_orgid, chuid->pc_orgid, other->pc_orgid_len);
		chuid->pc_orgid_len = other->pc_orgid_len;
	}

	if (other->pc_duns_len > 0) {
		chuid->pc_duns = malloc(other->pc_duns_len);
		if (chuid->pc_duns == NULL) {
			err = ERRF_NOMEM;
			goto out;
		}
		bcopy(other->pc_duns, chuid->pc_duns, other->pc_duns_len);
		chuid->pc_duns_len = other->pc_duns_len;
	}

	if (other->pc_sig != NULL) {
		len = i2d_CMS_ContentInfo(other->pc_sig, &buf);
		if (len == 0) {
			make_sslerrf(err, "i2d_CMS_ContentInfo", "encoding "
			    "chuid signature");
			goto out;
		}
		p = buf;
		chuid->pc_sig = d2i_CMS_ContentInfo(NULL, &p, len);
		if (chuid->pc_sig == NULL) {
			make_sslerrf(err, "d2i_CMS_ContentInfo",
			    "parsing issuer signature in CHUID");
			goto out;
		}
	}

	*out = chuid;
	chuid = NULL;
	err = ERRF_OK;

out:
	OPENSSL_free(buf);
	piv_chuid_free(chuid);
	return (err);
}

boolean_t
piv_chuid_is_expired(const struct piv_chuid *pc)
{
	return (B_FALSE);
}

void
piv_chuid_set_random_guid(struct piv_chuid *pc)
{
	arc4random_buf(pc->pc_guid, sizeof (pc->pc_guid));
	free(pc->pc_guidhex);
	pc->pc_guidhex = NULL;
}

void
piv_chuid_set_fascn(struct piv_chuid *pc, const struct piv_fascn *v)
{
	piv_fascn_free(pc->pc_fascn);
	pc->pc_fascn = piv_fascn_clone(v);
}

void
piv_chuid_set_guid(struct piv_chuid *pc, uint8_t *v)
{
	bcopy(v, pc->pc_guid, sizeof (pc->pc_guid));
	free(pc->pc_guidhex);
	pc->pc_guidhex = NULL;
}

const char *
piv_chuid_get_guidhex(const struct piv_chuid *pc)
{
	if (pc->pc_guidhex == NULL) {
		struct piv_chuid *pcw = (struct piv_chuid *)pc;
		pcw->pc_guidhex = buf_to_hex(pc->pc_guid, sizeof (pc->pc_guid),
		    B_FALSE);
		return (pcw->pc_guidhex);
	}
	return (pc->pc_guidhex);
}

void
piv_chuid_set_chuuid(struct piv_chuid *pc, uint8_t *v)
{
	if (v == NULL) {
		bzero(pc->pc_chuuid, sizeof (pc->pc_chuuid));
		pc->pc_flags &= ~PIV_CHUID_HAS_CHUUID;
	} else {
		bcopy(v, pc->pc_chuuid, sizeof (pc->pc_chuuid));
		pc->pc_flags |= PIV_CHUID_HAS_CHUUID;
	}
}

void
piv_chuid_set_expiry(struct piv_chuid *pc, uint8_t *v, size_t len)
{
	free(pc->pc_expiry);
	pc->pc_expiry = malloc(len);
	bcopy(v, pc->pc_expiry, len);
	pc->pc_expiry_len = len;
}

void
piv_chuid_set_expiry_rel(struct piv_chuid *pc, uint sec)
{
	char buf[9] = {0};
	time_t now;
	struct tm *tm;

	now = time(NULL);
	__CPROVER_assume(now > 0);
	__CPROVER_assume(((unsigned long)now + (unsigned long)sec) >= now);
	__CPROVER_assume(((unsigned long)now + (unsigned long)sec) < LONG_MAX);
	VERIFY3U((unsigned long)now + sec, >=, now);
	VERIFY3U((unsigned long)now + sec, <, LONG_MAX);
	now = (time_t)((unsigned long)now + sec);

	tm = gmtime(&now);

	snprintf(buf, sizeof (buf), "%04d%02d%02d", tm->tm_year + 1900,
	    tm->tm_mon + 1, tm->tm_mday);

	piv_chuid_set_expiry(pc, (uint8_t *)buf, strlen(buf));
}

static errf_t *
piv_chuid_write_tbs_tlv(const struct piv_chuid *pc, struct tlv_state *tlv)
{
	uint8_t *buf = NULL;
	size_t len;
	errf_t *err;

	if (pc->pc_flags & PIV_CHUID_HAS_BUFLEN) {
		tlv_push(tlv, 0xEE);
		tlv_write_u16(tlv, pc->pc_buflen);
		tlv_pop(tlv);
	}

	if (pc->pc_fascn != NULL) {
		err = piv_fascn_encode(pc->pc_fascn, &buf, &len);
		if (err != ERRF_OK) {
			err = errf("CHUIDEncodeError", err, "Failed to encode "
			    "FASC-N in CHUID");
			goto out;
		}
		tlv_push(tlv, 0x30);
		tlv_write(tlv, buf, len);
		tlv_pop(tlv);
		free(buf);
		buf = NULL;
	}

	if (pc->pc_orgid != NULL) {
		tlv_push(tlv, 0x32);
		tlv_write(tlv, pc->pc_orgid, pc->pc_orgid_len);
		tlv_pop(tlv);
	}

	if (pc->pc_duns != NULL) {
		tlv_push(tlv, 0x32);
		tlv_write(tlv, pc->pc_duns, pc->pc_duns_len);
		tlv_pop(tlv);
	}

	tlv_push(tlv, 0x34);
	tlv_write(tlv, pc->pc_guid, sizeof (pc->pc_guid));
	tlv_pop(tlv);

	if (pc->pc_expiry != NULL) {
		tlv_push(tlv, 0x35);
		tlv_write(tlv, pc->pc_expiry, pc->pc_expiry_len);
		tlv_pop(tlv);
	}

	if (pc->pc_flags & PIV_CHUID_HAS_CHUUID) {
		tlv_push(tlv, 0x36);
		tlv_write(tlv, pc->pc_chuuid, sizeof (pc->pc_chuuid));
		tlv_pop(tlv);
	}

	err = ERRF_OK;

out:
	free(buf);
	return (err);
}

errf_t *
piv_chuid_tbs(const struct piv_chuid *pc, uint8_t **out, size_t *len)
{
	struct tlv_state *tlv = NULL;
	errf_t *err;

	tlv = tlv_init_write();
	if (tlv == NULL) {
		err = errfno("tlv_init_write", errno, NULL);
		goto out;
	}

	if ((err = piv_chuid_write_tbs_tlv(pc, tlv)))
		goto out;

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
	return (err);
}

errf_t *
piv_chuid_encode(const struct piv_chuid *pc, uint8_t **out, size_t *outlen)
{
	struct tlv_state *tlv = NULL;
	uint8_t *buf = NULL;
	size_t len;
	errf_t *err;

	tlv = tlv_init_write();
	if (tlv == NULL) {
		err = errfno("tlv_init_write", errno, NULL);
		goto out;
	}

	if ((err = piv_chuid_write_tbs_tlv(pc, tlv)))
		goto out;

	if (pc->pc_sig != NULL) {
		len = i2d_CMS_ContentInfo(pc->pc_sig, &buf);
		if (len == 0) {
			make_sslerrf(err, "i2d_CMS_ContentInfo", "encoding "
			    "CHUID signature");
			goto out;
		}
		tlv_push(tlv, 0x3E);
		tlv_write(tlv, buf, len);
		tlv_pop(tlv);
	} else {
		/*
		 * The signature field is compulsory, so write an empty tag.
		 */
		tlv_push(tlv, 0x3E);
		tlv_pop(tlv);
	}

	len = tlv_len(tlv);
	*out = malloc(len);
	if (*out == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	bcopy(tlv_buf(tlv), *out, len);
	*outlen = len;

	err = ERRF_OK;

out:
	tlv_free(tlv);
	free(buf);
	return (err);
}

errf_t *
piv_chuid_decode(const uint8_t *data, size_t len, struct piv_chuid **out)
{
	struct tlv_state *tlv = NULL;
	uint tag;
	errf_t *err;
	struct piv_chuid *chuid = NULL;
	uint8_t *d;
	size_t dlen;
	const uint8_t *p;

	chuid = calloc(1, sizeof (struct piv_chuid));
	if (chuid == NULL) {
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
		case 0xEE:	/* Buffer Length */
			err = tlv_read_u16(tlv, &chuid->pc_buflen);
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			chuid->pc_flags |= PIV_CHUID_HAS_BUFLEN;
			break;
		case 0x30:	/* FASC-N */
			err = piv_fascn_decode(tlv_ptr(tlv), tlv_rem(tlv),
			    &chuid->pc_fascn);
			if (err)
				goto out;
			tlv_skip(tlv);
			break;
		case 0x32:	/* Organizational Identifier */
			err = tlv_read_alloc(tlv, &chuid->pc_orgid,
			    &chuid->pc_orgid_len);
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0x33:	/* DUNS */
			err = tlv_read_alloc(tlv, &chuid->pc_duns,
			    &chuid->pc_duns_len);
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0x34:	/* GUID */
			err = tlv_read(tlv, chuid->pc_guid,
			    sizeof (chuid->pc_guid));
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0x35:	/* Expiry */
			err = tlv_read_alloc(tlv, &chuid->pc_expiry,
			    &chuid->pc_expiry_len);
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			break;
		case 0x36:	/* Cardholder UUID */
			err = tlv_read(tlv, chuid->pc_chuuid,
			    sizeof (chuid->pc_chuuid));
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			chuid->pc_flags |= PIV_CHUID_HAS_CHUUID;
			break;
		case 0x3D:	/* Authentication Key Map (Deprecated) */
			tlv_skip(tlv);
			break;
		case 0x3E:	/* Issuer Signature */
			err = tlv_read_alloc(tlv, &d, &dlen);
			if (err)
				goto out;
			if ((err = tlv_end(tlv)))
				goto out;
			if (dlen == 0) {
				/* Skip an empty signature */
				free(d);
				break;
			}
			p = d;
			chuid->pc_sig = d2i_CMS_ContentInfo(NULL, &p, len);
			free(d);
			if (chuid->pc_sig == NULL) {
				make_sslerrf(err, "d2i_CMS_ContentInfo",
				    "parsing issuer signature in CHUID");
				goto out;
			}
			break;
		case 0xFE:	/* LRC */
			tlv_skip(tlv);
			break;
		default:
			err = tagerrf("CHUID", tag);
			goto out;
		}
	}

	*out = chuid;
	chuid = NULL;
	err = ERRF_OK;

out:
	if (err != ERRF_OK)
		tlv_abort(tlv);
	else
		tlv_free(tlv);
	piv_chuid_free(chuid);
	return (err);
}

const struct piv_fascn *
piv_chuid_get_fascn(const struct piv_chuid *c)
{
	return (c->pc_fascn);
}

const uint8_t *
piv_chuid_get_guid(const struct piv_chuid *c)
{
	return (c->pc_guid);
}

const uint8_t *
piv_chuid_get_chuuid(const struct piv_chuid *c)
{
	if (!(c->pc_flags & PIV_CHUID_HAS_CHUUID))
		return (NULL);
	return (c->pc_chuuid);
}

const uint8_t *
piv_chuid_get_expiry(const struct piv_chuid *c, size_t *plen)
{
	*plen = c->pc_expiry_len;
	return (c->pc_expiry);
}

CMS_ContentInfo *
piv_chuid_get_signature(struct piv_chuid *c)
{
	return (c->pc_sig);
}

boolean_t
piv_chuid_is_signed(const struct piv_chuid *c)
{
	return (c->pc_sig != NULL);
}

#if defined(__CPROVER) && __CPROVER_MAIN == __FILE_piv_chuid_c

uint8_t *
genbinstr(size_t minlen, size_t maxlen, size_t *plen)
{
	size_t len, i;
	uint8_t *buf;
	__CPROVER_assume(len >= minlen);
	__CPROVER_assume(len <= maxlen);
	buf = malloc(len);
	__CPROVER_assume(buf != NULL);
	*plen = len;
	return (buf);
}

void
chuid_write_proof(void)
{
	struct piv_chuid *chuid;
	uint8_t *data;
	size_t len;
	errf_t *err;

	chuid = piv_chuid_new();
	__CPROVER_assume(chuid != NULL);

	piv_chuid_set_random_guid(chuid);
	piv_chuid_set_expiry_rel(chuid, 3600*24*365);

	data = NULL;
	len = 0;
	err = piv_chuid_encode(chuid, &data, &len);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);
	assert(data != NULL);
	assert(len > 0);

	piv_chuid_free(chuid);
}

void
chuid_read_proof(void)
{
	struct piv_chuid *chuid;
	uint8_t *data;
	size_t len;
	errf_t *err;

	chuid = NULL;
	data = genbinstr(18, 20, &len);
	err = piv_chuid_decode(data, len, &chuid);
	__CPROVER_assume(err != ERRF_NOMEM);
	__CPROVER_assume(err != ERRF_OK);
	assert(chuid == NULL);

	data = genbinstr(18, 20, &len);
	err = piv_chuid_decode(data, len, &chuid);
	__CPROVER_assume(err == ERRF_OK);
	assert(chuid != NULL);

	assert(piv_chuid_get_guid(chuid) != NULL);

	piv_chuid_free(chuid);
}

int
main(int argc, char *argv[])
{
	__CPROVER_assume(ERRF_NOMEM != NULL);
	chuid_write_proof();
	chuid_read_proof();
	return (0);
}

#endif
