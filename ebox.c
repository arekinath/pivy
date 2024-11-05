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
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/errno.h>

#include "utils.h"
#include "debug.h"

#include "openssh/config.h"
#include "openssh/sshbuf.h"
#include "openssh/sshkey.h"
#include "openssh/digest.h"
#include "openssh/digest.h"
#include "openssh/cipher.h"
#include "openssh/hmac.h"
#include "openssh/ssherr.h"

#include "tlv.h"
#include "ebox.h"
#include "piv.h"
#include "bunyan.h"

#include "sss/hazmat.h"

#include "piv-internal.h"

#if defined(__sun) || defined(__APPLE__)
#include <netinet/in.h>
#define	htobe32(v)	(htonl(v))
#else
#include <endian.h>
#endif

struct buf {
	size_t b_len;
	uint8_t *b_data;
};

struct ebox_tpl {
	uint8_t et_version;
	struct ebox_tpl_config *et_configs;
	struct ebox_tpl_config *et_lastconfig;
	void *et_priv;
};

struct ebox_tpl_config {
	struct ebox_tpl_config *etc_next;
	struct ebox_tpl_config *etc_prev;
	enum ebox_config_type etc_type;
	uint8_t etc_n;
	uint8_t etc_m;
	struct ebox_tpl_part *etc_parts;
	struct ebox_tpl_part *etc_lastpart;
	void *etc_priv;
};

struct ebox_tpl_part {
	struct ebox_tpl_part *etp_next;
	struct ebox_tpl_part *etp_prev;
	char *etp_name;
	struct sshkey *etp_pubkey;
	struct sshkey *etp_cak;
	enum piv_slotid etp_slot;
	uint8_t etp_guid[16];
	void *etp_priv;
};

struct ebox {
	uint8_t e_version;
	struct ebox_tpl *e_tpl;
	struct ebox_config *e_configs;
	enum ebox_type e_type;

	struct ebox_ephem_key *e_ephemkeys;

	/* main key */
	size_t e_keylen;
	uint8_t *e_key;

	/* recovery box */
	char *e_rcv_cipher;
	struct buf e_rcv_key;
	struct buf e_rcv_iv;
	struct buf e_rcv_enc;
	struct buf e_rcv_plain;

	/* recovery token */
	size_t e_tokenlen;
	uint8_t *e_token;

	void *e_priv;
};

struct ebox_ephem_key {
	struct ebox_ephem_key *eek_next;
	int eek_nid;
	struct sshkey *eek_ephem;
};

struct ebox_config {
	struct ebox_config *ec_next;
	struct ebox_tpl_config *ec_tpl;

	struct ebox_part *ec_parts;

	/* key for collecting challenge-responses */
	struct sshkey *ec_chalkey;

	/* nonce for uniquifying recovery keys */
	uint8_t *ec_nonce;
	size_t ec_noncelen;

	void *ec_priv;
};

struct ebox_part {
	struct ebox_part *ep_next;
	struct ebox_tpl_part *ep_tpl;
	struct piv_ecdh_box *ep_box;
	uint8_t ep_id;
	struct ebox_challenge *ep_chal;
	size_t ep_sharelen;
	uint8_t *ep_share;
	void *ep_priv;
};

enum chaltag {
	CTAG_HOSTNAME = 1,
	CTAG_CTIME = 2,
	CTAG_DESCRIPTION = 3,
	CTAG_WORDS = 4,
};

enum resptag {
	RTAG_ID = 1,
	RTAG_KEYPIECE = 2,
};

enum ebox_recov_tag {
	EBOX_RECOV_TOKEN = 0x01,
	EBOX_RECOV_KEY = 0x02
};

struct ebox_challenge {
	uint8_t c_version;
	enum ebox_chaltype c_type;
	uint8_t c_id;
	char *c_description;
	char *c_hostname;
	uint64_t c_ctime;
	uint8_t c_words[4];
	struct sshkey *c_destkey;
	struct piv_ecdh_box *c_keybox;
};

struct ebox_stream {
	struct ebox *es_ebox;
	char *es_cipher;
	char *es_mac;
	size_t es_chunklen;
};

struct ebox_stream_chunk {
	struct ebox_stream *esc_stream;
	uint32_t esc_seqnr;
	size_t esc_enclen;
	uint8_t *esc_enc;
	size_t esc_plainlen;
	uint8_t *esc_plain;
};

enum ebox_part_tag {
	EBOX_PART_END = 0,
	EBOX_PART_PUBKEY = 1,
	EBOX_PART_NAME = 2,
	EBOX_PART_CAK = 3,
	EBOX_PART_GUID = 4,
	EBOX_PART_BOX = 5,
	EBOX_PART_SLOT = 6,
	EBOX_PART_OPTIONAL_FLAG = 0x80,
};

#define	EBOX_STREAM_DEFAULT_CHUNK	(128 * 1024)

enum ebox_version {
	EBOX_V1 = 0x01,
	EBOX_V2 = 0x02,
	EBOX_V3 = 0x03,
	EBOX_VNEXT,
	EBOX_VMIN = EBOX_V1
};

enum ebox_tpl_version {
	EBOX_TPL_V1 = 0x01,
	EBOX_TPL_VNEXT,
	EBOX_TPL_VMIN = EBOX_TPL_V1
};

#define eboxderrf(cause) \
    errf("InvalidDataError", cause, \
    "ebox contained invalid or corrupted data")

#define eboxverrf(cause) \
    errf("NotSupportedError", cause, \
    "ebox is not supported")

#define	chalderrf(cause) \
    errf("InvalidDataError", cause, \
    "ebox challenge contained invalid or corrupted data")

#define	chalverrf(cause) \
    errf("NotSupportedError", cause, \
    "ebox challenge is not supported")

static struct sshkey *
ebox_get_ephem_for_nid(const struct ebox *ebox, int nid)
{
	const struct ebox_ephem_key *eek;
	eek = ebox->e_ephemkeys;
	for (; eek != NULL; eek = eek->eek_next) {
		if (eek->eek_nid == nid) {
			return (eek->eek_ephem);
		}
	}
	return (NULL);
}

static struct sshkey *
ebox_make_ephem_for_nid(struct ebox *ebox, int nid)
{
	struct ebox_ephem_key *eek;
	uint bits;
	eek = ebox->e_ephemkeys;
	for (; eek != NULL; eek = eek->eek_next) {
		if (eek->eek_nid == nid) {
			return (eek->eek_ephem);
		}
	}
	bits = sshkey_curve_nid_to_bits(nid);
	eek = calloc(1, sizeof (struct ebox_ephem_key));
	VERIFY(eek != NULL);
	eek->eek_next = ebox->e_ephemkeys;
	ebox->e_ephemkeys = eek;
	eek->eek_nid = nid;
	VERIFY0(sshkey_generate(KEY_ECDSA, bits, &eek->eek_ephem));
	return (eek->eek_ephem);
}

static errf_t *
sshbuf_get_eckey8_sshkey(struct sshbuf *buf, int nid, struct sshkey **outkey)
{
	struct sshkey *k = NULL;
	EC_KEY *eck = NULL;
	EVP_PKEY *pkey = NULL;
	errf_t *err;
	int rc;

	k = sshkey_new(KEY_ECDSA);
	if (k == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	k->ecdsa_nid = nid;
	eck = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	if (eck == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	if ((rc = sshbuf_get_eckey8(buf, eck))) {
		err = ssherrf("sshbuf_get_eckey8", rc);
		goto out;
	}
	if ((rc = sshkey_ec_validate_public(EC_KEY_get0_group(eck),
	    EC_KEY_get0_public_key(eck)))) {
		err = ssherrf("sshkey_ec_validate_public", rc);
		goto out;
	}
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	EVP_PKEY_assign_EC_KEY(pkey, eck);
	eck = NULL;

	EVP_PKEY_free(k->pkey);
	k->pkey = pkey;
	pkey = NULL;

	*outkey = k;
	k = NULL;
	err = ERRF_OK;

out:
	EVP_PKEY_free(pkey);
	EC_KEY_free(eck);
	sshkey_free(k);
	return (err);
}

struct ebox_tpl *
ebox_tpl_alloc(void)
{
	struct ebox_tpl *tpl;
	tpl = calloc(1, sizeof (struct ebox_tpl));
	if (tpl == NULL)
		return (NULL);
	tpl->et_version = EBOX_TPL_VNEXT - 1;
	return (tpl);
}

void *
ebox_tpl_private(const struct ebox_tpl *tpl)
{
	return (tpl->et_priv);
}

void *
ebox_tpl_alloc_private(struct ebox_tpl *tpl, size_t sz)
{
	VERIFY(tpl->et_priv == NULL);
	tpl->et_priv = calloc(1, sz);
	return (tpl->et_priv);
}

void
ebox_tpl_free_private(struct ebox_tpl *tpl)
{
	VERIFY(tpl->et_priv != NULL);
	free(tpl->et_priv);
	tpl->et_priv = NULL;
}

void
ebox_tpl_add_config(struct ebox_tpl *tpl, struct ebox_tpl_config *config)
{
	VERIFY(config->etc_next == NULL);
	VERIFY(config->etc_prev == NULL);
	if (tpl->et_lastconfig == NULL) {
		tpl->et_configs = config;
	} else {
		config->etc_prev = tpl->et_lastconfig;
		tpl->et_lastconfig->etc_next = config;
	}
	tpl->et_lastconfig = config;
}

void
ebox_tpl_remove_config(struct ebox_tpl *tpl, struct ebox_tpl_config *config)
{
	if (config->etc_prev == NULL) {
		VERIFY(tpl->et_configs == config);
		tpl->et_configs = config->etc_next;
	} else {
		config->etc_prev->etc_next = config->etc_next;
	}
	if (config->etc_next == NULL) {
		VERIFY(tpl->et_lastconfig == config);
		tpl->et_lastconfig = config->etc_prev;
	} else {
		config->etc_next->etc_prev = config->etc_prev;
	}
	config->etc_next = NULL;
	config->etc_prev = NULL;
}

struct ebox_tpl_config *
ebox_tpl_next_config(const struct ebox_tpl *tpl,
    const struct ebox_tpl_config *prev)
{
	if (prev == NULL)
		return (tpl->et_configs);
	return (prev->etc_next);
}

void
ebox_tpl_free(struct ebox_tpl *tpl)
{
	struct ebox_tpl_config *config, *nconfig;
	if (tpl == NULL)
		return;
	free(tpl->et_priv);
	for (config = tpl->et_configs; config != NULL; config = nconfig) {
		nconfig = config->etc_next;
		ebox_tpl_config_free(config);
	}
	free(tpl);
}

struct ebox_tpl_config *
ebox_tpl_config_alloc(enum ebox_config_type type)
{
	struct ebox_tpl_config *config;
	config = calloc(1, sizeof (struct ebox_tpl_config));
	if (config == NULL)
		return (NULL);
	config->etc_type = type;
	if (type == EBOX_PRIMARY)
		config->etc_n = 1;
	return (config);
}

void *
ebox_tpl_config_private(const struct ebox_tpl_config *config)
{
	return (config->etc_priv);
}

void *
ebox_tpl_config_alloc_private(struct ebox_tpl_config *config, size_t sz)
{
	VERIFY(config->etc_priv == NULL);
	config->etc_priv = calloc(1, sz);
	return (config->etc_priv);
}

void
ebox_tpl_config_free_private(struct ebox_tpl_config *config)
{
	VERIFY(config->etc_priv != NULL);
	free(config->etc_priv);
	config->etc_priv = NULL;
}

errf_t *
ebox_tpl_config_set_n(struct ebox_tpl_config *config, uint n)
{
	if (n == 0)
		return (argerrf("n", "non-zero", "%u", n));
	if (n > config->etc_m) {
		return (argerrf("n", "smaller than m (%u)",
		    "%u", config->etc_m, n));
	}
	if (n != 1 && config->etc_type == EBOX_PRIMARY) {
		return (errf("ArgumentError", NULL, "Primary configs may "
		    "only have n=1 (tried to set n=%u)", n));
	}
	config->etc_n = n;
	return (ERRF_OK);
}

uint
ebox_tpl_config_n(const struct ebox_tpl_config *config)
{
	return (config->etc_n);
}

enum ebox_config_type
ebox_tpl_config_type(const struct ebox_tpl_config *config)
{
	return (config->etc_type);
}

void
ebox_tpl_config_add_part(struct ebox_tpl_config *config,
    struct ebox_tpl_part *part)
{
	VERIFY(part->etp_next == NULL);
	VERIFY(part->etp_prev == NULL);
	if (config->etc_lastpart == NULL) {
		config->etc_parts = part;
	} else {
		config->etc_lastpart->etp_next = part;
		part->etp_prev = config->etc_lastpart;
	}
	config->etc_lastpart = part;
	++config->etc_m;
}

void
ebox_tpl_config_remove_part(struct ebox_tpl_config *config,
    struct ebox_tpl_part *part)
{
	if (part->etp_prev == NULL) {
		VERIFY(config->etc_parts == part);
		config->etc_parts = part->etp_next;
	} else {
		part->etp_prev->etp_next = part->etp_next;
	}
	if (part->etp_next == NULL) {
		VERIFY(config->etc_lastpart == part);
		config->etc_lastpart = part->etp_prev;
	} else {
		part->etp_next->etp_prev = part->etp_prev;
	}
	part->etp_next = NULL;
	part->etp_prev = NULL;
	--config->etc_m;
}

struct ebox_tpl_part *
ebox_tpl_config_next_part(const struct ebox_tpl_config *config,
    const struct ebox_tpl_part *prev)
{
	if (prev == NULL)
		return (config->etc_parts);
	return (prev->etp_next);
}

void
ebox_tpl_config_free(struct ebox_tpl_config *config)
{
	struct ebox_tpl_part *part, *npart;
	if (config == NULL)
		return;
	free(config->etc_priv);
	for (part = config->etc_parts; part != NULL; part = npart) {
		npart = part->etp_next;
		ebox_tpl_part_free(part);
	}
	free(config);
}

struct ebox_tpl_part *
ebox_tpl_part_alloc(const uint8_t *guid, size_t guidlen,
    enum piv_slotid slotid, struct sshkey *pubkey)
{
	struct ebox_tpl_part *part;
	part = calloc(1, sizeof (struct ebox_tpl_part));
	if (part == NULL)
		return (NULL);
	VERIFY3U(guidlen, ==, sizeof (part->etp_guid));
	bcopy(guid, part->etp_guid, guidlen);
	if (sshkey_demote(pubkey, &part->etp_pubkey)) {
		free(part);
		return (NULL);
	}
	part->etp_slot = slotid;
	return (part);
}

void
ebox_tpl_part_free(struct ebox_tpl_part *part)
{
	if (part == NULL)
		return;
	free(part->etp_priv);
	free(part->etp_name);
	sshkey_free(part->etp_pubkey);
	sshkey_free(part->etp_cak);
	free(part);
}

void
ebox_tpl_part_set_name(struct ebox_tpl_part *part, const char *name)
{
	part->etp_name = strdup(name);
	VERIFY(part->etp_name != NULL);
}

void
ebox_tpl_part_set_cak(struct ebox_tpl_part *part, struct sshkey *cak)
{
	VERIFY0(sshkey_demote(cak, &part->etp_cak));
}

void *
ebox_tpl_part_private(const struct ebox_tpl_part *part)
{
	return (part->etp_priv);
}

void *
ebox_tpl_part_alloc_private(struct ebox_tpl_part *part, size_t sz)
{
	VERIFY(part->etp_priv == NULL);
	part->etp_priv = calloc(1, sz);
	return (part->etp_priv);
}

void
ebox_tpl_part_free_private(struct ebox_tpl_part *part)
{
	VERIFY(part->etp_priv != NULL);
	free(part->etp_priv);
	part->etp_priv = NULL;
}

const char *
ebox_tpl_part_name(const struct ebox_tpl_part *part)
{
	return (part->etp_name);
}

struct sshkey *
ebox_tpl_part_pubkey(const struct ebox_tpl_part *part)
{
	return (part->etp_pubkey);
}

struct sshkey *
ebox_tpl_part_cak(const struct ebox_tpl_part *part)
{
	return (part->etp_cak);
}

enum piv_slotid
ebox_tpl_part_slot(const struct ebox_tpl_part *part)
{
	return (part->etp_slot);
}

const uint8_t *
ebox_tpl_part_guid(const struct ebox_tpl_part *part)
{
	return (part->etp_guid);
}

struct ebox_tpl *
ebox_tpl_clone(const struct ebox_tpl *tpl)
{
	struct ebox_tpl *ntpl;
	struct ebox_tpl_config *pconfig, *nconfig, *config;
	struct ebox_tpl_part *ppart, *npart, *part;

	ntpl = calloc(1, sizeof (struct ebox_tpl));
	VERIFY(ntpl != NULL);

	ntpl->et_version = tpl->et_version;

	pconfig = NULL;
	config = tpl->et_configs;
	for (; config != NULL; config = config->etc_next) {
		nconfig = calloc(1, sizeof (struct ebox_tpl_config));
		VERIFY(nconfig != NULL);
		if (pconfig != NULL) {
			pconfig->etc_next = nconfig;
			nconfig->etc_prev = pconfig;
		} else {
			ntpl->et_configs = nconfig;
		}
		ntpl->et_lastconfig = nconfig;
		nconfig->etc_type = config->etc_type;
		nconfig->etc_n = config->etc_n;
		nconfig->etc_m = config->etc_m;

		ppart = NULL;
		part = config->etc_parts;
		for (; part != NULL; part = part->etp_next) {
			npart = calloc(1, sizeof (struct ebox_tpl_part));
			VERIFY(npart != NULL);
			if (ppart != NULL) {
				ppart->etp_next = npart;
				npart->etp_prev = ppart;
			} else {
				nconfig->etc_parts = npart;
			}
			nconfig->etc_lastpart = npart;
			if (part->etp_name != NULL)
				npart->etp_name = strdup(part->etp_name);
			bcopy(part->etp_guid, npart->etp_guid,
			    sizeof (npart->etp_guid));
			npart->etp_slot = part->etp_slot;
			if (part->etp_pubkey != NULL) {
				VERIFY0(sshkey_demote(part->etp_pubkey,
				    &npart->etp_pubkey));
			}
			if (part->etp_cak != NULL) {
				VERIFY0(sshkey_demote(part->etp_cak,
				    &npart->etp_cak));
			}

			ppart = npart;
		}

		pconfig = nconfig;
	}


	return (ntpl);
}

static errf_t *
sshbuf_put_ebox_tpl_part(struct sshbuf *buf, struct ebox_tpl_part *part)
{
	int rc = 0;
	errf_t *err;
	struct sshbuf *kbuf;
	const char *tname;
	EC_KEY *eck;

	if (part->etp_pubkey->type != KEY_ECDSA) {
		return (errf("ArgumentError", NULL,
		    "ebox part pubkeys must be ECDSA keys"));
	}
	tname = sshkey_curve_nid_to_name(part->etp_pubkey->ecdsa_nid);

	kbuf = sshbuf_new();
	VERIFY(kbuf != NULL);

	eck = EVP_PKEY_get1_EC_KEY(part->etp_pubkey->pkey);
	if ((rc = sshbuf_put_u8(buf, EBOX_PART_PUBKEY)) ||
	    (rc = sshbuf_put_cstring8(buf, tname)) ||
	    (rc = sshbuf_put_eckey8(buf, eck))) {
		err = ssherrf("sshbuf_put_*", rc);
		goto out;
	}

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_GUID)) ||
	    (rc = sshbuf_put_string8(buf, part->etp_guid,
	    sizeof (part->etp_guid)))) {
		err = ssherrf("sshbuf_put_u8/string8", rc);
		goto out;
	}

	if (part->etp_name != NULL) {
		if ((rc = sshbuf_put_u8(buf, EBOX_PART_NAME)) ||
		    (rc = sshbuf_put_cstring8(buf, part->etp_name))) {
			err = ssherrf("sshbuf_put_u8/cstring8", rc);
			goto out;
		}
	}

	if (part->etp_cak != NULL) {
		sshbuf_reset(kbuf);
		if ((rc = sshbuf_put_u8(buf, EBOX_PART_CAK)) ||
		    (rc = sshkey_putb(part->etp_cak, kbuf)) ||
		    (rc = sshbuf_put_stringb(buf, kbuf))) {
			err = ssherrf("sshbuf_put_*", rc);
			goto out;
		}
	}

	if (part->etp_slot != PIV_SLOT_KEY_MGMT) {
		if ((rc = sshbuf_put_u8(buf, EBOX_PART_SLOT)) ||
		    (rc = sshbuf_put_u8(buf, part->etp_slot))) {
			err = ssherrf("sshbuf_put_u8", rc);
			goto out;
		}
	}

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_END))) {
		err = ssherrf("sshbuf_put_u8", rc);
		goto out;
	}

	err = NULL;

out:
	sshbuf_free(kbuf);
	return (err);
}

static errf_t *
sshbuf_get_ebox_tpl_part(struct sshbuf *buf, struct ebox_tpl_part **ppart)
{
	struct ebox_tpl_part *part;
	struct sshbuf *kbuf;
	int rc = 0;
	errf_t *err = NULL;
	size_t len;
	uint8_t tag, *guid;
	char *tname = NULL;
	uint8_t slotid = PIV_SLOT_KEY_MGMT;
	boolean_t gotguid = B_FALSE;

	part = calloc(1, sizeof (struct ebox_tpl_part));
	VERIFY(part != NULL);

	kbuf = sshbuf_new();
	VERIFY(kbuf != NULL);

	if ((rc = sshbuf_get_u8(buf, &tag))) {
		err = ssherrf("sshbuf_get_u8", rc);
		goto out;
	}
	while (tag != EBOX_PART_END) {
		switch (tag & ~EBOX_PART_OPTIONAL_FLAG) {
		case EBOX_PART_PUBKEY:
			free(tname);
			tname = NULL;
			if ((rc = sshbuf_get_cstring8(buf, &tname, NULL))) {
				err = ssherrf("sshbuf_get_cstring8", rc);
				goto out;
			}

			err = sshbuf_get_eckey8_sshkey(buf,
			    sshkey_curve_name_to_nid(tname),
			    &part->etp_pubkey);
			if (err != ERRF_OK) {
				err = errf("ParseError", err, "failed to "
				    "parse part public key");
				goto out;
			}
			break;
		case EBOX_PART_CAK:
			sshbuf_reset(kbuf);
			rc = sshbuf_get_stringb(buf, kbuf);
			if (rc) {
				err = ssherrf("sshbuf_get_stringb", rc);
				goto out;
			}
			rc = sshkey_fromb(kbuf, &part->etp_cak);
			if (rc) {
				err = ssherrf("sshkey_fromb", rc);
				goto out;
			}
			break;
		case EBOX_PART_NAME:
			rc = sshbuf_get_cstring8(buf, &part->etp_name, &len);
			if (rc) {
				err = ssherrf("sshbuf_get_cstring8", rc);
				goto out;
			}
			break;
		case EBOX_PART_GUID:
			rc = sshbuf_get_string8(buf, &guid, &len);
			if (rc) {
				err = ssherrf("sshbuf_get_string8", rc);
				goto out;
			}
			if (len != sizeof (part->etp_guid)) {
				err = errf("LengthError", NULL, "ebox part "
				    "GUID tag must be %d bytes long (is %d)",
				    sizeof (part->etp_guid), len);
				goto out;
			}
			bcopy(guid, part->etp_guid, len);
			free(guid);
			guid = NULL;
			gotguid = B_TRUE;
			break;
		case EBOX_PART_SLOT:
			rc = sshbuf_get_u8(buf, &slotid);
			if (rc) {
				err = ssherrf("sshbuf_get_u8", rc);
				goto out;
			}
			break;
		default:
			if ((tag & EBOX_PART_OPTIONAL_FLAG) != 0) {
				rc = sshbuf_skip_string8(buf);
				if (rc) {
					err = ssherrf("sshbuf_skip_string8",
					    rc);
					goto out;
				}
				break;
			}
			err = errf("UnknownTagError", NULL, "unknown tag %d "
			    "at +%zx", tag, sshbuf_offset(buf));
			goto out;
		}
		if ((rc = sshbuf_get_u8(buf, &tag))) {
			err = ssherrf("sshbuf_get_u8", rc);
			goto out;
		}
	}

	part->etp_slot = slotid;

	if (part->etp_pubkey == NULL || !gotguid) {
		err = errf("IncompletePartError", NULL, "ebox part missing "
		    "compulsory tags (pubkey or guid) at +%zx",
		    sshbuf_offset(buf));
		goto out;
	}

	*ppart = part;
	part = NULL;
out:
	sshbuf_free(kbuf);
	ebox_tpl_part_free(part);
	free(tname);
	return (err);
}

static errf_t *
sshbuf_put_ebox_tpl_config(struct sshbuf *buf, struct ebox_tpl_config *config)
{
	struct ebox_tpl_part *part;
	int rc = 0;
	uint i = 0;
	errf_t *err;

	if ((rc = sshbuf_put_u8(buf, config->etc_type)) ||
	    (rc = sshbuf_put_u8(buf, config->etc_n)) ||
	    (rc = sshbuf_put_u8(buf, config->etc_m))) {
		return (ssherrf("sshbuf_put_u8", rc));
	}

	for (part = config->etc_parts; part != NULL; part = part->etp_next) {
		if ((err = sshbuf_put_ebox_tpl_part(buf, part))) {
			err = errf("PartError", err, "error writing out part "
			    "%u", i);
			return (err);
		}
		++i;
	}

	return (ERRF_OK);
}

static errf_t *
sshbuf_get_ebox_tpl_config(struct sshbuf *buf, struct ebox_tpl_config **pconfig)
{
	struct ebox_tpl_config *config;
	struct ebox_tpl_part *part;
	int rc = 0;
	errf_t *err = NULL;
	uint8_t type;
	uint i;

	config = calloc(1, sizeof (struct ebox_tpl_config));
	VERIFY(config != NULL);

	if ((rc = sshbuf_get_u8(buf, &type)) ||
	    (rc = sshbuf_get_u8(buf, &config->etc_n)) ||
	    (rc = sshbuf_get_u8(buf, &config->etc_m))) {
		err = ssherrf("sshbuf_get_u8", rc);
		goto out;
	}
	config->etc_type = (enum ebox_config_type)type;
	if (config->etc_type != EBOX_PRIMARY &&
	    config->etc_type != EBOX_RECOVERY) {
		err = errf("ArgumentError", NULL, "config can only be type "
		    "PRIMARY or RECOVERY (is %d)", config->etc_type);
		goto out;
	}
	if (config->etc_type == EBOX_PRIMARY &&
	    config->etc_n > 1) {
		err = errf("ArgumentError", NULL, "primary configs can only "
		    "use n=1 (using n=%d)", config->etc_n);
		goto out;
	}

	if ((err = sshbuf_get_ebox_tpl_part(buf, &part))) {
		err = errf("PartError", err, "error reading part 0");
		goto out;
	}
	config->etc_parts = part;
	config->etc_lastpart = part;

	for (i = 1; i < config->etc_m; ++i) {
		if ((err = sshbuf_get_ebox_tpl_part(buf, &part->etp_next))) {
			err = errf("PartError", err, "error reading part %u", i);
			goto out;
		}
		part->etp_next->etp_prev = part;
		part = part->etp_next;
		config->etc_lastpart = part;
	}

	*pconfig = config;
	config = NULL;

out:
	ebox_tpl_config_free(config);
	return (err);
}

errf_t *
sshbuf_put_ebox_tpl(struct sshbuf *buf, struct ebox_tpl *tpl)
{
	uint8_t nconfigs = 0;
	int rc = 0;
	errf_t *err;
	uint i = 0;
	struct ebox_tpl_config *config;

	config = tpl->et_configs;
	for (; config != NULL; config = config->etc_next) {
		++nconfigs;
	}

	if ((rc = sshbuf_put_u8(buf, 0xEB)) ||
	    (rc = sshbuf_put_u8(buf, 0x0C)) ||
	    (rc = sshbuf_put_u8(buf, tpl->et_version)) ||
	    (rc = sshbuf_put_u8(buf, EBOX_TEMPLATE))) {
		return (ssherrf("sshbuf_put_u8", rc));
	}

	if ((rc = sshbuf_put_u8(buf, nconfigs)))
		return (ssherrf("sshbuf_put_u8", rc));

	config = tpl->et_configs;
	for (; config != NULL; config = config->etc_next) {
		if ((err = sshbuf_put_ebox_tpl_config(buf, config))) {
			err = errf("ConfigError", NULL,
			    "error writing config %u", i);
			return (err);
		}
		++i;
	}

	return (ERRF_OK);
}

uint
ebox_tpl_version(const struct ebox_tpl *tpl)
{
	return (tpl->et_version);
}

uint
ebox_version(const struct ebox *ebox)
{
	return (ebox->e_version);
}

enum ebox_type
ebox_type(const struct ebox *ebox)
{
	return (ebox->e_type);
}

struct ebox_tpl *
ebox_tpl(const struct ebox *ebox)
{
	return (ebox->e_tpl);
}

const char *
ebox_cipher(const struct ebox *ebox)
{
	return (ebox->e_rcv_cipher);
}

uint
ebox_ephem_count(const struct ebox *ebox)
{
	uint n = 0;
	const struct ebox_ephem_key *eek;
	eek = ebox->e_ephemkeys;
	for (; eek != NULL; eek = eek->eek_next)
		++n;
	return (n);
}

const struct sshkey *
ebox_ephem_pubkey(const struct ebox *ebox, uint index)
{
	const struct ebox_ephem_key *eek;
	eek = ebox->e_ephemkeys;
	while (index > 0 && eek != NULL) {
		eek = eek->eek_next;
		--index;
	}
	if (eek == NULL)
		return (NULL);
	return (eek->eek_ephem);
}

void *
ebox_private(const struct ebox *ebox)
{
	return (ebox->e_priv);
}

void *
ebox_alloc_private(struct ebox *ebox, size_t sz)
{
	VERIFY(ebox->e_priv == NULL);
	ebox->e_priv = calloc(1, sz);
	return (ebox->e_priv);
}

void
ebox_free_private(struct ebox *ebox)
{
	VERIFY(ebox->e_priv != NULL);
	free(ebox->e_priv);
	ebox->e_priv = NULL;
}

errf_t *
sshbuf_get_ebox_tpl(struct sshbuf *buf, struct ebox_tpl **ptpl)
{
	struct ebox_tpl *tpl;
	struct ebox_tpl_config *config;
	int rc = 0;
	errf_t *err;
	uint8_t ver, magic[2], type, nconfigs;
	uint i;

	tpl = calloc(1, sizeof (struct ebox_tpl));
	VERIFY(tpl != NULL);

	if ((rc = sshbuf_get_u8(buf, &magic[0])) ||
	    (rc = sshbuf_get_u8(buf, &magic[1]))) {
		err = eboxderrf(errf("MagicError",
		    ssherrf("sshbuf_get_u8", rc), "failed reading ebox magic"));
		goto out;
	}
	if (magic[0] != 0xEB && magic[1] != 0x0C) {
		err = eboxderrf(errf("MagicError", NULL,
		    "bad ebox magic number"));
		goto out;
	}
	if ((rc = sshbuf_get_u8(buf, &ver)) ||
	    (rc = sshbuf_get_u8(buf, &type))) {
		err = eboxderrf(ssherrf("sshbuf_get_u8", rc));
		goto out;
	}
	if (ver < EBOX_TPL_VMIN || ver >= EBOX_TPL_VNEXT) {
		err = eboxverrf(errf("VersionError", NULL,
		    "unsupported version number 0x%02x", ver));
		goto out;
	}
	tpl->et_version = ver;
	if (type != EBOX_TEMPLATE) {
		err = eboxderrf(errf("EboxTypeError", NULL,
		    "buffer does not contain an ebox template"));
		goto out;
	}
	if ((rc = sshbuf_get_u8(buf, &nconfigs))) {
		err = eboxderrf(ssherrf("sshbuf_get_u8", rc));
		goto out;
	}

	if ((err = sshbuf_get_ebox_tpl_config(buf, &config))) {
		err = eboxderrf(errf("ConfigError", err,
		    "failed to read config 0"));
		goto out;
	}
	tpl->et_configs = config;
	tpl->et_lastconfig = config;

	for (i = 1; i < nconfigs; ++i) {
		if ((err = sshbuf_get_ebox_tpl_config(buf, &config->etc_next))) {
			err = eboxderrf(errf("ConfigError", err,
			    "failed to read config %u", i));
			goto out;
		}
		config->etc_next->etc_prev = config;
		config = config->etc_next;
		tpl->et_lastconfig = config;
	}

	*ptpl = tpl;
	tpl = NULL;

out:
	ebox_tpl_free(tpl);
	return (err);
}

void
ebox_part_free(struct ebox_part *part)
{
	if (part == NULL)
		return;
	piv_box_free(part->ep_box);
	ebox_challenge_free(part->ep_chal);
	if (part->ep_share != NULL) {
		explicit_bzero(part->ep_share, part->ep_sharelen);
		free(part->ep_share);
	}
	free(part->ep_priv);
	free(part);
}

void
ebox_config_free(struct ebox_config *config)
{
	struct ebox_part *part, *npart;
	if (config == NULL)
		return;
	if (config->ec_chalkey != NULL)
		sshkey_free(config->ec_chalkey);
	freezero(config->ec_nonce, config->ec_noncelen);
	free(config->ec_priv);
	for (part = config->ec_parts; part != NULL; part = npart) {
		npart = part->ep_next;
		ebox_part_free(part);
	}
	free(config);
}

void
ebox_free(struct ebox *box)
{
	struct ebox_config *config, *nconfig;
	struct ebox_ephem_key *eek, *neek;
	if (box == NULL)
		return;
	free(box->e_priv);
	if (box->e_key != NULL) {
		explicit_bzero(box->e_key, box->e_keylen);
		free(box->e_key);
	}
	if (box->e_token != NULL) {
		explicit_bzero(box->e_token, box->e_tokenlen);
		free(box->e_token);
	}
	if (box->e_rcv_key.b_data != NULL) {
		explicit_bzero(box->e_rcv_key.b_data, box->e_rcv_key.b_len);
		free(box->e_rcv_key.b_data);
	}
	free(box->e_rcv_cipher);
	if (box->e_rcv_iv.b_data != NULL)
		free(box->e_rcv_iv.b_data);
	if (box->e_rcv_enc.b_data != NULL)
		free(box->e_rcv_enc.b_data);
	if (box->e_rcv_plain.b_data != NULL) {
		explicit_bzero(box->e_rcv_plain.b_data,
		    box->e_rcv_plain.b_len);
		free(box->e_rcv_plain.b_data);
	}
	for (config = box->e_configs; config != NULL; config = nconfig) {
		nconfig = config->ec_next;
		ebox_config_free(config);
	}
	for (eek = box->e_ephemkeys; eek != NULL; eek = neek) {
		neek = eek->eek_next;
		sshkey_free(eek->eek_ephem);
		free(eek);
	}
	ebox_tpl_free(box->e_tpl);
	free(box);
}

void *
ebox_config_private(const struct ebox_config *config)
{
	return (config->ec_priv);
}

void *
ebox_config_alloc_private(struct ebox_config *config, size_t sz)
{
	VERIFY(config->ec_priv == NULL);
	config->ec_priv = calloc(1, sz);
	return (config->ec_priv);
}

void
ebox_config_free_private(struct ebox_config *config)
{
	VERIFY(config->ec_priv != NULL);
	free(config->ec_priv);
	config->ec_priv = NULL;
}

void *
ebox_part_private(const struct ebox_part *part)
{
	return (part->ep_priv);
}

void *
ebox_part_alloc_private(struct ebox_part *part, size_t sz)
{
	VERIFY(part->ep_priv == NULL);
	part->ep_priv = calloc(1, sz);
	return (part->ep_priv);
}

void
ebox_part_free_private(struct ebox_part *part)
{
	VERIFY(part->ep_priv != NULL);
	free(part->ep_priv);
	part->ep_priv = NULL;
}

errf_t *
ebox_stream_new(const struct ebox_tpl *tpl, struct ebox_stream **str)
{
	struct ebox_stream *es;
	uint8_t *key;
	size_t keylen;
	errf_t *err;
	const struct sshcipher *cipher;

	es = calloc(1, sizeof (struct ebox_stream));
	VERIFY(es != NULL);
	es->es_chunklen = EBOX_STREAM_DEFAULT_CHUNK;

	es->es_cipher = strdup("aes256-ctr");
	es->es_mac = strdup("sha256");
	cipher = cipher_by_name(es->es_cipher);
	VERIFY(cipher != NULL);
	keylen = cipher_keylen(cipher);

	key = malloc_conceal(keylen);
	VERIFY(key != NULL);
	arc4random_buf(key, keylen);

	err = ebox_create(tpl, key, keylen, NULL, 0, &es->es_ebox);

	es->es_ebox->e_key = key;
	es->es_ebox->e_keylen = keylen;

	if (err) {
		ebox_stream_free(es);
		return (errf("EboxCreateFailed", err, "failed to create ebox "
		    "for ebox_stream"));
	}

	es->es_ebox->e_type = EBOX_STREAM;

	*str = es;
	return (ERRF_OK);
}

errf_t *
sshbuf_put_ebox_stream(struct sshbuf *buf, struct ebox_stream *es)
{
	int rc;
	errf_t *err;

	err = sshbuf_put_ebox(buf, es->es_ebox);
	if (err)
		return (err);

	if ((rc = sshbuf_put_u64(buf, es->es_chunklen)))
		return (ssherrf("sshbuf_put_u64", rc));
	if ((rc = sshbuf_put_cstring8(buf, es->es_cipher)) ||
	    (rc = sshbuf_put_cstring8(buf, es->es_mac)))
		return (ssherrf("sshbuf_put_cstring8", rc));

	return (ERRF_OK);
}

errf_t *
sshbuf_put_ebox_stream_chunk(struct sshbuf *buf,
    struct ebox_stream_chunk *esc)
{
	int rc;

	if (esc->esc_enc == NULL) {
		return (argerrf("chunk", "an encrypted chunk",
		    "a chunk that hasn't had ebox_stream_encrypt_chunk() "
		    "called yet"));
	}

	if ((rc = sshbuf_put_u32(buf, esc->esc_seqnr)))
		return (ssherrf("sshbuf_put_u32", rc));
	if ((rc = sshbuf_put_string(buf, esc->esc_enc, esc->esc_enclen)))
		return (ssherrf("sshbuf_put_string", rc));

	return (ERRF_OK);
}

errf_t *
sshbuf_get_ebox_stream_chunk(struct sshbuf *buf, const struct ebox_stream *es,
    struct ebox_stream_chunk **chunk)
{
	struct ebox_stream_chunk *esc = NULL;
	int rc;
	errf_t *err;

	esc = calloc(1, sizeof (struct ebox_stream_chunk));
	if (esc == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	esc->esc_stream = (struct ebox_stream *)es;

	if ((rc = sshbuf_get_u32(buf, &esc->esc_seqnr))) {
		err = eboxderrf(ssherrf("sshbuf_get_u32", rc));
		goto out;
	}

	if ((rc = sshbuf_get_string(buf, &esc->esc_enc, &esc->esc_enclen))) {
		err = eboxderrf(ssherrf("sshbuf_get_string", rc));
		goto out;
	}

	*chunk = esc;
	esc = NULL;
	err = NULL;

out:
	ebox_stream_chunk_free(esc);
	return (err);
}

void
ebox_stream_chunk_free(struct ebox_stream_chunk *chunk)
{
	if (chunk == NULL)
		return;
	free(chunk->esc_enc);
	if (chunk->esc_plainlen > 0)
		explicit_bzero(chunk->esc_plain, chunk->esc_plainlen);
	free(chunk->esc_plain);
	free(chunk);
}

errf_t *
sshbuf_get_ebox_stream(struct sshbuf *buf, struct ebox_stream **pes)
{
	struct ebox_stream *es = NULL;
	struct ebox *e = NULL;
	int rc;
	errf_t *err;
	const struct sshcipher *cipher;
	int dgalg;
	uint64_t chunklen;

	err = sshbuf_get_ebox(buf, &e);
	if (err)
		return (err);

	if (e->e_type != EBOX_STREAM) {
		err = eboxverrf(errf("EboxTypeError", NULL,
		    "buffer contains an ebox, but not an ebox stream"));
		goto out;
	}

	es = calloc(1, sizeof (struct ebox_stream));
	if (es == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	es->es_ebox = e;
	e = NULL;

	if ((rc = sshbuf_get_u64(buf, &chunklen))) {
		err = eboxderrf(ssherrf("sshbuf_get_u64", rc));
		goto out;
	}
	if (chunklen > SIZE_MAX) {
		err = eboxderrf(errf("OverflowError", NULL,
		    "stream chunk size (%" PRIu64 ") too large", chunklen));
		goto out;
	}
	es->es_chunklen = chunklen;

	if ((rc = sshbuf_get_cstring8(buf, &es->es_cipher, NULL)) ||
	    (rc = sshbuf_get_cstring8(buf, &es->es_mac, NULL))) {
		err = eboxderrf(ssherrf("sshbuf_get_cstring8", rc));
		goto out;
	}

	cipher = cipher_by_name(es->es_cipher);
	if (cipher == NULL) {
		err = eboxverrf(errf("BadAlgorithmError", NULL,
		    "unsupported cipher '%s'", es->es_cipher));
		goto out;
	}
	dgalg = ssh_digest_alg_by_name(es->es_mac);
	if (dgalg == -1) {
		err = eboxverrf(errf("BadAlgorithmError", NULL,
		    "unsupported MAC algorithm '%s'", es->es_mac));
		goto out;
	}

	*pes = es;
	es = NULL;
	err = NULL;

out:
	ebox_stream_free(es);
	ebox_free(e);
	return (err);
}

errf_t *
ebox_stream_encrypt_chunk(struct ebox_stream_chunk *esc)
{
	struct ebox_stream *es;
	const struct sshcipher *cipher;
	int dgalg = -1;
	size_t blocksz, ivlen, authlen, keylen, plainlen, enclen, maclen;
	size_t padding, i;
	uint8_t *key, *plain, *enc, *iv;
	struct sshcipher_ctx *cctx = NULL;
	struct ssh_hmac_ctx *hctx = NULL;

	es = esc->esc_stream;
	plainlen = esc->esc_plainlen;

	cipher = cipher_by_name(es->es_cipher);
	VERIFY(cipher != NULL);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);

	if (ivlen > 0) {
		iv = calloc(1, ivlen);
		VERIFY3U(ivlen, >=, sizeof (uint32_t));
		*(uint32_t *)iv = htobe32(esc->esc_seqnr);
	} else {
		iv = NULL;
	}

	if (authlen == 0) {
		dgalg = ssh_digest_alg_by_name(es->es_mac);
		VERIFY(dgalg != -1);
		maclen = ssh_digest_bytes(dgalg);
	} else {
		maclen = 0;
	}

	VERIFY3U(es->es_ebox->e_keylen, >=, keylen);
	key = es->es_ebox->e_key;
	VERIFY(key != NULL);

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
	plain = malloc(plainlen);
	VERIFY3P(plain, !=, NULL);
	bcopy(esc->esc_plain, plain, esc->esc_plainlen);
	for (i = esc->esc_plainlen; i < plainlen; ++i)
		plain[i] = padding;

	enclen = plainlen + authlen + maclen;
	esc->esc_enc = (enc = malloc(enclen));
	VERIFY(enc != NULL);
	esc->esc_enclen = enclen;

	VERIFY0(cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 1));
	VERIFY0(cipher_crypt(cctx, esc->esc_seqnr, enc, plain, plainlen, 0,
	    authlen));
	cipher_free(cctx);

	freezero(plain, plainlen);
	freezero(iv, ivlen);

	if (dgalg != -1) {
		hctx = ssh_hmac_start(dgalg);
		VERIFY(hctx != NULL);
		VERIFY0(ssh_hmac_init(hctx, key, keylen));
		VERIFY0(ssh_hmac_update(hctx, enc, enclen - maclen));
		VERIFY0(ssh_hmac_final(hctx, &enc[enclen - maclen], maclen));
		ssh_hmac_free(hctx);
	}

	return (ERRF_OK);
}

errf_t *
ebox_stream_decrypt_chunk(struct ebox_stream_chunk *esc)
{
	struct ebox_stream *es;
	const struct sshcipher *cipher;
	int dgalg = -1;
	size_t blocksz, ivlen, authlen, keylen, plainlen, enclen, maclen;
	size_t padding, i, reallen;
	uint8_t *key, *plain, *enc, *mac, *iv;
	struct sshcipher_ctx *cctx = NULL;
	struct ssh_hmac_ctx *hctx = NULL;
	int rc;
	errf_t *err;

	es = esc->esc_stream;

	cipher = cipher_by_name(es->es_cipher);
	VERIFY(cipher != NULL);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);

	if (ivlen > 0) {
		iv = calloc(1, ivlen);
		VERIFY3U(ivlen, >=, sizeof (uint32_t));
		*(uint32_t *)iv = htobe32(esc->esc_seqnr);
	} else {
		iv = NULL;
	}

	if (authlen == 0) {
		dgalg = ssh_digest_alg_by_name(es->es_mac);
		VERIFY(dgalg != -1);
		maclen = ssh_digest_bytes(dgalg);
	} else {
		maclen = 0;
	}

	VERIFY3U(es->es_ebox->e_keylen, >=, keylen);
	key = es->es_ebox->e_key;
	VERIFY(key != NULL);

	enc = esc->esc_enc;
	enclen = esc->esc_enclen;
	if (enclen < authlen + blocksz) {
		err = errf("LengthError", NULL, "Ciphertext length (%d) "
		    "is smaller than minimum length (auth tag + 1 block = %d)",
		    enclen, authlen + blocksz);
		free(iv);
		return (err);
	}

	if (dgalg != -1) {
		mac = malloc(maclen);
		VERIFY(mac != NULL);
		hctx = ssh_hmac_start(dgalg);
		VERIFY(hctx != NULL);
		VERIFY0(ssh_hmac_init(hctx, key, keylen));
		VERIFY0(ssh_hmac_update(hctx, enc, enclen - maclen));
		VERIFY0(ssh_hmac_final(hctx, mac, maclen));
		ssh_hmac_free(hctx);
		if (timingsafe_bcmp(mac, &enc[enclen - maclen], maclen) != 0) {
			explicit_bzero(mac, maclen);
			free(mac);
			free(iv);
			return (errf("MACError", NULL, "Ciphertext MAC failed "
			    "validation"));
		}
		explicit_bzero(mac, maclen);
		free(mac);
	}

	plainlen = enclen - authlen - maclen;
	plain = malloc(plainlen);
	VERIFY(plain != NULL);

	VERIFY0(cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 0));
	rc = cipher_crypt(cctx, esc->esc_seqnr, plain, enc,
	    enclen - authlen - maclen, 0, authlen);
	cipher_free(cctx);

	free(iv);
	iv = NULL;

	if (rc != 0) {
		err = ssherrf("cipher_crypt", rc);
		explicit_bzero(plain, plainlen);
		free(plain);
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

	esc->esc_plain = plain;
	esc->esc_plainlen = reallen;

	return (ERRF_OK);

paderr:
	err = errf("PaddingError", NULL, "Padding failed validation");
	explicit_bzero(plain, plainlen);
	free(plain);
	return (err);
}

const uint8_t *
ebox_stream_chunk_data(const struct ebox_stream_chunk *esc, size_t *size)
{
	*size = esc->esc_plainlen;
	return (esc->esc_plain);
}

struct sshbuf *
ebox_stream_chunk_data_buf(const struct ebox_stream_chunk *esc)
{
	struct sshbuf *b;
	b = sshbuf_from(esc->esc_plain, esc->esc_plainlen);
	return (b);
}

errf_t *
ebox_stream_chunk_new(const struct ebox_stream *es, const void *data,
    size_t len, size_t seqnr, struct ebox_stream_chunk **chunk)
{
	struct ebox_stream_chunk *esc;

	esc = calloc(1, sizeof (struct ebox_stream_chunk));
	if (esc == NULL)
		return (ERRF_NOMEM);
	esc->esc_stream = (struct ebox_stream *)es;
	esc->esc_seqnr = seqnr;
	esc->esc_plainlen = len;
	esc->esc_plain = malloc(len);
	if (esc->esc_plain == NULL) {
		free(esc);
		return (ERRF_NOMEM);
	}

	bcopy(data, esc->esc_plain, len);

	*chunk = esc;
	return (ERRF_OK);
}

void
ebox_stream_free(struct ebox_stream *str)
{
	if (str == NULL)
		return;
	free(str->es_cipher);
	free(str->es_mac);
	ebox_free(str->es_ebox);
	free(str);
}

struct ebox *
ebox_stream_ebox(const struct ebox_stream *es)
{
	return (es->es_ebox);
}

const char *
ebox_stream_cipher(const struct ebox_stream *es)
{
	return (es->es_cipher);
}

const char *
ebox_stream_mac(const struct ebox_stream *es)
{
	return (es->es_mac);
}

size_t
ebox_stream_chunk_size(const struct ebox_stream *es)
{
	return (es->es_chunklen);
}

static errf_t *
sshbuf_get_ebox_part(struct sshbuf *buf, const struct ebox *ebox,
    struct ebox_part **ppart)
{
	struct ebox_part *part;
	struct ebox_tpl_part *tpart;
	struct sshbuf *kbuf;
	int rc = 0;
	size_t len;
	uint8_t tag, *guid;
	errf_t *err = NULL;
	char *tname = NULL;
	struct sshkey *k = NULL, *ephk;
	struct piv_ecdh_box *box = NULL;
	boolean_t gotguid = B_FALSE;
	uint8_t slot = PIV_SLOT_KEY_MGMT;
	EC_KEY *eck = NULL;
	EVP_PKEY *pkey = NULL;

	part = calloc(1, sizeof (struct ebox_part));
	VERIFY(part != NULL);

	part->ep_tpl = calloc(1, sizeof (struct ebox_tpl_part));
	VERIFY(part->ep_tpl != NULL);
	tpart = part->ep_tpl;

	kbuf = sshbuf_new();
	VERIFY(kbuf != NULL);

	if ((rc = sshbuf_get_u8(buf, &tag))) {
		err = ssherrf("sshbuf_get_u8", rc);
		goto out;
	}
	while (tag != EBOX_PART_END) {
		switch (tag & ~EBOX_PART_OPTIONAL_FLAG) {
		case EBOX_PART_PUBKEY:
			free(tname);
			tname = NULL;
			if ((rc = sshbuf_get_cstring8(buf, &tname, NULL))) {
				err = ssherrf("sshbuf_get_cstring8", rc);
				goto out;
			}

			err = sshbuf_get_eckey8_sshkey(buf,
			    sshkey_curve_name_to_nid(tname),
			    &tpart->etp_pubkey);
			if (err != ERRF_OK) {
				err = errf("ParseError", err, "failed to parse "
				    "ebox part pubkey");
				goto out;
			}
			break;
		case EBOX_PART_CAK:
			sshbuf_reset(kbuf);
			rc = sshbuf_get_stringb(buf, kbuf);
			if (rc) {
				err = ssherrf("sshbuf_get_stringb", rc);
				goto out;
			}
			rc = sshkey_fromb(kbuf, &tpart->etp_cak);
			if (rc) {
				err = ssherrf("sshkey_fromb", rc);
				goto out;
			}
			break;
		case EBOX_PART_NAME:
			rc = sshbuf_get_cstring8(buf, &tpart->etp_name, &len);
			if (rc) {
				err = ssherrf("sshbuf_get_cstring8", rc);
				goto out;
			}
			break;
		case EBOX_PART_SLOT:
			rc = sshbuf_get_u8(buf, &slot);
			if (rc) {
				err = ssherrf("sshbuf_get_u8", rc);
				goto out;
			}
			break;
		case EBOX_PART_GUID:
			rc = sshbuf_get_string8(buf, &guid, &len);
			if (rc) {
				err = ssherrf("sshbuf_get_string8", rc);
				goto out;
			}
			if (len != sizeof (tpart->etp_guid)) {
				err = errf("LengthError", NULL,
				    "guid is too short (%u bytes)", len);
				goto out;
			}
			bcopy(guid, tpart->etp_guid, len);
			free(guid);
			guid = NULL;
			gotguid = B_TRUE;
			break;
		case EBOX_PART_BOX:
			if (ebox->e_version < EBOX_V2) {
				err = sshbuf_get_piv_box(buf, &part->ep_box);
				if (err)
					goto out;
				break;
			}
			box = piv_box_new();
			if (box == NULL) {
				err = ERRF_NOMEM;
				goto out;
			}
			box->pdb_guidslot_valid = B_TRUE;
			box->pdb_slot = PIV_SLOT_KEY_MGMT;
			box->pdb_free_str = B_TRUE;
			rc = sshbuf_get_cstring8(buf, (char **)&box->pdb_cipher,
			    NULL);
			if (rc) {
				err = ssherrf("sshbuf_get_cstring8", rc);
				goto out;
			}
			rc = sshbuf_get_cstring8(buf, (char **)&box->pdb_kdf,
			    NULL);
			if (rc) {
				err = ssherrf("sshbuf_get_cstring8", rc);
				goto out;
			}
			rc = sshbuf_get_string8(buf, &box->pdb_nonce.b_data,
			    &box->pdb_nonce.b_size);
			if (rc) {
				err = ssherrf("sshbuf_get_string8", rc);
				goto out;
			}
			box->pdb_nonce.b_len = box->pdb_nonce.b_size;
			free(tname);
			tname = NULL;
			if ((rc = sshbuf_get_cstring8(buf, &tname, NULL))) {
				err = ssherrf("sshbuf_get_cstring8", rc);
				goto out;
			}

			err = sshbuf_get_eckey8_sshkey(buf,
			    sshkey_curve_name_to_nid(tname),
			    &box->pdb_pub);
			if (err != ERRF_OK) {
				err = errf("ParseError", err, "failed to parse "
				    "ebox box pubkey");
				goto out;
			}

			ephk = ebox_get_ephem_for_nid(ebox,
			    box->pdb_pub->ecdsa_nid);
			if (ephk == NULL) {
				err = errf("CurveError", NULL, "No ephemeral "
				    "key found for EC curve '%s'", tname);
				goto out;
			}
			VERIFY0(sshkey_demote(ephk, &box->pdb_ephem_pub));

			if ((rc = sshbuf_get_string8(buf, &box->pdb_iv.b_data,
			    &box->pdb_iv.b_size))) {
				err = ssherrf("sshbuf_put_string8", rc);
				goto out;
			}
			box->pdb_iv.b_len = box->pdb_iv.b_size;

			if ((rc = sshbuf_get_string(buf, &box->pdb_enc.b_data,
			    &box->pdb_enc.b_size))) {
				err = ssherrf("sshbuf_put_string", rc);
				goto out;
			}
			box->pdb_enc.b_len = box->pdb_enc.b_size;

			part->ep_box = box;
			box = NULL;
			break;
		default:
			if ((tag & EBOX_PART_OPTIONAL_FLAG) != 0) {
				rc = sshbuf_skip_string8(buf);
				if (rc) {
					err = ssherrf("sshbuf_skip_string8",
					    rc);
					goto out;
				}
				break;
			}
			err = errf("TagError", NULL,
			    "invalid ebox part tag 0x%02x at +%zx",
			    tag, sshbuf_offset(buf));
			goto out;
		}
		if ((rc = sshbuf_get_u8(buf, &tag))) {
			err = ssherrf("sshbuf_get_u8", rc);
			goto out;
		}
	}

	if (part->ep_box == NULL) {
		err = errf("MissingTagError", NULL,
		    "ebox part did not contain 'box' tag");
		goto out;
	}

	if (!gotguid) {
		err = errf("MissingTagError", NULL,
		    "ebox part did not contain 'guid' tag");
		goto out;
	}

	part->ep_box->pdb_slot = slot;
	tpart->etp_slot = slot;
	bcopy(tpart->etp_guid, part->ep_box->pdb_guid,
	    sizeof (part->ep_box->pdb_guid));

	if (tpart->etp_pubkey == NULL) {
		rc = sshkey_demote(part->ep_box->pdb_pub, &tpart->etp_pubkey);
		if (rc) {
			err = ssherrf("sshkey_demote", rc);
			goto out;
		}
	}

	if (!sshkey_equal_public(tpart->etp_pubkey, part->ep_box->pdb_pub)) {
		err = errf("KeyMismatchError", NULL,
		    "part pubkey and box pubkey do not match");
		goto out;
	}

	*ppart = part;
	part = NULL;
out:
	EVP_PKEY_free(pkey);
	EC_KEY_free(eck);
	sshbuf_free(kbuf);
	ebox_part_free(part);
	piv_box_free(box);
	sshkey_free(k);
	free(tname);
	return (err);
}

static errf_t *
sshbuf_get_ebox_config(struct sshbuf *buf, const struct ebox *ebox,
    struct ebox_config **pconfig)
{
	struct ebox_config *config;
	struct ebox_tpl_config *tconfig;
	struct ebox_part *part;
	struct ebox_tpl_part *tpart;
	int rc = 0;
	uint8_t type;
	uint i, id;
	errf_t *err = NULL;

	config = calloc(1, sizeof (struct ebox_config));
	VERIFY(config != NULL);

	config->ec_tpl = calloc(1, sizeof (struct ebox_tpl_config));
	VERIFY(config->ec_tpl != NULL);
	tconfig = config->ec_tpl;

	if ((rc = sshbuf_get_u8(buf, &type)) ||
	    (rc = sshbuf_get_u8(buf, &tconfig->etc_n)) ||
	    (rc = sshbuf_get_u8(buf, &tconfig->etc_m))) {
		err = ssherrf("sshbuf_get_u8", rc);
		goto out;
	}
	tconfig->etc_type = (enum ebox_config_type)type;
	if (tconfig->etc_type != EBOX_PRIMARY &&
	    tconfig->etc_type != EBOX_RECOVERY) {
		err = errf("UnknownConfigType", NULL,
		    "ebox config has unknown type: 0x%02x", tconfig->etc_type);
		goto out;
	}
	if (ebox->e_version >= EBOX_V3) {
		rc = sshbuf_get_string8(buf, &config->ec_nonce,
		    &config->ec_noncelen);
		if (rc) {
			err = ssherrf("sshbuf_get_string8", rc);
			goto out;
		}
		if (config->ec_noncelen > 0 &&
		    tconfig->etc_type != EBOX_RECOVERY) {
			err = errf("InvalidConfig", NULL,
			    "ebox config is PRIMARY but has config nonce");
			goto out;
		}
	}
	if (tconfig->etc_type == EBOX_PRIMARY &&
	    tconfig->etc_n > 1) {
		err = errf("InvalidConfig", NULL,
		    "ebox config is PRIMARY but has n > 1 (n = %d)",
		    tconfig->etc_n);
		goto out;
	}
	id = 1;

	if ((err = sshbuf_get_ebox_part(buf, ebox, &part)))
		goto out;
	part->ep_id = id++;
	config->ec_parts = part;
	tpart = part->ep_tpl;
	config->ec_tpl->etc_parts = tpart;

	for (i = 1; i < tconfig->etc_m; ++i) {
		if ((err = sshbuf_get_ebox_part(buf, ebox, &part->ep_next)))
			goto out;
		part = part->ep_next;
		part->ep_id = id++;
		tpart->etp_next = part->ep_tpl;
		part->ep_tpl->etp_prev = tpart;
		tpart = part->ep_tpl;
	}

	*pconfig = config;
	config = NULL;

out:
	ebox_config_free(config);
	return (err);
}

static errf_t *
sshbuf_get_ebox_ephem_key(struct sshbuf *buf, struct ebox_ephem_key **peek)
{
	struct ebox_ephem_key *eek = NULL;
	char *tname = NULL;
	errf_t *err = NULL;
	int rc;

	eek = calloc(1, sizeof (struct ebox_ephem_key));
	if (eek == NULL)
		return (ERRF_NOMEM);

	if ((rc = sshbuf_get_cstring8(buf, &tname, NULL))) {
		err = ssherrf("sshbuf_get_cstring8", rc);
		goto out;
	}
	eek->eek_nid = sshkey_curve_name_to_nid(tname);

	err = sshbuf_get_eckey8_sshkey(buf, eek->eek_nid, &eek->eek_ephem);
	if (err != ERRF_OK) {
		err = errf("ParseError", err, "failed to parse "
		    "ebox ephemeral key");
		goto out;
	}

	*peek = eek;
	eek = NULL;
	err = ERRF_OK;

out:
	free(eek);
	free(tname);
	return (err);
}

errf_t *
sshbuf_get_ebox(struct sshbuf *buf, struct ebox **pbox)
{
	struct ebox *box;
	struct ebox_config *config;
	struct ebox_tpl_config *tconfig;
	int rc = 0;
	uint8_t ver, magic[2], type, nconfigs;
	uint i;
	errf_t *err = NULL;

	box = calloc(1, sizeof (struct ebox));
	VERIFY(box != NULL);

	box->e_tpl = calloc(1, sizeof (struct ebox_tpl));
	VERIFY(box->e_tpl != NULL);

	box->e_tpl->et_version = EBOX_TPL_VNEXT - 1;

	if ((rc = sshbuf_get_u8(buf, &magic[0])) ||
	    (rc = sshbuf_get_u8(buf, &magic[1]))) {
		err = eboxderrf(errf("MagicError",
		    ssherrf("sshbuf_get_u8", rc), "failed reading ebox magic"));
		goto out;
	}
	if (magic[0] != 0xEB && magic[1] != 0x0C) {
		err = eboxderrf(errf("MagicError", NULL,
		    "bad ebox magic number"));
		goto out;
	}
	if ((rc = sshbuf_get_u8(buf, &ver)) ||
	    (rc = sshbuf_get_u8(buf, &type))) {
		err = eboxderrf(ssherrf("sshbuf_get_u8", rc));
		goto out;
	}
	if (ver < EBOX_VMIN || ver >= EBOX_VNEXT) {
		err = eboxverrf(errf("VersionError", NULL,
		    "unsupported version number 0x%02x", ver));
		goto out;
	}
	if (type != EBOX_KEY && type != EBOX_STREAM) {
		err = eboxderrf(errf("EboxTypeError", NULL,
		    "buffer does not contain an ebox"));
		goto out;
	}
	box->e_version = ver;
	box->e_type = (enum ebox_type)type;

	if ((rc = sshbuf_get_cstring8(buf, &box->e_rcv_cipher, NULL))) {
		err = eboxderrf(ssherrf("sshbuf_get_u8", rc));
		goto out;
	}
	rc = sshbuf_get_string8(buf, &box->e_rcv_iv.b_data,
	    &box->e_rcv_iv.b_len);
	if (rc) {
		err = eboxderrf(ssherrf("sshbuf_get_string8", rc));
		goto out;
	}

	rc = sshbuf_get_string8(buf, &box->e_rcv_enc.b_data,
	    &box->e_rcv_enc.b_len);
	if (rc) {
		err = eboxderrf(ssherrf("sshbuf_get_string8", rc));
		goto out;
	}

	if (box->e_version >= EBOX_V2) {
		struct ebox_ephem_key *eek = NULL;
		uint8_t neeks;

		if ((rc = sshbuf_get_u8(buf, &neeks))) {
			err = eboxderrf(ssherrf("sshbuf_get_u8", rc));
			goto out;
		}

		for (i = 0; i < neeks; ++i) {
			if ((err = sshbuf_get_ebox_ephem_key(buf, &eek))) {
				err = eboxderrf(err);
				goto out;
			}
			eek->eek_next = box->e_ephemkeys;
			box->e_ephemkeys = eek;
		}
	}

	if ((rc = sshbuf_get_u8(buf, &nconfigs))) {
		err = eboxderrf(ssherrf("sshbuf_get_u8", rc));
		goto out;
	}

	if ((err = sshbuf_get_ebox_config(buf, box, &config))) {
		err = eboxderrf(err);
		goto out;
	}
	box->e_configs = config;
	tconfig = config->ec_tpl;
	box->e_tpl->et_configs = tconfig;

	for (i = 1; i < nconfigs; ++i) {
		if ((err = sshbuf_get_ebox_config(buf, box,
		    &config->ec_next))) {
			err = eboxderrf(err);
			goto out;
		}
		config = config->ec_next;
		tconfig->etc_next = config->ec_tpl;
		config->ec_tpl->etc_prev = tconfig;
		tconfig = config->ec_tpl;
	}

	*pbox = box;
	box = NULL;

out:
	ebox_free(box);
	return (err);
}

static errf_t *
sshbuf_put_ebox_part(struct sshbuf *buf, struct ebox *ebox,
    struct ebox_part *part)
{
	struct ebox_tpl_part *tpart;
	struct sshbuf *kbuf;
	int rc = 0;
	errf_t *err;
	EC_KEY *eck;

	tpart = part->ep_tpl;

	kbuf = sshbuf_new();
	VERIFY(kbuf != NULL);

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_GUID)) ||
	    (rc = sshbuf_put_string8(buf, tpart->etp_guid,
	    sizeof (tpart->etp_guid)))) {
		err = ssherrf("sshbuf_put_*", rc);
		goto out;
	}

	if (tpart->etp_name != NULL) {
		if ((rc = sshbuf_put_u8(buf, EBOX_PART_NAME)) ||
		    (rc = sshbuf_put_cstring8(buf, tpart->etp_name))) {
			err = ssherrf("sshbuf_put_*", rc);
			goto out;
		}
	}

	if (tpart->etp_cak != NULL) {
		sshbuf_reset(kbuf);
		if ((rc = sshbuf_put_u8(buf, EBOX_PART_CAK)) ||
		    (rc = sshkey_putb(tpart->etp_cak, kbuf)) ||
		    (rc = sshbuf_put_stringb(buf, kbuf))) {
			err = ssherrf("sshbuf_put_*", rc);
			goto out;
		}
	}

	if (tpart->etp_slot != PIV_SLOT_KEY_MGMT) {
		if ((rc = sshbuf_put_u8(buf, EBOX_PART_SLOT)) ||
		    (rc = sshbuf_put_u8(buf, tpart->etp_slot))) {
			err = ssherrf("sshbuf_put_u8", rc);
			goto out;
		}
	}

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_BOX))) {
		err = ssherrf("sshbuf_put_u8", rc);
		goto out;
	}
	if (ebox->e_version >= EBOX_V2) {
		struct piv_ecdh_box *box = part->ep_box;
		const char *tname;
		struct sshkey *ephk;

		if ((rc = sshbuf_put_cstring8(buf, box->pdb_cipher)) ||
		    (rc = sshbuf_put_cstring8(buf, box->pdb_kdf))) {
			err = ssherrf("sshbuf_put_cstring8", rc);
			goto out;
		}
		if ((rc = sshbuf_put_string8(buf, box->pdb_nonce.b_data,
		    box->pdb_nonce.b_len))) {
			err = ssherrf("sshbuf_put_string8", rc);
			goto out;
		}

		ephk = ebox_get_ephem_for_nid(ebox, box->pdb_pub->ecdsa_nid);
		VERIFY(sshkey_equal_public(ephk, box->pdb_ephem_pub));
		VERIFY3U(box->pdb_version, >=, PIV_BOX_V2);
		tname = sshkey_curve_nid_to_name(box->pdb_pub->ecdsa_nid);
		VERIFY(tname != NULL);
		if ((rc = sshbuf_put_cstring8(buf, tname))) {
			err = ssherrf("sshbuf_put_cstring8", rc);
			goto out;
		}
		eck = EVP_PKEY_get1_EC_KEY(box->pdb_pub->pkey);
		if ((rc = sshbuf_put_eckey8(buf, eck))) {
			err = ssherrf("sshbuf_put_eckey8", rc);
			goto out;
		}
		if ((rc = sshbuf_put_string8(buf, box->pdb_iv.b_data,
		    box->pdb_iv.b_len))) {
			err = ssherrf("sshbuf_put_string8", rc);
			goto out;
		}

		if ((rc = sshbuf_put_string(buf, box->pdb_enc.b_data,
		    box->pdb_enc.b_len))) {
			err = ssherrf("sshbuf_put_string", rc);
			goto out;
		}
	} else {
		if ((err = sshbuf_put_piv_box(buf, part->ep_box)))
			goto out;
	}

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_END))) {
		err = ssherrf("sshbuf_put_u8", rc);
		goto out;
	}

	err = NULL;

out:
	sshbuf_free(kbuf);
	return (err);
}

static errf_t *
sshbuf_put_ebox_config(struct sshbuf *buf, struct ebox *ebox,
    struct ebox_config *config)
{
	struct ebox_tpl_config *tconfig;
	struct ebox_part *part;
	int rc;
	errf_t *err;

	tconfig = config->ec_tpl;

	if ((rc = sshbuf_put_u8(buf, tconfig->etc_type)) ||
	    (rc = sshbuf_put_u8(buf, tconfig->etc_n)) ||
	    (rc = sshbuf_put_u8(buf, tconfig->etc_m))) {
		return (ssherrf("sshbuf_put_u8", rc));
	}

	if (config->ec_noncelen > 0 && config->ec_nonce != NULL) {
		VERIFY3S(ebox->e_version, >=, EBOX_V3);
		VERIFY3S(tconfig->etc_type, ==, EBOX_RECOVERY);
		rc = sshbuf_put_string8(buf, config->ec_nonce,
		    config->ec_noncelen);
		if (rc)
			return (ssherrf("sshbuf_put_string8", rc));
	} else {
		rc = sshbuf_put_u8(buf, 0);
		if (rc)
			return (ssherrf("sshbuf_put_u8", rc));
	}

	part = config->ec_parts;
	for (; part != NULL; part = part->ep_next) {
		if ((err = sshbuf_put_ebox_part(buf, ebox, part)))
			return (err);
	}

	return (NULL);
}

static errf_t *
sshbuf_put_ebox_ephem_key(struct sshbuf *buf, struct ebox_ephem_key *eek)
{
	struct sshkey *k = eek->eek_ephem;
	EC_KEY *eck = EVP_PKEY_get1_EC_KEY(k->pkey);
	const char *tname;
	int rc;

	tname = sshkey_curve_nid_to_name(eek->eek_nid);

	if ((rc = sshbuf_put_cstring8(buf, tname)) ||
	    (rc = sshbuf_put_eckey8(buf, eck))) {
		return (ssherrf("sshbuf_put_*", rc));
	}

	return (ERRF_OK);
}

errf_t *
sshbuf_put_ebox(struct sshbuf *buf, struct ebox *ebox)
{
	uint8_t nconfigs = 0, neeks = 0;
	int rc = 0;
	struct ebox_config *config;
	struct ebox_ephem_key *eek;
	errf_t *err;

	config = ebox->e_configs;
	for (; config != NULL; config = config->ec_next) {
		++nconfigs;
	}
	for (eek = ebox->e_ephemkeys; eek != NULL; eek = eek->eek_next) {
		++neeks;
	}

	if ((rc = sshbuf_put_u8(buf, 0xEB)) ||
	    (rc = sshbuf_put_u8(buf, 0x0C)) ||
	    (rc = sshbuf_put_u8(buf, ebox->e_version)) ||
	    (rc = sshbuf_put_u8(buf, ebox->e_type))) {
		return (ssherrf("sshbuf_put_u8", rc));
	}

	if ((rc = sshbuf_put_cstring8(buf, ebox->e_rcv_cipher))) {
		return (ssherrf("sshbuf_put_cstring8", rc));
	}

	rc = sshbuf_put_string8(buf, ebox->e_rcv_iv.b_data,
	    ebox->e_rcv_iv.b_len);
	if (rc) {
		return (ssherrf("sshbuf_put_string8", rc));
	}
	rc = sshbuf_put_string8(buf, ebox->e_rcv_enc.b_data,
	    ebox->e_rcv_enc.b_len);
	if (rc) {
		return (ssherrf("sshbuf_put_string8", rc));
	}

	if (ebox->e_version >= EBOX_V2) {
		if ((rc = sshbuf_put_u8(buf, neeks))) {
			return (ssherrf("sshbuf_put_u8", rc));
		}

		eek = ebox->e_ephemkeys;
		for (; eek != NULL; eek = eek->eek_next) {
			if ((err = sshbuf_put_ebox_ephem_key(buf, eek)))
				return (err);
		}
	}

	if ((rc = sshbuf_put_u8(buf, nconfigs))) {
		return (ssherrf("sshbuf_put_u8", rc));
	}

	config = ebox->e_configs;
	for (; config != NULL; config = config->ec_next) {
		if ((err = sshbuf_put_ebox_config(buf, ebox, config)))
			return (err);
	}

	return (NULL);
}

struct ebox_config *
ebox_next_config(const struct ebox *box, const struct ebox_config *prev)
{
	if (prev == NULL)
		return (box->e_configs);
	return (prev->ec_next);
}

struct ebox_part *
ebox_config_next_part(const struct ebox_config *config,
    const struct ebox_part *prev)
{
	if (prev == NULL)
		return (config->ec_parts);
	return (prev->ep_next);
}

struct ebox_tpl_config *
ebox_config_tpl(const struct ebox_config *config)
{
	return (config->ec_tpl);
}

struct piv_ecdh_box *
ebox_part_box(const struct ebox_part *part)
{
	return (part->ep_box);
}

struct ebox_tpl_part *
ebox_part_tpl(const struct ebox_part *part)
{
	return (part->ep_tpl);
}

const struct ebox_challenge *
ebox_part_challenge(const struct ebox_part *part)
{
	return (part->ep_chal);
}

const uint8_t *
ebox_key(const struct ebox *box, size_t *len)
{
	*len = 0;
	if (box->e_key == NULL || box->e_keylen == 0)
		return (NULL);
	*len = box->e_keylen;
	return (box->e_key);
}

boolean_t
ebox_is_unlocked(const struct ebox *box)
{
	return (box->e_key != NULL && box->e_keylen > 0);
}

const uint8_t *
ebox_recovery_token(const struct ebox *box, size_t *len)
{
	*len = 0;
	if (box->e_token == NULL || box->e_tokenlen == 0)
		return (NULL);
	*len = box->e_tokenlen;
	return (box->e_token);
}

static errf_t *
ebox_decrypt_recovery(struct ebox *box)
{
	const struct sshcipher *cipher;
	struct sshcipher_ctx *cctx;
	size_t ivlen, authlen, blocksz, keylen;
	size_t plainlen, padding;
	size_t enclen, reallen;
	uint8_t *iv, *enc, *plain = NULL, *key;
	size_t i;
	int rc;
	errf_t *err;

	cipher = cipher_by_name(box->e_rcv_cipher);
	if (cipher == NULL) {
		err = errf("BadAlgorithmError", NULL,
		    "recovery box uses cipher '%s' which is not supported",
		    box->e_rcv_cipher);
		goto out;
	}
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	/* TODO: support non-authenticated ciphers by adding an HMAC? */
	VERIFY3U(authlen, >, 0);

	iv = box->e_rcv_iv.b_data;
	VERIFY(iv != NULL);
	if (box->e_rcv_iv.b_len < ivlen) {
		err = errf("LengthError", NULL, "IV length (%d) is not "
		    "appropriate for cipher '%s'", box->e_rcv_iv.b_len,
		    box->e_rcv_cipher);
		goto out;
	}

	key = box->e_rcv_key.b_data;
	VERIFY(key != NULL);
	if (box->e_rcv_key.b_len < keylen) {
		err = errf("LengthError", NULL, "Key length (%d) is too "
		    "short for cipher '%s'", box->e_rcv_key.b_len,
		    box->e_rcv_cipher);
		goto out;
	}

	enc = box->e_rcv_enc.b_data;
	VERIFY(enc != NULL);
	enclen = box->e_rcv_enc.b_len;
	if (enclen < blocksz + authlen) {
		err = errf("LengthError", NULL, "Ciphertext length is too "
		    "short for cipher '%s'", box->e_rcv_cipher);
		goto out;
	}

	plainlen = enclen - authlen;
	plain = malloc(plainlen);
	if (plain == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	if ((rc = cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 0))) {
		err = ssherrf("cipher_init", rc);
		goto out;
	}
	rc = cipher_crypt(cctx, 0, plain, enc, enclen - authlen, 0, authlen);
	cipher_free(cctx);
	if (rc) {
		err = ssherrf("cipher_crypt", rc);
		goto out;
	}

	/* Strip off the pkcs#7 padding and verify it. */
	padding = plain[plainlen - 1];
	if (padding > blocksz || padding == 0) {
		err = errf("InvalidPadding", NULL,
		    "recovery box padding was invalid");
		goto out;
	}
	reallen = plainlen - padding;
	for (i = reallen; i < plainlen; ++i) {
		if (plain[i] != padding) {
			err = errf("InvalidPadding", NULL,
			    "recovery box padding was inconsistent");
			goto out;
		}
	}

	explicit_bzero(&plain[reallen], padding);
	box->e_rcv_plain.b_data = plain;
	box->e_rcv_plain.b_len = reallen;

	err = ERRF_OK;
	plain = NULL;

out:
	if (plain != NULL)
		explicit_bzero(plain, plainlen);
	free(plain);
	return (err);
}

static void
ebox_encrypt_recovery(struct ebox *box)
{
	const struct sshcipher *cipher;
	struct sshcipher_ctx *cctx;
	size_t ivlen, authlen, blocksz, keylen;
	size_t plainlen, padding;
	size_t enclen;
	uint8_t *iv, *enc, *plain, *key;
	size_t i;

	cipher = cipher_by_name(box->e_rcv_cipher);
	VERIFY(cipher != NULL);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	/* TODO: support non-authenticated ciphers by adding an HMAC? */
	VERIFY3U(authlen, >, 0);

	plainlen = box->e_rcv_plain.b_len;
	padding = blocksz - (plainlen % blocksz);
	VERIFY3U(padding, <=, blocksz);
	VERIFY3U(padding, >, 0);
	plainlen += padding;
	plain = malloc_conceal(plainlen);
	bcopy(box->e_rcv_plain.b_data, plain, box->e_rcv_plain.b_len);
	for (i = box->e_rcv_plain.b_len; i < plainlen; ++i)
		plain[i] = padding;

	freezero(box->e_rcv_plain.b_data, box->e_rcv_plain.b_len);
	box->e_rcv_plain.b_data = NULL;
	box->e_rcv_plain.b_len = 0;

	box->e_rcv_iv.b_data = (iv = malloc(ivlen));
	box->e_rcv_iv.b_len = ivlen;
	VERIFY(iv != NULL);
	arc4random_buf(iv, ivlen);

	box->e_rcv_key.b_data = (key = malloc_conceal(keylen));
	VERIFY(key != NULL);
	box->e_rcv_key.b_len = keylen;
	arc4random_buf(key, keylen);

	VERIFY0(cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 1));
	enclen = plainlen + authlen;
	enc = malloc(enclen);
	VERIFY3P(enc, !=, NULL);
	VERIFY0(cipher_crypt(cctx, 0, enc, plain, plainlen, 0, authlen));
	cipher_free(cctx);

	freezero(plain, plainlen);

	box->e_rcv_enc.b_data = enc;
	box->e_rcv_enc.b_len = enclen;
}

errf_t *
ebox_create(const struct ebox_tpl *tpl, const uint8_t *key, size_t keylen,
    const uint8_t *token, size_t tokenlen, struct ebox **pebox)
{
	struct ebox *box;
	struct ebox_tpl_config *tconfig;
	struct ebox_config *pconfig, *nconfig;
	struct ebox_tpl_part *tpart;
	struct ebox_part *ppart, *npart;
	size_t plainlen;
	uint8_t *plain;
	uint8_t *configkey;
	struct sshbuf *buf;
	struct piv_ecdh_box *pbox;
	sss_Keyshare *share, *shares = NULL;
	size_t shareslen = 0;
	uint i;

	box = calloc(1, sizeof (struct ebox));
	VERIFY(box != NULL);

	box->e_version = EBOX_VNEXT - 1;
	box->e_type = EBOX_KEY;

	/* Need a cipher with a 32-byte key, AES256-GCM is the easiest. */
	box->e_rcv_cipher = strdup("aes256-gcm");

	/* Construct the recovery box data */
	buf = sshbuf_new();
	VERIFY(buf != NULL);
	if (token != NULL) {
		VERIFY0(sshbuf_put_u8(buf, EBOX_RECOV_TOKEN));
		VERIFY0(sshbuf_put_string8(buf, token, tokenlen));
	}
	VERIFY0(sshbuf_put_u8(buf, EBOX_RECOV_KEY));
	VERIFY0(sshbuf_put_string8(buf, key, keylen));
	plainlen = sshbuf_len(buf);
	box->e_rcv_plain.b_data = (plain = malloc_conceal(plainlen));
	VERIFY(plain != NULL);
	box->e_rcv_plain.b_len = plainlen;
	VERIFY0(sshbuf_get(buf, plain, plainlen));
	sshbuf_free(buf);

	/* Encrypt the recovery box */
	ebox_encrypt_recovery(box);

	pconfig = NULL;
	tconfig = tpl->et_configs;
	for (; tconfig != NULL; tconfig = tconfig->etc_next) {
		nconfig = calloc(1, sizeof (struct ebox_config));
		VERIFY(nconfig != NULL);
		nconfig->ec_tpl = calloc(1, sizeof (struct ebox_tpl_config));
		VERIFY(nconfig->ec_tpl != NULL);
		if (pconfig != NULL)
			pconfig->ec_next = nconfig;
		else
			box->e_configs = nconfig;
		nconfig->ec_tpl->etc_type = tconfig->etc_type;
		nconfig->ec_tpl->etc_n = tconfig->etc_n;
		nconfig->ec_tpl->etc_m = tconfig->etc_m;

		if (tconfig->etc_type == EBOX_RECOVERY) {
			/* sss_* only supports 32-byte keys */
			VERIFY3U(box->e_rcv_key.b_len, ==, 32);

			nconfig->ec_nonce = calloc(1, box->e_rcv_key.b_len);
			nconfig->ec_noncelen = box->e_rcv_key.b_len;
			VERIFY(nconfig->ec_nonce != NULL);
			arc4random_buf(nconfig->ec_nonce, nconfig->ec_noncelen);

			configkey = calloc_conceal(1, nconfig->ec_noncelen);
			for (i = 0; i < nconfig->ec_noncelen; ++i) {
				configkey[i] = nconfig->ec_nonce[i] ^
				    box->e_rcv_key.b_data[i];
			}

			shareslen = tconfig->etc_m * sizeof (sss_Keyshare);
			shares = calloc_conceal(1, shareslen);
			sss_create_keyshares(shares, configkey, tconfig->etc_m,
			    tconfig->etc_n);

			freezero(configkey, nconfig->ec_noncelen);
		}

		ppart = NULL;
		tpart = tconfig->etc_parts;
		i = 1;
		for (; tpart != NULL; tpart = tpart->etp_next) {
			npart = calloc(1, sizeof (struct ebox_part));
			VERIFY(npart != NULL);
			npart->ep_tpl = calloc(1,
			    sizeof (struct ebox_tpl_part));
			VERIFY(npart->ep_tpl != NULL);
			if (ppart != NULL)
				ppart->ep_next = npart;
			else
				nconfig->ec_parts = npart;

			npart->ep_id = i++;
			if (tpart->etp_name != NULL) {
				npart->ep_tpl->etp_name =
				    strdup(tpart->etp_name);
			}
			npart->ep_tpl->etp_slot = tpart->etp_slot;
			bcopy(tpart->etp_guid, npart->ep_tpl->etp_guid,
			    sizeof (npart->ep_tpl->etp_guid));
			if (tpart->etp_pubkey != NULL) {
				VERIFY0(sshkey_demote(tpart->etp_pubkey,
				    &npart->ep_tpl->etp_pubkey));
			}
			if (tpart->etp_cak != NULL) {
				VERIFY0(sshkey_demote(tpart->etp_cak,
				    &npart->ep_tpl->etp_cak));
			}

			npart->ep_box = (pbox = piv_box_new());
			VERIFY(pbox != NULL);
			bcopy(tpart->etp_guid, pbox->pdb_guid,
			    sizeof (pbox->pdb_guid));
			pbox->pdb_slot = tpart->etp_slot;
			pbox->pdb_guidslot_valid = B_TRUE;
			if (shares != NULL) {
				share = &shares[npart->ep_id - 1];
				VERIFY0(piv_box_set_data(pbox, (uint8_t *)share,
				    sizeof (sss_Keyshare)));
				explicit_bzero(share, sizeof (sss_Keyshare));
			} else {
				VERIFY0(piv_box_set_data(pbox, key, keylen));
			}
			pbox->pdb_ephem = ebox_make_ephem_for_nid(box,
			    tpart->etp_pubkey->ecdsa_nid);
			VERIFY0(piv_box_seal_offline(tpart->etp_pubkey, pbox));

			ppart = npart;
		}

		if (shares != NULL) {
			freezero(shares, shareslen);
			shares = NULL;
			shareslen = 0;
		}

		pconfig = nconfig;
	}

	*pebox = box;
	return (ERRF_OK);
}

errf_t *
ebox_unlock(struct ebox *ebox, struct ebox_config *config)
{
	struct ebox_part *part;

	for (part = config->ec_parts; part != NULL; part = part->ep_next) {
		struct piv_ecdh_box *box = part->ep_box;
		if (box->pdb_plain.b_data == NULL)
			continue;
		if (box->pdb_plain.b_len < 1)
			continue;
		return (piv_box_take_data(box, &ebox->e_key, &ebox->e_keylen));
	}

	return (errf("InsufficientParts", NULL, "ebox_unlock requires at "
	    "least one part box to be unlocked"));
}

size_t
ebox_config_nonce_len(const struct ebox_config *config)
{
	return (config->ec_noncelen);
}

errf_t *
ebox_recover(struct ebox *ebox, struct ebox_config *config)
{
	struct ebox_part *part;
	struct ebox_tpl_config *tconfig = config->ec_tpl;
	struct sshbuf *buf = NULL;
	uint n = tconfig->etc_n, m = tconfig->etc_m;
	uint i = 0, j;
	errf_t *err;
	int rc;
	uint8_t tag;
	uint8_t *configkey;
	size_t cklen;
	sss_Keyshare *share, *shares = NULL;

	if (ebox->e_key != NULL || ebox->e_keylen > 0) {
		return (errf("AlreadyUnlocked", NULL,
		    "ebox has already been unlocked"));
	}
	if (ebox->e_token != NULL || ebox->e_tokenlen > 0) {
		return (errf("AlreadyUnlocked", NULL,
		    "ebox has already been recovered"));
	}
	if (ebox->e_rcv_key.b_data != NULL || ebox->e_rcv_key.b_len > 0) {
		return (errf("AlreadyUnlocked", NULL,
		    "ebox has already been recovered"));
	}

	shares = calloc_conceal(m, sizeof (sss_Keyshare));

	for (part = config->ec_parts; part != NULL; part = part->ep_next) {
		if (part->ep_share != NULL && part->ep_sharelen >= 1) {
			VERIFY3U(part->ep_sharelen, ==, sizeof (sss_Keyshare));
			share = &shares[i++];
			bcopy(part->ep_share, share, sizeof (sss_Keyshare));
		} else if (!piv_box_sealed(part->ep_box)) {
			/*
			 * We can't use take_data_* because we don't want to
			 * consume the data buffer (we're not sure yet whether
			 * we actually have enough pieces here).
			 */
			VERIFY3U(part->ep_box->pdb_plain.b_len, ==,
			    sizeof (sss_Keyshare));
			share = &shares[i++];
			bcopy(part->ep_box->pdb_plain.b_data +
			    part->ep_box->pdb_plain.b_offset,
			    share, sizeof (sss_Keyshare));
		}
	}

	if (i < n) {
		err = errf("InsufficientParts", NULL,
		    "ebox needs %u parts available to recover (has %u)",
		    n, i);
		goto out;
	}

	/* sss_* only supports 32-byte keys */
	ebox->e_rcv_key.b_len = (cklen = 32);
	ebox->e_rcv_key.b_data = calloc_conceal(1, cklen);

	configkey = calloc_conceal(1, cklen);
	sss_combine_keyshares(configkey, (const sss_Keyshare *)shares, n);

	if (config->ec_noncelen > 0 && config->ec_nonce != NULL) {
		if (config->ec_noncelen < cklen) {
			free(ebox->e_rcv_key.b_data);
			freezero(configkey, cklen);
			freezero(shares, m * sizeof (sss_Keyshare));
			return (errf("RecoveryFailed", errf("BadConfigNonce",
			    NULL, "recovery config nonce has bad length: %zu "
			    "(need %zu bytes)", config->ec_noncelen, cklen),
			    "ebox recovery failed"));
		}
		VERIFY3U(config->ec_noncelen, ==, cklen);
		for (i = 0; i < cklen; ++i) {
			ebox->e_rcv_key.b_data[i] = configkey[i] ^
			    config->ec_nonce[i];
		}
	} else {
		bcopy(configkey, ebox->e_rcv_key.b_data, cklen);
	}
	free(configkey);

	err = ebox_decrypt_recovery(ebox);
	if (err) {
		err = errf("RecoveryFailed", err, "ebox recovery failed");
		goto out;
	}

	buf = sshbuf_from(ebox->e_rcv_plain.b_data, ebox->e_rcv_plain.b_len);
	VERIFY(buf != NULL);

	if ((rc = sshbuf_get_u8(buf, &tag))) {
		err = ssherrf("sshbuf_get_u8", rc);
		goto out;
	}
	if (tag == EBOX_RECOV_TOKEN) {
		rc = sshbuf_get_string8(buf, &ebox->e_token, &ebox->e_tokenlen);
		if (rc) {
			err = ssherrf("sshbuf_get_string8", rc);
			goto out;
		}
		if ((rc = sshbuf_get_u8(buf, &tag))) {
			err = ssherrf("sshbuf_get_u8", rc);
			goto out;
		}
	}
	if (tag != EBOX_RECOV_KEY) {
		err = errf("RecoveryFailed", errf("InvalidTagError", NULL,
		    "Invalid or unsupported recovery data tag: 0x%02x", tag),
		    "ebox recovery failed");
		goto out;
	}
	rc = sshbuf_get_string8_conceal(buf, &ebox->e_key, &ebox->e_keylen);
	if (rc) {
		err = ssherrf("sshbuf_get_string8", rc);
		goto out;
	}

	for (part = config->ec_parts; part != NULL; part = part->ep_next) {
		if (part->ep_share != NULL) {
			freezero(part->ep_share, part->ep_sharelen);
			part->ep_share = NULL;
			part->ep_sharelen = 0;
		}
		if (!piv_box_sealed(part->ep_box)) {
			freezero(part->ep_box->pdb_plain.b_data,
			    part->ep_box->pdb_plain.b_size);
			part->ep_box->pdb_plain.b_data = NULL;
			part->ep_box->pdb_plain.b_len = 0;
			part->ep_box->pdb_plain.b_size = 0;
		}
	}

	err = NULL;

out:
	sshbuf_free(buf);
	for (j = 0; j < m; ++j)
		explicit_bzero(&shares[j], sizeof (sss_Keyshare));
	free(shares);
	return (err);
}

errf_t *
ebox_gen_challenge(struct ebox_config *config, struct ebox_part *part,
    const char *descfmt, ...)
{
	struct ebox_challenge *chal;
	int rc = 0;
	size_t hnamelen;
	char *hostname = NULL;
	char desc[255] = {0};
	va_list ap;
	int wrote;
	errf_t *err = NULL;

#if defined(HOST_NAME_MAX)
	hnamelen = HOST_NAME_MAX;
#elif defined(_SC_HOST_NAME_MAX)
	hnamelen = sysconf(_SC_HOST_NAME_MAX);
#else
	hnamelen = 1024;
#endif
	hostname = calloc(1, hnamelen);
	if (hostname == NULL)
		return (ERRF_NOMEM);

	chal = calloc(1, sizeof (struct ebox_challenge));
	if (chal == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	chal->c_version = 1;
	chal->c_type = CHAL_RECOVERY;
	chal->c_id = part->ep_id;
	if (gethostname(hostname, hnamelen)) {
		err = errfno("gethostname", errno, NULL);
		goto out;
	}
	chal->c_hostname = strdup(hostname);
	free(hostname);
	hostname = NULL;
	if (chal->c_hostname == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	chal->c_ctime = time(NULL);
	if (chal->c_ctime == (time_t)-1) {
		err = errfno("time", errno, NULL);
		goto out;
	}
	chal->c_keybox = piv_box_clone(part->ep_box);
	if (chal->c_keybox == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	if (config->ec_chalkey == NULL) {
		uint bits;
		VERIFY3S(part->ep_box->pdb_pub->type, ==, KEY_ECDSA);
		bits = sshkey_size(part->ep_box->pdb_pub);
		rc = sshkey_generate(KEY_ECDSA, bits, &config->ec_chalkey);
		if (rc) {
			err = ssherrf("sshkey_generate", rc);
			goto out;
		}
	} else {
		VERIFY3S(part->ep_box->pdb_pub->type, ==, KEY_ECDSA);
		VERIFY3S(config->ec_chalkey->ecdsa_nid, ==,
		    part->ep_box->pdb_pub->ecdsa_nid);
	}
	if ((rc = sshkey_demote(config->ec_chalkey, &chal->c_destkey))) {
		err = ssherrf("sshkey_demote", rc);
		goto out;
	}

	va_start(ap, descfmt);
	wrote = vsnprintf(desc, sizeof (desc), descfmt, ap);
	if (wrote < 0) {
		err = errfno("vsnprintf", errno, NULL);
		goto out;
	}
	if (wrote >= sizeof (desc)) {
		err = errf("LengthError", NULL, "description field is too "
		    "long to fit in challenge");
		goto out;
	}
	va_end(ap);
	chal->c_description = strdup(desc);
	if (chal->c_description == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	arc4random_buf(chal->c_words, sizeof (chal->c_words));

	part->ep_chal = chal;
	chal = NULL;

out:
	free(hostname);
	ebox_challenge_free(chal);
	return (err);
}

static errf_t *
sshbuf_put_ebox_challenge_raw(struct sshbuf *buf,
    const struct ebox_challenge *chal)
{
	int rc = 0;
	const struct piv_ecdh_box *kb = chal->c_keybox;
	const struct apdubuf *nonce = &kb->pdb_nonce;
	const struct apdubuf *iv = &kb->pdb_iv;
	const struct apdubuf *enc = &kb->pdb_enc;
	const EC_KEY *eck;

	if ((rc = sshbuf_put_u8(buf, chal->c_version)) ||
	    (rc = sshbuf_put_u8(buf, chal->c_type)) ||
	    (rc = sshbuf_put_u8(buf, chal->c_id)))
		return (ssherrf("sshbuf_put_u8", rc));
	eck = EVP_PKEY_get1_EC_KEY(chal->c_destkey->pkey);
	if ((rc = sshbuf_put_eckey8(buf, eck)))
		return (ssherrf("sshbuf_put_eckey8", rc));
	eck = EVP_PKEY_get1_EC_KEY(kb->pdb_ephem_pub->pkey);
	if ((rc = sshbuf_put_eckey8(buf, eck)) ||
	    (rc = sshbuf_put_string8(buf, nonce->b_data, nonce->b_len)) ||
	    (rc = sshbuf_put_string8(buf, iv->b_data, iv->b_len)) ||
	    (rc = sshbuf_put_string8(buf, enc->b_data, enc->b_len)))
		return (ssherrf("sshbuf_put_*", rc));
	if ((rc = sshbuf_put_u8(buf, CTAG_HOSTNAME)) ||
	    (rc = sshbuf_put_cstring8(buf, chal->c_hostname)) ||
	    (rc = sshbuf_put_u8(buf, CTAG_CTIME)) ||
	    (rc = sshbuf_put_u8(buf, 8)) ||
	    (rc = sshbuf_put_u64(buf, chal->c_ctime)) ||
	    (rc = sshbuf_put_u8(buf, CTAG_DESCRIPTION)) ||
	    (rc = sshbuf_put_cstring8(buf, chal->c_description)) ||
	    (rc = sshbuf_put_u8(buf, CTAG_WORDS)) ||
	    (rc = sshbuf_put_u8(buf, 4)) ||
	    (rc = sshbuf_put_u8(buf, chal->c_words[0])) ||
	    (rc = sshbuf_put_u8(buf, chal->c_words[1])) ||
	    (rc = sshbuf_put_u8(buf, chal->c_words[2])) ||
	    (rc = sshbuf_put_u8(buf, chal->c_words[3])))
		return (ssherrf("sshbuf_put_*", rc));

	return (ERRF_OK);
}

errf_t *
sshbuf_put_ebox_challenge(struct sshbuf *buf, const struct ebox_challenge *chal)
{
	struct piv_ecdh_box *box;
	struct sshbuf *cbuf;
	struct piv_ecdh_box *kb = chal->c_keybox;
	errf_t *err;

	box = piv_box_new();
	VERIFY(box != NULL);

	cbuf = sshbuf_new();
	VERIFY(cbuf != NULL);

	if ((err = sshbuf_put_ebox_challenge_raw(cbuf, chal)))
		goto out;

	box->pdb_cipher = strdup(kb->pdb_cipher);
	box->pdb_kdf = strdup(kb->pdb_kdf);
	bcopy(kb->pdb_guid, box->pdb_guid, sizeof (box->pdb_guid));
	box->pdb_slot = kb->pdb_slot;
	box->pdb_guidslot_valid = kb->pdb_guidslot_valid;
	if ((err = piv_box_set_datab(box, cbuf)))
		goto out;
	if ((err = piv_box_seal_offline(kb->pdb_pub, box)))
		goto out;
	if ((err = sshbuf_put_piv_box(buf, box)))
		goto out;
	err = ERRF_OK;

out:
	sshbuf_free(cbuf);
	piv_box_free(box);
	return (err);
}

errf_t *
sshbuf_get_ebox_challenge(struct piv_ecdh_box *box,
    struct ebox_challenge **pchal)
{
	int rc;
	errf_t *err;
	struct sshbuf *buf = NULL, *kbuf = NULL;
	struct ebox_challenge *chal;
	uint8_t type;

	VERIFY0(piv_box_take_datab(box, &buf));

	chal = calloc(1, sizeof (struct ebox_challenge));
	VERIFY(chal != NULL);

	if ((rc = sshbuf_get_u8(buf, &chal->c_version))) {
		err = ssherrf("sshbuf_get_u8", rc);
		goto out;
	}
	if (chal->c_version != 1) {
		err = chalverrf(errf("VersionError", NULL,
		    "unsupported challenge version: v%d",
		    (int)chal->c_version));
		goto out;
	}

	if ((rc = sshbuf_get_u8(buf, &type))) {
		err = ssherrf("sshbuf_get_u8", rc);
		goto out;
	}
	chal->c_type = (enum ebox_chaltype)type;

	if ((rc = sshbuf_get_u8(buf, &chal->c_id))) {
		err = ssherrf("sshbuf_get_u8", rc);
		goto out;
	}

	err = sshbuf_get_eckey8_sshkey(buf, box->pdb_pub->ecdsa_nid,
	    &chal->c_destkey);
	if (err) {
		err = errf("KeyParseError", err, "failed to parse "
		    "challenge dest key");
		goto out;
	}

	chal->c_keybox = piv_box_new();
	if (chal->c_keybox == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	chal->c_keybox->pdb_guidslot_valid = box->pdb_guidslot_valid;
	chal->c_keybox->pdb_slot = box->pdb_slot;
	bcopy(box->pdb_guid, chal->c_keybox->pdb_guid, sizeof (box->pdb_guid));

	chal->c_keybox->pdb_cipher = strdup(box->pdb_cipher);
	chal->c_keybox->pdb_kdf = strdup(box->pdb_kdf);
	chal->c_keybox->pdb_free_str = B_TRUE;
	if (chal->c_keybox->pdb_cipher == NULL ||
	    chal->c_keybox->pdb_kdf == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	rc = sshkey_demote(box->pdb_pub, &chal->c_keybox->pdb_pub);
	if (rc) {
		err = ssherrf("sshkey_demote", rc);
		goto out;
	}

	err = sshbuf_get_eckey8_sshkey(buf, box->pdb_pub->ecdsa_nid,
	    &chal->c_keybox->pdb_ephem_pub);
	if (err) {
		err = errf("KeyParseError", err, "failed to parse "
		    "challenge ephemeral key");
		goto out;
	}

	if ((rc = sshbuf_get_string8(buf, &chal->c_keybox->pdb_nonce.b_data,
	    &chal->c_keybox->pdb_nonce.b_size))) {
		err = ssherrf("sshbuf_get_string8", rc);
		goto out;
	}
	chal->c_keybox->pdb_nonce.b_len = chal->c_keybox->pdb_nonce.b_size;

	if ((rc = sshbuf_get_string8(buf, &chal->c_keybox->pdb_iv.b_data,
	    &chal->c_keybox->pdb_iv.b_size))) {
		err = ssherrf("sshbuf_get_string8", rc);
		goto out;
	}
	chal->c_keybox->pdb_iv.b_len = chal->c_keybox->pdb_iv.b_size;
	if ((rc = sshbuf_get_string8(buf, &chal->c_keybox->pdb_enc.b_data,
	    &chal->c_keybox->pdb_enc.b_size))) {
		err = ssherrf("sshbuf_get_string8", rc);
		goto out;
	}
	chal->c_keybox->pdb_enc.b_len = chal->c_keybox->pdb_enc.b_size;

	kbuf = sshbuf_new();
	if (kbuf == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	while (sshbuf_len(buf) > 0) {
		uint8_t tag;
		sshbuf_reset(kbuf);
		if ((rc = sshbuf_get_u8(buf, &tag))) {
			err = ssherrf("sshbuf_get_u8", rc);
			goto out;
		}
		if ((rc = sshbuf_get_stringb8(buf, kbuf))) {
			err = ssherrf("sshbuf_get_stringb8", rc);
			goto out;
		}
		switch (tag) {
		case CTAG_HOSTNAME:
			chal->c_hostname = sshbuf_dup_string(kbuf);
			if (chal->c_hostname == NULL) {
				err = ERRF_NOMEM;
				goto out;
			}
			break;
		case CTAG_CTIME:
			if ((rc = sshbuf_get_u64(kbuf, &chal->c_ctime))) {
				err = ssherrf("sshbuf_get_u64", rc);
				goto out;
			}
			break;
		case CTAG_DESCRIPTION:
			chal->c_description = sshbuf_dup_string(kbuf);
			if (chal->c_description == NULL) {
				err = ERRF_NOMEM;
				goto out;
			}
			break;
		case CTAG_WORDS:
			if ((rc = sshbuf_get_u8(kbuf, &chal->c_words[0])) ||
			    (rc = sshbuf_get_u8(kbuf, &chal->c_words[1])) ||
			    (rc = sshbuf_get_u8(kbuf, &chal->c_words[2])) ||
			    (rc = sshbuf_get_u8(kbuf, &chal->c_words[3]))) {
				err = ssherrf("sshbuf_get_u8", rc);
				goto out;
			}
			break;
		default:
			/* do nothing */
			break;
		}
	}

	*pchal = chal;
	chal = NULL;
	err = NULL;

out:
	sshbuf_free(buf);
	sshbuf_free(kbuf);
	ebox_challenge_free(chal);
	return (err);
}

uint
ebox_challenge_id(const struct ebox_challenge *chal)
{
	return (chal->c_id);
}

enum ebox_chaltype
ebox_challenge_type(const struct ebox_challenge *chal)
{
	return (chal->c_type);
}

const char *
ebox_challenge_desc(const struct ebox_challenge *chal)
{
	return (chal->c_description);
}

const char *
ebox_challenge_hostname(const struct ebox_challenge *chal)
{
	return (chal->c_hostname);
}

uint64_t
ebox_challenge_ctime(const struct ebox_challenge *chal)
{
	return (chal->c_ctime);
}

const uint8_t *
ebox_challenge_words(const struct ebox_challenge *chal, size_t *len)
{
	*len = sizeof (chal->c_words);
	return (chal->c_words);
}

struct sshkey *
ebox_challenge_destkey(const struct ebox_challenge *chal)
{
	return (chal->c_destkey);
}

struct piv_ecdh_box *
ebox_challenge_box(const struct ebox_challenge *chal)
{
	return (chal->c_keybox);
}

errf_t *
ebox_challenge_response(struct ebox_config *config, struct piv_ecdh_box *rbox,
    struct ebox_part **ppart)
{
	int rc = 0;
	struct ebox_part *part;
	struct sshbuf *buf = NULL;
	boolean_t gotid = B_FALSE;
	uint8_t tag, id;
	errf_t *err;
	uint8_t *keypiece = NULL;
	size_t klen = 0;

	VERIFY(config->ec_chalkey != NULL);
	if ((err = piv_box_open_offline(config->ec_chalkey, rbox)))
		goto out;
	if ((err = piv_box_take_datab(rbox, &buf)))
		goto out;

	while (sshbuf_len(buf) > 0) {
		if ((rc = sshbuf_get_u8(buf, &tag))) {
			err = ssherrf("sshbuf_get_u8", rc);
			goto out;
		}
		switch ((enum resptag)tag) {
		case RTAG_ID:
			if ((rc = sshbuf_get_u8(buf, &id))) {
				err = ssherrf("sshbuf_get_u8", rc);
				goto out;
			}
			gotid = B_TRUE;
			break;
		case RTAG_KEYPIECE:
			rc = sshbuf_get_string8_conceal(buf, &keypiece, &klen);
			if (rc) {
				err = ssherrf("sshbuf_get_string8", rc);
				goto out;
			}
			break;
		default:
			/* For forwards compatibility, ignore unknown tags. */
			break;
		}
	}

	if (!gotid || keypiece == NULL) {
		err = errf("InvalidDataError", NULL,
		    "Challenge response data was missing compulsory fields");
		goto out;
	}

	for (part = config->ec_parts; part != NULL; part = part->ep_next) {
		if (part->ep_id == id)
			break;
	}
	if (part == NULL || part->ep_id != id) {
		err = errf("InvalidDataError", NULL,
		    "Challenge response refers to challenge ID that was not "
		    "generated as part of this configuration");
		goto out;
	}
	freezero(part->ep_share, part->ep_sharelen);
	part->ep_sharelen = klen;
	part->ep_share = keypiece;
	*ppart = part;
	keypiece = NULL;
	err = NULL;

out:
	freezero(keypiece, klen);
	piv_box_free(rbox);
	sshbuf_free(buf);
	return (err);
}

errf_t *
sshbuf_put_ebox_challenge_response(struct sshbuf *dbuf,
    const struct ebox_challenge *chal)
{
	struct sshbuf *buf;
	errf_t *err;
	int rc;
	uint8_t *keypiece = NULL;
	size_t klen = 0;
	struct piv_ecdh_box *box = NULL;

	buf = sshbuf_new();
	if (buf == NULL)
		return (ERRF_NOMEM);

	if ((rc = sshbuf_put_u8(buf, RTAG_ID)) ||
	    (rc = sshbuf_put_u8(buf, chal->c_id))) {
		err = ssherrf("sshbuf_put_u8", rc);
		goto out;
	}

	if ((rc = sshbuf_put_u8(buf, RTAG_KEYPIECE))) {
		err = ssherrf("sshbuf_put_u8", rc);
		goto out;
	}

	if ((err = piv_box_take_data(chal->c_keybox, &keypiece, &klen)))
		goto out;

	if ((rc = sshbuf_put_string8(buf, keypiece, klen))) {
		err = ssherrf("sshbuf_put_string8", rc);
		goto out;
	}

	freezero(keypiece, klen);
	keypiece = NULL;

	box = piv_box_new();
	if (box == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

	if ((err = piv_box_set_datab(box, buf)))
		goto out;
	if ((err = piv_box_seal_offline(chal->c_destkey, box)))
		goto out;

	if ((err = sshbuf_put_piv_box(dbuf, box)))
		goto out;

	err = NULL;

out:
	sshbuf_free(buf);
	freezero(keypiece, klen);
	piv_box_free(box);
	return (err);
}

void
ebox_challenge_free(struct ebox_challenge *chal)
{
	if (chal == NULL)
		return;
	free(chal->c_description);
	free(chal->c_hostname);
	sshkey_free(chal->c_destkey);
	piv_box_free(chal->c_keybox);
	explicit_bzero(chal->c_words, sizeof (chal->c_words));
	free(chal);
}
