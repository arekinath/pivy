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
#include <sys/errno.h>

#include "libssh/sshkey.h"
#include "libssh/sshbuf.h"
#include "libssh/digest.h"
#include "libssh/digest.h"
#include "libssh/cipher.h"
#include "libssh/ssherr.h"

#include "sss/hazmat.h"

#include "debug.h"
#include "tlv.h"
#include "ebox.h"
#include "piv.h"
#include "bunyan.h"

#include "words.h"

#include "piv-internal.h"

struct buf {
	size_t b_len;
	uint8_t *b_data;
};

struct ebox_tpl {
	struct ebox_tpl_config *et_configs;
	struct ebox_tpl_config *et_lastconfig;
	void *et_priv;
};

struct ebox_tpl_config {
	struct ebox_tpl_config *etc_next;
	enum ebox_config_type etc_type;
	uint8_t etc_n;
	uint8_t etc_m;
	struct ebox_tpl_part *etc_parts;
	struct ebox_tpl_part *etc_lastpart;
	void *etc_priv;
};

struct ebox_tpl_part {
	struct ebox_tpl_part *etp_next;
	char *etp_name;
	struct sshkey *etp_pubkey;
	struct sshkey *etp_cak;
	uint8_t etp_guid[16];
	void *etp_priv;
};

struct ebox {
	struct ebox_tpl *e_tpl;
	struct ebox_config *e_configs;
	enum ebox_type e_type;

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

struct ebox_config {
	struct ebox_config *ec_next;
	struct ebox_tpl_config *ec_tpl;

	struct ebox_part *ec_parts;

	/* key for collecting challenge-responses */
	struct sshkey *ec_chalkey;

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

enum chaltype {
	CHAL_RECOVERY = 1,
	CHAL_VERIFY_AUDIT = 2,
};

enum chaltag {
	CTAG_HOSTNAME = 1,
	CTAG_CTIME = 2,
	CTAG_DESCRIPTION = 3,
	CTAG_WORDS = 4,
};

struct ebox_challenge {
	uint8_t c_version;
	enum chaltype c_type;
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
	struct sshbuf *es_buf;
	enum ebox_stream_mode es_mode;
};

struct ebox_stream_chunk {
	uint32_t esc_len;
	uint8_t *esc_data;

	uint32_t esc_enclen;
	uint8_t *esc_encdata;

	uint8_t *esc_nextk;
	uint32_t esc_nextklen;
};

enum ebox_part_tag {
	EBOX_PART_END = 0,
	EBOX_PART_PUBKEY = 1,
	EBOX_PART_NAME = 2,
	EBOX_PART_CAK = 3,
	EBOX_PART_GUID = 4,
	EBOX_PART_BOX = 5
};

#define boxderrf(cause) \
    errf("InvalidDataError", cause, \
    "ebox contained invalid or corrupted data")

#define boxverrf(cause) \
    errf("NotSupportedError", cause, \
    "ebox is not supported")

struct ebox_tpl *
ebox_tpl_alloc(void)
{
	struct ebox_tpl *tpl;
	tpl = calloc(1, sizeof (struct ebox_tpl));
	if (tpl == NULL)
		return (NULL);
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
ebox_tpl_add_config(struct ebox_tpl *tpl, struct ebox_tpl_config *config)
{
	VERIFY(config->etc_next == NULL);
	if (tpl->et_lastconfig == NULL)
		tpl->et_configs = config;
	else
		tpl->et_lastconfig->etc_next = config;
	tpl->et_lastconfig = config;
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
	if (config->etc_lastpart == NULL)
		config->etc_parts = part;
	else
		config->etc_lastpart->etp_next = part;
	config->etc_lastpart = part;
	++config->etc_m;
}

struct ebox_tpl_part *
ebox_tpl_config_next_part(const struct ebox_config *config,
    const struct ebox_tpl_part *prev)
{
	if (prev == NULL)
		return (config->ec_parts);
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
ebox_tpl_part_alloc(uint8_t *guid, size_t guidlen, struct sshkey *pubkey)
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

const uint8_t *
ebox_tpl_part_guid(const struct ebox_tpl_part *part)
{
	return (part->etp_guid);
}

struct ebox_tpl *
ebox_tpl_clone(struct ebox_tpl *tpl)
{
	struct ebox_tpl *ntpl;
	struct ebox_tpl_config *pconfig, *nconfig, *config;
	struct ebox_tpl_part *ppart, *npart, *part;

	ntpl = calloc(1, sizeof (struct ebox_tpl));
	VERIFY(ntpl != NULL);

	pconfig = NULL;
	config = tpl->et_configs;
	for (; config != NULL; config = config->etc_next) {
		nconfig = calloc(1, sizeof (struct ebox_tpl_config));
		VERIFY(nconfig != NULL);
		if (pconfig != NULL)
			pconfig->etc_next = nconfig;
		else
			ntpl->et_configs = nconfig;
		nconfig->etc_type = config->etc_type;
		nconfig->etc_n = config->etc_n;
		nconfig->etc_m = config->etc_m;

		ppart = NULL;
		part = config->etc_parts;
		for (; part != NULL; part = part->etp_next) {
			npart = calloc(1, sizeof (struct ebox_tpl_part));
			VERIFY(npart != NULL);
			if (ppart != NULL)
				ppart->etp_next = npart;
			else
				nconfig->etc_parts = npart;
			npart->etp_name = strdup(part->etp_name);
			bcopy(part->etp_guid, npart->etp_guid,
			    sizeof (npart->etp_guid));
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

	kbuf = sshbuf_new();
	VERIFY(kbuf != NULL);

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_PUBKEY)) ||
	    (rc = sshkey_putb(part->etp_pubkey, kbuf)) ||
	    (rc = sshbuf_put_stringb(buf, kbuf))) {
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
		    (rc = sshkey_putb(part->etp_cak, buf)) ||
		    (rc = sshbuf_put_stringb(buf, kbuf))) {
			err = ssherrf("sshbuf_put_*", rc);
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

	part = calloc(1, sizeof (struct ebox_tpl_part));
	VERIFY(part != NULL);

	kbuf = sshbuf_new();
	VERIFY(kbuf != NULL);

	if ((rc = sshbuf_get_u8(buf, &tag))) {
		err = ssherrf("sshbuf_get_u8", rc);
		goto out;
	}
	while (tag != EBOX_PART_END) {
		switch (tag) {
		case EBOX_PART_PUBKEY:
			sshbuf_reset(kbuf);
			rc = sshbuf_get_stringb(buf, kbuf);
			if (rc) {
				err = ssherrf("sshbuf_get_stringb", rc);
				goto out;
			}
			rc = sshkey_fromb(kbuf, &part->etp_pubkey);
			if (rc) {
				err = ssherrf("sshkey_fromb", rc);
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
			break;
		default:
			err = errf("UnknownTagError", NULL, "unknown tag %d "
			    "at +%lx", tag, buf->off);
			goto out;
		}
		if ((rc = sshbuf_get_u8(buf, &tag))) {
			err = ssherrf("sshbuf_get_u8", rc);
			goto out;
		}
	}

	*ppart = part;
	part = NULL;
out:
	sshbuf_free(kbuf);
	ebox_tpl_part_free(part);
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

	for (i = 1; i < config->etc_m; ++i) {
		if ((err = sshbuf_get_ebox_tpl_part(buf, &part->etp_next))) {
			err = errf("PartError", err, "error reading part %u", i);
			goto out;
		}
		part = part->etp_next;
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
	    (rc = sshbuf_put_u8(buf, 0x01)) ||
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
		err = boxderrf(errf("MagicError",
		    ssherrf("sshbuf_get_u8", rc), "failed reading ebox magic"));
		goto out;
	}
	if (magic[0] != 0xEB && magic[1] != 0x0C) {
		err = boxderrf(errf("MagicError", NULL,
		    "bad ebox magic number"));
		goto out;
	}
	if ((rc = sshbuf_get_u8(buf, &ver)) ||
	    (rc = sshbuf_get_u8(buf, &type))) {
		err = boxderrf(ssherrf("sshbuf_get_u8", rc));
		goto out;
	}
	if (ver != 0x01) {
		err = boxverrf(errf("VersionError", NULL,
		    "unsupported version number 0x%02x", ver));
		goto out;
	}
	if (type != EBOX_TEMPLATE) {
		err = boxderrf(errf("EboxTypeError", NULL,
		    "buffer does not contain an ebox template"));
		goto out;
	}
	if ((rc = sshbuf_get_u8(buf, &nconfigs))) {
		err = boxderrf(ssherrf("sshbuf_get_u8", rc));
		goto out;
	}

	if ((err = sshbuf_get_ebox_tpl_config(buf, &config))) {
		err = boxderrf(errf("ConfigError", err,
		    "failed to read config 0"));
		goto out;
	}
	tpl->et_configs = config;

	for (i = 1; i < nconfigs; ++i) {
		if ((err = sshbuf_get_ebox_tpl_config(buf, &config->etc_next))) {
			err = boxderrf(errf("ConfigError", err,
			    "failed to read config %u", i));
			goto out;
		}
		config = config->etc_next;
	}

	*ptpl = tpl;
	tpl = NULL;

out:
	ebox_tpl_free(tpl);
	return (err);
}

void
ebox_free(struct ebox *box)
{
	struct ebox_config *config, *nconfig;
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
	ebox_tpl_free(box->e_tpl);
	free(box);
}

void
ebox_config_free(struct ebox_config *config)
{
	struct ebox_part *part, *npart;
	if (config == NULL)
		return;
	if (config->ec_chalkey != NULL)
		sshkey_free(config->ec_chalkey);
	free(config->ec_priv);
	for (part = config->ec_parts; part != NULL; part = npart) {
		npart = part->ep_next;
		ebox_part_free(part);
	}
	free(config);
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

struct ebox_stream *
ebox_stream_init_decrypt(void)
{
	struct ebox_stream *es;

	es = calloc(1, sizeof (struct ebox_stream));
	VERIFY(es != NULL);
	es->es_mode = EBOX_MODE_DECRYPT;
	es->es_buf = sshbuf_new();
	VERIFY(es->es_buf != NULL);

	return (es);
}

struct ebox_stream *
ebox_stream_init_encrypt(struct ebox_tpl *tpl)
{
	struct ebox_stream *es;
	uint8_t *key;
	size_t keylen;
	errf_t *err;
	const struct sshcipher *cipher;

	es = calloc(1, sizeof (struct ebox_stream));
	VERIFY(es != NULL);
	es->es_mode = EBOX_MODE_ENCRYPT;
	es->es_buf = sshbuf_new();
	VERIFY(es->es_buf != NULL);

	es->es_cipher = strdup("aes256-ctr");
	es->es_mac = strdup("sha256");
	cipher = cipher_by_name(es->es_cipher);
	VERIFY(cipher != NULL);
	keylen = cipher_keylen(cipher);

	key = malloc(keylen);
	VERIFY(key != NULL);
	arc4random_buf(key, keylen);

	err = ebox_create(tpl, key, keylen, NULL, 0, &es->es_ebox);
	VERIFY(es->es_ebox != NULL);

	explicit_bzero(key, keylen);
	free(key);

	return (es);
}

static errf_t *
sshbuf_get_ebox_part(struct sshbuf *buf, struct ebox_part **ppart)
{
	struct ebox_part *part;
	struct ebox_tpl_part *tpart;
	struct sshbuf *kbuf;
	int rc = 0;
	size_t len;
	uint8_t tag, *guid;

	part = calloc(1, sizeof (struct ebox_part));
	VERIFY(part != NULL);

	part->ep_tpl = calloc(1, sizeof (struct ebox_tpl_part));
	VERIFY(part->ep_tpl != NULL);
	tpart = part->ep_tpl;

	kbuf = sshbuf_new();
	VERIFY(kbuf != NULL);

	if ((rc = sshbuf_get_u8(buf, &tag)))
		goto out;
	while (tag != EBOX_PART_END) {
		switch (tag) {
		case EBOX_PART_PUBKEY:
			sshbuf_reset(kbuf);
			rc = sshbuf_get_stringb(buf, kbuf);
			if (rc)
				goto out;
			rc = sshkey_fromb(kbuf, &tpart->etp_pubkey);
			if (rc)
				goto out;
			break;
		case EBOX_PART_CAK:
			sshbuf_reset(kbuf);
			rc = sshbuf_get_stringb(buf, kbuf);
			if (rc)
				goto out;
			rc = sshkey_fromb(kbuf, &tpart->etp_cak);
			if (rc)
				goto out;
			break;
		case EBOX_PART_NAME:
			rc = sshbuf_get_cstring8(buf, &tpart->etp_name, &len);
			if (rc)
				goto out;
			break;
		case EBOX_PART_GUID:
			rc = sshbuf_get_string8(buf, &guid, &len);
			if (rc)
				goto out;
			if (len != sizeof (tpart->etp_guid)) {
				rc = EBADF;
				goto out;
			}
			bcopy(guid, tpart->etp_guid, len);
			free(guid);
			guid = NULL;
			break;
		case EBOX_PART_BOX:
			rc = sshbuf_get_piv_box(buf, &part->ep_box);
			if (rc)
				goto out;
			break;
		default:
			fprintf(stderr, "unknown tag %d at +%lx\n", tag,
			    buf->off);
			rc = EBADF;
			goto out;
		}
		if ((rc = sshbuf_get_u8(buf, &tag)))
			goto out;
	}

	if (part->ep_box == NULL) {
		rc = EINVAL;
		goto out;
	}

	if (tpart->etp_pubkey == NULL) {
		VERIFY0(sshkey_demote(part->ep_box->pdb_pub,
		    &tpart->etp_pubkey));
	}

	if (!sshkey_equal_public(tpart->etp_pubkey, part->ep_box->pdb_pub)) {
		rc = EINVAL;
		goto out;
	}

	*ppart = part;
	part = NULL;
out:
	sshbuf_free(kbuf);
	ebox_part_free(part);
	return (rc);
}

static errf_t *
sshbuf_get_ebox_config(struct sshbuf *buf, struct ebox_config **pconfig)
{
	struct ebox_config *config;
	struct ebox_tpl_config *tconfig;
	struct ebox_part *part;
	struct ebox_tpl_part *tpart;
	int rc = 0;
	uint8_t type;
	uint i, id;

	config = calloc(1, sizeof (struct ebox_config));
	VERIFY(config != NULL);

	config->ec_tpl = calloc(1, sizeof (struct ebox_tpl_config));
	VERIFY(config->ec_tpl != NULL);
	tconfig = config->ec_tpl;

	if ((rc = sshbuf_get_u8(buf, &type)) ||
	    (rc = sshbuf_get_u8(buf, &tconfig->etc_n)) ||
	    (rc = sshbuf_get_u8(buf, &tconfig->etc_m)))
		goto out;
	tconfig->etc_type = (enum ebox_config_type)type;
	if (tconfig->etc_type != EBOX_PRIMARY &&
	    tconfig->etc_type != EBOX_RECOVERY) {
		fprintf(stderr, "bad etc_type\n");
		rc = EBADF;
		goto out;
	}
	if (tconfig->etc_type == EBOX_PRIMARY &&
	    tconfig->etc_n > 1) {
		fprintf(stderr, "primary n>1\n");
		rc = EBADF;
		goto out;
	}
	id = 1;

	if ((rc = sshbuf_get_ebox_part(buf, &part)))
		goto out;
	part->ep_id = id++;
	config->ec_parts = part;
	tpart = part->ep_tpl;
	config->ec_tpl->etc_parts = tpart;

	for (i = 1; i < tconfig->etc_m; ++i) {
		if ((rc = sshbuf_get_ebox_part(buf, &part->ep_next)))
			goto out;
		part = part->ep_next;
		part->ep_id = id++;
		tpart->etp_next = part->ep_tpl;
		tpart = part->ep_tpl;
	}

	*pconfig = config;
	config = NULL;

out:
	ebox_config_free(config);
	return (rc);
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

	box = calloc(1, sizeof (struct ebox));
	VERIFY(box != NULL);

	box->e_tpl = calloc(1, sizeof (struct ebox_tpl));
	VERIFY(box->e_tpl != NULL);

	if ((rc = sshbuf_get_u8(buf, &magic[0])) ||
	    (rc = sshbuf_get_u8(buf, &magic[1])))
		goto out;
	if (magic[0] != 0xEB && magic[1] != 0x0C) {
		bunyan_log(TRACE, "bad ebox magic",
		    "magic[0]", BNY_UINT, (uint)magic[0],
		    "magic[1]", BNY_UINT, (uint)magic[1], NULL);
		rc = ENOTSUP;
		goto out;
	}
	if ((rc = sshbuf_get_u8(buf, &ver)) ||
	    (rc = sshbuf_get_u8(buf, &type)))
		goto out;
	if (ver != 0x01) {
		bunyan_log(TRACE, "bad ebox version",
		    "version", BNY_UINT, (uint)ver, NULL);
		rc = ENOTSUP;
		goto out;
	}
	if (type != EBOX_KEY && type != EBOX_STREAM) {
		bunyan_log(TRACE, "not an ebox",
		    "type", BNY_UINT, (uint)type, NULL);
		rc = EDOM;
		goto out;
	}
	box->e_type = (enum ebox_type)type;

	if ((rc = sshbuf_get_cstring8(buf, &box->e_rcv_cipher, NULL)))
		goto out;
	rc = sshbuf_get_string8(buf, &box->e_rcv_iv.b_data, 
	    &box->e_rcv_iv.b_len);
	if (rc)
		goto out;

	rc = sshbuf_get_string8(buf, &box->e_rcv_enc.b_data,
	    &box->e_rcv_enc.b_len);
	if (rc)
		goto out;

	if ((rc = sshbuf_get_u8(buf, &nconfigs)))
		goto out;

	if ((rc = sshbuf_get_ebox_config(buf, &config)))
		goto out;
	box->e_configs = config;
	tconfig = config->ec_tpl;
	box->e_tpl->et_configs = tconfig;

	for (i = 1; i < nconfigs; ++i) {
		if ((rc = sshbuf_get_ebox_config(buf, &config->ec_next)))
			goto out;
		config = config->ec_next;
		tconfig->etc_next = config->ec_tpl;
		tconfig = config->ec_tpl;
	}

	*pbox = box;
	box = NULL;

out:
	ebox_free(box);
	return (rc);
}

static errf_t *
sshbuf_put_ebox_part(struct sshbuf *buf, struct ebox_part *part)
{
	struct ebox_tpl_part *tpart;
	struct sshbuf *kbuf;
	int rc = 0;

	tpart = part->ep_tpl;

	kbuf = sshbuf_new();
	VERIFY(kbuf != NULL);

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_GUID)) ||
	    (rc = sshbuf_put_string8(buf, tpart->etp_guid,
	    sizeof (tpart->etp_guid))))
		goto out;

	if (tpart->etp_name != NULL) {
		if ((rc = sshbuf_put_u8(buf, EBOX_PART_NAME)) ||
		    (rc = sshbuf_put_cstring8(buf, tpart->etp_name)))
			goto out;
	}

	if (tpart->etp_cak != NULL) {
		sshbuf_reset(kbuf);
		if ((rc = sshbuf_put_u8(buf, EBOX_PART_CAK)) ||
		    (rc = sshkey_putb(tpart->etp_cak, buf)) ||
		    (rc = sshbuf_put_stringb(buf, kbuf)))
			goto out;
	}

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_BOX)) ||
	    (rc = sshbuf_put_piv_box(buf, part->ep_box)))
		goto out;

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_END)))
		goto out;

	rc = 0;

out:
	sshbuf_free(kbuf);
	return (rc);
}

static errf_t *
sshbuf_put_ebox_config(struct sshbuf *buf, struct ebox_config *config)
{
	struct ebox_tpl_config *tconfig;
	struct ebox_part *part;
	int rc;

	tconfig = config->ec_tpl;

	if ((rc = sshbuf_put_u8(buf, tconfig->etc_type)) ||
	    (rc = sshbuf_put_u8(buf, tconfig->etc_n)) ||
	    (rc = sshbuf_put_u8(buf, tconfig->etc_m)))
		return (rc);

	part = config->ec_parts;
	for (; part != NULL; part = part->ep_next) {
		if ((rc = sshbuf_put_ebox_part(buf, part)))
			return (rc);
	}

	return (0);
}

errf_t *
sshbuf_put_ebox(struct sshbuf *buf, struct ebox *ebox)
{
	uint8_t nconfigs = 0;
	int rc = 0;
	struct ebox_config *config;

	config = ebox->e_configs;
	for (; config != NULL; config = config->ec_next) {
		++nconfigs;
	}

	if ((rc = sshbuf_put_u8(buf, 0xEB)) ||
	    (rc = sshbuf_put_u8(buf, 0x0C)) ||
	    (rc = sshbuf_put_u8(buf, 0x01)) ||
	    (rc = sshbuf_put_u8(buf, ebox->e_type)))
		return (rc);

	if ((rc = sshbuf_put_cstring8(buf, ebox->e_rcv_cipher)))
		return (rc);

	rc = sshbuf_put_string8(buf, ebox->e_rcv_iv.b_data,
	    ebox->e_rcv_iv.b_len);
	if (rc)
		return (rc);
	rc = sshbuf_put_string8(buf, ebox->e_rcv_enc.b_data,
	    ebox->e_rcv_enc.b_len);
	if (rc)
		return (rc);

	if ((rc = sshbuf_put_u8(buf, nconfigs)))
		return (rc);

	config = ebox->e_configs;
	for (; config != NULL; config = config->ec_next) {
		if ((rc = sshbuf_put_ebox_config(buf, config)))
			return (rc);
	}

	return (0);
}

static errf_t *
ebox_decrypt_recovery(struct ebox *box)
{
	const struct sshcipher *cipher;
	struct sshcipher_ctx *cctx;
	size_t ivlen, authlen, blocksz, keylen;
	size_t plainlen, padding;
	size_t enclen, reallen;
	uint8_t *iv, *enc, *plain, *key;
	size_t i;
	int rc = 0;

	cipher = cipher_by_name(box->e_rcv_cipher);
	if (cipher == NULL)
		return (ENOTSUP);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);

	iv = box->e_rcv_iv.b_data;
	VERIFY(iv != NULL);
	VERIFY3U(box->e_rcv_iv.b_len, >=, ivlen);

	key = box->e_rcv_key.b_data;
	VERIFY(key != NULL);
	VERIFY3U(box->e_rcv_key.b_len, >=, keylen);

	enc = box->e_rcv_enc.b_data;
	VERIFY(enc != NULL);
	enclen = box->e_rcv_enc.b_len;
	VERIFY3U(enclen, >=, blocksz + authlen);

	plainlen = enclen - authlen;
	plain = malloc(plainlen);
	VERIFY(plain != NULL);

	VERIFY0(cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 0));
	rc = cipher_crypt(cctx, 0, plain, enc, enclen - authlen, 0, authlen);
	cipher_free(cctx);
	if (rc) {
		explicit_bzero(plain, plainlen);
		free(plain);
		return (rc);
	}

	/* Strip off the pkcs#7 padding and verify it. */
	padding = plain[plainlen - 1];
	VERIFY3U(padding, <=, blocksz);
	VERIFY3U(padding, >, 0);
	reallen = plainlen - padding;
	for (i = reallen; i < plainlen; ++i)
		VERIFY3U(plain[i], ==, padding);

	explicit_bzero(&plain[reallen], padding);
	box->e_rcv_plain.b_data = plain;
	box->e_rcv_plain.b_len = reallen;
}

static errf_t *
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

	plainlen = box->e_rcv_plain.b_len;
	padding = blocksz - (plainlen % blocksz);
	VERIFY3U(padding, <=, blocksz);
	VERIFY3U(padding, >, 0);
	plainlen += padding;
	plain = malloc(plainlen);
	bcopy(box->e_rcv_plain.b_data, plain, box->e_rcv_plain.b_len);
	for (i = box->e_rcv_plain.b_len; i < plainlen; ++i)
		plain[i] = padding;

	explicit_bzero(box->e_rcv_plain.b_data, box->e_rcv_plain.b_len);
	free(box->e_rcv_plain.b_data);
	box->e_rcv_plain.b_data = NULL;
	box->e_rcv_plain.b_len = 0;

	box->e_rcv_iv.b_data = (iv = malloc(ivlen));
	box->e_rcv_iv.b_len = ivlen;
	VERIFY(iv != NULL);
	arc4random_buf(iv, ivlen);

	box->e_rcv_key.b_data = (key = malloc(keylen));
	box->e_rcv_key.b_len = keylen;
	arc4random_buf(key, keylen);

	VERIFY0(cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 1));
	enclen = plainlen + authlen;
	enc = malloc(enclen);
	VERIFY3P(enc, !=, NULL);
	VERIFY0(cipher_crypt(cctx, 0, enc, plain, plainlen, 0, authlen));
	cipher_free(cctx);

	explicit_bzero(plain, plainlen);
	free(plain);

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
	struct sshbuf *buf;
	struct piv_ecdh_box *pbox;
	sss_Keyshare *share, *shares = NULL;
	size_t shareslen = 0;
	uint i;

	box = calloc(1, sizeof (struct ebox));
	VERIFY(box != NULL);

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
	box->e_rcv_plain.b_data = (plain = malloc(plainlen));
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

			shareslen = tconfig->etc_m * sizeof (sss_Keyshare);
			shares = calloc(1, shareslen);
			sss_create_keyshares(shares, box->e_rcv_key.b_data,
			    tconfig->etc_m, tconfig->etc_n);
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
			npart->ep_tpl->etp_name = strdup(tpart->etp_name);
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
			pbox->pdb_slot = PIV_SLOT_KEY_MGMT;
			pbox->pdb_guidslot_valid = B_TRUE;
			if (shares != NULL) {
				share = &shares[npart->ep_id - 1];
				VERIFY0(piv_box_set_data(pbox, (uint8_t *)share,
				    sizeof (sss_Keyshare)));
				explicit_bzero(share, sizeof (sss_Keyshare));
			} else {
				VERIFY0(piv_box_set_data(pbox, key, keylen));
			}
			VERIFY0(piv_box_seal_offline(tpart->etp_pubkey, pbox));

			ppart = npart;
		}

		if (shares != NULL) {
			explicit_bzero(shares, shareslen);
			free(shares);
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

	return (EINVAL);
}

errf_t *
ebox_recover(struct ebox *ebox, struct ebox_config *config)
{
	struct ebox_part *part;
	struct ebox_tpl_config *tconfig = config->ec_tpl;
	struct sshbuf *buf;
	uint n = tconfig->etc_n, m = tconfig->etc_m;
	uint i = 0, j;
	int rc = 0;
	uint8_t tag;
	sss_Keyshare *share, *shares = NULL;

	if (ebox->e_key != NULL || ebox->e_keylen > 0)
		return (EAGAIN);
	if (ebox->e_token != NULL || ebox->e_tokenlen > 0)
		return (EAGAIN);
	if (ebox->e_rcv_key.b_data != NULL || ebox->e_rcv_key.b_len > 0)
		return (EAGAIN);

	shares = calloc(m, sizeof (sss_Keyshare));

	for (part = config->ec_parts; part != NULL; part = part->ep_next) {
		if (part->ep_share == NULL || part->ep_sharelen < 1)
			continue;
		VERIFY3U(part->ep_sharelen, ==, sizeof (sss_Keyshare));
		share = &shares[i++];
		bcopy(part->ep_share, share, sizeof (sss_Keyshare));
	}

	if (i != n) {
		rc = EINVAL;
		goto out;
	}

	ebox->e_rcv_key.b_data = calloc(1, sizeof (sss_Keyshare));
	ebox->e_rcv_key.b_len = sizeof (sss_Keyshare);
	sss_combine_keyshares(ebox->e_rcv_key.b_data,
	    (const sss_Keyshare *)shares, n);

	rc = ebox_decrypt_recovery(ebox);
	if (rc) {
		rc = EBADF;
		goto out;
	}

	buf = sshbuf_from(ebox->e_rcv_plain.b_data, ebox->e_rcv_plain.b_len);
	VERIFY(buf != NULL);

	if ((rc = sshbuf_get_u8(buf, &tag)))
		goto out;
	if (tag == EBOX_RECOV_TOKEN) {
		rc = sshbuf_get_string8(buf, &ebox->e_token, &ebox->e_tokenlen);
		if (rc)
			goto out;
		if ((rc = sshbuf_get_u8(buf, &tag)))
			goto out;
	}
	if (tag != EBOX_RECOV_KEY) {
		rc = EBADF;
		goto out;
	}
	rc = sshbuf_get_string8(buf, &ebox->e_key, &ebox->e_keylen);
	if (rc)
		goto out;

out:
	sshbuf_free(buf);
	for (j = 0; j < m; ++j)
		explicit_bzero(&shares[j], sizeof (sss_Keyshare));
	free(shares);
	return (rc);
}

errf_t *
ebox_gen_challenge(struct ebox_config *config, struct ebox_part *part,
    const char *descfmt, ...)
{
	struct ebox_challenge *chal;
	int rc = 0;
	char hostname[HOST_NAME_MAX] = {0};
	char desc[255] = {0};
	va_list ap;
	size_t wrote;

	chal = calloc(1, sizeof (struct ebox_challenge));
	VERIFY(chal != NULL);

	chal->c_version = 1;
	chal->c_type = CHAL_RECOVERY;
	chal->c_id = part->ep_id;
	VERIFY0(gethostname(hostname, sizeof (hostname)));
	chal->c_hostname = strdup(hostname);
	chal->c_ctime = time(NULL);
	chal->c_keybox = piv_box_clone(part->ep_box);

	if (config->ec_chalkey == NULL) {
		uint bits;
		VERIFY3S(part->ep_box->pdb_pub->type, ==, KEY_ECDSA);
		bits = sshkey_size(part->ep_box->pdb_pub);
		VERIFY0(sshkey_generate(KEY_ECDSA, bits, &config->ec_chalkey));
	} else {
		VERIFY3S(part->ep_box->pdb_pub->type, ==, KEY_ECDSA);
		VERIFY3S(config->ec_chalkey->ecdsa_nid, ==,
		    part->ep_box->pdb_pub->ecdsa_nid);
	}
	VERIFY0(sshkey_demote(config->ec_chalkey, &chal->c_destkey));

	va_start(ap, descfmt);
	wrote = vsnprintf(desc, sizeof (desc), descfmt, ap);
	if (wrote >= sizeof (desc)) {
		rc = ENOMEM;
		goto out;
	}
	va_end(ap);
	chal->c_description = strdup(desc);

	part->ep_chal = chal;
	chal = NULL;

out:
	ebox_challenge_free(chal);
	return (rc);
}

static errf_t *
sshbuf_put_ebox_challenge_raw(struct sshbuf *buf, struct ebox_challenge *chal)
{
	int rc = 0;
	struct piv_ecdh_box *kb = chal->c_keybox;
	struct apdubuf *iv = &kb->pdb_iv;
	struct apdubuf *enc = &kb->pdb_enc;

	if ((rc = sshbuf_put_u8(buf, chal->c_version)) ||
	    (rc = sshbuf_put_u8(buf, chal->c_type)) ||
	    (rc = sshbuf_put_u8(buf, chal->c_id)))
		return (rc);
	if ((rc = sshbuf_put_eckey8(buf, chal->c_destkey->ecdsa)))
		return (rc);
	if ((rc = sshbuf_put_eckey8(buf, kb->pdb_ephem_pub->ecdsa)) ||
	    (rc = sshbuf_put_string8(buf, iv->b_data, iv->b_len)) ||
	    (rc = sshbuf_put_string8(buf, enc->b_data, enc->b_len)))
		return (rc);
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
		return (rc);

	return (rc);
}

errf_t *
sshbuf_put_ebox_challenge(struct sshbuf *buf, struct ebox_challenge *chal)
{
	struct piv_ecdh_box *box;
	struct sshbuf *cbuf;
	struct piv_ecdh_box *kb = chal->c_keybox;
	int rc = 0;

	box = piv_box_new();
	VERIFY(box != NULL);

	cbuf = sshbuf_new();
	VERIFY(cbuf != NULL);

	if ((rc = sshbuf_put_ebox_challenge_raw(cbuf, chal)))
		goto out;

	box->pdb_cipher = strdup(kb->pdb_cipher);
	box->pdb_kdf = strdup(kb->pdb_kdf);
	bcopy(kb->pdb_guid, box->pdb_guid, sizeof (box->pdb_guid));
	box->pdb_slot = kb->pdb_slot;
	box->pdb_guidslot_valid = kb->pdb_guidslot_valid;
	if ((rc = piv_box_set_datab(box, cbuf)))
		goto out;
	if ((rc = piv_box_seal_offline(kb->pdb_pub, box)))
		goto out;
	if ((rc = sshbuf_put_piv_box(buf, box)))
		goto out;
	rc = 0;

out:
	sshbuf_free(cbuf);
	piv_box_free(box);
	return (rc);
}

errf_t *
sshbuf_get_ebox_challenge(struct piv_ecdh_box *box,
    struct ebox_challenge **pchal)
{
	int rc = 0;
	struct sshbuf *buf = NULL, *kbuf = NULL;
	struct ebox_challenge *chal;
	uint8_t type;
	struct sshkey *k;
	size_t len;

	VERIFY0(piv_box_take_datab(box, &buf));

	chal = calloc(1, sizeof (struct ebox_challenge));
	VERIFY(chal != NULL);

	if ((rc = sshbuf_get_u8(buf, &chal->c_version)))
		goto out;
	if (chal->c_version != 1) {
		fprintf(stderr, "error: invalid challenge version: v%d "
		    "(only v1 is supported)\n", (int)chal->c_version);
		rc = ENOTSUP;
		goto out;
	}

	if ((rc = sshbuf_get_u8(buf, &type)))
		goto out;
	chal->c_type = (enum chaltype)type;

	if ((rc = sshbuf_get_u8(buf, &chal->c_id)))
		goto out;

	chal->c_destkey = (k = sshkey_new(KEY_ECDSA));
	k->ecdsa_nid = box->pdb_pub->ecdsa_nid;
	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY(k->ecdsa != NULL);
	if ((rc = sshbuf_get_eckey8(buf, k->ecdsa)) ||
	    (rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa))))
		goto out;

	chal->c_keybox = piv_box_new();
	VERIFY(chal->c_keybox != NULL);

	chal->c_keybox->pdb_cipher = strdup(box->pdb_cipher);
	chal->c_keybox->pdb_kdf = strdup(box->pdb_kdf);
	chal->c_keybox->pdb_free_str = B_TRUE;

	VERIFY0(sshkey_demote(box->pdb_pub, &chal->c_keybox->pdb_pub));

	chal->c_keybox->pdb_ephem_pub = (k = sshkey_new(KEY_ECDSA));
	k->ecdsa_nid = box->pdb_pub->ecdsa_nid;
	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY(k->ecdsa != NULL);
	if ((rc = sshbuf_get_eckey8(buf, k->ecdsa)) ||
	    (rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa))))
		goto out;

	if ((rc = sshbuf_get_string8(buf, &chal->c_keybox->pdb_iv.b_data,
	    &chal->c_keybox->pdb_iv.b_size)))
		goto out;
	chal->c_keybox->pdb_iv.b_len = chal->c_keybox->pdb_iv.b_size;
	if ((rc = sshbuf_get_string8(buf, &chal->c_keybox->pdb_enc.b_data,
	    &chal->c_keybox->pdb_enc.b_size)))
		goto out;
	chal->c_keybox->pdb_enc.b_len = chal->c_keybox->pdb_enc.b_size;

	kbuf = sshbuf_new();
	VERIFY(kbuf != NULL);

	while (sshbuf_len(buf) > 0) {
		uint8_t tag;
		sshbuf_reset(kbuf);
		if ((rc = sshbuf_get_u8(buf, &tag)) ||
		    (rc = sshbuf_get_stringb8(buf, kbuf)))
			goto out;
		len = sshbuf_len(kbuf);
		switch (tag) {
		case CTAG_HOSTNAME:
			chal->c_hostname = sshbuf_dup_string(kbuf);
			VERIFY(chal->c_hostname != NULL);
			break;
		case CTAG_CTIME:
			if ((rc = sshbuf_get_u64(kbuf, &chal->c_ctime)))
				goto out;
			break;
		case CTAG_DESCRIPTION:
			chal->c_description = sshbuf_dup_string(kbuf);
			VERIFY(chal->c_description != NULL);
			break;
		case CTAG_WORDS:
			if ((rc = sshbuf_get_u8(kbuf, &chal->c_words[0])) ||
			    (rc = sshbuf_get_u8(kbuf, &chal->c_words[1])) ||
			    (rc = sshbuf_get_u8(kbuf, &chal->c_words[2])) ||
			    (rc = sshbuf_get_u8(kbuf, &chal->c_words[3])))
				goto out;
			break;
		default:
			/* do nothing */
			break;
		}
	}

	*pchal = chal;
	chal = NULL;

out:
	sshbuf_free(buf);
	sshbuf_free(kbuf);
	ebox_challenge_free(chal);
	return (rc);
}

errf_t *
ebox_challenge_response(struct ebox_config *config, struct piv_ecdh_box *rbox,
    struct ebox_part **ppart)
{
	int rc = 0;
	struct ebox_part *part;
	struct sshbuf *buf = NULL;

	VERIFY(config->ec_chalkey != NULL);
	rc = piv_box_open_offline(config->ec_chalkey, rbox);
	if (rc)
		goto out;
	rc = piv_box_take_datab(rbox, &buf);
	if (rc)
		goto out;


out:
	piv_box_free(rbox);
	sshbuf_free(buf);
	return (rc);
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

int
ebox_stream_put(struct ebox_stream *es, struct iovec *vecs, size_t nvecs)
{
}

int
ebox_stream_get(struct ebox_stream *es, struct iovec *vecs, size_t nvecs)
{
}