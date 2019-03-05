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

#define	chalderrf(cause) \
    errf("InvalidDataError", cause, \
    "ebox challenge contained invalid or corrupted data")

#define	chalverrf(cause) \
    errf("NotSupportedError", cause, \
    "ebox challenge is not supported")

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
		    (rc = sshkey_putb(part->etp_cak, kbuf)) ||
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
	errf_t *err = NULL;

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
		switch (tag) {
		case EBOX_PART_PUBKEY:
			sshbuf_reset(kbuf);
			rc = sshbuf_get_stringb(buf, kbuf);
			if (rc) {
				err = ssherrf("sshbuf_get_stringb", rc);
				goto out;
			}
			rc = sshkey_fromb(kbuf, &tpart->etp_pubkey);
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
			break;
		case EBOX_PART_BOX:
			err = sshbuf_get_piv_box(buf, &part->ep_box);
			if (err)
				goto out;
			break;
		default:
			err = errf("TagError", NULL,
			    "invalid ebox part tag 0x%02x at +%lx",
			    tag, buf->off);
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
	sshbuf_free(kbuf);
	ebox_part_free(part);
	return (err);
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
	if (tconfig->etc_type == EBOX_PRIMARY &&
	    tconfig->etc_n > 1) {
		err = errf("InvalidConfig", NULL,
		    "ebox config is PRIMARY but has n > 1 (n = %d)",
		    tconfig->etc_n);
		goto out;
	}
	id = 1;

	if ((err = sshbuf_get_ebox_part(buf, &part)))
		goto out;
	part->ep_id = id++;
	config->ec_parts = part;
	tpart = part->ep_tpl;
	config->ec_tpl->etc_parts = tpart;

	for (i = 1; i < tconfig->etc_m; ++i) {
		if ((err = sshbuf_get_ebox_part(buf, &part->ep_next)))
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
	if (type != EBOX_KEY && type != EBOX_STREAM) {
		err = boxderrf(errf("EboxTypeError", NULL,
		    "buffer does not contain an ebox"));
		goto out;
	}
	box->e_type = (enum ebox_type)type;

	if ((rc = sshbuf_get_cstring8(buf, &box->e_rcv_cipher, NULL))) {
		err = boxderrf(ssherrf("sshbuf_get_u8", rc));
		goto out;
	}
	rc = sshbuf_get_string8(buf, &box->e_rcv_iv.b_data, 
	    &box->e_rcv_iv.b_len);
	if (rc) {
		err = boxderrf(ssherrf("sshbuf_get_string8", rc));
		goto out;
	}

	rc = sshbuf_get_string8(buf, &box->e_rcv_enc.b_data,
	    &box->e_rcv_enc.b_len);
	if (rc) {
		err = boxderrf(ssherrf("sshbuf_get_string8", rc));
		goto out;
	}

	if ((rc = sshbuf_get_u8(buf, &nconfigs))) {
		err = boxderrf(ssherrf("sshbuf_get_u8", rc));
		goto out;
	}

	if ((err = sshbuf_get_ebox_config(buf, &config))) {
		err = boxderrf(err);
		goto out;
	}
	box->e_configs = config;
	tconfig = config->ec_tpl;
	box->e_tpl->et_configs = tconfig;

	for (i = 1; i < nconfigs; ++i) {
		if ((err = sshbuf_get_ebox_config(buf, &config->ec_next))) {
			err = boxderrf(err);
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
sshbuf_put_ebox_part(struct sshbuf *buf, struct ebox_part *part)
{
	struct ebox_tpl_part *tpart;
	struct sshbuf *kbuf;
	int rc = 0;
	errf_t *err;

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
		    (rc = sshkey_putb(tpart->etp_cak, buf)) ||
		    (rc = sshbuf_put_stringb(buf, kbuf))) {
			err = ssherrf("sshbuf_put_*", rc);
			goto out;
		}
	}

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_BOX))) {
		err = ssherrf("sshbuf_put_u8", rc);
		goto out;
	}
	if ((err = sshbuf_put_piv_box(buf, part->ep_box)))
		goto out;

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
sshbuf_put_ebox_config(struct sshbuf *buf, struct ebox_config *config)
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

	part = config->ec_parts;
	for (; part != NULL; part = part->ep_next) {
		if ((err = sshbuf_put_ebox_part(buf, part)))
			return (err);
	}

	return (NULL);
}

errf_t *
sshbuf_put_ebox(struct sshbuf *buf, struct ebox *ebox)
{
	uint8_t nconfigs = 0;
	int rc = 0;
	struct ebox_config *config;
	errf_t *err;

	config = ebox->e_configs;
	for (; config != NULL; config = config->ec_next) {
		++nconfigs;
	}

	if ((rc = sshbuf_put_u8(buf, 0xEB)) ||
	    (rc = sshbuf_put_u8(buf, 0x0C)) ||
	    (rc = sshbuf_put_u8(buf, 0x01)) ||
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

	if ((rc = sshbuf_put_u8(buf, nconfigs))) {
		return (ssherrf("sshbuf_put_u8", rc));
	}

	config = ebox->e_configs;
	for (; config != NULL; config = config->ec_next) {
		if ((err = sshbuf_put_ebox_config(buf, config)))
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

struct piv_ecdh_box *
ebox_part_box(const struct ebox_part *part)
{
	return (part->ep_box);
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
	if (padding > blocksz || padding <= 0) {
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

	return (ERRF_OK);
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

	return (errf("InsufficientParts", NULL, "ebox_unlock requires at "
	    "least one part box to be unlocked"));
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

	shares = calloc(m, sizeof (sss_Keyshare));

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

	ebox->e_rcv_key.b_data = calloc(1, sizeof (sss_Keyshare));
	ebox->e_rcv_key.b_len = sizeof (sss_Keyshare);
	sss_combine_keyshares(ebox->e_rcv_key.b_data,
	    (const sss_Keyshare *)shares, n);

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
	rc = sshbuf_get_string8(buf, &ebox->e_key, &ebox->e_keylen);
	if (rc) {
		err = ssherrf("sshbuf_get_string8", rc);
		goto out;
	}

	for (part = config->ec_parts; part != NULL; part = part->ep_next) {
		if (part->ep_share != NULL) {
			explicit_bzero(part->ep_share, part->ep_sharelen);
			free(part->ep_share);
		}
		if (!piv_box_sealed(part->ep_box)) {
			explicit_bzero(part->ep_box->pdb_plain.b_data,
			    part->ep_box->pdb_plain.b_size);
			free(part->ep_box->pdb_plain.b_data);
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
	char hostname[HOST_NAME_MAX] = {0};
	char desc[255] = {0};
	va_list ap;
	size_t wrote;
	errf_t *err = NULL;

	chal = calloc(1, sizeof (struct ebox_challenge));
	if (chal == NULL)
		return (ERRF_NOMEM);

	chal->c_version = 1;
	chal->c_type = CHAL_RECOVERY;
	chal->c_id = part->ep_id;
	if (gethostname(hostname, sizeof (hostname))) {
		err = errfno("gethostname", errno, NULL);
		goto out;
	}
	chal->c_hostname = strdup(hostname);
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

	part->ep_chal = chal;
	chal = NULL;

out:
	ebox_challenge_free(chal);
	return (err);
}

static errf_t *
sshbuf_put_ebox_challenge_raw(struct sshbuf *buf,
    const struct ebox_challenge *chal)
{
	int rc = 0;
	const struct piv_ecdh_box *kb = chal->c_keybox;
	const struct apdubuf *iv = &kb->pdb_iv;
	const struct apdubuf *enc = &kb->pdb_enc;

	if ((rc = sshbuf_put_u8(buf, chal->c_version)) ||
	    (rc = sshbuf_put_u8(buf, chal->c_type)) ||
	    (rc = sshbuf_put_u8(buf, chal->c_id)))
		return (ssherrf("sshbuf_put_u8", rc));
	if ((rc = sshbuf_put_eckey8(buf, chal->c_destkey->ecdsa)))
		return (ssherrf("sshbuf_put_eckey8", rc));
	if ((rc = sshbuf_put_eckey8(buf, kb->pdb_ephem_pub->ecdsa)) ||
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
	struct sshkey *k;

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

	chal->c_destkey = (k = sshkey_new(KEY_ECDSA));
	if (k == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	k->ecdsa_nid = box->pdb_pub->ecdsa_nid;
	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	if (k->ecdsa == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	if ((rc = sshbuf_get_eckey8(buf, k->ecdsa))) {
		err = ssherrf("sshbuf_get_eckey8", rc);
		goto out;
	}
	if ((rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa)))) {
		err = ssherrf("sshkey_ec_validate_public", rc);
		goto out;
	}

	chal->c_keybox = piv_box_new();
	if (chal->c_keybox == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}

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

	chal->c_keybox->pdb_ephem_pub = (k = sshkey_new(KEY_ECDSA));
	if (k == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	k->ecdsa_nid = box->pdb_pub->ecdsa_nid;
	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	if (k->ecdsa == NULL) {
		err = ERRF_NOMEM;
		goto out;
	}
	if ((rc = sshbuf_get_eckey8(buf, k->ecdsa))) {
		err = ssherrf("sshbuf_get_eckey8", rc);
		goto out;
	}
	if ((rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa)))) {
		err = ssherrf("sshkey_ec_validate_public", rc);
		goto out;
	}

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
	size_t klen;

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
			if ((rc = sshbuf_get_string8(buf, &keypiece, &klen))) {
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
	if (part->ep_share != NULL)
		explicit_bzero(part->ep_share, part->ep_sharelen);
	free(part->ep_share);
	part->ep_sharelen = klen;
	part->ep_share = keypiece;
	*ppart = part;
	keypiece = NULL;
	err = NULL;

out:
	if (keypiece != NULL)
		explicit_bzero(keypiece, klen);
	free(keypiece);
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
	size_t klen;
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

	explicit_bzero(keypiece, klen);
	free(keypiece);
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
	if (keypiece != NULL)
		explicit_bzero(keypiece, klen);
	free(keypiece);
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

int
ebox_stream_put(struct ebox_stream *es, struct iovec *vecs, size_t nvecs)
{
}

int
ebox_stream_get(struct ebox_stream *es, struct iovec *vecs, size_t nvecs)
{
}
