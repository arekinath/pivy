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
#include <limits.h>
#include <sys/errno.h>

#include "libssh/sshkey.h"
#include "libssh/sshbuf.h"
#include "libssh/digest.h"
#include "libssh/digest.h"
#include "libssh/cipher.h"

#include "sss/hazmat.h"

#include "debug.h"
#include "tlv.h"
#include "ebox.h"
#include "piv.h"
#include "bunyan.h"

#include "words.h"

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

static int
sshbuf_put_ebox_tpl_part(struct sshbuf *buf, struct ebox_tpl_part *part)
{
	int rc = 0;
	struct sshbuf *kbuf;

	kbuf = sshbuf_new();
	VERIFY(kbuf != NULL);

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_PUBKEY)) ||
	    (rc = sshkey_putb(part->etp_pubkey, kbuf)) ||
	    (rc = sshbuf_put_stringb(buf, kbuf)))
		goto out;

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_GUID)) ||
	    (rc = sshbuf_put_string8(buf, part->etp_guid,
	    sizeof (part->etp_guid))))
		goto out;

	if (part->etp_name != NULL) {
		if ((rc = sshbuf_put_u8(buf, EBOX_PART_NAME)) ||
		    (rc = sshbuf_put_cstring8(buf, part->etp_name)))
			goto out;
	}

	if (part->etp_cak != NULL) {
		sshbuf_reset(kbuf);
		if ((rc = sshbuf_put_u8(buf, EBOX_PART_CAK)) ||
		    (rc = sshkey_putb(part->etp_cak, buf)) ||
		    (rc = sshbuf_put_stringb(buf, kbuf)))
			goto out;
	}

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_END)))
		goto out;

	rc = 0;

out:
	sshbuf_free(kbuf);
	return (rc);
}

static int
sshbuf_get_ebox_tpl_part(struct sshbuf *buf, struct ebox_tpl_part **ppart)
{
	struct ebox_tpl_part *part;
	struct sshbuf *kbuf;
	int rc = 0;
	size_t len;
	uint8_t tag, *guid;

	part = calloc(1, sizeof (struct ebox_tpl_part));
	VERIFY(part != NULL);

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
			rc = sshkey_fromb(kbuf, &part->etp_pubkey);
			if (rc)
				goto out;
			break;
		case EBOX_PART_CAK:
			sshbuf_reset(kbuf);
			rc = sshbuf_get_stringb(buf, kbuf);
			if (rc)
				goto out;
			rc = sshkey_fromb(kbuf, &part->etp_cak);
			if (rc)
				goto out;
			break;
		case EBOX_PART_NAME:
			rc = sshbuf_get_cstring8(buf, &part->etp_name, &len);
			if (rc)
				goto out;
			break;
		case EBOX_PART_GUID:
			rc = sshbuf_get_string8(buf, &guid, &len);
			if (rc)
				goto out;
			if (len != sizeof (part->etp_guid)) {
				rc = EBADF;
				goto out;
			}
			bcopy(guid, part->etp_guid, len);
			free(guid);
			guid = NULL;
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

	*ppart = part;
	part = NULL;
out:
	sshbuf_free(kbuf);
	ebox_tpl_part_free(part);
	return (rc);
}

static int
sshbuf_put_ebox_tpl_config(struct sshbuf *buf, struct ebox_tpl_config *config)
{
	struct ebox_tpl_part *part;
	int rc = 0;

	if ((rc = sshbuf_put_u8(buf, config->etc_type)) ||
	    (rc = sshbuf_put_u8(buf, config->etc_n)) ||
	    (rc = sshbuf_put_u8(buf, config->etc_m)))
		return (rc);

	for (part = config->etc_parts; part != NULL; part = part->etp_next) {
		if ((rc = sshbuf_put_ebox_tpl_part(buf, part)))
			return (rc);
	}

	return (0);
}

static int
sshbuf_get_ebox_tpl_config(struct sshbuf *buf, struct ebox_tpl_config **pconfig)
{
	struct ebox_tpl_config *config;
	struct ebox_tpl_part *part;
	int rc = 0;
	uint8_t type;
	uint i;

	config = calloc(1, sizeof (struct ebox_tpl_config));
	VERIFY(config != NULL);

	if ((rc = sshbuf_get_u8(buf, &type)) ||
	    (rc = sshbuf_get_u8(buf, &config->etc_n)) ||
	    (rc = sshbuf_get_u8(buf, &config->etc_m)))
		goto out;
	config->etc_type = (enum ebox_config_type)type;
	if (config->etc_type != EBOX_PRIMARY &&
	    config->etc_type != EBOX_RECOVERY) {
		fprintf(stderr, "bad etc_type\n");
		rc = EBADF;
		goto out;
	}
	if (config->etc_type == EBOX_PRIMARY &&
	    config->etc_n > 1) {
		fprintf(stderr, "primary n>1\n");
		rc = EBADF;
		goto out;
	}

	if ((rc = sshbuf_get_ebox_tpl_part(buf, &part)))
		goto out;
	config->etc_parts = part;

	for (i = 1; i < config->etc_m; ++i) {
		if ((rc = sshbuf_get_ebox_tpl_part(buf, &part->etp_next)))
			goto out;
		part = part->etp_next;
	}

	*pconfig = config;
	config = NULL;

out:
	ebox_tpl_config_free(config);
	return (rc);
}

int
sshbuf_put_ebox_tpl(struct sshbuf *buf, struct ebox_tpl *tpl)
{
	uint8_t nconfigs = 0;
	int rc = 0;
	struct ebox_tpl_config *config;

	config = tpl->et_configs;
	for (; config != NULL; config = config->etc_next) {
		++nconfigs;
	}

	if ((rc = sshbuf_put_u8(buf, 0xEB)) ||
	    (rc = sshbuf_put_u8(buf, 0x0C)) ||
	    (rc = sshbuf_put_u8(buf, 0x01)) ||
	    (rc = sshbuf_put_u8(buf, EBOX_TEMPLATE)))
		return (rc);

	if ((rc = sshbuf_put_u8(buf, nconfigs)))
		return (rc);

	config = tpl->et_configs;
	for (; config != NULL; config = config->etc_next) {
		if ((rc = sshbuf_put_ebox_tpl_config(buf, config)))
			return (rc);
	}

	return (0);
}

int
sshbuf_get_ebox_tpl(struct sshbuf *buf, struct ebox_tpl **ptpl)
{
	struct ebox_tpl *tpl;
	struct ebox_tpl_config *config;
	int rc = 0;
	uint8_t ver, magic[2], type, nconfigs;
	uint i;

	tpl = calloc(1, sizeof (struct ebox_tpl));
	VERIFY(tpl != NULL);

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
	if (type != EBOX_TEMPLATE) {
		bunyan_log(TRACE, "not an ebox template",
		    "type", BNY_UINT, (uint)type, NULL);
		rc = EDOM;
		goto out;
	}
	if ((rc = sshbuf_get_u8(buf, &nconfigs)))
		goto out;

	if ((rc = sshbuf_get_ebox_tpl_config(buf, &config)))
		goto out;
	tpl->et_configs = config;

	for (i = 1; i < nconfigs; ++i) {
		if ((rc = sshbuf_get_ebox_tpl_config(buf, &config->etc_next)))
			goto out;
		config = config->etc_next;
	}

	*ptpl = tpl;
	tpl = NULL;

out:
	ebox_tpl_free(tpl);
	return (rc);
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
	//ebox_challenge_free(part->ep_chal);
	piv_box_free(part->ep_resp);
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

	es->es_ebox = ebox_create(tpl, key, keylen, NULL, 0);
	VERIFY(es->es_ebox != NULL);

	explicit_bzero(key, keylen);
	free(key);

	return (es);
}

static int
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

	*ppart = part;
	part = NULL;
out:
	sshbuf_free(kbuf);
	ebox_part_free(part);
	return (rc);
}

static int
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

int
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

static int
sshbuf_put_ebox_part(struct sshbuf *buf, struct ebox_part *part)
{
	struct ebox_tpl_part *tpart;
	struct sshbuf *kbuf;
	int rc = 0;

	tpart = part->ep_tpl;

	kbuf = sshbuf_new();
	VERIFY(kbuf != NULL);

	if ((rc = sshbuf_put_u8(buf, EBOX_PART_PUBKEY)) ||
	    (rc = sshkey_putb(tpart->etp_pubkey, kbuf)) ||
	    (rc = sshbuf_put_stringb(buf, kbuf)))
		goto out;

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

static int
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

int
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

static void
ebox_decrypt_recovery(struct ebox *box)
{
	const struct sshcipher *cipher;
	struct sshcipher_ctx *cctx;
	size_t ivlen, authlen, blocksz, keylen;
	size_t plainlen, padding;
	size_t enclen, reallen;
	uint8_t *iv, *enc, *plain, *key;
	size_t i;

	cipher = cipher_by_name(box->e_rcv_cipher);
	VERIFY(cipher != NULL);
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
	VERIFY0(cipher_crypt(cctx, 0, plain, enc, enclen - authlen, 0,
	    authlen));
	cipher_free(cctx);

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

struct ebox *
ebox_create(const struct ebox_tpl *tpl, const uint8_t *key, size_t keylen,
    const uint8_t *token, size_t tokenlen)
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


	return (box);
}

int
ebox_stream_put(struct ebox_stream *es, struct iovec *vecs, size_t nvecs)
{
}

int
ebox_stream_get(struct ebox_stream *es, struct iovec *vecs, size_t nvecs)
{
}
