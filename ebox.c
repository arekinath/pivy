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
#include <sys/errno.h>

#include "libssh/sshkey.h"
#include "libssh/sshbuf.h"
#include "libssh/digest.h"

#include "sss/hazmat.h"

#include "debug.h"
#include "tlv.h"
#include "ebox.h"
#include "piv.h"
#include "bunyan.h"

#include "words.h"

int
ebox_tpl_to_binary(struct ebox_tpl *tpl, uint8_t **output, size_t *len)
{
}

int
ebox_tpl_from_binary(const uint8_t *input, size_t len, struct ebox_tpl **tpl)
{
}

void
ebox_tpl_free(struct ebox_tpl *tpl)
{
	struct ebox_tpl_config *config, *nconfig;
	if (tpl == NULL)
		return;
	VERIFY(tpl->et_priv == NULL);
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
	VERIFY(config->etc_priv == NULL);
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
	VERIFY(part->etp_priv == NULL);
	free(part->etp_name);
	sshkey_free(part->etp_pubkey);
	sshkey_free(part->etp_cak);
	free(part);
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
			fprintf(stderr, "unknown tag %d\n", tag);
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
