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
#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <strings.h>
#include <limits.h>

#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <wintypes.h>
#include <winscard.h>
#endif

#include <sys/types.h>
#include <sys/errno.h>
#include "debug.h"
#if defined(__sun)
#include <sys/fork.h>
#endif
#include <sys/wait.h>

#include "libssh/sshkey.h"
#include "libssh/sshbuf.h"
#include "libssh/digest.h"

#include "sss/hazmat.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if defined(__sun)
#include <libtecla.h>
#else
#include <editline/readline.h>
#endif

#include "tlv.h"
#include "ebox.h"
#include "piv.h"
#include "bunyan.h"

int
main(int argc, char *argv[])
{
	struct ebox_tpl *tpl;
	struct ebox_tpl_config *config;
	struct ebox_tpl_part *part;
	struct ebox *ebox, *ebox2;
	struct sshbuf *buf, *rbuf;
	uint8_t key[8] = {1,2,3,4,5,6,7,8};

	tpl = calloc(1, sizeof (struct ebox_tpl));
	config = calloc(1, sizeof (struct ebox_tpl_config));
	part = calloc(1, sizeof (struct ebox_tpl_part));

	part->etp_name = strdup("testing");
	VERIFY0(sshkey_generate(KEY_ECDSA, 256, &part->etp_pubkey));
	part->etp_guid[0] = 0x12;
	part->etp_guid[1] = 0x34;

	config->etc_parts = part;
	config->etc_n = 1;
	config->etc_m = 1;
	config->etc_type = EBOX_PRIMARY;

	tpl->et_configs = config;

	config = (config->etc_next = calloc(1, sizeof (struct ebox_tpl_config)));
	config->etc_n = 2;
	config->etc_m = 2;
	config->etc_type = EBOX_RECOVERY;
	part = calloc(1, sizeof (struct ebox_tpl_part));
	part->etp_name = strdup("k1");
	VERIFY0(sshkey_generate(KEY_ECDSA, 256, &part->etp_pubkey));
	part->etp_guid[0] = 0x21;
	part->etp_guid[1] = 0x43;
	config->etc_parts = part;
	part = (part->etp_next = calloc(1, sizeof (struct ebox_tpl_part)));
	part->etp_name = strdup("k2");
	VERIFY0(sshkey_generate(KEY_ECDSA, 256, &part->etp_pubkey));
	part->etp_guid[0] = 0x44;
	part->etp_guid[1] = 0x55;

	ebox = ebox_create(tpl, key, sizeof (key), NULL, 0);

	buf = sshbuf_new();
	VERIFY0(sshbuf_put_ebox(buf, ebox));

	fprintf(stdout, "%s\n", sshbuf_dtob64(buf));

	rbuf = sshbuf_fromb(buf);
	VERIFY0(sshbuf_get_ebox(rbuf, &ebox2));

	return (0);
}
