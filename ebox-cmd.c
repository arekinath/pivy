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
#include "errf.h"
#include "ebox.h"
#include "piv.h"
#include "bunyan.h"

int
main(int argc, char *argv[])
{
	errf_t *err = NULL;
	struct ebox_tpl *tpl;
	struct ebox_tpl_config *config;
	struct ebox_tpl_part *part;
	struct ebox *ebox, *ebox2;
	struct sshbuf *buf, *rbuf;
	struct sshkey *k;
	//uint8_t key[8] = {1,2,3,4,5,6,7,8};
	uint8_t guid[16] = { 0x12, 0x34 };

	tpl = ebox_tpl_alloc();

	/* First our primary config for a single yubikey */
	config = ebox_tpl_config_alloc(EBOX_PRIMARY);

	VERIFY0(sshkey_generate(KEY_ECDSA, 256, &k));
	part = ebox_tpl_part_alloc(guid, sizeof (guid), k);
	sshkey_free(k);
	ebox_tpl_part_set_name(part, "testing");
	ebox_tpl_config_add_part(config, part);

	ebox_tpl_add_config(tpl, config);

	/* And a secondary 2/2 recovery config */
	config = ebox_tpl_config_alloc(EBOX_RECOVERY);

	VERIFY0(sshkey_generate(KEY_ECDSA, 256, &k));
	guid[0] = 0x23;
	guid[1] = 0x43;
	part = ebox_tpl_part_alloc(guid, sizeof (guid), k);
	sshkey_free(k);
	ebox_tpl_part_set_name(part, "k1");
	ebox_tpl_config_add_part(config, part);

	VERIFY0(sshkey_generate(KEY_ECDSA, 256, &k));
	guid[0] = 0x41;
	guid[1] = 0x26;
	part = ebox_tpl_part_alloc(guid, sizeof (guid), k);
	sshkey_free(k);
	ebox_tpl_part_set_name(part, "k2");
	ebox_tpl_config_add_part(config, part);

	ebox_tpl_config_set_n(config, 2);

	ebox_tpl_add_config(tpl, config);

	//ebox = ebox_create(tpl, key, sizeof (key), NULL, 0);

	buf = sshbuf_new();
	err = sshbuf_put_ebox_tpl(buf, tpl);
	if (err)
		perrfexit(err);

	fprintf(stdout, "%s\n", sshbuf_dtob64(buf));

	/*rbuf = sshbuf_fromb(buf);
	VERIFY0(sshbuf_get_ebox(rbuf, &ebox2));*/

	return (0);
}