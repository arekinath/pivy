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
	struct sshbuf *buf, *rbuf;

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

	buf = sshbuf_new();
	VERIFY0(sshbuf_put_ebox_tpl(buf, tpl));

	rbuf = sshbuf_fromb(buf);
	VERIFY0(sshbuf_get_ebox_tpl(rbuf, &tpl));

	VERIFY3U(tpl->et_configs->etc_n, ==, 1);
	VERIFY3U(tpl->et_configs->etc_m, ==, 1);
	VERIFY3S(tpl->et_configs->etc_type, ==, EBOX_PRIMARY);
	VERIFY0(strcmp("testing", tpl->et_configs->etc_parts->etp_name));

	fprintf(stdout, "%s\n", sshbuf_dtob64(buf));

	return (0);
}
