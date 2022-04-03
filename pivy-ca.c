/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2021, The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
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
#include <err.h>

#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <wintypes.h>
#include <winscard.h>
#endif

#include <sys/types.h>
#include <sys/errno.h>
#if defined(__sun)
#include <sys/fork.h>
#endif
#include <sys/wait.h>

#include "openssh/sshkey.h"
#include "openssh/sshbuf.h"
#include "openssh/digest.h"
#include "openssh/ssherr.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <json_object.h>
#include <json_tokener.h>

int PEM_write_X509(FILE *fp, X509 *x);

#include "utils.h"
#include "tlv.h"
#include "piv.h"
#include "bunyan.h"
#include "utils.h"
#include "debug.h"
#include "pkinit_asn1.h"
#include "piv-ca.h"
#include "ebox-cmd.h"

/* We need the piv_cert_comp enum */
#include "piv-internal.h"

#if defined(__sun) || defined(__APPLE__)
#include <netinet/in.h>
#define	be16toh(v)	(ntohs(v))
#else
#include <endian.h>
#endif

boolean_t debug = B_FALSE;
static boolean_t parseable = B_FALSE;
static boolean_t enum_all_retired = B_FALSE;
static const char *cn = NULL;
static const char *upn = NULL;
static boolean_t save_pinfo_admin = B_TRUE;
static uint8_t *guid = NULL;
static size_t guid_len = 0;
static uint min_retries = 1;
static struct sshkey *opubkey = NULL;
static const char *pin = NULL;
static const uint8_t DEFAULT_ADMIN_KEY[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};
static const uint8_t *admin_key = DEFAULT_ADMIN_KEY;

static enum ykpiv_pin_policy pinpolicy = YKPIV_PIN_DEFAULT;
static enum ykpiv_touch_policy touchpolicy = YKPIV_TOUCH_DEFAULT;

static struct piv_token *ks = NULL;
static struct piv_token *selk = NULL;
//static struct piv_token *sysk = NULL;
static struct piv_slot *override = NULL;

SCARDCONTEXT ctx;

#ifndef LINT
#define	funcerrf(cause, fmt, ...)	\
    errf(__func__, cause, fmt , ##__VA_ARGS__)
#define pcscerrf(call, rv)	\
    errf("PCSCError", NULL, call " failed: %d (%s)", \
    rv, pcsc_stringify_error(rv))
#endif

enum pivca_exit_status {
	/*EXIT_OK = 0,
	EXIT_USAGE = 1,
	EXIT_ERROR = 2,
	EXIT_INTERACTIVE = 3,
	EXIT_PIN = 4,
	EXIT_PIN_LOCKED = 5,
	EXIT_ALREADY_UNLOCKED = 6,*/
	EXIT_NO_CARD = 7,
	EXIT_IO_ERROR = 8,

	EXIT_BAD_ARGS = EXIT_USAGE,
};

#if defined(__sun)
const char *
_umem_debug_init()
{
	return ("guards");
}
#endif

void
usage(void)
{
	exit(EXIT_BAD_ARGS);
}

static errf_t *
cmd_setup(void)
{
	/*
	 * collect info:
	 *  - CA's DN,
	 *  - CRL URLs
	 *  - constraints (e.g. nameconstraints)
	 *  - CRL timing settings
	 *  - key gen settings
	 *
	 * provision config:
	 *  - pin, puk and admin key
	 *  - require attestation? choose attestation CAs
	 *  - templates and slots
	 *  - variable definitions (and free variables)
	 */

}

const char *optstring = "";

int
main(int argc, char *argv[])
{
	LONG rv;
	errf_t *err = ERRF_OK;
	extern char *optarg;
	extern int optind;
	int c;
	uint len;
	char *ptr;
	uint8_t *buf;
	uint d_level = 0;
	enum piv_alg overalg = 0;
	boolean_t hasover = B_FALSE;
	char *v;

	bunyan_init();
	bunyan_set_name("pivy-ca");

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'd':
			bunyan_set_level(BNY_TRACE);
			if (++d_level > 1)
				piv_full_apdu_debug = B_TRUE;
			break;
		}
	}

	if (optind >= argc) {
		warnx("operation required");
		usage();
	}

	const char *op = argv[optind++];

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
	if (rv != SCARD_S_SUCCESS) {
		errfx(EXIT_IO_ERROR, pcscerrf("SCardEstablishContext", rv),
		    "failed to initialise libpcsc");
	}

	struct ca_new_args *cna;
	X509_NAME *dn;
	struct ebox_tpl *tpl;
	struct ca *ca;
	struct piv_token *tokens, *tok;

	err = piv_enumerate(ctx, &tokens);
	if (err)
		errfx(EXIT_IO_ERROR, err, "failed to enumerate PIV tokens");
	if (tokens == NULL)
		errx(EXIT_NO_CARD, "no PIV cards/tokens found");
	for (tok = tokens; tok != NULL; tok = piv_token_next(tok)) {
		if (!piv_token_has_chuid(tok))
			break;
	}
	if (tok == NULL || piv_token_has_chuid(tok))
		errx(EXIT_NO_CARD, "no uninit'd PIV token/card found");

	parse_tpl_path_env();

	dn = X509_NAME_new();
	err = parse_dn("cn=Cyber OpenVPN CA,ou=EAIT,o=The University of Queensland", dn);
	if (err)
		errfx(EXIT_FAILURE, err, "parsing dn");

	cna = cana_new();
	cana_initial_pin(cna, "123456");
	cana_initial_puk(cna, "12345678");
	cana_initial_admin_key(cna, PIV_ALG_3DES, DEFAULT_ADMIN_KEY,
	    sizeof (DEFAULT_ADMIN_KEY));
	cana_key_alg(cna, PIV_ALG_RSA2048);
	cana_dn(cna, dn);
	tpl = read_tpl_file("default");
	cana_pin_tpl(cna, "default", tpl);
	tpl = read_tpl_file("eait3");
	cana_backup_tpl(cna, "eait3", tpl);
	cana_puk_tpl(cna, "eait3", tpl);

	err = ca_generate("cyber-vpn-ca", cna, tok, &ca);
	if (err)
		errfx(EXIT_FAILURE, err, "generating CA");

	ca_close(ca);

	return (0);
}

void
cleanup_exit(int i)
{
	exit(i);
}
