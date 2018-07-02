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

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <libzfs.h>
#include <libzfs_core.h>
#include <libnvpair.h>

#define USING_SPL
#include "tlv.h"
#include "piv.h"
#include "bunyan.h"
#include "json.h"

static struct piv_token *ks = NULL;
static struct piv_token *selk = NULL;
static int min_retries = 2;

static libzfs_handle_t *zfshdl = NULL;

const char *optstring = "d";

extern char *buf_to_hex(const uint8_t *buf, size_t len, boolean_t spaces);

static uint8_t *
parse_hex(const char *str, uint *outlen)
{
	const uint len = strlen(str);
	uint8_t *data = calloc(1, len / 2 + 1);
	uint idx = 0;
	uint shift = 4;
	uint i;
	for (i = 0; i < len; ++i) {
		const char c = str[i];
		boolean_t skip = B_FALSE;
		if (c >= '0' && c <= '9') {
			data[idx] |= (c - '0') << shift;
		} else if (c >= 'a' && c <= 'f') {
			data[idx] |= (c - 'a' + 0xa) << shift;
		} else if (c >= 'A' && c <= 'F') {
			data[idx] |= (c - 'A' + 0xA) << shift;
		} else if (c == ':' || c == ' ' || c == '\t' ||
		    c == '\n' || c == '\r') {
			skip = B_TRUE;
		} else {
			fprintf(stderr, "error: invalid hex digit: '%c'\n", c);
			exit(1);
		}
		if (skip == B_FALSE) {
			if (shift == 4) {
				shift = 0;
			} else if (shift == 0) {
				++idx;
				shift = 4;
			}
		}
	}
	if (shift == 0) {
		fprintf(stderr, "error: odd number of hex digits "
		    "(incomplete)\n");
		exit(1);
	}
	*outlen = idx;
	return (data);
}

static void
assert_pin(struct piv_token *pk)
{
	int rv;
	uint retries = min_retries;
	char prompt[64];
	char *guid;
	char *pin = NULL;
	guid = buf_to_hex(pk->pt_guid, 4, B_FALSE);
	snprintf(prompt, 64, "Enter PIV PIN for token %s: ", guid);
	do {
		pin = getpass(prompt);
	} while (pin == NULL && errno == EINTR);
	if (pin == NULL && errno == ENXIO) {
		piv_txn_end(pk);
		fprintf(stderr, "error: a PIN code is required to "
		    "unlock token %s\n", guid);
		exit(4);
	} else if (pin == NULL) {
		piv_txn_end(pk);
		perror("getpass");
		exit(3);
	}
	pin = strdup(pin);
	free(guid);

	rv = piv_verify_pin(pk, pin, &retries);
	if (rv == EACCES) {
		piv_txn_end(pk);
		if (retries == 0) {
			fprintf(stderr, "error: token is locked due to too "
			    "many invalid PIN code entries\n");
			exit(10);
		}
		fprintf(stderr, "error: invalid PIN code (%d attempts "
		    "remaining)\n", retries);
		exit(4);
	} else if (rv == EAGAIN) {
		piv_txn_end(pk);
		fprintf(stderr, "error: insufficient retries remaining "
		    "(%d left)\n", retries);
		exit(4);
	} else if (rv != 0) {
		piv_txn_end(pk);
		fprintf(stderr, "error: failed to verify PIN\n");
		exit(4);
	}
}

const char *
_umem_debug_init()
{
	return ("guards");
}

void
usage(void)
{
	fprintf(stderr,
	    "usage: piv-zfs [options] operation\n");
	exit(3);
}

int
main(int argc, char *argv[])
{
	LONG rv;
	SCARDCONTEXT ctx;
	extern char *optarg;
	extern int optind;
	int c, rc;

	bunyan_init();
	bunyan_set_name("piv-zfs");

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'd':
			bunyan_set_level(TRACE);
			break;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "error: operation required\n");
		usage();
	}

	const char *op = argv[optind++];

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardEstablishContext failed: %s\n",
		    pcsc_stringify_error(rv));
		return (1);
	}

	ks = piv_enumerate(ctx);

	zfshdl = libzfs_init();

	if (strcmp(op, "unlock") == 0) {
		const char *fsname;
		zfs_handle_t *ds;
		nvlist_t *props, *prop, *config, *opts, *opt;
		uint32_t nopts;
		uint64_t kstatus;
		size_t jsonlen;
		char *json;
		int32_t ver;
		int i;

		if (optind >= argc) {
			fprintf(stderr, "error: target zfs required\n");
			usage();
		}
		fsname = argv[optind++];

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		ds = zfs_open(zfshdl, fsname, ZFS_TYPE_DATASET);
		if (ds == NULL) {
			fprintf(stderr, "error: failed to open dataset %s\n",
			    fsname);
			exit(1);
		}

		props = zfs_get_all_props(ds);
		VERIFY(props != NULL);

		if (nvlist_lookup_nvlist(props, "keystatus", &prop)) {
			fprintf(stderr, "error: no keystatus property "
			    "could be read on dataset %s\n", fsname);
			exit(1);
		}
		VERIFY0(nvlist_lookup_uint64(prop, "value", &kstatus));

		if (kstatus == ZFS_KEYSTATUS_AVAILABLE) {
			fprintf(stderr, "error: key already loaded for %s\n",
			    fsname);
			exit(1);
		}

		if (nvlist_lookup_nvlist(props, "rfd77:config", &prop)) {
			fprintf(stderr, "error: no rfd77:config property "
			    "could be read on dataset %s\n", fsname);
			exit(1);
		}

		VERIFY0(nvlist_lookup_string(prop, "value", &json));

		if (nvlist_parse_json(json, strlen(json), &config,
		    NVJSON_FORCE_INTEGER | NVJSON_ERRORS_TO_STDERR, NULL)) {
			fprintf(stderr, "error: failed to parse rfd77:config "
			    "property on dataset %s\n", fsname);
			exit(2);
		}
		VERIFY(config != NULL);

		VERIFY0(nvlist_lookup_int32(config, "v", &ver));
		if (ver != 1) {
			fprintf(stderr, "error: unsupported config version: "
			    "%d found on dataset %s", (int)ver, fsname);
			exit(2);
		}

		VERIFY0(nvlist_lookup_nvlist(config, "o", &opts));
		VERIFY0(nvlist_lookup_uint32(opts, "length", &nopts));
		if (nopts < 1) {
			fprintf(stderr, "error: config needs at least one "
			    "valid option\n");
			exit(2);
		}

		fprintf(stderr, "Attempting to unlock ZFS '%s'...\n", fsname);

		/* First pass: try all n=m=1 options. */
		for (i = 0; i < nopts; ++i) {
			char nbuf[8];
			int32_t n, m;
			nvlist_t *parts, *part;
			uint32_t nparts;
			struct piv_token *t;
			struct piv_slot *slot;
			struct piv_ecdh_box *box;
			struct sshbuf *buf;

			char *guidhex, *name, *cakenc, *boxenc;
			uint8_t *guid;
			uint guidlen;
			struct sshkey *cak;
			char *ptr;

			snprintf(nbuf, sizeof (nbuf), "%d", i);
			VERIFY0(nvlist_lookup_nvlist(opts, nbuf, &opt));

			VERIFY0(nvlist_lookup_int32(opt, "n", &n));
			VERIFY0(nvlist_lookup_int32(opt, "m", &m));

			if (n != 1 || m != 1)
				continue;

			VERIFY0(nvlist_lookup_nvlist(opt, "p", &parts));
			VERIFY0(nvlist_lookup_uint32(parts, "length", &nparts));
			VERIFY3U(nparts, ==, 1);

			VERIFY0(nvlist_lookup_nvlist(parts, "0", &part));
			VERIFY0(nvlist_lookup_string(part, "n", &name));
			VERIFY0(nvlist_lookup_string(part, "g", &guidhex));

			guid = parse_hex(guidhex, &guidlen);
			VERIFY(guid != NULL);
			VERIFY3U(guidlen, ==, 16);

			for (t = ks; t != NULL; t = t->pt_next) {
				if (bcmp(t->pt_guid, guid, guidlen) == 0) {
					selk = t;
					break;
				}
			}
			free(guid);
			if (selk == NULL)
				continue;

			VERIFY0(nvlist_lookup_string(part, "p", &cakenc));

			cak = sshkey_new(KEY_UNSPEC);
			VERIFY(cak != NULL);
			ptr = cakenc;
			VERIFY0(sshkey_read(cak, &ptr));

			VERIFY0(nvlist_lookup_string(part, "b", &boxenc));
			buf = sshbuf_new();
			VERIFY(buf != NULL);
			VERIFY0(sshbuf_b64tod(buf, boxenc));
			VERIFY0(piv_box_from_binary(sshbuf_ptr(buf),
			    sshbuf_len(buf), &box));

			VERIFY0(piv_txn_begin(selk));
			VERIFY0(piv_select(selk));

			VERIFY0(piv_read_cert(selk, PIV_SLOT_CARD_AUTH));
			slot = piv_get_slot(selk, PIV_SLOT_CARD_AUTH);
			VERIFY(slot != NULL);

			if (piv_auth_key(selk, slot, cak) != 0) {
				piv_txn_end(selk);
				fprintf(stderr, "error: found a token with "
				    "GUID match for %s (%s), but CAK auth "
				    "failed!\n", name, guidhex);
				exit(3);
			}
			fprintf(stderr, "Using '%s' (%s)\n", name, guidhex);

			VERIFY0(piv_read_cert(selk, PIV_SLOT_KEY_MGMT));
			slot = piv_get_slot(selk, PIV_SLOT_KEY_MGMT);
			VERIFY(slot != NULL);

again:
			rc = piv_box_open(selk, slot, box);
			if (rc == EPERM) {
				assert_pin(selk);
				goto again;
			} else if (rc != 0) {
				fprintf(stderr, "error: failed to open "
				    "PIV box: %d (%s)\n", rc, strerror(rc));
				piv_txn_end(selk);
				exit(3);
			}

			piv_txn_end(selk);

			uint8_t *key;
			size_t keylen;
			VERIFY0(piv_box_take_data(box, &key, &keylen));

			rc = lzc_load_key(fsname, B_FALSE, key, keylen);
			if (rc != 0) {
				fprintf(stderr, "error: failed to load key "
				    "material into ZFS: %d (%s)\n",
				    rc, strerror(rc));
				exit(4);
			}

			exit(0);
		}

	} else {
		fprintf(stderr, "error: invalid operation '%s'\n", op);
		usage();
	}

	libzfs_fini(zfshdl);

	return (0);
}
