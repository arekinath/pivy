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

#include "words.h"

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

enum chaltype {
	CHAL_RECOVERY = 1,
	CHAL_VERIFY_AUDIT = 2,
};

struct challenge {
	uint8_t c_version;
	enum chaltype c_type;
	struct piv_ecdh_box *c_keybox;
	struct piv_ecdh_box *c_infobox;

	/* These are kept in the infobox */
	char *c_description;
	char *c_hostname;
	uint64_t c_ctime;
	uint8_t c_words[4];
	struct sshkey *c_destkey;
};

static void
sshbuf_get_challenge(struct sshbuf *buf, struct challenge **outchal)
{
	struct challenge *chal;
	uint8_t temp8;
	uint8_t *tmpbuf;
	size_t len;
	struct sshkey *k;
	char *tname;

	chal = calloc(1, sizeof (struct challenge));
	VERIFY(chal != NULL);

	VERIFY0(sshbuf_get_u8(buf, &chal->c_version));
	if (chal->c_version != 1) {
		fprintf(stderr, "error: invalid challenge version: v%d "
		    "(only v1 is supported)\n", (int)chal->c_version);
		exit(1);
	}
	VERIFY0(sshbuf_get_u8(buf, &temp8));
	chal->c_type = (enum chaltype)temp8;

	chal->c_keybox = piv_box_new();
	VERIFY(chal->c_keybox != NULL);
	chal->c_infobox = piv_box_new();
	VERIFY(chal->c_infobox != NULL);

	VERIFY0(sshbuf_get_string8(buf, &tmpbuf, &len));
	VERIFY3U(len, ==, sizeof (chal->c_keybox->pdb_guid));
	bcopy(tmpbuf, chal->c_keybox->pdb_guid, len);
	bcopy(tmpbuf, chal->c_infobox->pdb_guid, len);
	free(tmpbuf);
	VERIFY0(sshbuf_get_u8(buf, &chal->c_keybox->pdb_slot));
	chal->c_infobox->pdb_slot = chal->c_keybox->pdb_slot;

	VERIFY0(sshbuf_get_cstring8(buf, &tname));
	k = sshkey_new(KEY_ECDSA);
	k->ecdsa_nid = sshkey_ecdsa_nid_from_name(tname);
	free(tname);
	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY0(sshbuf_get_eckey(buf, k->ecdsa));
	VERIFY0(sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa)));
	chal->c_keybox->pdb_pub = k;
	VERIFY0(sshkey_demote(k, &chal->c_infobox->pdb_pub));

	VERIFY0(sshkey_get_cstring8(buf, &chal->c_keybox->pdb_cipher));
	VERIFY0(sshkey_get_cstring8(buf, &chal->c_keybox->pdb_kdf));
	chal->c_keybox->pdb_free_str = B_TRUE;

	chal->c_infobox->pdb_cipher = strdup(chal->c_keybox->pdb_cipher);
	chal->c_infobox->pdb_kdf = strdup(chal->c_keybox->pdb_kdf);
	chal->c_infobox->pdb_free_str = B_TRUE;

	VERIFY0(sshbuf_get_cstring8(buf, &tname));
	k = sshkey_new(KEY_ECDSA);
	k->ecdsa_nid = sshkey_ecdsa_nid_from_name(tname);
	free(tname);
	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY0(sshbuf_get_eckey(buf, k->ecdsa));
	VERIFY0(sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa)));
	chal->c_keybox->pdb_ephem_pub = k;

	VERIFY0(sshbuf_get_string8(buf, &chal->c_keybox->pdb_iv.b_data,
	    &chal->c_keybox->pdb_iv.b_size));
	chal->c_keybox->pdb_iv.b_len = chal->c_keybox->pdb_iv.b_size;
	VERIFY0(sshbuf_get_string(buf, &chal->c_keybox->pdb_enc.b_data,
	    &chal->c_keybox->pdb_enc.b_size));
	chal->c_keybox->pdb_enc.b_len = chal->c_keybox->pdb_enc.b_size;

	VERIFY0(sshbuf_get_cstring8(buf, &tname));
	k = sshkey_new(KEY_ECDSA);
	k->ecdsa_nid = sshkey_ecdsa_nid_from_name(tname);
	free(tname);
	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	VERIFY0(sshbuf_get_eckey(buf, k->ecdsa));
	VERIFY0(sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa)));
	chal->c_infobox->pdb_ephem_pub = k;

	VERIFY0(sshbuf_get_string8(buf, &chal->c_infobox->pdb_iv.b_data,
	    &chal->c_infobox->pdb_iv.b_size));
	chal->c_infobox->pdb_iv.b_len = chal->c_infobox->pdb_iv.b_size;
	VERIFY0(sshbuf_get_string(buf, &chal->c_infobox->pdb_enc.b_data,
	    &chal->c_infobox->pdb_enc.b_size));
	chal->c_infobox->pdb_enc.b_len = chal->c_infobox->pdb_enc.b_size;

	*outchal = chal;
}

static void
sshbuf_put_challenge(struct sshbuf *buf, struct challenge *chal)
{
	const char *tname = NULL;
	struct sshkey *k;

	if (chal->c_infobox == NULL) {
		struct sshbuf *ibuf = sshbuf_new();
		VERIFY(ibuf != NULL);

		chal->c_infobox = piv_box_new();
		VERIFY(chal->c_infobox != NULL);

		VERIFY0(sshbuf_put_cstring8(ibuf, chal->c_hostname));
		VERIFY0(sshbuf_put_u64(ibuf, chal->c_ctime));
		VERIFY0(sshbuf_put_cstring8(ibuf, chal->c_description));
		VERIFY0(sshbuf_put_u8(ibuf, chal->c_words[0]));
		VERIFY0(sshbuf_put_u8(ibuf, chal->c_words[1]));
		VERIFY0(sshbuf_put_u8(ibuf, chal->c_words[2]));
		VERIFY0(sshbuf_put_u8(ibuf, chal->c_words[3]));

		k = chal->c_destkey;
		tname = sshkey_curve_nid_to_name(k->ecdsa_nid);
		VERIFY(tname != NULL);
		VERIFY0(sshbuf_put_cstring8(ibuf, tname));
		VERIFY0(sshbuf_put_eckey(ibuf, k->ecdsa));

		VERIFY0(piv_box_set_data(chal->c_infobox, sshbuf_ptr(ibuf),
		    sshbuf_len(ibuf)));

		bcopy(chal->c_keybox->pdb_guid, chal->c_infobox->pdb_guid,
		    sizeof (chal->c_keybox->pdb_guid));
		chal->c_infobox->pdb_slot = chal->c_keybox->pdb_slot;

		VERIFY0(piv_box_seal_offline(chal->c_keybox->pdb_pub,
		    chal->c_infobox));

		sshbuf_free(ibuf);
	}

	VERIFY0(sshbuf_put_u8(buf, chal->c_version));
	VERIFY0(sshbuf_put_u8(buf, (uint8_t)chal->c_type));

	VERIFY0(bcmp(chal->c_keybox->pdb_guid, chal->c_infobox->pdb_guid,
	    sizeof (chal->c_keybox->pdb_guid)));
	VERIFY3U(chal->c_keybox->pdb_slot, ==, chal->c_infobox->pdb_slot);
	VERIFY0(strcmp(chal->c_keybox->pdb_cipher,
	    chal->c_infobox->pdb_cipher));
	VERIFY0(strcmp(chal->c_keybox->pdb_kdf,
	    chal->c_infobox->pdb_kdf));

	VERIFY0(sshbuf_put_string8(buf, chal->c_keybox->pdb_guid,
	    sizeof (chal->c_keybox->pdb_guid)));
	VERIFY0(sshbuf_put_u8(buf, chal->c_keybox->pdb_slot));

	k = chal->c_keybox->pdb_pub;
	tname = sshkey_curve_nid_to_name(k->ecdsa_nid);
	VERIFY(tname != NULL);
	VERIFY0(sshbuf_put_cstring8(buf, tname));
	VERIFY0(sshbuf_put_eckey(buf, k->ecdsa));

	VERIFY0(sshbuf_put_cstring8(buf, chal->c_keybox->pdb_cipher));
	VERIFY0(sshbuf_put_cstring8(buf, chal->c_keybox->pdb_kdf));

	k = chal->c_keybox->pdb_ephem_pub;
	tname = sshkey_curve_nid_to_name(k->ecdsa_nid);
	VERIFY(tname != NULL);
	VERIFY0(sshbuf_put_cstring8(buf, tname));
	VERIFY0(sshbuf_put_eckey(buf, k->ecdsa));

	VERIFY0(sshbuf_put_string8(buf, chal->c_keybox->pdb_iv.b_data,
	    chal->c_keybox->pdb_iv.b_len));
	VERIFY0(sshbuf_put_string(buf, chal->c_keybox->pdb_enc.b_data,
	    chal->c_keybox->pdb_enc.b_len));

	k = chal->c_infobox->pdb_ephem_pub;
	tname = sshkey_curve_nid_to_name(k->ecdsa_nid);
	VERIFY(tname != NULL);
	VERIFY0(sshbuf_put_cstring8(buf, tname));
	VERIFY0(sshbuf_put_eckey(buf, k->ecdsa));

	VERIFY0(sshbuf_put_string8(buf, chal->c_infobox->pdb_iv.b_data,
	    chal->c_infobox->pdb_iv.b_len));
	VERIFY0(sshbuf_put_string(buf, chal->c_infobox->pdb_enc.b_data,
	    chal->c_infobox->pdb_enc.b_len));
}

static void
unlock_generic(nvlist_t *config,
    void (*usekey)(const uint8_t *, size_t, void *), void *cookie)
{
	nvlist_t *opts, *opt;
	uint32_t nopts;
	int32_t ver, i;
	int rc;

	VERIFY0(nvlist_lookup_int32(config, "v", &ver));
	if (ver != 1) {
		fprintf(stderr, "error: unsupported config version: "
		    "v%d found (v1 supported)", (int)ver);
		exit(2);
	}

	VERIFY0(nvlist_lookup_nvlist(config, "o", &opts));
	VERIFY0(nvlist_lookup_uint32(opts, "length", &nopts));
	if (nopts < 1) {
		fprintf(stderr, "error: config needs at least one "
		    "valid option\n");
		exit(2);
	}

	/*
	 * To prepare for the second pass (recovery), generate an in-memory
	 * EC key. We will use this as the recipient of challenge-response
	 * boxes.
	 */
	struct sshkey *ephem = NULL, *ephempub = NULL;
	VERIFY0(sshkey_generate(KEY_ECDSA, 256, &ephem));
	VERIFY0(sshkey_demote(ephem, &ephempub));

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

		struct challenge *ch = calloc(1, sizeof (struct challenge));
		ch->c_version = 1;
		ch->c_type = CHAL_RECOVERY;
		ch->c_keybox = box;
		ch->c_description = "test description";
		ch->c_hostname = "test";
		ch->c_ctime = time(NULL);
		ch->c_destkey = ephempub;
		struct sshbuf *chalbuf = sshbuf_new();
		sshbuf_put_challenge(chalbuf, ch);
		fprintf(stderr, "challenge: %s\n", sshbuf_dtob64(chalbuf));

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

		usekey(key, keylen, cookie);
		return;
	}


	for (i = 0; i < nopts; ++i) {
		char nbuf[8];
		int32_t n, m;
		nvlist_t *parts, *part;
		uint32_t nparts;

		snprintf(nbuf, sizeof (nbuf), "%d", i);
		VERIFY0(nvlist_lookup_nvlist(opts, nbuf, &opt));

		VERIFY0(nvlist_lookup_int32(opt, "n", &n));
		VERIFY0(nvlist_lookup_int32(opt, "m", &m));

		VERIFY0(nvlist_lookup_nvlist(opt, "p", &parts));
		VERIFY0(nvlist_lookup_uint32(parts, "length", &nparts));
	}
}

static void
do_zfs_unlock(const uint8_t *key, size_t keylen, void *cookie)
{
	int rc;
	const char *fsname = (const char *)cookie;

	rc = lzc_load_key(fsname, B_FALSE, key, keylen);
	if (rc != 0) {
		fprintf(stderr, "error: failed to load key "
		    "material into ZFS: %d (%s)\n",
		    rc, strerror(rc));
		exit(4);
	}
	exit(0);
}

static void
cmd_unlock(const char *fsname)
{
	zfs_handle_t *ds;
	nvlist_t *props, *prop, *config;
	uint64_t kstatus;
	char *json;

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

	/*if (kstatus == ZFS_KEYSTATUS_AVAILABLE) {
		fprintf(stderr, "error: key already loaded for %s\n",
		    fsname);
		exit(1);
	}*/

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

	fprintf(stderr, "Attempting to unlock ZFS '%s'...\n", fsname);
	unlock_generic(config, do_zfs_unlock, fsname);
}

static void
cmd_respond(void)
{
	
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

		if (optind >= argc) {
			fprintf(stderr, "error: target zfs required\n");
			usage();
		}
		fsname = argv[optind++];

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		cmd_unlock(fsname);

	} else if (strcmp(op, "respond") == 0) {

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		cmd_respond();

	} else {
		fprintf(stderr, "error: invalid operation '%s'\n", op);
		usage();
	}

	libzfs_fini(zfshdl);

	return (0);
}
