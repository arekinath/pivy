/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
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

#include "ed25519/crypto_api.h"

#include "tlv.h"
#include "piv.h"
#include "bunyan.h"

boolean_t debug = B_FALSE;
static boolean_t parseable = B_FALSE;
static const char *cn = NULL;
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

static struct piv_token *ks = NULL;
static struct piv_token *selk = NULL;
//static struct piv_token *sysk = NULL;
static struct piv_slot *override = NULL;

extern char *buf_to_hex(const uint8_t *buf, size_t len, boolean_t spaces);

static boolean_t
sniff_hex(uint8_t *buf, uint len)
{
	uint i, count = 0;
	len = len > 16 ? 16 : len;
	for (i = 0; i < len; ++i) {
		char c;
		if (buf[i] > CHAR_MAX)
			return (B_FALSE);
		c = buf[i];
		if (c >= '0' && c <= '9') {
			++count;
			continue;
		}
		if (c >= 'a' && c <= 'f') {
			++count;
			continue;
		}
		if (c == ':' || c == ' ' || c == '\t' || c == '\n' ||
		    c == '\r') {
			++count;
			continue;
		}
		return (B_FALSE);
	}
	if (count >= 8)
		return (B_TRUE);
	return (B_FALSE);
}

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

#define	MAX_KEYFILE_LEN		(1024)

static uint8_t *
read_key_file(const char *fname, uint *outlen)
{
	FILE *f;
	uint len;
	uint8_t *buf;

	f = fopen(fname, "r");
	if (f == NULL) {
		fprintf(stderr, "error: failed to open %s: %s\n", fname,
		    strerror(errno));
		exit(2);
	}

	buf = calloc(1, MAX_KEYFILE_LEN);
	VERIFY(buf != NULL);

	len = fread(buf, 1, MAX_KEYFILE_LEN, f);
	if (len <= 0) {
		fprintf(stderr, "error: keyfile %s is too short\n", fname);
		exit(2);
	}
	if (!feof(f)) {
		fprintf(stderr, "error: keyfile %s is too long\n", fname);
		exit(2);
	}

	*outlen = len;

	fclose(f);

	return (buf);
}

static uint8_t *
read_stdin(size_t limit, size_t *outlen)
{
	uint8_t *buf = calloc(1, limit * 3);
	size_t n;

	n = fread(buf, 1, limit * 3 - 1, stdin);
	if (!feof(stdin)) {
		fprintf(stderr, "error: input too long (max %lu bytes)\n",
		    limit);
		exit(1);
	}

	if (n > limit) {
		fprintf(stderr, "error: input too long (max %lu bytes)\n",
		    limit);
		exit(1);
	}

	*outlen = n;
	return (buf);
}

static void
assert_select(struct piv_token *tk)
{
	int rv;

	rv = piv_select(tk);
	if (rv != 0) {
		piv_txn_end(tk);
		fprintf(stderr, "error: failed to select PIV applet "
		    "(rv = %d)\n", rv);
		exit(1);
	}
}

static const char *
pin_type_to_name(enum piv_pin type)
{
	switch (type) {
	case PIV_PIN:
		return ("PIV PIN");
	case PIV_GLOBAL_PIN:
		return ("Global PIN");
	case PIV_PUK:
		return ("PUK");
	default:
		VERIFY(0);
		return (NULL);
	}
}

static void
assert_pin(struct piv_token *pk, boolean_t prompt)
{
	int rv;
	uint retries = min_retries;

#if 0
	if (pin == NULL && pk == sysk) {
		rv = piv_system_token_auth(pk);
		if (rv == 0)
			return;
	}
#endif

	if (pin == NULL && !prompt)
		return;

	if (prompt) {
		char prompt[64];
		char *guid;
		guid = buf_to_hex(pk->pt_guid, 4, B_FALSE);
		snprintf(prompt, 64, "Enter %s for token %s: ",
		    pin_type_to_name(pk->pt_auth), guid);
		do {
			pin = getpass(prompt);
		} while (pin == NULL && errno == EINTR);
		if (pin == NULL && errno == ENXIO) {
			piv_txn_end(pk);
			fprintf(stderr, "error: a PIN is required to "
			    "unlock token %s\n", guid);
			exit(4);
		} else if (pin == NULL) {
			piv_txn_end(pk);
			perror("getpass");
			exit(3);
		}
		pin = strdup(pin);
		free(guid);
	}
	rv = piv_verify_pin(pk, pk->pt_auth, pin, &retries, B_FALSE);
	if (rv == EACCES) {
		piv_txn_end(pk);
		if (retries == 0) {
			fprintf(stderr, "error: token is locked due to too "
			    "many invalid PIN entries\n");
			exit(10);
		}
		fprintf(stderr, "error: invalid PIN (%d attempts "
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


static const char *
alg_to_string(uint alg)
{
	switch (alg) {
	case PIV_ALG_3DES:
		return ("3DES");
	case PIV_ALG_RSA1024:
		return ("RSA1024");
	case PIV_ALG_RSA2048:
		return ("RSA2048");
	case PIV_ALG_AES128:
		return ("AES128");
	case PIV_ALG_AES192:
		return ("AES192");
	case PIV_ALG_AES256:
		return ("AES256");
	case PIV_ALG_ECCP256:
		return ("ECCP256");
	case PIV_ALG_ECCP384:
		return ("ECCP384");
	case PIV_ALG_ECCP256_SHA1:
		return ("ECCP256-SHA1");
	case PIV_ALG_ECCP256_SHA256:
		return ("ECCP256-SHA256");
	default:
		return ("?");
	}
}

static void
cmd_list(SCARDCONTEXT ctx)
{
	struct piv_token *pk;
	struct piv_slot *slot;
	uint i;
	char *buf = NULL;

	for (pk = ks; pk != NULL; pk = pk->pt_next) {
		if (guid != NULL &&
		    bcmp(pk->pt_guid, guid, guid_len) != 0) {
			continue;
		}

		assert(piv_txn_begin(pk) == 0);
		assert_select(pk);
		piv_read_all_certs(pk);
		piv_txn_end(pk);

		if (parseable) {
			free(buf);
			buf = buf_to_hex(pk->pt_guid, sizeof (pk->pt_guid),
			    B_FALSE);
			printf("%s:%s:%s:%s:%d.%d.%d:",
			    pk->pt_rdrname, buf,
			    pk->pt_nochuid ? "true" : "false",
			    pk->pt_ykpiv ? "true" : "false",
			    pk->pt_ykver[0], pk->pt_ykver[1], pk->pt_ykver[2]);
			for (i = 0; i < pk->pt_alg_count; ++i) {
				printf("%s%s", alg_to_string(pk->pt_algs[i]),
				    (i + 1 < pk->pt_alg_count) ? "," : "");
			}
			for (i = 0x9A; i < 0x9F; ++i) {
				slot = piv_get_slot(pk, i);
				if (slot == NULL) {
					printf(":%02X", i);
				} else {
					printf(":%02X;%s;%s;%d",
					    i, slot->ps_subj,
					    sshkey_type(slot->ps_pubkey),
					    sshkey_size(slot->ps_pubkey));
				}
			}
			printf("\n");
			continue;
		}

		free(buf);
		buf = buf_to_hex(pk->pt_guid, 4, B_FALSE);
		printf("%10s: %s\n", "card", buf);
		printf("%10s: %s\n", "device", pk->pt_rdrname);
		if (pk->pt_nochuid) {
			printf("%10s: %s\n", "chuid", "not set "
			    "(needs initialization)");
		} else if (pk->pt_signedchuid) {
			printf("%10s: %s\n", "chuid", "ok, signed");
		} else {
			printf("%10s: %s\n", "chuid", "ok");
		}
		free(buf);
		buf = buf_to_hex(pk->pt_guid, sizeof (pk->pt_guid), B_FALSE);
		printf("%10s: %s\n", "guid", buf);
		free(buf);
		buf = buf_to_hex(pk->pt_chuuid, sizeof (pk->pt_chuuid),
		    B_FALSE);
		printf("%10s: %s\n", "owner", buf);
		free(buf);
		buf = buf_to_hex(pk->pt_fascn, pk->pt_fascn_len, B_FALSE);
		printf("%10s: %s\n", "fasc-n", buf);
		if (pk->pt_expiry[0] >= '0' && pk->pt_expiry[0] <= '9') {
			printf("%10s: %c%c%c%c-%c%c-%c%c\n", "expiry",
			    pk->pt_expiry[0], pk->pt_expiry[1],
			    pk->pt_expiry[2], pk->pt_expiry[3],
			    pk->pt_expiry[4], pk->pt_expiry[5],
			    pk->pt_expiry[6], pk->pt_expiry[7]);
		}
		if (pk->pt_ykpiv) {
			printf("%10s: implements YubicoPIV extensions "
			    "(v%d.%d.%d)\n", "yubico", pk->pt_ykver[0],
			    pk->pt_ykver[1], pk->pt_ykver[2]);
		}
		printf("%10s:", "auth");
		if (pk->pt_pin_app && pk->pt_auth == PIV_PIN)
			printf(" PIN*");
		else if (pk->pt_pin_app)
			printf(" PIN");
		if (pk->pt_pin_global && pk->pt_auth == PIV_GLOBAL_PIN)
			printf(" GlobalPIN*");
		else if (pk->pt_pin_global)
			printf(" GlobalPIN");
		if (pk->pt_occ && pk->pt_auth == PIV_OCC)
			printf(" Biometrics*");
		else if (pk->pt_occ)
			printf(" Biometrics");
		printf("\n");
		if (pk->pt_vci) {
			printf("%10s: supports VCI (secure contactless)\n",
			    "vci");
		}
		if (pk->pt_alg_count > 0) {
			printf("%10s: ", "algos");
			for (i = 0; i < pk->pt_alg_count; ++i) {
				printf("%s ", alg_to_string(pk->pt_algs[i]));
			}
			printf("\n");
		}
		if (pk->pt_nochuid) {
			printf("%10s:\n", "action");
			printf("%10s Initialize this card using 'piv-tool "
			    "init'\n", "");
			printf("%10s No keys can be stored on an uninitialized"
			    " card\n", "");
			printf("\n");
			continue;
		}
		printf("%10s:\n", "slots");
		printf("%10s %-3s  %-6s  %-4s  %-30s\n", "", "ID", "TYPE",
		    "BITS", "CERTIFICATE");
		for (slot = pk->pt_slots; slot != NULL; slot = slot->ps_next) {
			printf("%10s %-3x  %-6s  %-4d  %-30s\n", "",
			    slot->ps_slot, sshkey_type(slot->ps_pubkey),
			    sshkey_size(slot->ps_pubkey), slot->ps_subj);
		}
		printf("\n");
	}
}

static void
cmd_init(void)
{
	int rv;
	struct tlv_state *ccc, *chuid;
	uint8_t guid[16];
	uint8_t fascn[25];
	uint8_t expiry[8] = { '2', '0', '5', '0', '0', '1', '0', '1' };
	uint8_t cardId[21] = {
		/* GSC-RID: GSC-IS data model */
		0xa0, 0x00, 0x00, 0x01, 0x16,
		/* Manufacturer: ff (unknown) */
		0xff,
		/* Card type: JavaCard */
		0x02,
		0x00
	};

	arc4random_buf(guid, sizeof (guid));
	arc4random_buf(&cardId[6], sizeof (cardId) - 6);
	bzero(fascn, sizeof (fascn));

	/* First, the CCC */
	ccc = tlv_init_write();

	/* Our card ID */
	tlv_push(ccc, 0xF0);
	tlv_write(ccc, cardId, 0, sizeof (cardId));
	tlv_pop(ccc);

	/* Container version numbers */
	tlv_push(ccc, 0xF1);
	tlv_write_byte(ccc, 0x21);
	tlv_pop(ccc);
	tlv_push(ccc, 0xF2);
	tlv_write_byte(ccc, 0x21);
	tlv_pop(ccc);

	tlv_push(ccc, 0xF3);
	tlv_pop(ccc);
	tlv_push(ccc, 0xF4);
	tlv_pop(ccc);

	/* Data Model number */
	tlv_push(ccc, 0xF5);
	tlv_write_byte(ccc, 0x10);
	tlv_pop(ccc);

	tlv_push(ccc, 0xF6);
	tlv_pop(ccc);
	tlv_push(ccc, 0xF7);
	tlv_pop(ccc);
	tlv_push(ccc, 0xFA);
	tlv_pop(ccc);
	tlv_push(ccc, 0xFB);
	tlv_pop(ccc);
	tlv_push(ccc, 0xFC);
	tlv_pop(ccc);
	tlv_push(ccc, 0xFD);
	tlv_pop(ccc);
	tlv_push(ccc, 0xFE);
	tlv_pop(ccc);

	/* Now, set up the CHUID file */
	chuid = tlv_init_write();

	tlv_push(chuid, 0x30);
	tlv_write(chuid, fascn, 0, sizeof (fascn));
	tlv_pop(chuid);

	tlv_push(chuid, 0x34);
	tlv_write(chuid, guid, 0, sizeof (guid));
	tlv_pop(chuid);

	tlv_push(chuid, 0x35);
	tlv_write(chuid, expiry, 0, sizeof (expiry));
	tlv_pop(chuid);

	tlv_push(chuid, 0x3E);
	tlv_pop(chuid);
	tlv_push(chuid, 0xFE);
	tlv_pop(chuid);

	piv_txn_begin(selk);
	assert_select(selk);
	rv = piv_auth_admin(selk, admin_key, 24);
	if (rv == 0) {
		rv = piv_write_file(selk, PIV_TAG_CARDCAP,
		    tlv_buf(ccc), tlv_len(ccc));
	}
	if (rv == 0) {
		rv = piv_write_file(selk, PIV_TAG_CHUID,
		    tlv_buf(chuid), tlv_len(chuid));
	}
	piv_txn_end(selk);

	tlv_free(ccc);
	tlv_free(chuid);

	if (rv == ENOMEM) {
		fprintf(stderr, "error: card is out of EEPROM\n");
		exit(1);
	} else if (rv == EPERM) {
		fprintf(stderr, "error: admin authentication failed\n");
		exit(1);
	} else if (rv != 0) {
		fprintf(stderr, "error: failed to write to card\n");
		exit(1);
	}

	exit(0);
}

#if 0
static void
cmd_set_system(void)
{
	int rv;
	char prompt[64];
	char *guid;
	uint retries = min_retries;

	if (pin == NULL) {
		guid = buf_to_hex(selk->pt_guid, 4, B_FALSE);
		snprintf(prompt, 64, "Enter PIV PIN for token %s: ", guid);
		do {
			pin = getpass(prompt);
		} while (pin == NULL && errno == EINTR);
		if (pin == NULL && errno == ENXIO) {
			fprintf(stderr, "error: a PIN code is required to "
			    "unlock token %s\n", guid);
			exit(4);
		} else if (pin == NULL) {
			perror("getpass");
			exit(3);
		}
		pin = strdup(pin);
		free(guid);
	}

	VERIFY0(piv_txn_begin(selk));
	assert_select(selk);
#if 0
	rv = piv_system_token_set(selk, pin, &retries);
#endif
	piv_txn_end(selk);

	if (rv == EACCES) {
		if (retries == 0) {
			fprintf(stderr, "error: token is locked due to too "
			    "many invalid PIN code entries\n");
			exit(10);
		}
		fprintf(stderr, "error: invalid PIN code (%d attempts "
		    "remaining)\n", retries);
		exit(4);
	} else if (rv == EAGAIN) {
		fprintf(stderr, "error: PIN code only has %d retries "
		    "remaining, refusing to attempt unlock\n", retries);
		exit(5);
	} else if (rv != 0) {
		fprintf(stderr, "error: failed to set system token (rv = %d)\n",
		    rv);
		exit(1);
	}

	exit(0);
}
#endif

static void
cmd_change_pin(void)
{
	int rv;
	char prompt[64];
	char *p, *newpin, *guid;

	guid = buf_to_hex(selk->pt_guid, 4, B_FALSE);
	snprintf(prompt, 64, "Enter current PIV PIN (%s): ", guid);
	do {
		p = getpass(prompt);
	} while (p == NULL && errno == EINTR);
	if (p == NULL) {
		perror("getpass");
		exit(1);
	}
	pin = strdup(p);
again:
	snprintf(prompt, 64, "Enter new PIV PIN (%s): ", guid);
	do {
		p = getpass(prompt);
	} while (p == NULL && errno == EINTR);
	if (p == NULL) {
		perror("getpass");
		exit(1);
	}
	if (strlen(p) < 6 || strlen(p) > 10) {
		fprintf(stderr, "error: PIN must be 6-10 digits\n");
		goto again;
	}
	newpin = strdup(p);
	snprintf(prompt, 64, "Confirm new PIV PIN (%s): ", guid);
	do {
		p = getpass(prompt);
	} while (p == NULL && errno == EINTR);
	if (p == NULL) {
		perror("getpass");
		exit(1);
	}
	if (strcmp(p, newpin) != 0) {
		fprintf(stderr, "error: PINs do not match\n");
		goto again;
	}
	free(guid);

	VERIFY0(piv_txn_begin(selk));
	assert_select(selk);
	rv = piv_change_pin(selk, PIV_PIN, pin, newpin);
	piv_txn_end(selk);

	if (rv == EACCES) {
		fprintf(stderr, "error: current PIN was incorrect; PIN change "
		    "attempt failed\n");
		exit(4);
	} else if (rv != 0) {
		fprintf(stderr, "error: failed to set new PIN\n");
		exit(1);
	}
	exit(0);
}

static void
cmd_generate(uint slotid, enum piv_alg alg)
{
	char *buf;
	int rv;
	struct sshkey *pub;
	X509 *cert;
	EVP_PKEY *pkey;
	X509_NAME *subj;
	const char *ku, *basic;
	char *name;
	enum sshdigest_types wantalg, hashalg;
	int nid;
	ASN1_TYPE null_parameter;
	uint8_t *tbs = NULL, *sig, *cdata = NULL;
	size_t tbslen, siglen, cdlen;
	uint flags;
	uint i;
	BIGNUM *serial;
	ASN1_INTEGER *serial_asn1;
	X509_EXTENSION *ext;
	X509V3_CTX x509ctx;
	char *guid;

	guid = buf_to_hex(selk->pt_guid, sizeof (selk->pt_guid), B_FALSE);

	switch (slotid) {
	case 0x9A:
		name = "piv-auth";
		basic = "critical,CA:FALSE";
		ku = "critical,digitalSignature,nonRepudiation";
		break;
	case 0x9C:
		name = "piv-sign";
		basic = "critical,CA:TRUE";
		ku = "critical,digitalSignature,nonRepudiation,"
		    "keyCertSign,cRLSign";
		break;
	case 0x9D:
		name = "piv-key-mgmt";
		basic = "critical,CA:FALSE";
		ku = "critical,keyAgreement,keyEncipherment,dataEncipherment";
		break;
	case 0x9E:
		name = "piv-card-auth";
		basic = "critical,CA:FALSE";
		ku = "critical,digitalSignature,nonRepudiation";
		break;
	case 0x82:
	case 0x83:
	case 0x84:
	case 0x85:
	case 0x86:
	case 0x87:
	case 0x88:
	case 0x89:
	case 0x8A:
	case 0x8B:
	case 0x8C:
	case 0x8D:
	case 0x8E:
	case 0x8F:
	case 0x90:
	case 0x91:
	case 0x92:
	case 0x93:
	case 0x94:
	case 0x95:
		name = calloc(1, 64);
		snprintf(name, 64, "piv-retired-%u", slotid - 0x81);
		basic = "critical,CA:FALSE";
		ku = "critical,digitalSignature,nonRepudiation";
		if (slotid - 0x82 > selk->pt_hist_oncard) {
			fprintf(stderr, "error: next available key history "
			    "slot is %02X (must be used in order)\n",
			    0x82 + selk->pt_hist_oncard);
			exit(3);
		}
		break;
	default:
		fprintf(stderr, "error: PIV slot %02X cannot be "
		    "used for asymmetric crypto\n", slotid);
		exit(3);
	}

	piv_txn_begin(selk);
	assert_select(selk);
	rv = piv_auth_admin(selk, admin_key, 24);
	if (rv == 0)
		rv = piv_generate(selk, slotid, alg, &pub);

	if (rv != 0) {
		piv_txn_end(selk);
		fprintf(stderr, "error: key generation failed (%d)\n", rv);
		exit(1);
	}

	pkey = EVP_PKEY_new();
	assert(pkey != NULL);
	if (pub->type == KEY_RSA) {
		RSA *copy = RSA_new();
		assert(copy != NULL);
		copy->e = BN_dup(pub->rsa->e);
		assert(copy->e != NULL);
		copy->n = BN_dup(pub->rsa->n);
		assert(copy->n != NULL);
		rv = EVP_PKEY_assign_RSA(pkey, copy);
		assert(rv == 1);
		nid = NID_sha256WithRSAEncryption;
		wantalg = SSH_DIGEST_SHA256;
	} else if (pub->type == KEY_ECDSA) {
		boolean_t haveSha256 = B_FALSE;
		boolean_t haveSha1 = B_FALSE;

		EC_KEY *copy = EC_KEY_dup(pub->ecdsa);
		rv = EVP_PKEY_assign_EC_KEY(pkey, copy);
		assert(rv == 1);

		for (i = 0; i < selk->pt_alg_count; ++i) {
			if (selk->pt_algs[i] == PIV_ALG_ECCP256_SHA256) {
				haveSha256 = B_TRUE;
			} else if (selk->pt_algs[i] == PIV_ALG_ECCP256_SHA1) {
				haveSha1 = B_TRUE;
			}
		}
		if (haveSha1 && !haveSha256) {
			nid = NID_ecdsa_with_SHA1;
			wantalg = SSH_DIGEST_SHA1;
		} else {
			nid = NID_ecdsa_with_SHA256;
			wantalg = SSH_DIGEST_SHA256;
		}
	} else {
		assert(0);
	}

	serial = BN_new();
	serial_asn1 = ASN1_INTEGER_new();
	assert(serial != NULL);
	assert(BN_pseudo_rand(serial, 64, 0, 0) == 1);
	assert(BN_to_ASN1_INTEGER(serial, serial_asn1) != NULL);

	cert = X509_new();
	assert(cert != NULL);
	assert(X509_set_version(cert, 2) == 1);
	assert(X509_set_serialNumber(cert, serial_asn1) == 1);
	assert(X509_gmtime_adj(X509_get_notBefore(cert), 0) != NULL);
	assert(X509_gmtime_adj(X509_get_notAfter(cert), 315360000L) != NULL);

	subj = X509_NAME_new();
	assert(subj != NULL);
	if (cn == NULL) {
		assert(X509_NAME_add_entry_by_NID(subj, NID_title, MBSTRING_ASC,
		    (unsigned char *)name, -1, -1, 0) == 1);
		assert(X509_NAME_add_entry_by_NID(subj, NID_commonName,
		    MBSTRING_ASC, (unsigned char *)guid, -1, -1, 0) == 1);
	} else {
		assert(X509_NAME_add_entry_by_NID(subj, NID_commonName,
		    MBSTRING_ASC, (unsigned char *)cn, -1, -1, 0) == 1);
	}
	/*assert(X509_NAME_add_entry_by_NID(subj, NID_organizationalUnitName,
	    MBSTRING_ASC, (unsigned char *)"tokens", -1, -1, 0) == 1);
	assert(X509_NAME_add_entry_by_NID(subj, NID_organizationName,
	    MBSTRING_ASC, (unsigned char *)"triton", -1, -1, 0) == 1);*/
	assert(X509_set_subject_name(cert, subj) == 1);
	assert(X509_set_issuer_name(cert, subj) == 1);

	X509V3_set_ctx_nodb(&x509ctx);
	X509V3_set_ctx(&x509ctx, cert, cert, NULL, NULL, 0);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_basic_constraints,
	    (char *)basic);
	VERIFY(ext != NULL);
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);

	ext = X509V3_EXT_conf_nid(NULL, &x509ctx, NID_key_usage, (char *)ku);
	VERIFY(ext != NULL);
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);

	assert(X509_set_pubkey(cert, pkey) == 1);

	cert->sig_alg->algorithm = OBJ_nid2obj(nid);
	cert->cert_info->signature->algorithm = cert->sig_alg->algorithm;
	if (pub->type == KEY_RSA) {
		bzero(&null_parameter, sizeof (null_parameter));
		null_parameter.type = V_ASN1_NULL;
		null_parameter.value.ptr = NULL;
		cert->sig_alg->parameter = &null_parameter;
		cert->cert_info->signature->parameter = &null_parameter;
	}

	cert->cert_info->enc.modified = 1;
	tbslen = i2d_X509_CINF(cert->cert_info, &tbs);
	assert(tbs != NULL);
	assert(tbslen > 0);

	hashalg = wantalg;

	assert_pin(selk, B_FALSE);

signagain:
	rv = piv_sign(selk, override, tbs, tbslen, &hashalg, &sig, &siglen);

	if (rv == EPERM) {
		assert_pin(selk, B_TRUE);
		goto signagain;
	} else if (rv != 0) {
		piv_txn_end(selk);
		fprintf(stderr, "error: failed to sign cert with key\n");
		exit(1);
	}

	if (hashalg != wantalg) {
		piv_txn_end(selk);
		fprintf(stderr, "error: card could not sign with the "
		    "requested hash algorithm\n");
		exit(1);
	}

	M_ASN1_BIT_STRING_set(cert->signature, sig, siglen);
	cert->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;

	cdlen = i2d_X509(cert, &cdata);
	assert(cdata != NULL);
	assert(cdlen > 0);

	flags = PIV_COMP_NONE;
	rv = piv_write_cert(selk, slotid, cdata, cdlen, flags);

	if (rv == 0 && slotid >= 0x82 && slotid <= 0x95 &&
	    selk->pt_hist_oncard <= slotid - 0x82) {
		struct tlv_state *khtlv;
		khtlv = tlv_init_write();

		tlv_push(khtlv, 0xC1);
		tlv_write_uint(khtlv, selk->pt_hist_oncard + 1);
		tlv_pop(khtlv);

		tlv_push(khtlv, 0xC2);
		tlv_write_uint(khtlv, selk->pt_hist_offcard);
		tlv_pop(khtlv);

		if (selk->pt_hist_url != NULL) {
			tlv_push(khtlv, 0xF3);
			tlv_write(khtlv, (uint8_t *)selk->pt_hist_url, 0,
			    strlen(selk->pt_hist_url));
			tlv_pop(khtlv);
		}

		rv = piv_write_file(selk, PIV_TAG_KEYHIST, tlv_buf(khtlv),
		    tlv_len(khtlv));
		if (rv != 0) {
			fprintf(stderr, "warning: failed to update key history "
			    "object with new cert\n");
			rv = 0;
		}
	}

	piv_txn_end(selk);

	if (rv != 0) {
		fprintf(stderr, "error: failed to write cert\n");
		exit(1);
	}

	rv = sshkey_write(pub, stdout);
	if (rv != 0) {
		fprintf(stderr, "error: failed to write out key\n");
		exit(1);
	}
	buf = buf_to_hex(selk->pt_guid, sizeof (selk->pt_guid), B_FALSE);
	fprintf(stdout, " PIV_slot_%02X@%s\n", slotid, buf);
	free(buf);

	free(guid);

	exit(0);
}

static void
cmd_pubkey(uint slotid)
{
	struct piv_slot *cert;
	char *buf;
	int rv;

	switch (slotid) {
	case 0x9A:
	case 0x9C:
	case 0x9D:
	case 0x9E:
		break;
	default:
		fprintf(stderr, "error: PIV slot %02X cannot be "
		    "used for asymmetric signing\n", slotid);
		exit(3);
	}

	piv_txn_begin(selk);
	assert_select(selk);
	rv = piv_read_cert(selk, slotid);
	piv_txn_end(selk);

	cert = piv_get_slot(selk, slotid);

	if (cert == NULL && rv == ENOENT) {
		fprintf(stderr, "error: PIV slot %02X has no key present\n",
		    slotid);
		exit(1);
	} else if (cert == NULL) {
		fprintf(stderr, "error: failed to read cert in PIV slot %02X\n",
		    slotid);
		exit(1);
	}

	rv = sshkey_write(cert->ps_pubkey, stdout);
	if (rv != 0) {
		fprintf(stderr, "error: failed to write out key\n");
		exit(1);
	}
	buf = buf_to_hex(selk->pt_guid, sizeof (selk->pt_guid), B_FALSE);
	fprintf(stdout, " PIV_slot_%02X@%s \"%s\"\n", slotid, buf,
	    cert->ps_subj);
	free(buf);
	exit(0);
}

static void
cmd_cert(uint slotid)
{
	struct piv_slot *cert;
	int rv;

	switch (slotid) {
	case 0x9A:
	case 0x9C:
	case 0x9D:
	case 0x9E:
		break;
	default:
		fprintf(stderr, "error: PIV slot %02X cannot be "
		    "used for asymmetric signing\n", slotid);
		exit(3);
	}

	piv_txn_begin(selk);
	assert_select(selk);
	rv = piv_read_cert(selk, slotid);
	piv_txn_end(selk);

	cert = piv_get_slot(selk, slotid);

	if (cert == NULL && rv == ENOENT) {
		fprintf(stderr, "error: PIV slot %02X has no key present\n",
		    slotid);
		exit(1);
	} else if (cert == NULL) {
		fprintf(stderr, "error: failed to read cert in PIV slot %02X\n",
		    slotid);
		exit(1);
	}

	VERIFY(i2d_X509_fp(stdout, cert->ps_x509) == 1);
	exit(0);
}

static void
cmd_sign(uint slotid)
{
	struct piv_slot *cert;
	uint8_t *buf, *sig;
	enum sshdigest_types hashalg;
	size_t inplen, siglen;
	int rv;

	switch (slotid) {
	case 0x9A:
	case 0x9C:
	case 0x9D:
	case 0x9E:
		break;
	default:
		fprintf(stderr, "error: PIV slot %02X cannot be "
		    "used for asymmetric signing\n", slotid);
		exit(3);
	}

	if (override == NULL) {
		piv_txn_begin(selk);
		assert_select(selk);
		rv = piv_read_cert(selk, slotid);
		piv_txn_end(selk);

		cert = piv_get_slot(selk, slotid);
	} else {
		cert = override;
	}

	if (cert == NULL && rv == ENOENT) {
		fprintf(stderr, "error: PIV slot %02X has no key present\n",
		    slotid);
		exit(1);
	} else if (cert == NULL) {
		fprintf(stderr, "error: failed to read cert in PIV slot %02X\n",
		    slotid);
		exit(1);
	}

	buf = read_stdin(16384, &inplen);
	assert(buf != NULL);

	piv_txn_begin(selk);
	assert_select(selk);
	assert_pin(selk, B_FALSE);
again:
	hashalg = 0;
	rv = piv_sign(selk, cert, buf, inplen, &hashalg, &sig, &siglen);
	if (rv == EPERM) {
		assert_pin(selk, B_TRUE);
		goto again;
	}
	piv_txn_end(selk);
	if (rv == EPERM) {
		fprintf(stderr, "error: key in slot %02X requires PIN\n",
		    slotid);
		exit(4);
	} else if (rv != 0) {
		fprintf(stderr, "error: piv_sign_hash returned %d\n", rv);
		exit(1);
	}

	fwrite(sig, 1, siglen, stdout);

	free(buf);
	exit(0);
}

static void
cmd_box(uint slotid)
{
	struct piv_slot *slot = NULL;
	struct piv_ecdh_box *box;
	int rv;
	size_t len;
	uint8_t *buf;

	if (slotid != 0 || opubkey == NULL) {
		piv_txn_begin(selk);
		assert_select(selk);
		rv = piv_read_cert(selk, slotid);
		piv_txn_end(selk);
		if (rv == ENOENT) {
			fprintf(stderr, "error: slot %02X does not contain "
			    "a key\n", slotid);
			exit(1);
		} else if (rv != 0) {
			fprintf(stderr, "error: slot %02X reading cert "
			    "failed\n", slotid);
			exit(1);
		}

		slot = piv_get_slot(selk, slotid);
		VERIFY3P(slot, !=, NULL);
	}

	box = piv_box_new();
	VERIFY3P(box, !=, NULL);

	buf = read_stdin(8192, &len);
	assert(buf != NULL);
	VERIFY3U(len, >, 0);
	VERIFY0(piv_box_set_data(box, buf, len));
	explicit_bzero(buf, len);
	free(buf);

	if (opubkey == NULL) {
		VERIFY0(piv_box_seal(selk, slot, box));
	} else {
		VERIFY0(piv_box_seal_offline(opubkey, box));
	}

	VERIFY0(piv_box_to_binary(box, &buf, &len));
	piv_box_free(box);

	fwrite(buf, 1, len, stdout);
	explicit_bzero(buf, len);
	free(buf);
	exit(0);
}

static void
cmd_unbox(void)
{
	struct piv_token *tk;
	struct piv_slot *sl;
	struct piv_ecdh_box *box;
	int rv;
	size_t len;
	uint8_t *buf;
	char *guid;

	buf = read_stdin(8192, &len);
	assert(buf != NULL);
	VERIFY3U(len, >, 0);

	if (piv_box_from_binary(buf, len, &box)) {
		fprintf(stderr, "error: failed parsing ecdh box\n");
		exit(1);
	}
	free(buf);

	rv = piv_box_find_token(ks, box, &tk, &sl);
	if (rv == ENOENT) {
		fprintf(stderr, "error: no token found on system that can "
		    "unlock this box\n");
		exit(5);
	} else if (rv != 0) {
		fprintf(stderr, "error: failed to communicate with token\n");
		exit(1);
	}

	piv_txn_begin(tk);
	assert_select(tk);
	assert_pin(tk, B_FALSE);
again:
	rv = piv_box_open(tk, sl, box);
	if (rv == EPERM) {
		assert_pin(tk, B_TRUE);
		goto again;
	}
	piv_txn_end(tk);

	if (rv == EPERM) {
		guid = buf_to_hex(tk->pt_guid, sizeof (tk->pt_guid), B_FALSE);
		fprintf(stderr, "error: token %s slot %02X requires a PIN\n",
		    guid, sl->ps_slot);
		free(guid);
		exit(4);
	} else if (rv != 0) {
		fprintf(stderr, "error: failed to communicate with token "
		    "(rv = %d)\n", rv);
		exit(1);
	}

	VERIFY0(piv_box_take_data(box, &buf, &len));
	fwrite(buf, 1, len, stdout);
	explicit_bzero(buf, len);
	free(buf);
	exit(0);
}


struct sgdebugbuf {
	uint8_t sb_id;
	uint8_t sb_flags;
	uint16_t sb_size;
	uint16_t sb_offset;
	uint16_t sb_len;
} __attribute__((packed));
struct sgdebugdata {
	uint16_t sg_buf;
	uint16_t sg_off;
	struct sgdebugbuf sg_bufs[1];
} __attribute__((packed));

static void
cmd_sgdebug(void)
{
	struct apdu *apdu;
	int rc;

	apdu = piv_apdu_make(CLA_ISO, 0xE0, 0x00, 0x00);
	VERIFY(apdu != NULL);

	piv_txn_begin(selk);
	assert_select(selk);
	rc = piv_apdu_transceive(selk, apdu);
	piv_txn_end(selk);

	if (rc != 0) {
		fprintf(stderr, "error: failed to run command (rc = %d)\n",
		    rc);
		exit(1);
	}

	const uint8_t *reply = &apdu->a_reply.b_data[apdu->a_reply.b_offset];
	const size_t len = apdu->a_reply.b_len;
	struct sgdebugdata *data = (struct sgdebugdata *)reply;
	struct sgdebugbuf *buf;
	data->sg_buf = ntohs(data->sg_buf);
	data->sg_off = ntohs(data->sg_off);
	printf("== SGList debug data ==\n");
	printf("current position = %d + 0x%04x\n", data->sg_buf, data->sg_off);
	buf = data->sg_bufs;
	while ((char *)buf - (char *)data < len) {
		buf->sb_size = ntohs(buf->sb_size);
		buf->sb_offset = ntohs(buf->sb_offset);
		buf->sb_len = ntohs(buf->sb_len);
		printf("buf %-3d: ", buf->sb_id);
		if (buf->sb_flags & 0x02)
			printf("transient ");
		if (buf->sb_flags & 0x01)
			printf("dynamic ");
		printf("size=%04x offset=%04x len=%04x\n",
		    buf->sb_size, buf->sb_offset, buf->sb_len);
		++buf;
	}

	piv_apdu_free(apdu);
}

static void
cmd_box_info(void)
{
	struct piv_ecdh_box *box;
	size_t len;
	uint8_t *buf;
	char *hex;

	buf = read_stdin(8192, &len);
	assert(buf != NULL);
	VERIFY3U(len, >, 0);

	if (piv_box_from_binary(buf, len, &box)) {
		fprintf(stderr, "error: failed parsing ecdh box\n");
		exit(1);
	}
	free(buf);

	hex = buf_to_hex(box->pdb_guid, sizeof (box->pdb_guid), B_FALSE);
	printf("guid:         %s\n", hex);
	free(hex);
	printf("slot:         %02X\n", box->pdb_slot);

	printf("pubkey:       ");
	VERIFY0(sshkey_write(box->pdb_pub, stdout));
	printf("\n");

	printf("ephem_pubkey: ");
	VERIFY0(sshkey_write(box->pdb_ephem_pub, stdout));
	printf("\n");

	printf("cipher:       %s\n", box->pdb_cipher);
	printf("kdf:          %s\n", box->pdb_kdf);
	printf("ivsize:       %lu\n", box->pdb_iv.b_size);
	printf("encsize:      %lu\n", box->pdb_enc.b_size);

	exit(0);
}

static void
cmd_auth(uint slotid)
{
	struct piv_slot *cert;
	struct sshkey *pubkey;
	uint8_t *buf;
	char *ptr;
	size_t boff;
	int rv;

	switch (slotid) {
	case 0x9A:
	case 0x9C:
	case 0x9D:
	case 0x9E:
		break;
	default:
		fprintf(stderr, "error: PIV slot %02X cannot be "
		    "used for signing\n", slotid);
		exit(3);
	}

	if (override == NULL) {
		piv_txn_begin(selk);
		assert_select(selk);
		rv = piv_read_cert(selk, slotid);
		piv_txn_end(selk);

		cert = piv_get_slot(selk, slotid);
	} else {
		cert = override;
	}

	if (cert == NULL && rv == ENOENT) {
		fprintf(stderr, "error: PIV slot %02X has no key present\n",
		    slotid);
		exit(1);
	} else if (cert == NULL) {
		fprintf(stderr, "error: failed to read cert in PIV slot %02X\n",
		    slotid);
		exit(1);
	}

	buf = read_stdin(16384, &boff);
	assert(buf != NULL);
	buf[boff] = 0;

	pubkey = sshkey_new(cert->ps_pubkey->type);
	assert(pubkey != NULL);
	ptr = (char *)buf;
	rv = sshkey_read(pubkey, &ptr);
	if (rv != 0) {
		fprintf(stderr, "error: failed to parse public key: %d\n",
		    rv);
		exit(1);
	}

	piv_txn_begin(selk);
	assert_select(selk);
	assert_pin(selk, B_FALSE);
again:
	rv = piv_auth_key(selk, cert, pubkey);
	if (rv == EPERM) {
		assert_pin(selk, B_TRUE);
		goto again;
	}
	piv_txn_end(selk);
	if (rv == EPERM) {
		fprintf(stderr, "error: key in slot %02X requires PIN\n",
		    slotid);
		exit(4);
	} else if (rv == ESRCH) {
		fprintf(stderr, "error: keys do not match, or signature "
		    "validation failed\n");
		exit(1);
	} else if (rv != 0) {
		fprintf(stderr, "error: piv_ecdh returned %d\n", rv);
		exit(1);
	}

	exit(0);
}

static void
cmd_ecdh(uint slotid)
{
	struct piv_slot *cert;
	struct sshkey *pubkey;
	uint8_t *buf, *secret;
	char *ptr;
	size_t boff, seclen;
	int rv;

	switch (slotid) {
	case 0x9A:
	case 0x9C:
	case 0x9D:
	case 0x9E:
		break;
	default:
		fprintf(stderr, "error: PIV slot %02X cannot be "
		    "used for ECDH\n", slotid);
		exit(3);
	}

	if (override == NULL) {
		piv_txn_begin(selk);
		assert_select(selk);
		rv = piv_read_cert(selk, slotid);
		piv_txn_end(selk);

		cert = piv_get_slot(selk, slotid);
	} else {
		cert = override;
	}

	if (cert == NULL && rv == ENOENT) {
		fprintf(stderr, "error: PIV slot %02X has no key present\n",
		    slotid);
		exit(1);
	} else if (cert == NULL) {
		fprintf(stderr, "error: failed to read cert in PIV slot %02X\n",
		    slotid);
		exit(1);
	}

	switch (cert->ps_alg) {
	case PIV_ALG_ECCP256:
	case PIV_ALG_ECCP384:
		break;
	default:
		fprintf(stderr, "error: PIV slot %02X does not contain an EC "
		    "key\n", slotid);
		exit(1);
	}

	buf = read_stdin(8192, &boff);
	assert(buf != NULL);
	buf[boff] = 0;

	pubkey = sshkey_new(cert->ps_pubkey->type);
	assert(pubkey != NULL);
	ptr = (char *)buf;
	rv = sshkey_read(pubkey, &ptr);
	if (rv != 0) {
		fprintf(stderr, "error: failed to parse public key: %d\n",
		    rv);
		exit(1);
	}

	piv_txn_begin(selk);
	assert_select(selk);
	assert_pin(selk, B_FALSE);
again:
	rv = piv_ecdh(selk, cert, pubkey, &secret, &seclen);
	if (rv == EPERM) {
		assert_pin(selk, B_TRUE);
		goto again;
	}
	piv_txn_end(selk);
	if (rv == EPERM) {
		fprintf(stderr, "error: key in slot %02X requires PIN\n",
		    slotid);
		exit(4);
	} else if (rv != 0) {
		fprintf(stderr, "error: piv_ecdh returned %d\n", rv);
		exit(1);
	}

	fwrite(secret, 1, seclen, stdout);

	exit(0);
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
	    "usage: pivtool [options] <operation>\n"
	    "Available operations:\n"
	    "  list                   Lists PIV tokens present\n"
	    "  init                   Writes GUID and card capabilities\n"
	    "                         (used to init a new Yubico PIV)\n"
	    "  pubkey <slot>          Outputs a public key in SSH format\n"
	    "  sign <slot>            Signs data on stdin\n"
	    "  ecdh <slot>            Do ECDH with pubkey on stdin\n"
	    "  auth <slot>            Does a round-trip signature test to\n"
	    "                         verify that the pubkey on stdin\n"
	    "                         matches the one in the slot\n"
	    "  generate <slot>        Generate a new private key and a\n"
	    "                         self-signed cert\n"
	    "  change-pin             Changes the PIV PIN\n"
	    "  box [slot]             Encrypts stdin data with an ECDH box\n"
	    "  unbox                  Decrypts stdin data with an ECDH box\n"
	    "                         Chooses token and slot automatically\n"
	    "\n"
	    "Options:\n"
	    "  --pin|-P <code>        PIN code to authenticate with\n"
	    "  --debug|-d             Spit out lots of debug info to stderr\n"
	    "                         (incl. APDU trace)\n"
	    "  --parseable|-p         Generate parseable output from 'list'\n"
	    "  --guid|-g              GUID of the PIV token to use\n"
	    "  --algorithm|-a <algo>  Override algorithm for the slot and\n"
	    "                         don't use the certificate\n"
	    "  --admin-key|-K <hex|@file>\n"
	    "                         Provides the admin 3DES key to use for\n"
	    "                         auth to the card with admin ops (e.g.\n"
	    "                         generate or init)\n"
	    "  --key|-k <pubkey>      Use a public key for box operation\n"
	    "                         instead of a slot\n"
	    "  --force|-f             Attempt to unlock with PIN code even\n"
	    "                         if there is only 1 attempt left before\n"
	    "                         card lock\n"
	    "  -n <cn>                Used with 'generate', to customise the\n"
	    "                         CN= attribute used on certificate\n");
	exit(3);
}

static void
check_select_key(void)
{
	struct piv_token *t;

	if (ks == NULL) {
		fprintf(stderr, "error: no PIV cards present\n");
		exit(1);
	}

	if (guid != NULL) {
		for (t = ks; t != NULL; t = t->pt_next) {
			if (bcmp(t->pt_guid, guid, guid_len) == 0) {
				if (selk == NULL) {
					selk = t;
				} else {
					fprintf(stderr, "error: GUID prefix "
					    "specified is not unique\n");
					exit(3);
				}
			}
		}
		if (selk == NULL) {
			fprintf(stderr, "error: no PIV card present "
			    "matching given GUID\n");
			exit(3);
		}
	}

#if 0
	if (selk == NULL)
		selk = sysk;
#endif

	if (selk == NULL) {
		selk = ks;
		if (selk->pt_next != NULL) {
			fprintf(stderr, "error: multiple PIV cards "
			    "present and no system token set; you "
			    "must provide -g|--guid to select one\n");
			exit(3);
		}
	}
}

/*const char *optstring =
    "d(debug)"
    "p(parseable)"
    "g:(guid)"
    "P:(pin)"
    "a:(algorithm)"
    "f(force)"
    "K:(admin-key)"
    "k:(key)";*/
const char *optstring = "dpg:P:a:fK:k:n:";

int
main(int argc, char *argv[])
{
	LONG rv;
	SCARDCONTEXT ctx;
	extern char *optarg;
	extern int optind;
	int c;
	uint len;
	char *ptr;
	uint8_t *buf;
	uint d_level = 0;

	bunyan_init();
	bunyan_set_name("pivtool");

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'd':
			bunyan_set_level(TRACE);
			if (++d_level > 1)
				piv_full_apdu_debug = B_TRUE;
			break;
		case 'K':
			if (optarg[0] == '@') {
				buf = read_key_file(&optarg[1], &len);
				if (len > 24 && sniff_hex(buf, len)) {
					admin_key = parse_hex(
					    (const char *)buf, &len);
				} else {
					admin_key = buf;
				}
			} else {
				admin_key = parse_hex(optarg, &len);
			}
			if (len != 24) {
				fprintf(stderr, "error: admin key must be "
				    "24 bytes in length (you gave %d)\n", len);
				exit(3);
			}
			break;
		case 'n':
			cn = optarg;
			break;
		case 'f':
			min_retries = 0;
			break;
		case 'a':
			override = calloc(1, sizeof (struct piv_slot));
			if (strcasecmp(optarg, "rsa1024") == 0) {
				override->ps_alg = PIV_ALG_RSA1024;
			} else if (strcasecmp(optarg, "rsa2048") == 0) {
				override->ps_alg = PIV_ALG_RSA2048;
			} else if (strcasecmp(optarg, "eccp256") == 0) {
				override->ps_alg = PIV_ALG_ECCP256;
			} else if (strcasecmp(optarg, "eccp384") == 0) {
				override->ps_alg = PIV_ALG_ECCP384;
			} else if (strcasecmp(optarg, "3des") == 0) {
				override->ps_alg = PIV_ALG_3DES;
			} else {
				fprintf(stderr, "error: invalid algorithm\n");
				exit(3);
			}
			/* ps_slot will be set after we've parsed the slot */
			break;
		case 'g':
			guid = parse_hex(optarg, &len);
			guid_len = len;
			if (len > 16) {
				fprintf(stderr, "error: GUID must be <=16 bytes"
				    " in length (you gave %d)\n", len);
				exit(3);
			}
			break;
		case 'P':
			pin = optarg;
			break;
		case 'p':
			parseable = B_TRUE;
			break;
		case 'k':
			opubkey = sshkey_new(KEY_UNSPEC);
			assert(opubkey != NULL);
			ptr = optarg;
			rv = sshkey_read(opubkey, &ptr);
			if (rv != 0) {
				fprintf(stderr, "error: failed to parse public "
				    "key: %ld\n", rv);
				exit(3);
			}
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

#if 0
	if (piv_system_token_find(ks, &sysk) != 0)
		sysk = NULL;
#endif

	if (strcmp(op, "list") == 0) {
		if (optind < argc)
			usage();
		cmd_list(ctx);

	} else if (strcmp(op, "init") == 0) {
		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}
		check_select_key();
		cmd_init();

#if 0
	} else if (strcmp(op, "set-system") == 0) {
		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}
		check_select_key();
		cmd_set_system();
#endif

	} else if (strcmp(op, "change-pin") == 0) {
		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}
		check_select_key();
		cmd_change_pin();

	} else if (strcmp(op, "sign") == 0) {
		uint slotid;

		if (optind >= argc)
			usage();
		slotid = strtol(argv[optind++], NULL, 16);

		if (optind < argc)
			usage();

		if (override != NULL)
			override->ps_slot = slotid;

		check_select_key();
		cmd_sign(slotid);

	} else if (strcmp(op, "pubkey") == 0) {
		uint slotid;

		if (optind >= argc) {
			fprintf(stderr, "error: slot required\n");
			usage();
		}
		slotid = strtol(argv[optind++], NULL, 16);

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		check_select_key();
		cmd_pubkey(slotid);

	} else if (strcmp(op, "cert") == 0) {
		uint slotid;

		if (optind >= argc) {
			fprintf(stderr, "error: slot required\n");
			usage();
		}
		slotid = strtol(argv[optind++], NULL, 16);

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		check_select_key();
		cmd_cert(slotid);

	} else if (strcmp(op, "ecdh") == 0) {
		uint slotid;

		if (optind >= argc) {
			fprintf(stderr, "error: slot required\n");
			usage();
		}
		slotid = strtol(argv[optind++], NULL, 16);

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		if (override != NULL)
			override->ps_slot = slotid;

		check_select_key();
		cmd_ecdh(slotid);

	} else if (strcmp(op, "auth") == 0) {
		uint slotid;

		if (optind >= argc) {
			fprintf(stderr, "error: slot required\n");
			usage();
		}
		slotid = strtol(argv[optind++], NULL, 16);

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		if (override != NULL)
			override->ps_slot = slotid;

		check_select_key();
		cmd_auth(slotid);

	} else if (strcmp(op, "box") == 0) {
		uint slotid;

		if (opubkey == NULL) {
			if (optind >= argc) {
				slotid = PIV_SLOT_KEY_MGMT;
			} else {
				slotid = strtol(argv[optind++], NULL, 16);
			}
			check_select_key();
		} else {
			slotid = 0;
		}

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		cmd_box(slotid);

	} else if (strcmp(op, "unbox") == 0) {
		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}
		cmd_unbox();

	} else if (strcmp(op, "box-info") == 0) {
		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}
		cmd_box_info();

	} else if (strcmp(op, "sgdebug") == 0) {
		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}
		check_select_key();
		cmd_sgdebug();

	} else if (strcmp(op, "generate") == 0) {
		uint slotid;

		if (optind >= argc) {
			fprintf(stderr, "error: slot required\n");
			usage();
		}
		slotid = strtol(argv[optind++], NULL, 16);

		if (optind < argc) {
			fprintf(stderr, "error: too many arguments\n");
			usage();
		}

		if (override == NULL) {
			fprintf(stderr, "error: algorithm required\n");
			usage();
		}
		override->ps_slot = slotid;

		check_select_key();
		cmd_generate(slotid, override->ps_alg);

	} else {
		fprintf(stderr, "error: invalid operation '%s'\n", op);
		usage();
	}

	return (0);
}
