/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#include <stdint.h>
#include <assert.h>

#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <wintypes.h>
#include <winscard.h>
#endif

#include <sys/types.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "piv.h"
#include "libssh/digest.h"

enum ebox_type {
	EBOX_TEMPLATE = 0x01,
	EBOX_KEYONLY = 0x02,
	EBOX_STREAM = 0x03
};

enum ebox_config_type {
	EBOX_PRIMARY = 0x01,
	EBOX_RECOVERY = 0x02
};

enum ebox_part_tag {
	EBOX_PART_END = 0,
	EBOX_PART_PUBKEY = 1,
	EBOX_PART_NAME = 2,
	EBOX_PART_CAK = 3,
	EBOX_PART_GUID = 4
};

struct ebox_tpl {
	struct ebox_tpl_config *et_configs;
	void *et_priv;
};

struct ebox_tpl_config {
	struct ebox_tpl_config *etc_next;
	enum ebox_config_type etc_type;
	uint8_t etc_n;
	uint8_t etc_m;
	struct ebox_tpl_part *etc_parts;
	void *etc_priv;
};

struct ebox_tpl_part {
	struct ebox_tpl_part *etp_next;
	char *etp_name;
	struct sshkey *etp_pubkey;
	struct sshkey *etp_cak;
	uint8_t etp_guid[16];
	void *etp_priv;
};

struct ebox {
	struct ebox_tpl *e_tpl;
	struct ebox_config *e_configs;
	struct piv_ecdh_box *e_recovbox;
	size_t e_keylen;
	uint8_t *e_key;
	size_t e_tokenlen;
	uint8_t *e_token;
	void *e_priv;
};

struct ebox_config {
	struct ebox_config *ec_next;
	struct ebox_tpl_config *ec_tpl;
	struct ebox_part *ec_parts;
	void *ec_priv;
};

struct ebox_part {
	struct ebox_part *ep_next;
	struct ebox_tpl_part *ep_tpl;
	struct piv_ecdh_box *ep_box;
	uint8_t ep_id;
	struct ebox_challenge *ep_chal;
	struct piv_ecdh_box *ep_resp;
	size_t ep_sharelen;
	uint8_t *ep_share;
	void *ep_priv;
};

enum chaltype {
	CHAL_RECOVERY = 1,
	CHAL_VERIFY_AUDIT = 2,
};

enum chaltag {
	CTAG_HOSTNAME = 1,
	CTAG_CTIME = 2,
	CTAG_DESCRIPTION = 3,
	CTAG_WORDS = 4,
};

struct ebox_challenge {
	uint8_t c_version;
	enum chaltype c_type;
	uint8_t c_id;
	char *c_description;
	char *c_hostname;
	uint64_t c_ctime;
	uint8_t c_words[4];
	struct sshkey *c_destkey;
	struct piv_ecdh_box *c_keybox;
};

void ebox_tpl_free(struct ebox_tpl *tpl);
void ebox_tpl_config_free(struct ebox_tpl_config *config);
void ebox_tpl_part_free(struct ebox_tpl_part *part);

int ebox_tpl_to_binary(struct ebox_tpl *tpl, uint8_t **output, size_t *len);
int ebox_tpl_from_binary(const uint8_t *input, size_t len,
    struct ebox_tpl **tpl);
int sshbuf_get_ebox_tpl(struct sshbuf *buf, struct ebox_tpl **tpl);
int sshbuf_put_ebox_tpl(struct sshbuf *buf, struct ebox_tpl *tpl);

int ebox_to_binary(struct ebox *ebox, uint8_t **output, size_t *len);
int ebox_from_binary(const uint8_t *input, size_t len, struct ebox **ebox);

int ebox_gen_challenge(struct ebox_part *part, const char *descfmt, ...);
int ebox_challenge_to_binary(struct ebox_challenge *chal, uint8_t **output,
    size_t *len);
int ebox_challenge_response(struct ebox_part *part,
    struct piv_ecdh_box *respbox);
