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
#include <sys/uio.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "piv.h"
#include "libssh/digest.h"

enum ebox_type {
	EBOX_TEMPLATE = 0x01,
	EBOX_KEY = 0x02,
	EBOX_STREAM = 0x03
};

enum ebox_recov_tag {
	EBOX_RECOV_TOKEN = 0x01,
	EBOX_RECOV_KEY = 0x02
};

enum ebox_config_type {
	EBOX_PRIMARY = 0x01,
	EBOX_RECOVERY = 0x02
};

enum ebox_stream_mode {
	EBOX_MODE_ENCRYPT = 0x01,
	EBOX_MODE_DECRYPT = 0x02
};

enum ebox_part_tag {
	EBOX_PART_END = 0,
	EBOX_PART_PUBKEY = 1,
	EBOX_PART_NAME = 2,
	EBOX_PART_CAK = 3,
	EBOX_PART_GUID = 4,
	EBOX_PART_BOX = 5
};

struct buf {
	size_t b_len;
	uint8_t *b_data;
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
	enum ebox_type e_type;

	/* main key */
	size_t e_keylen;
	uint8_t *e_key;

	/* recovery box */
	char *e_rcv_cipher;
	struct buf e_rcv_key;
	struct buf e_rcv_iv;
	struct buf e_rcv_enc;
	struct buf e_rcv_plain;

	/* recovery token */
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

struct ebox_stream {
	struct ebox *es_ebox;
	char *es_cipher;
	char *es_mac;
	struct sshbuf *es_buf;
	enum ebox_stream_mode es_mode;
};

struct ebox_stream_chunk {
	uint32_t esc_len;
	uint8_t *esc_data;

	uint32_t esc_enclen;
	uint8_t *esc_encdata;

	uint8_t *esc_nextk;
	uint32_t esc_nextklen;
};

void ebox_tpl_free(struct ebox_tpl *tpl);
void ebox_tpl_config_free(struct ebox_tpl_config *config);
void ebox_tpl_part_free(struct ebox_tpl_part *part);

struct ebox_tpl *ebox_tpl_clone(struct ebox_tpl *tpl);

int sshbuf_get_ebox_tpl(struct sshbuf *buf, struct ebox_tpl **tpl);
int sshbuf_put_ebox_tpl(struct sshbuf *buf, struct ebox_tpl *tpl);

void ebox_free(struct ebox *box);
void ebox_config_free(struct ebox_config *config);
void ebox_part_free(struct ebox_part *part);

int sshbuf_get_ebox(struct sshbuf *buf, struct ebox **box);
int sshbuf_put_ebox(struct sshbuf *buf, struct ebox *box);

void ebox_stream_free(struct ebox_stream *str);
void ebox_stream_chunk_free(struct ebox_stream_chunk *chunk);

/*
 * Creates a new ebox based on a given template, sealing up the provided key
 * and (optional) recovery token.
 */
struct ebox *ebox_create(const struct ebox_tpl *tpl, const uint8_t *key,
    size_t keylen, const uint8_t *token, size_t tokenlen);

int sshbuf_get_ebox_stream(struct sshbuf *buf, struct ebox_stream **str);
int sshbuf_put_ebox_stream(struct sshbuf *buf, struct ebox_stream *str);
int sshbuf_get_ebox_stream_chunk(struct sshbuf *buf,
    struct ebox_stream_chunk **chunk);
int sshbuf_put_ebox_stream_chunk(struct sshbuf *buf,
    struct ebox_stream_chunk *chunk);

struct ebox_stream *ebox_stream_init_decrypt(void);
struct ebox_stream *ebox_stream_init_encrypt(struct ebox_tpl *tpl);
int ebox_stream_put(struct ebox_stream *str, struct iovec *vecs, size_t nvecs);
int ebox_stream_get(struct ebox_stream *str, struct iovec *vecs, size_t nvecs);

int ebox_gen_challenge(struct ebox_part *part, const char *descfmt, ...);
int ebox_challenge_to_binary(struct ebox_challenge *chal, uint8_t **output,
    size_t *len);
int ebox_challenge_response(struct ebox_part *part,
    struct piv_ecdh_box *respbox);
