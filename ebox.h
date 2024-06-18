/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2018, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_EBOX_H)
#define _EBOX_H

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

#include "errf.h"
#include "piv.h"

#include "openssh/config.h"
#include "openssh/digest.h"

/*
 * This file contains the API for dealing with ebox structures, as well as
 * recovery challenge-response messages and ebox streams.
 *
 * For background on the ebox format and what it does, see the file
 * docs/box-ebox-formats.adoc
 *
 * Eboxes protect some amount of key material, and give you multiple
 * "configurations" which are alternative ways to obtain it. Configurations
 * may either be PRIMARY (in which case unlocking a single piv_ecdh_box gives
 * you the final key), or RECOVERY (in which case you have to unlock some N out
 * of the M available).
 */

enum ebox_type {
	EBOX_TEMPLATE = 0x01,
	EBOX_KEY = 0x02,
	EBOX_STREAM = 0x03
};

enum ebox_config_type {
	EBOX_PRIMARY = 0x01,
	EBOX_RECOVERY = 0x02
};

enum ebox_chaltype {
	CHAL_RECOVERY = 1,
	CHAL_VERIFY_AUDIT = 2,
};

struct ebox_tpl;
struct ebox_tpl_config;
struct ebox_tpl_part;
struct ebox;
struct ebox_config;
struct ebox_part;
struct ebox_challenge;
struct ebox_stream;
struct ebox_stream_chunk;

/*
 * Ebox templates (ebox_tpl_*) store the metadata about possible configurations
 * separately to an actual ebox, so that they can be kept and re-used for
 * storing multiple keys.
 */
struct ebox_tpl *ebox_tpl_alloc(void);
void ebox_tpl_free(struct ebox_tpl *tpl);
uint ebox_tpl_version(const struct ebox_tpl *tpl);

/* Recursively clones the entire ebox_tpl, all configurations and parts. */
struct ebox_tpl *ebox_tpl_clone(const struct ebox_tpl *tpl);

void ebox_tpl_add_config(struct ebox_tpl *tpl, struct ebox_tpl_config *config);
void ebox_tpl_remove_config(struct ebox_tpl *tpl, struct ebox_tpl_config *config);

struct ebox_tpl_config *ebox_tpl_next_config(const struct ebox_tpl *tpl,
    const struct ebox_tpl_config *prev);

struct ebox_tpl_config *ebox_tpl_config_alloc(enum ebox_config_type type);
void ebox_tpl_config_free(struct ebox_tpl_config *config);

uint ebox_tpl_config_n(const struct ebox_tpl_config *config);
enum ebox_config_type ebox_tpl_config_type(
    const struct ebox_tpl_config *config);

errf_t *ebox_tpl_config_set_n(struct ebox_tpl_config *config, uint n);
void ebox_tpl_config_add_part(struct ebox_tpl_config *config,
    struct ebox_tpl_part *part);
void ebox_tpl_config_remove_part(struct ebox_tpl_config *config,
    struct ebox_tpl_part *part);
struct ebox_tpl_part *ebox_tpl_config_next_part(
    const struct ebox_tpl_config *config, const struct ebox_tpl_part *prev);

struct ebox_tpl_part *ebox_tpl_part_alloc(const uint8_t *guid, size_t guidlen,
    enum piv_slotid slot, struct sshkey *pubkey);
void ebox_tpl_part_free(struct ebox_tpl_part *part);

/* Read-only attributes of the part. */
const char *ebox_tpl_part_name(const struct ebox_tpl_part *part);
/*
 * Note that these "struct sshkey *" pointers are owned by the ebox_tpl_part
 * and should not be modified. They should be const but aren't because of
 * some sshkey functions.
 */
struct sshkey *ebox_tpl_part_pubkey(const struct ebox_tpl_part *part);
struct sshkey *ebox_tpl_part_cak(const struct ebox_tpl_part *part);
const uint8_t *ebox_tpl_part_guid(const struct ebox_tpl_part *part);
enum piv_slotid ebox_tpl_part_slot(const struct ebox_tpl_part *part);

/* These both make a copy of their argument. */
void ebox_tpl_part_set_name(struct ebox_tpl_part *part, const char *name);
void ebox_tpl_part_set_cak(struct ebox_tpl_part *part, struct sshkey *cak);

/*
 * These functions allow an opaque "private" data pointer to be stashed on
 * a struct ebox_tpl_*, which can be freely used by client applications.
 */
void *ebox_tpl_private(const struct ebox_tpl *tpl);
void *ebox_tpl_alloc_private(struct ebox_tpl *tpl, size_t sz);
void ebox_tpl_config_free_private(struct ebox_tpl_config *config);
void *ebox_tpl_config_private(const struct ebox_tpl_config *config);
void *ebox_tpl_config_alloc_private(struct ebox_tpl_config *config, size_t sz);
void *ebox_tpl_part_private(const struct ebox_tpl_part *part);
void *ebox_tpl_part_alloc_private(struct ebox_tpl_part *part, size_t sz);
void ebox_tpl_part_free_private(struct ebox_tpl_part *part);

/* Serialise and de-serialise an ebox structure. */
MUST_CHECK
errf_t *sshbuf_get_ebox_tpl(struct sshbuf *buf, struct ebox_tpl **tpl);
MUST_CHECK
errf_t *sshbuf_put_ebox_tpl(struct sshbuf *buf, struct ebox_tpl *tpl);

/*
 * Creates a new ebox based on a given template, sealing up the provided key
 * and (optional) recovery token.
 */
MUST_CHECK
errf_t *ebox_create(const struct ebox_tpl *tpl, const uint8_t *key,
    size_t keylen, const uint8_t *rtoken, size_t rtokenlen,
    struct ebox **pebox);
void ebox_free(struct ebox *box);

uint ebox_version(const struct ebox *ebox);
enum ebox_type ebox_type(const struct ebox *ebox);
uint ebox_ephem_count(const struct ebox *ebox);
const struct sshkey *ebox_ephem_pubkey(const struct ebox *ebox, uint index);
size_t ebox_config_nonce_len(const struct ebox_config *config);

boolean_t ebox_is_unlocked(const struct ebox *box);

const char *ebox_cipher(const struct ebox *box);
const uint8_t *ebox_key(const struct ebox *box, size_t *len);
const uint8_t *ebox_recovery_token(const struct ebox *box, size_t *len);

/*
 * Returns the template "shadow" of the ebox. This is an ebox_tpl that's
 * owned by the struct ebox (so you must not free or modify it). It contains
 * a complete copy of a template that would produce this ebox if given the
 * same key (so it contains the same number of configs and parts and the
 * parts have all the information on them that's in the ebox).
 *
 * The ebox_config_tpl and ebox_part_tpl() functions are conveniences that
 * return the shadow of a particular ebox_config or ebox_part. For a lot of
 * the information that you might want to know about an ebox_part, you will
 * have to use the shadow template (e.g. the friendly name).
 */
struct ebox_tpl *ebox_tpl(const struct ebox *ebox);
struct ebox_tpl_config *ebox_config_tpl(const struct ebox_config *config);
struct ebox_tpl_part *ebox_part_tpl(const struct ebox_part *part);

struct ebox_config *ebox_next_config(const struct ebox *box,
    const struct ebox_config *prev);
struct ebox_part *ebox_config_next_part(const struct ebox_config *config,
    const struct ebox_part *prev);

/*
 * Returns a pointer to the ebox part secret box.
 *
 * You can and should modify this box by unsealing it, but don't free it (it's
 * part of the ebox_part). Functions like ebox_unlock() and ebox_recover()
 * expect you to iterate over the parts in a config and use this method to
 * retrieve the piv_ecdh_box and call piv_box_open().
 *
 * You don't need to call piv_box_take_data() though.
 */
struct piv_ecdh_box *ebox_part_box(const struct ebox_part *part);

/* Serialise/de-serialise an ebox */
MUST_CHECK
errf_t *sshbuf_get_ebox(struct sshbuf *buf, struct ebox **box);
MUST_CHECK
errf_t *sshbuf_put_ebox(struct sshbuf *buf, struct ebox *box);

/*
 * Unlock an ebox using a primary config.
 *
 * One of the primary config's part boxes must have been already unsealed
 * before calling this (see ebox_part_box() and piv_box_open()).
 *
 * Errors:
 *  - InsufficientParts: none of the part boxes were unsealed
 */
MUST_CHECK
errf_t *ebox_unlock(struct ebox *ebox, struct ebox_config *config);

/*
 * Perform recovery on an ebox using a recovery config.
 *
 * N out of M of the parts on this config must have been processed with
 * ebox_challenge_response() before calling this.
 *
 * Errors:
 *  - InsufficientParts: insufficient number of parts available on this config
 *                       that are ready for recovery
 *  - AlreadyUnlocked: the ebox is already unlocked or recovered
 *  - RecoveryFailed: the recovery box data was invalid or corrupt
 */
MUST_CHECK
errf_t *ebox_recover(struct ebox *ebox, struct ebox_config *config);

/*
 * These functions allow an opaque "private" data pointer to be stashed on
 * a struct ebox_*, which can be freely used by client applications. This is
 * particularly useful because of functions like ebox_challenge_response() which
 * give you back a pointer to an ebox_part (so you can then transform that back
 * into some application-specific information about the part).
 */
void *ebox_private(const struct ebox *ebox);
void *ebox_alloc_private(struct ebox *ebox, size_t sz);
void ebox_free_private(struct ebox *ebox);
void *ebox_config_private(const struct ebox_config *config);
void *ebox_config_alloc_private(struct ebox_config *config, size_t sz);
void ebox_config_free_private(struct ebox_config *config);
void *ebox_part_private(const struct ebox_part *part);
void *ebox_part_alloc_private(struct ebox_part *part, size_t sz);
void ebox_part_free_private(struct ebox_part *part);

/*
 * Generate a challenge for a given recovery config + part.
 *
 * The challenge can then be serialised using sshbuf_put_ebox_challenge() and
 * sent to the remote side. The "descfmt", ... arguments are given to vsnprintf
 * to create the "description" field for the challenge (displayed on the
 * remote end).
 *
 * Errors:
 *  - LengthError: description was too long for available space
 */
MUST_CHECK
errf_t *ebox_gen_challenge(struct ebox_config *config, struct ebox_part *part,
    const char *descfmt, ...);
const struct ebox_challenge *ebox_part_challenge(const struct ebox_part *part);

void ebox_challenge_free(struct ebox_challenge *chal);

/*
 * Serializes an ebox challenge inside a piv_ecdh_box as a one-step process.
 *
 * The data written in the buf is ready to be transported to a remote machine.
 */
MUST_CHECK
errf_t *sshbuf_put_ebox_challenge(struct sshbuf *buf,
    const struct ebox_challenge *chal);

/*
 * De-serializes an ebox challenge from inside a piv_ecdh_box. The piv_ecdh_box
 * must be already unsealed.
 */
MUST_CHECK
errf_t *sshbuf_get_ebox_challenge(struct piv_ecdh_box *box,
    struct ebox_challenge **chal);

enum ebox_chaltype ebox_challenge_type(const struct ebox_challenge *chal);
uint ebox_challenge_id(const struct ebox_challenge *chal);
const char *ebox_challenge_desc(const struct ebox_challenge *chal);
const char *ebox_challenge_hostname(const struct ebox_challenge *chal);
uint64_t ebox_challenge_ctime(const struct ebox_challenge *chal);
const uint8_t *ebox_challenge_words(const struct ebox_challenge *chal,
    size_t *len);
struct sshkey *ebox_challenge_destkey(const struct ebox_challenge *chal);

/*
 * Returns a pointer to the keybox within the ebox_challenge, in the same style
 * as ebox_part_box().
 *
 * You'll need to call piv_box_open() on this before you can use
 * sshbuf_put_ebox_challenge_response() to generate a response.
 */
struct piv_ecdh_box *ebox_challenge_box(const struct ebox_challenge *chal);


/*
 * Generate and serialise a response to an ebox challenge inside a piv_ecdh_box
 * as a one-step process. The keybox on chal must be already unsealed.
 *
 * The data written in the buf is ready to be transported to the original
 * requesting machine.
 */
MUST_CHECK
errf_t *sshbuf_put_ebox_challenge_response(struct sshbuf *buf,
    const struct ebox_challenge *chal);

/*
 * Process an incoming response to a recovery challenge for the given config.
 *
 * *ppart is set to point at the part that this response was from. Takes
 * ownership of respbox, and will free it.
 *
 * Errors:
 *  - EAGAIN: this challenge matched a part that is already unlocked
 */
MUST_CHECK
errf_t *ebox_challenge_response(struct ebox_config *config,
    struct piv_ecdh_box *respbox, struct ebox_part **ppart);

MUST_CHECK
errf_t *sshbuf_get_ebox_stream(struct sshbuf *buf, struct ebox_stream **str);
MUST_CHECK
errf_t *sshbuf_put_ebox_stream(struct sshbuf *buf, struct ebox_stream *str);
MUST_CHECK
errf_t *sshbuf_get_ebox_stream_chunk(struct sshbuf *buf,
    const struct ebox_stream *stream, struct ebox_stream_chunk **chunk);
MUST_CHECK
errf_t *sshbuf_put_ebox_stream_chunk(struct sshbuf *buf,
    struct ebox_stream_chunk *chunk);

struct ebox *ebox_stream_ebox(const struct ebox_stream *str);
const char *ebox_stream_cipher(const struct ebox_stream *str);
const char *ebox_stream_mac(const struct ebox_stream *str);
size_t ebox_stream_chunk_size(const struct ebox_stream *str);
size_t ebox_stream_seek_offset(const struct ebox_stream *str, size_t offset);

MUST_CHECK
errf_t *ebox_stream_new(const struct ebox_tpl *tpl, struct ebox_stream **str);
MUST_CHECK
errf_t *ebox_stream_chunk_new(const struct ebox_stream *str, const void *data,
    size_t size, size_t seqnr, struct ebox_stream_chunk **chunk);

MUST_CHECK
errf_t *ebox_stream_decrypt_chunk(struct ebox_stream_chunk *chunk);
MUST_CHECK
errf_t *ebox_stream_encrypt_chunk(struct ebox_stream_chunk *chunk);
const uint8_t *ebox_stream_chunk_data(const struct ebox_stream_chunk *chunk,
    size_t *size);
struct sshbuf *ebox_stream_chunk_data_buf(const struct ebox_stream_chunk *chunk);

void ebox_stream_free(struct ebox_stream *str);
void ebox_stream_chunk_free(struct ebox_stream_chunk *chunk);

#endif
