/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_TLV_H)
#define _TLV_H

#include <stdint.h>
#include <sys/types.h>
#include <assert.h>
#include <strings.h>
#include "errf.h"

#define	MAX_APDU_SIZE	16384

/*
 * This is a parser and generator for ISO7816 BER-TLV, a limited subset of
 * ASN.1 BER used by ISO7816 compliant smartcards.
 *
 * In this implementation we also use "raw" tag numbers so that when you
 * see tag numbers in piv.c using this parser, they match exactly what's
 * written in the PIV spec.
 */

/*
 * A TLV "context" is a range within the buffer -- either the root context
 * which normally spans the entire buffer, or a context resulting from a
 * parsed tag.
 *
 * Each time we read a tag in tlv_read_tag() we create a new one of these
 * which spans some subset of the context above it and set ts_now to point at
 * it.
 */
struct tlv_context {
	struct tlv_context *tc_next;
	size_t tc_begin;	/* beginning index in ts_buf */
	size_t tc_end;		/* final index in ts_buf */
	size_t tc_lenptr;	/* index of the first byte of len */
	int tc_depth;		/* root = 0, tag = 1, child tag = 2, etc */
};

struct tlv_state {
	struct tlv_context *ts_root;	/* top-level ctx spanning whole buf */
	struct tlv_context *ts_now;	/* current tag ctx */
	uint8_t *ts_buf;
	size_t ts_pos;
	boolean_t ts_freebuf;		/* if B_TRUE we malloc'd the buffer */
	boolean_t ts_debug;
};

/*
 * Begins a "read" mode TLV parser, over the data in "buf" from index "offset"
 * to index "offset + len" (len is the length of data to be parsed, not length
 * of the buffer).
 */
struct tlv_state *tlv_init(const uint8_t *buf, size_t offset, size_t len);
void tlv_free(struct tlv_state *ts);

void tlv_enable_debug(struct tlv_state *ts);

/*
 * Begins reading a BER-TLV tag. This will perform length validation before
 * returning.
 */
errf_t *tlv_read_tag(struct tlv_state *ts, uint *tag);

/*
 * Ends the parsing of the current tag, asserting that all bytes in the tag
 * have been consumed. Error will be returned if there are outstanding bytes.
 */
errf_t *tlv_end(struct tlv_state *ts);

/*
 * Skips all remaining bytes in the current tag and ends parsing of the tag.
 */
void tlv_skip(struct tlv_state *ts);

/*
 * Aborts parsing, consuming all data to the end of the root context.
 * Does not free the tlv_state, though.
 */
void tlv_abort(struct tlv_state *ts);

/* Read an integer from the current tag. */
errf_t *tlv_read_u8(struct tlv_state *ts, uint8_t *out);
errf_t *tlv_read_u16(struct tlv_state *ts, uint16_t *out);
/*
 * Reads the remainder of the current tag as a single number, from 1-4 bytes
 * in length.
 */
errf_t *tlv_read_u8to32(struct tlv_state *ts, uint32_t *out);

/*
 * Read the remaining contents of the current tag as a fixed-length buffer. If
 * the length doesn't match exactly, returns error.
 */
errf_t *tlv_read(struct tlv_state *ts, uint8_t *dest, size_t len);
/*
 * Read the remaining contents of the current tag as a newly allocated buffer.
 * Writes the length of the buffer into *len. Caller has to free the buffer
 * with free().
 */
errf_t *tlv_read_alloc(struct tlv_state *ts, uint8_t **data, size_t *len);
/*
 * Reads up to maxLen bytes into dest. If the end of the tag is encountered
 * before maxLen bytes are read, will read to the end of the tag. Length
 * actually written is placed in *len.
 */
errf_t *tlv_read_upto(struct tlv_state *ts, uint8_t *dest, size_t maxLen,
    size_t *len);

errf_t *tlv_read_string(struct tlv_state *ts, char **dest);

static inline boolean_t
tlv_at_root_end(const struct tlv_state *ts)
{
	return (ts->ts_pos >= ts->ts_root->tc_end);
}

static inline boolean_t
tlv_at_end(const struct tlv_state *ts)
{
	return (tlv_at_root_end(ts) || ts->ts_pos >= ts->ts_now->tc_end);
}

static inline size_t
tlv_root_rem(const struct tlv_state *ts)
{
	return (ts->ts_root->tc_end - ts->ts_pos);
}

static inline size_t
tlv_rem(const struct tlv_state *ts)
{
	return (ts->ts_now->tc_end - ts->ts_pos);
}

static inline uint8_t *
tlv_buf(const struct tlv_state *ts)
{
	return (ts->ts_buf);
}

static inline uint8_t *
tlv_ptr(const struct tlv_state *ts)
{
	return (&ts->ts_buf[ts->ts_pos]);
}

/* Begins a write-mode BER-TLV generator with an internal buffer. */
struct tlv_state *tlv_init_write(void);

void tlv_pushl(struct tlv_state *ts, uint tag, size_t maxlen);
void tlv_pop(struct tlv_state *ts);

void tlv_write(struct tlv_state *ts, const uint8_t *src, size_t len);
void tlv_write_u8to32(struct tlv_state *ts, uint32_t val);
void tlv_write_byte(struct tlv_state *ts, uint8_t val);

static inline size_t
tlv_len(const struct tlv_state *ts)
{
	return (ts->ts_pos);
}

static inline void
tlv_push(struct tlv_state *ts, uint tag)
{
	tlv_pushl(ts, tag, 127);
}

static inline void
tlv_push256(struct tlv_state *ts, uint tag)
{
	tlv_pushl(ts, tag, 255);
}

static inline void
tlv_push64k(struct tlv_state *ts, uint tag)
{
	tlv_pushl(ts, tag, 65535);
}

#endif
