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

#if !defined(__sun)
typedef enum { B_FALSE = 0, B_TRUE = 1 } boolean_t;
typedef unsigned int uint;
#endif

#define	MAX_APDU_SIZE	16384

extern boolean_t debug;

struct tlv_state {
	struct tlv_stack_frame *ts_stack;
	int ts_stklvl;
	uint8_t *ts_buf;
	boolean_t ts_freebuf;
	boolean_t ts_debug;
	size_t ts_offset;
	size_t ts_ptr;
	size_t ts_len;
	size_t ts_end;
};

struct tlv_state *tlv_init(const uint8_t *buf, size_t offset, size_t len);
struct tlv_state *tlv_init_write(void);
void tlv_enable_debug(struct tlv_state *ts);
uint tlv_read_tag(struct tlv_state *ts);
uint8_t tlv_read_byte(struct tlv_state *ts);
uint16_t tlv_read_short(struct tlv_state *ts);
uint tlv_read_uint(struct tlv_state *ts);
size_t tlv_read(struct tlv_state *ts, uint8_t *dest, size_t offset,
    size_t maxLen);
void tlv_skip(struct tlv_state *ts);
void tlv_end(struct tlv_state *ts);

void tlv_pushl(struct tlv_state *ts, uint tag, size_t maxlen);
void tlv_pop(struct tlv_state *ts);
void tlv_write(struct tlv_state *ts, const uint8_t *src, size_t offset,
    size_t len);
void tlv_write_uint(struct tlv_state *ts, uint val);
void tlv_write_byte(struct tlv_state *ts, uint8_t val);

void tlv_free(struct tlv_state *ts);

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

static inline boolean_t
tlv_at_buf_end(const struct tlv_state *ts)
{
	return (ts->ts_offset >= ts->ts_end);
}

static inline boolean_t
tlv_at_end(const struct tlv_state *ts)
{
	return (tlv_at_buf_end(ts) || ts->ts_len == 0);
}

static inline size_t
tlv_buf_rem(const struct tlv_state *ts)
{
	return (ts->ts_end - ts->ts_offset);
}

static inline size_t
tlv_rem(const struct tlv_state *ts)
{
	return (ts->ts_len);
}

static inline size_t
tlv_len(const struct tlv_state *ts)
{
	return (ts->ts_offset);
}

static inline uint8_t *
tlv_buf(const struct tlv_state *ts)
{
	return (ts->ts_buf);
}

static inline uint8_t *
tlv_ptr(const struct tlv_state *ts)
{
	return (&ts->ts_buf[ts->ts_offset]);
}

#endif
