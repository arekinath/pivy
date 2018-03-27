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

#include "tlv.h"
#include "libssh/sshbuf.h"

enum tlv_tag_bits {
	TLV_TYPE_MASK = (1 << 7 | 1 << 6 | 1 << 5),
	TLV_TAG_MASK = ~(TLV_TYPE_MASK),
	TLV_TAG_CONT = 0xFF & TLV_TAG_MASK,
};

struct tlv_stack_frame {
	struct tlv_stack_frame *tsf_next;
	size_t tsf_len;
	size_t tsf_ptr;
	size_t tsf_offset;
};

struct tlv_state *
tlv_init(const uint8_t *buf, size_t offset, size_t len)
{
	struct tlv_state *ts = calloc(1, sizeof (struct tlv_state));
	assert(ts != NULL);
	ts->ts_buf = (uint8_t *)buf;
	ts->ts_offset = offset;
	ts->ts_end = offset + len;
	return (ts);
}

void
tlv_enable_debug(struct tlv_state *ts)
{
	ts->ts_debug = B_TRUE;
}

struct tlv_state *
tlv_init_write(void)
{
	struct tlv_state *ts = calloc(1, sizeof (struct tlv_state));
	assert(ts != NULL);
	ts->ts_buf = calloc(1, MAX_APDU_SIZE);
	assert(ts->ts_buf != NULL);
	ts->ts_end = MAX_APDU_SIZE;
	ts->ts_freebuf = B_TRUE;
	return (ts);
}

const uint8_t TLV_CONT = (1 << 7);

void
tlv_pushl(struct tlv_state *ts, uint tag, size_t maxlen)
{
	uint8_t *buf = ts->ts_buf;
	struct tlv_stack_frame *sf;

	tlv_write_uint(ts, tag);

	if (ts->ts_ptr > 0) {
		sf = calloc(1, sizeof (*sf));
		assert(sf != NULL);
		sf->tsf_ptr = ts->ts_ptr;
		sf->tsf_next = ts->ts_stack;
		ts->ts_stack = sf;
		++ts->ts_stklvl;
	}

	ts->ts_ptr = ts->ts_offset;

	if (maxlen < (1 << 7)) {
		buf[ts->ts_offset++] = 0x00;
	} else if (maxlen < (1 << 8)) {
		buf[ts->ts_offset++] = 0x81;
		ts->ts_offset++;
	} else if (maxlen < (1 << 16)) {
		buf[ts->ts_offset++] = 0x82;
		ts->ts_offset += 2;
	} else if (maxlen < (1 << 24)) {
		buf[ts->ts_offset++] = 0x83;
		ts->ts_offset += 3;
	} else {
		assert(0);
	}
}

void
tlv_pop(struct tlv_state *ts)
{
	uint8_t *buf = ts->ts_buf;
	size_t len = (ts->ts_offset - ts->ts_ptr);
	struct tlv_stack_frame *sf;

	if (buf[ts->ts_ptr] == 0x00) {
		len -= 1;
		assert(len < (1 << 7));
		buf[ts->ts_ptr] = len;
	} else if (buf[ts->ts_ptr] == 0x81) {
		len -= 2;
		assert(len < (1 << 8));
		buf[ts->ts_ptr + 1] = len;
	} else if (buf[ts->ts_ptr] == 0x82) {
		len -= 3;
		assert(len < (1 << 16));
		buf[ts->ts_ptr + 1] = (len & 0xFF00) >> 8;
		buf[ts->ts_ptr + 2] = (len & 0x00FF);
	} else if (buf[ts->ts_ptr] == 0x83) {
		len -= 4;
		assert(len < (1 << 24));
		buf[ts->ts_ptr + 1] = (len & 0xFF0000) >> 16;
		buf[ts->ts_ptr + 2] = (len & 0x00FF00) >> 8;
		buf[ts->ts_ptr + 3] = (len & 0x0000FF);
	}

	if (ts->ts_stack != NULL) {
		sf = ts->ts_stack;
		ts->ts_stack = sf->tsf_next;
		ts->ts_ptr = sf->tsf_ptr;
		free(sf);
		--ts->ts_stklvl;
	}
}

uint
tlv_read_tag(struct tlv_state *ts)
{
	const uint8_t *buf = ts->ts_buf;
	uint8_t d;
	uint tag, len, octs;
	struct tlv_stack_frame *sf;
	size_t origin = ts->ts_offset;

	assert(!tlv_at_buf_end(ts));
	d = buf[ts->ts_offset++];
	ts->ts_len--;
	tag = d;

	if ((d & TLV_TAG_MASK) == TLV_TAG_CONT) {
		do {
			assert(!tlv_at_buf_end(ts));
			d = buf[ts->ts_offset++];
			ts->ts_len--;
			tag <<= 8;
			tag |= d;
		} while ((d & TLV_CONT) == TLV_CONT);
	}

	assert(!tlv_at_buf_end(ts));
	d = buf[ts->ts_offset++];
	ts->ts_len--;
	if ((d & TLV_CONT) == TLV_CONT) {
		octs = d & (~TLV_CONT);
		assert(octs > 0 && octs <= 4);
		len = 0;
		assert(tlv_buf_rem(ts) >= octs);
		for (; octs > 0; --octs) {
			d = buf[ts->ts_offset++];
			ts->ts_len--;
			len <<= 8;
			len |= d;
		}
	} else {
		len = d;
	}
	assert(tlv_buf_rem(ts) >= len);

	sf = calloc(1, sizeof (*sf));
	assert(sf != NULL);
	sf->tsf_ptr = ts->ts_ptr;
	sf->tsf_len = ts->ts_len - len;
	sf->tsf_offset = ts->ts_offset + len;
	sf->tsf_next = ts->ts_stack;
	ts->ts_stack = sf;
	++ts->ts_stklvl;

	if (ts->ts_debug) {
		fprintf(stderr, "%*stag at +%lu: 0x%x (%u bytes)\n",
		    ts->ts_stklvl, "", origin, tag, len);
	}

	ts->ts_len = len;
	ts->ts_ptr = origin;

	return (tag);
}

void
tlv_end(struct tlv_state *ts)
{
	struct tlv_stack_frame *sf = ts->ts_stack;
	if (ts->ts_debug) {
		fprintf(stderr, "%*send tag from +%lu (%lu bytes left)\n",
		    ts->ts_stklvl + 1, "", ts->ts_ptr, ts->ts_len);
	}
	assert(ts->ts_len == 0);
	if (sf != NULL) {
		ts->ts_stack = sf->tsf_next;
		ts->ts_len = sf->tsf_len;
		ts->ts_ptr = sf->tsf_ptr;
		assert(ts->ts_offset == sf->tsf_offset);
		free(sf);
		--ts->ts_stklvl;
	}
}

void
tlv_skip(struct tlv_state *ts)
{
	struct tlv_stack_frame *sf = ts->ts_stack;
	uint lvl;
	if (ts->ts_debug) {
		fprintf(stderr, "%*sskip tag from +%lu (%lu bytes left)\n",
		    ts->ts_stklvl + 1, "", ts->ts_ptr, ts->ts_len);
	}
	ts->ts_offset += ts->ts_len;
	ts->ts_len = 0;
	if (sf != NULL) {
		ts->ts_stack = sf->tsf_next;
		ts->ts_len = sf->tsf_len;
		ts->ts_ptr = sf->tsf_ptr;
		assert(ts->ts_offset == sf->tsf_offset);
		free(sf);
		--ts->ts_stklvl;
	}
}

uint8_t
tlv_read_byte(struct tlv_state *ts)
{
	assert(!tlv_at_end(ts));
	ts->ts_len--;
	return (ts->ts_buf[ts->ts_offset++]);
}

uint16_t
tlv_read_short(struct tlv_state *ts)
{
	uint16_t rv;
	assert(tlv_rem(ts) >= 2);
	ts->ts_len -= 2;
	rv = ts->ts_buf[ts->ts_offset++] << 8;
	rv |= ts->ts_buf[ts->ts_offset++];
	return (rv);
}

uint
tlv_read_uint(struct tlv_state *ts)
{
	uint val = 0;
	const uint8_t *buf = ts->ts_buf;
	assert(tlv_rem(ts) <= 4);
	while (!tlv_at_end(ts)) {
		val <<= 8;
		val |= buf[ts->ts_offset++];
		ts->ts_len--;
	}
	return (val);
}

size_t
tlv_read(struct tlv_state *ts, uint8_t *dest, size_t offset, size_t maxLen)
{
	size_t len = maxLen;
	if (len > tlv_rem(ts))
		len = tlv_rem(ts);
	bcopy(&ts->ts_buf[ts->ts_offset], &dest[offset], len);
	ts->ts_offset += len;
	ts->ts_len -= len;
	return (len);
}

void
tlv_free(struct tlv_state *ts)
{
	assert(ts->ts_stack == NULL);
	if (ts->ts_freebuf) {
		explicit_bzero(ts->ts_buf, MAX_APDU_SIZE);
		free(ts->ts_buf);
	}
	free(ts);
}

void
tlv_write(struct tlv_state *ts, const uint8_t *src, size_t offset, size_t len)
{
	assert(tlv_buf_rem(ts) >= len);
	bcopy(&src[offset], &ts->ts_buf[ts->ts_offset], len);
	ts->ts_offset += len;
}

void
tlv_write_uint(struct tlv_state *ts, uint val)
{
	uint8_t *buf = ts->ts_buf;
	uint mask = 0xFF << 24;
	int shift = 24;
	uint part;

	while (shift >= 0) {
		part = (val & mask) >> shift;
		if (part != 0) {
			assert(!tlv_at_buf_end(ts));
			buf[ts->ts_offset++] = part;
		}
		mask >>= 8;
		shift -= 8;
	}
}

void
tlv_write_byte(struct tlv_state *ts, uint8_t val)
{
	assert(!tlv_at_buf_end(ts));
	ts->ts_buf[ts->ts_offset++] = val;
}
