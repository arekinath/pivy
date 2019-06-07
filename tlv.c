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

#include "tlv.h"
#include "debug.h"
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
	VERIFY(ts != NULL);
	ts->ts_buf = (uint8_t *)buf;
	ts->ts_offset = offset;
	ts->ts_len = len;
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
	VERIFY(ts != NULL);
	ts->ts_buf = calloc(1, MAX_APDU_SIZE);
	VERIFY(ts->ts_buf != NULL);
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
		VERIFY(sf != NULL);
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
		VERIFY(0);
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
		VERIFY3U(len, <, (1 << 7));
		buf[ts->ts_ptr] = len;
	} else if (buf[ts->ts_ptr] == 0x81) {
		len -= 2;
		VERIFY3U(len, <, (1 << 8));
		buf[ts->ts_ptr + 1] = len;
	} else if (buf[ts->ts_ptr] == 0x82) {
		len -= 3;
		VERIFY3U(len, <, (1 << 16));
		buf[ts->ts_ptr + 1] = (len & 0xFF00) >> 8;
		buf[ts->ts_ptr + 2] = (len & 0x00FF);
	} else if (buf[ts->ts_ptr] == 0x83) {
		len -= 4;
		VERIFY3U(len, <, (1 << 24));
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

errf_t *
tlv_read_tag(struct tlv_state *ts, uint *ptag)
{
	const uint8_t *buf = ts->ts_buf;
	uint8_t d;
	uint tag, len, octs;
	struct tlv_stack_frame *sf;
	size_t origin = ts->ts_offset;
	errf_t *error;

	if (tlv_at_end(ts)) {
		error = errf("LengthError", NULL, "tlv_read_tag called "
		    "past end of buffer");
		return (error);
	}
	d = buf[ts->ts_offset++];
	ts->ts_len--;
	tag = d;

	if ((d & TLV_TAG_MASK) == TLV_TAG_CONT) {
		do {
			if (tlv_at_end(ts)) {
				error = errf("LengthError", NULL, "TLV tag "
				    "continued past end of buffer");
				return (error);
			}
			d = buf[ts->ts_offset++];
			ts->ts_len--;
			tag <<= 8;
			tag |= d;
		} while ((d & TLV_CONT) == TLV_CONT);
	}

	if (tlv_at_end(ts)) {
		error = errf("LengthError", NULL, "TLV tag length continued "
		    "past end of buffer");
		return (error);
	}
	d = buf[ts->ts_offset++];
	ts->ts_len--;
	if ((d & TLV_CONT) == TLV_CONT) {
		octs = d & (~TLV_CONT);
		if (octs < 1 || octs > 4) {
			error = errf("LengthError", NULL, "TLV tag had invalid "
			    "length indicator: %d octets", octs);
			return (error);
		}
		len = 0;
		if (tlv_buf_rem(ts) < octs) {
			error = errf("LengthError", NULL, "TLV tag length "
			    "bytes continued past end of buffer");
			return (error);
		}
		for (; octs > 0; --octs) {
			d = buf[ts->ts_offset++];
			ts->ts_len--;
			len <<= 8;
			len |= d;
		}
	} else {
		len = d;
	}
	if (tlv_buf_rem(ts) < len) {
		error = errf("LengthError", NULL, "TLV tag length is too "
		    "long for buffer: %u", len);
		return (error);
	}
	if (tlv_rem(ts) < len) {
		error = errf("LengthError", NULL, "TLV tag length is too "
		    "long for enclosing tag: %u", len);
		return (error);
	}

	sf = calloc(1, sizeof (*sf));
	if (sf == NULL)
		return (ERRF_NOMEM);
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

	*ptag = tag;
	return (NULL);
}

errf_t *
tlv_end(struct tlv_state *ts)
{
	struct tlv_stack_frame *sf = ts->ts_stack;
	if (ts->ts_debug) {
		fprintf(stderr, "%*send tag from +%lu (%lu bytes left)\n",
		    ts->ts_stklvl + 1, "", ts->ts_ptr, ts->ts_len);
	}
	if (ts->ts_len != 0) {
		return (errf("LengthError", NULL, "tlv_end() called with %u "
		    "bytes still remaining in tag", ts->ts_len));
	}
	if (sf != NULL) {
		ts->ts_stack = sf->tsf_next;
		ts->ts_len = sf->tsf_len;
		ts->ts_ptr = sf->tsf_ptr;
		VERIFY3U(ts->ts_offset, ==, sf->tsf_offset);
		free(sf);
		--ts->ts_stklvl;
	}
	return (NULL);
}

void
tlv_skip(struct tlv_state *ts)
{
	struct tlv_stack_frame *sf = ts->ts_stack;
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
		VERIFY3U(ts->ts_offset, ==, sf->tsf_offset);
		free(sf);
		--ts->ts_stklvl;
	}
}

void
tlv_abort(struct tlv_state *ts)
{
	struct tlv_stack_frame *sf, *sfn = ts->ts_stack;
	while ((sf = sfn) != NULL) {
		sfn = sf->tsf_next;
		free(sf);
		--ts->ts_stklvl;
	}
	ts->ts_stack = NULL;
	ts->ts_offset = ts->ts_end;
	ts->ts_len = 0;
}


errf_t *
tlv_read_byte(struct tlv_state *ts, uint8_t *out)
{
	if (tlv_at_end(ts)) {
		return (errf("LengthError", NULL, "tlv_read_byte() called "
		    "with no bytes remaining"));
	}
	ts->ts_len--;
	*out = ts->ts_buf[ts->ts_offset++];
	return (NULL);
}

errf_t *
tlv_read_short(struct tlv_state *ts, uint16_t *out)
{
	if (tlv_rem(ts) < 2) {
		return (errf("LengthError", NULL, "tlv_read_short() called "
		    "with only %u bytes remaining", tlv_rem(ts)));
	}
	ts->ts_len -= 2;
	*out = ts->ts_buf[ts->ts_offset++] << 8;
	*out |= ts->ts_buf[ts->ts_offset++];
	return (NULL);
}

errf_t *
tlv_read_uint(struct tlv_state *ts, uint *out)
{
	*out = 0;
	const uint8_t *buf = ts->ts_buf;
	if (tlv_rem(ts) < 1) {
		return (errf("LengthError", NULL, "tlv_read_uint() called "
		    "with no bytes remaining"));
	}
	if (tlv_rem(ts) > 4) {
		return (errf("LengthError", NULL, "tlv_read_uint() called "
		    "with %u bytes remaining (supports max 4)", tlv_rem(ts)));
	}
	while (!tlv_at_end(ts)) {
		*out <<= 8;
		*out |= buf[ts->ts_offset++];
		ts->ts_len--;
	}
	return (NULL);
}

errf_t *
tlv_read(struct tlv_state *ts, uint8_t *dest, size_t offset, size_t maxLen,
    size_t *plen)
{
	size_t len = maxLen;
	if (len > tlv_rem(ts))
		len = tlv_rem(ts);
	if (len == 0) {
		return (errf("LengthError", NULL, "tlv_read() called "
		    "with no bytes remaining"));
	}
	bcopy(&ts->ts_buf[ts->ts_offset], &dest[offset], len);
	ts->ts_offset += len;
	ts->ts_len -= len;
	*plen = len;
	return (NULL);
}

void
tlv_free(struct tlv_state *ts)
{
	if (ts == NULL)
		return;
	VERIFY(ts->ts_stack == NULL);
	if (ts->ts_freebuf) {
		explicit_bzero(ts->ts_buf, MAX_APDU_SIZE);
		free(ts->ts_buf);
	}
	free(ts);
}

void
tlv_write(struct tlv_state *ts, const uint8_t *src, size_t offset, size_t len)
{
	VERIFY3U(tlv_buf_rem(ts), >=, len);
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
			VERIFY(!tlv_at_buf_end(ts));
			buf[ts->ts_offset++] = part;
		}
		mask >>= 8;
		shift -= 8;
	}
}

void
tlv_write_byte(struct tlv_state *ts, uint8_t val)
{
	VERIFY(!tlv_at_buf_end(ts));
	ts->ts_buf[ts->ts_offset++] = val;
}
