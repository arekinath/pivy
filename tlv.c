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

#include "utils.h"
#include "tlv.h"
#include "debug.h"
#include "openssh/sshbuf.h"

enum tlv_tag_bits {
	TLV_TYPE_MASK = (1 << 7 | 1 << 6 | 1 << 5),
	TLV_TAG_MASK = ~(TLV_TYPE_MASK),
	TLV_TAG_CONT = 0xFF & TLV_TAG_MASK,
};

struct tlv_state *
tlv_init(const uint8_t *buf, size_t offset, size_t len)
{
	struct tlv_state *ts = calloc(1, sizeof (struct tlv_state));
	if (ts == NULL)
		return (NULL);
	struct tlv_context *tc = calloc(1, sizeof (struct tlv_context));
	if (tc == NULL) {
		free(ts);
		return (NULL);
	}
	ts->ts_root = tc;
	ts->ts_now = tc;

	ts->ts_buf = (uint8_t *)buf;
	ts->ts_pos = offset;

	tc->tc_begin = offset;
	tc->tc_end = offset + len;
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
	if (ts == NULL)
		return (NULL);
	struct tlv_context *tc = calloc(1, sizeof (struct tlv_context));
	if (tc == NULL) {
		free(ts);
		return (NULL);
	}
	ts->ts_root = tc;
	ts->ts_now = tc;

	ts->ts_buf = calloc(1, MAX_APDU_SIZE);
	if (ts->ts_buf == NULL) {
		free(ts);
		free(tc);
		return (NULL);
	}
	ts->ts_freebuf = B_TRUE;
	tc->tc_end = MAX_APDU_SIZE;
	return (ts);
}

const uint8_t TLV_CONT = (1 << 7);

static void
tlv_ctx_push(struct tlv_state *ts, struct tlv_context *tc)
{
	tc->tc_next = ts->ts_now;
	tc->tc_depth = ts->ts_now->tc_depth + 1;
	ts->ts_now = tc;
}

static struct tlv_context *
tlv_ctx_pop(struct tlv_state *ts)
{
	struct tlv_context *tc = ts->ts_now;
	VERIFY(tc != ts->ts_root);
	ts->ts_now = tc->tc_next;
	return (tc);
}

void
tlv_pushl(struct tlv_state *ts, uint tag, size_t maxlen)
{
	uint8_t *buf = ts->ts_buf;
	struct tlv_context *tc;

	tc = calloc(1, sizeof (struct tlv_context));
	VERIFY(tc != NULL);

	tlv_write_u8to32(ts, tag);

	tc->tc_lenptr = ts->ts_pos;

	if (maxlen < (1 << 7)) {
		buf[ts->ts_pos++] = 0x00;
	} else if (maxlen < (1 << 8)) {
		buf[ts->ts_pos++] = 0x81;
		ts->ts_pos++;
	} else if (maxlen < (1 << 16)) {
		buf[ts->ts_pos++] = 0x82;
		ts->ts_pos += 2;
	} else if (maxlen < (1 << 24)) {
		buf[ts->ts_pos++] = 0x83;
		ts->ts_pos += 3;
	} else {
		VERIFY(0);
	}

	tc->tc_begin = ts->ts_pos;
	tlv_ctx_push(ts, tc);
}

void
tlv_pop(struct tlv_state *ts)
{
	uint8_t *buf = ts->ts_buf;
	struct tlv_context *tc = tlv_ctx_pop(ts);
	size_t len = (ts->ts_pos - tc->tc_begin);

	if (buf[tc->tc_lenptr] == 0x00) {
		VERIFY3U(len, <, (1 << 7));
		buf[tc->tc_lenptr] = len;
	} else if (buf[tc->tc_lenptr] == 0x81) {
		VERIFY3U(len, <, (1 << 8));
		buf[tc->tc_lenptr + 1] = len;
	} else if (buf[tc->tc_lenptr] == 0x82) {
		VERIFY3U(len, <, (1 << 16));
		buf[tc->tc_lenptr + 1] = (len & 0xFF00) >> 8;
		buf[tc->tc_lenptr + 2] = (len & 0x00FF);
	} else if (buf[tc->tc_lenptr] == 0x83) {
		VERIFY3U(len, <, (1 << 24));
		buf[tc->tc_lenptr + 1] = (len & 0xFF0000) >> 16;
		buf[tc->tc_lenptr + 2] = (len & 0x00FF00) >> 8;
		buf[tc->tc_lenptr + 3] = (len & 0x0000FF);
	}

	free(tc);
}

errf_t *
tlv_read_tag(struct tlv_state *ts, uint *ptag)
{
	const uint8_t *buf = ts->ts_buf;
	uint8_t d;
	uint tag, octs;
	size_t len;
	struct tlv_context *tc;
	size_t origin = ts->ts_pos;
	errf_t *error;

	tc = calloc(1, sizeof (struct tlv_context));
	if (tc == NULL)
		return (ERRF_NOMEM);

	if (tlv_at_end(ts)) {
		error = errf("LengthError", NULL, "tlv_read_tag called "
		    "past end of context");
		free(tc);
		return (error);
	}
	d = buf[ts->ts_pos++];
	tag = d;

	if ((d & TLV_TAG_MASK) == TLV_TAG_CONT) {
		do {
			if (tlv_at_end(ts)) {
				error = errf("LengthError", NULL, "TLV tag "
				    "continued past end of context");
				free(tc);
				return (error);
			}
			d = buf[ts->ts_pos++];
			tag <<= 8;
			tag |= d;
		} while ((d & TLV_CONT) == TLV_CONT);
	}

	tc->tc_lenptr = ts->ts_pos;

	if (tlv_at_end(ts)) {
		error = errf("LengthError", NULL, "TLV tag length continued "
		    "past end of context");
		free(tc);
		return (error);
	}
	d = buf[ts->ts_pos++];
	if ((d & TLV_CONT) == TLV_CONT) {
		octs = d & (~TLV_CONT);
		if (octs < 1 || octs > 4) {
			error = errf("LengthError", NULL, "TLV tag had invalid "
			    "length indicator: %d octets", octs);
			free(tc);
			return (error);
		}
		len = 0;
		if (tlv_rem(ts) < octs) {
			error = errf("LengthError", NULL, "TLV tag length "
			    "bytes continued past end of context");
			free(tc);
			return (error);
		}
		for (; octs > 0; --octs) {
			d = buf[ts->ts_pos++];
			len <<= 8;
			len |= d;
		}
	} else {
		len = d;
	}
	if (tlv_root_rem(ts) < len) {
		error = errf("LengthError", NULL, "TLV tag length is too "
		    "long for buffer: %zu", len);
		free(tc);
		return (error);
	}
	if (tlv_rem(ts) < len) {
		error = errf("LengthError", NULL, "TLV tag length is too "
		    "long for enclosing tag: %zu", len);
		free(tc);
		return (error);
	}

	tc->tc_begin = ts->ts_pos;
	tc->tc_end = ts->ts_pos + len;

	tlv_ctx_push(ts, tc);

	if (ts->ts_debug) {
		fprintf(stderr, "%*stag at +%zu: 0x%x (%zu bytes)\n",
		    tc->tc_depth, "", origin, tag, len);
	}

	*ptag = tag;
	return (NULL);
}

errf_t *
tlv_end(struct tlv_state *ts)
{
	struct tlv_context *tc = tlv_ctx_pop(ts);
	if (ts->ts_debug) {
		fprintf(stderr, "%*send tag from +%zu (%zu bytes left)\n",
		    tc->tc_depth, "", tc->tc_begin, tc->tc_end - ts->ts_pos);
	}
	VERIFY3U(ts->ts_pos, >=, tc->tc_begin);
	if (ts->ts_pos != tc->tc_end) {
		return (errf("LengthError", NULL, "tlv_end() called at +%zu "
		    "but tag ends at +%zu", ts->ts_pos, tc->tc_end));
	}
	free(tc);
	return (NULL);
}

void
tlv_skip(struct tlv_state *ts)
{
	struct tlv_context *tc = tlv_ctx_pop(ts);
	if (ts->ts_debug) {
		fprintf(stderr, "%*sskip tag from +%zu (%zu bytes left)\n",
		    tc->tc_depth, "", tc->tc_begin, tc->tc_end - ts->ts_pos);
	}
	VERIFY3U(ts->ts_pos, >=, tc->tc_begin);
	VERIFY3U(ts->ts_pos, <=, tc->tc_end);
	ts->ts_pos = tc->tc_end;
	free(tc);
}

void
tlv_abort(struct tlv_state *ts)
{
	struct tlv_context *tc = ts->ts_now;
	while (tc != ts->ts_root) {
		struct tlv_context *tofree = tc;
		tc = tc->tc_next;
		VERIFY3U(ts->ts_pos, >=, tc->tc_begin);
		VERIFY3U(ts->ts_pos, <=, tc->tc_end);
		free(tofree);
	}
	ts->ts_now = ts->ts_root;
	ts->ts_pos = ts->ts_root->tc_end;
}


errf_t *
tlv_read_u8(struct tlv_state *ts, uint8_t *out)
{
	if (tlv_at_end(ts)) {
		return (errf("LengthError", NULL, "tlv_read_u8() called "
		    "with no bytes remaining"));
	}
	*out = ts->ts_buf[ts->ts_pos++];
	return (NULL);
}

errf_t *
tlv_read_u16(struct tlv_state *ts, uint16_t *out)
{
	if (tlv_rem(ts) < 2) {
		return (errf("LengthError", NULL, "tlv_read_u16() called "
		    "with only %zu bytes remaining", tlv_rem(ts)));
	}
	*out = ts->ts_buf[ts->ts_pos++] << 8;
	*out |= ts->ts_buf[ts->ts_pos++];
	return (NULL);
}

errf_t *
tlv_read_u8to32(struct tlv_state *ts, uint32_t *out)
{
	*out = 0;
	const uint8_t *buf = ts->ts_buf;
	if (tlv_rem(ts) < 1) {
		return (errf("LengthError", NULL, "tlv_read_u8to32() called "
		    "with no bytes remaining"));
	}
	if (tlv_rem(ts) > 4) {
		return (errf("LengthError", NULL, "tlv_read_u8to32() called "
		    "with %zu bytes remaining (supports max 4)", tlv_rem(ts)));
	}
	while (!tlv_at_end(ts)) {
		*out <<= 8;
		*out |= buf[ts->ts_pos++];
	}
	return (NULL);
}

errf_t *
tlv_read_upto(struct tlv_state *ts, uint8_t *dest, size_t maxLen,
    size_t *plen)
{
	size_t len = maxLen;
	if (len > tlv_rem(ts))
		len = tlv_rem(ts);
	if (len == 0) {
		return (errf("LengthError", NULL, "tlv_read() called "
		    "with no bytes remaining"));
	}
	bcopy(&ts->ts_buf[ts->ts_pos], dest, len);
	ts->ts_pos += len;
	*plen = len;
	return (NULL);
}

errf_t *
tlv_read_string(struct tlv_state *ts, char **dest)
{
	const size_t len = tlv_rem(ts);
	char *buf;
	size_t i;

	buf = malloc(len + 1);
	if (buf == NULL)
		return (ERRF_NOMEM);

	for (i = 0; i < len; ++i) {
		if (ts->ts_buf[ts->ts_pos] == 0) {
			free(buf);
			return (errf("StringError", NULL, "tlv_read_string() "
			    "encountered a NUL character unexpectedly"));
		}
		buf[i] = (char)ts->ts_buf[ts->ts_pos++];
	}
	buf[len] = '\0';
	*dest = buf;

	return (NULL);
}

errf_t *
tlv_read_alloc(struct tlv_state *ts, uint8_t **pdata, size_t *plen)
{
	size_t len = tlv_rem(ts);
	uint8_t *data;
	data = calloc(1, len);
	if (data == NULL)
		return (ERRF_NOMEM);
	*plen = len;
	bcopy(&ts->ts_buf[ts->ts_pos], data, len);
	ts->ts_pos += len;
	*pdata = data;
	return (NULL);
}

errf_t *
tlv_read(struct tlv_state *ts, uint8_t *dest, size_t len)
{
	if (tlv_rem(ts) != len) {
		return (errf("LengthError", NULL, "tlv_read() called "
		    "for %zu bytes but %zu are left in tag", len,
		    tlv_rem(ts)));
	}
	bcopy(&ts->ts_buf[ts->ts_pos], dest, len);
	ts->ts_pos += len;
	return (NULL);
}

void
tlv_free(struct tlv_state *ts)
{
	struct tlv_context *root;
	if (ts == NULL)
		return;
	root = ts->ts_root;
	VERIFY(root == ts->ts_now);
	if (ts->ts_freebuf) {
		explicit_bzero(&ts->ts_buf[root->tc_begin],
		    root->tc_end - root->tc_begin);
		free(ts->ts_buf);
	}
	free(root);
	free(ts);
}

void
tlv_write(struct tlv_state *ts, const uint8_t *src, size_t len)
{
	VERIFY3U(tlv_root_rem(ts), >=, len);
	bcopy(src, &ts->ts_buf[ts->ts_pos], len);
	ts->ts_pos += len;
}

void
tlv_write_u8to32(struct tlv_state *ts, uint32_t val)
{
	uint8_t *buf = ts->ts_buf;
	uint32_t mask = 0xFF << 24;
	int shift = 24;
	uint32_t part;

	if (val == 0) {
		VERIFY(!tlv_at_root_end(ts));
		buf[ts->ts_pos++] = 0;
		return;
	}

	/* Skip any leading zero bytes. */
	while (shift >= 0) {
		part = (val & mask) >> shift;
		if (part != 0)
			break;
		mask >>= 8;
		shift -= 8;
	}
	/* And then write out the rest. */
	while (shift >= 0) {
		part = (val & mask) >> shift;
		VERIFY(!tlv_at_root_end(ts));
		buf[ts->ts_pos++] = part;
		mask >>= 8;
		shift -= 8;
	}
}

void
tlv_write_byte(struct tlv_state *ts, uint8_t val)
{
	VERIFY(!tlv_at_root_end(ts));
	ts->ts_buf[ts->ts_pos++] = val;
}
