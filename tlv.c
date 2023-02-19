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

#include "openssh/config.h"
#include "openssh/sshbuf.h"

#if defined(__sun) || defined(__APPLE__)
#include <netinet/in.h>
#define htobe16(v)      (htons(v))
#else
#include <endian.h>
#endif

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

	tc->tc_buf = (uint8_t *)buf;
	tc->tc_pos = offset;

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

	tc->tc_buf = calloc(1, MAX_APDU_SIZE);
	if (tc->tc_buf == NULL) {
		free(ts);
		free(tc);
		return (NULL);
	}
	tc->tc_freebuf = B_TRUE;
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
tlv_push(struct tlv_state *ts, uint tag)
{
	struct tlv_context *tc;
	struct tlv_context *p = ts->ts_now;

	tc = calloc(1, sizeof (struct tlv_context));
	VERIFY(tc != NULL);

	/* Write the tag into our parent buffer now */
	tlv_write_u8to32(ts, tag);

	/*
	 * Reserve enough space in the new context for the longest possible
	 * length
	 */
	tc->tc_end = p->tc_end - p->tc_pos - 4;

	tc->tc_buf = malloc(tc->tc_end);
	VERIFY(tc->tc_buf != NULL);
	tc->tc_freebuf = B_TRUE;

	tlv_ctx_push(ts, tc);
}

void
tlv_pop(struct tlv_state *ts)
{
	struct tlv_context *tc = tlv_ctx_pop(ts);
	struct tlv_context *p = ts->ts_now;
	uint8_t *buf = p->tc_buf;
	size_t len = tc->tc_pos;

	/*
	 * We wrote just the tag in tlv_push(), now we know the length, so
	 * write that and then the actual data inside the tag.
	 */
	if (len < (1 << 7)) {
		VERIFY3U(p->tc_pos + len + 1, <=, p->tc_end);
		buf[p->tc_pos++] = len;
	} else if (len < (1 << 8)) {
		VERIFY3U(p->tc_pos + len + 2, <=, p->tc_end);
		buf[p->tc_pos++] = 0x81;
		buf[p->tc_pos++] = len;
	} else if (len < (1 << 16)) {
		VERIFY3U(p->tc_pos + len + 3, <=, p->tc_end);
		buf[p->tc_pos++] = 0x82;
		buf[p->tc_pos++] = (len & 0xFF00) >> 8;
		buf[p->tc_pos++] = (len & 0x00FF);
	} else if (len < (1 << 24)) {
		VERIFY3U(p->tc_pos + len + 4, <=, p->tc_end);
		buf[p->tc_pos++] = 0x83;
		buf[p->tc_pos++] = (len & 0xFF0000) >> 16;
		buf[p->tc_pos++] = (len & 0x00FF00) >> 8;
		buf[p->tc_pos++] = (len & 0x0000FF);
	} else {
		VERIFY(0);
	}
	bcopy(tc->tc_buf, &buf[p->tc_pos], len);
	p->tc_pos += len;

	/* We're done with the child tag context now. */
	VERIFY(tc->tc_freebuf);
	explicit_bzero(tc->tc_buf, tc->tc_pos);
	free(tc->tc_buf);
	free(tc);
}

errf_t *
tlv_read_tag(struct tlv_state *ts, uint *ptag)
{
	struct tlv_context *p = ts->ts_now;
	const uint8_t *buf = p->tc_buf;
	uint8_t d;
	uint tag, octs;
	size_t len;
	struct tlv_context *tc;
	size_t origin = p->tc_pos;
	errf_t *error;

	tc = calloc(1, sizeof (struct tlv_context));
	if (tc == NULL)
		return (ERRF_NOMEM);

	tc->tc_buf = p->tc_buf;

	if (tlv_at_end(ts)) {
		error = errf("LengthError", NULL, "tlv_read_tag called "
		    "past end of context");
		free(tc);
		return (error);
	}
	d = buf[p->tc_pos++];
	tag = d;

	if ((d & TLV_TAG_MASK) == TLV_TAG_CONT) {
		do {
			if (tlv_at_end(ts)) {
				error = errf("LengthError", NULL, "TLV tag "
				    "continued past end of context");
				free(tc);
				return (error);
			}
			d = buf[p->tc_pos++];
			tag <<= 8;
			tag |= d;
		} while ((d & TLV_CONT) == TLV_CONT);
	}

	if (tlv_at_end(ts)) {
		error = errf("LengthError", NULL, "TLV tag length continued "
		    "past end of context");
		free(tc);
		return (error);
	}
	d = buf[p->tc_pos++];
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
			d = buf[p->tc_pos++];
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

	tc->tc_begin = p->tc_pos;
	tc->tc_pos = p->tc_pos;
	tc->tc_end = p->tc_pos + len;

	p->tc_pos += len;

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
	struct tlv_context *p = ts->ts_now;
	if (ts->ts_debug) {
		fprintf(stderr, "%*send tag from +%zu (%zu bytes left)\n",
		    tc->tc_depth, "", tc->tc_begin, tc->tc_end - tc->tc_pos);
	}
	VERIFY3U(p->tc_pos, >=, tc->tc_end);
	if (tc->tc_pos != tc->tc_end) {
		return (errf("LengthError", NULL, "tlv_end() called at +%zu "
		    "but tag ends at +%zu", tc->tc_pos, tc->tc_end));
	}
	free(tc);
	return (NULL);
}

void
tlv_skip(struct tlv_state *ts)
{
	struct tlv_context *tc = tlv_ctx_pop(ts);
	struct tlv_context *p = ts->ts_now;
	if (ts->ts_debug) {
		fprintf(stderr, "%*sskip tag from +%zu (%zu bytes left)\n",
		    tc->tc_depth, "", tc->tc_begin, tc->tc_end - tc->tc_pos);
	}
	VERIFY3U(tc->tc_pos, >=, tc->tc_begin);
	VERIFY3U(tc->tc_pos, <=, tc->tc_end);
	VERIFY3U(p->tc_pos, >=, tc->tc_end);
	free(tc);
}

void
tlv_abort(struct tlv_state *ts)
{
	struct tlv_context *tc = ts->ts_now;
	while (tc != ts->ts_root) {
		struct tlv_context *tofree = tc;
		tc = tc->tc_next;
		VERIFY3U(tc->tc_pos, >=, tc->tc_begin);
		VERIFY3U(tc->tc_pos, <=, tc->tc_end);
		if (tofree->tc_freebuf)
			free(tofree->tc_buf);
		free(tofree);
	}
	ts->ts_now = ts->ts_root;
	ts->ts_root->tc_pos = ts->ts_root->tc_end;
}


errf_t *
tlv_read_u8(struct tlv_state *ts, uint8_t *out)
{
	struct tlv_context *tc = ts->ts_now;
	if (tlv_at_end(ts)) {
		return (errf("LengthError", NULL, "tlv_read_u8() called "
		    "with no bytes remaining"));
	}
	*out = tc->tc_buf[tc->tc_pos++];
	return (NULL);
}

errf_t *
tlv_read_u16(struct tlv_state *ts, uint16_t *out)
{
	struct tlv_context *tc = ts->ts_now;
	if (tlv_rem(ts) < 2) {
		return (errf("LengthError", NULL, "tlv_read_u16() called "
		    "with only %zu bytes remaining", tlv_rem(ts)));
	}
	*out = tc->tc_buf[tc->tc_pos++] << 8;
	*out |= tc->tc_buf[tc->tc_pos++];
	return (NULL);
}

errf_t *
tlv_read_u8to32(struct tlv_state *ts, uint32_t *out)
{
	struct tlv_context *tc = ts->ts_now;
	*out = 0;
	const uint8_t *buf = tc->tc_buf;
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
		*out |= buf[tc->tc_pos++];
	}
	return (NULL);
}

errf_t *
tlv_read_upto(struct tlv_state *ts, uint8_t *dest, size_t maxLen,
    size_t *plen)
{
	struct tlv_context *tc = ts->ts_now;
	size_t len = maxLen;
	if (len > tlv_rem(ts))
		len = tlv_rem(ts);
	if (len == 0) {
		return (errf("LengthError", NULL, "tlv_read() called "
		    "with no bytes remaining"));
	}
	bcopy(&tc->tc_buf[tc->tc_pos], dest, len);
	tc->tc_pos += len;
	*plen = len;
	return (NULL);
}

errf_t *
tlv_read_string(struct tlv_state *ts, char **dest)
{
	struct tlv_context *tc = ts->ts_now;
	const size_t len = tlv_rem(ts);
	char *buf;
	size_t i;

	buf = malloc(len + 1);
	if (buf == NULL)
		return (ERRF_NOMEM);

	for (i = 0; i < len; ++i) {
		if (tc->tc_buf[tc->tc_pos] == 0) {
			free(buf);
			return (errf("StringError", NULL, "tlv_read_string() "
			    "encountered a NUL character unexpectedly"));
		}
		buf[i] = (char)tc->tc_buf[tc->tc_pos++];
	}
	buf[len] = '\0';
	*dest = buf;

	return (NULL);
}

errf_t *
tlv_read_alloc(struct tlv_state *ts, uint8_t **pdata, size_t *plen)
{
	struct tlv_context *tc = ts->ts_now;
	size_t len = tlv_rem(ts);
	uint8_t *data;
	data = calloc(1, len);
	if (data == NULL)
		return (ERRF_NOMEM);
	*plen = len;
	bcopy(&tc->tc_buf[tc->tc_pos], data, len);
	tc->tc_pos += len;
	*pdata = data;
	return (NULL);
}

errf_t *
tlv_read(struct tlv_state *ts, uint8_t *dest, size_t len)
{
	struct tlv_context *tc = ts->ts_now;
	if (tlv_rem(ts) != len) {
		return (errf("LengthError", NULL, "tlv_read() called "
		    "for %zu bytes but %zu are left in tag", len,
		    tlv_rem(ts)));
	}
	bcopy(&tc->tc_buf[tc->tc_pos], dest, len);
	tc->tc_pos += len;
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
	if (root->tc_freebuf) {
		explicit_bzero(&root->tc_buf[root->tc_begin],
		    root->tc_end - root->tc_begin);
		free(root->tc_buf);
	}
	free(root);
	free(ts);
}

void
tlv_write(struct tlv_state *ts, const uint8_t *src, size_t len)
{
	struct tlv_context *tc = ts->ts_now;
	VERIFY3U(tlv_rem(ts), >=, len);
	bcopy(src, &tc->tc_buf[tc->tc_pos], len);
	tc->tc_pos += len;
}

void
tlv_write_u16(struct tlv_state *ts, uint16_t val)
{
	struct tlv_context *tc = ts->ts_now;
	VERIFY3U(tlv_rem(ts), >=, sizeof (val));
	val = htobe16(val);
	bcopy(&val, &tc->tc_buf[tc->tc_pos], sizeof (val));
	tc->tc_pos += sizeof (val);
}

void
tlv_write_u8to32(struct tlv_state *ts, uint32_t val)
{
	struct tlv_context *tc = ts->ts_now;
	uint8_t *buf = tc->tc_buf;
	uint32_t mask = 0xFF << 24;
	int shift = 24;
	uint32_t part;

	if (val == 0) {
		VERIFY(!tlv_at_end(ts));
		buf[tc->tc_pos++] = 0;
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
		VERIFY(!tlv_at_end(ts));
		buf[tc->tc_pos++] = part;
		mask >>= 8;
		shift -= 8;
	}
}

void
tlv_write_byte(struct tlv_state *ts, uint8_t val)
{
	struct tlv_context *tc = ts->ts_now;
	VERIFY(!tlv_at_end(ts));
	tc->tc_buf[tc->tc_pos++] = val;
}
