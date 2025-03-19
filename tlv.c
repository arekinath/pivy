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

#include "debug.h"

#include "utils.h"
#include "tlv.h"

#include "openssh/config.h"
#include "openssh/sshbuf.h"

#if defined(__sun) || defined(__APPLE__)
#include <netinet/in.h>
#define htobe16(v)      (htons(v))
#else
#include <endian.h>
#endif

struct tlv_context {
	struct tlv_context 	*tc_next;
	size_t		 tc_begin;	/* R: beginning index in tc_buf */
	size_t		 tc_end;	/* RW: final index in tc_buf */
	int		 tc_depth;	/* RW: root = 0, tag = 1, child = 2 */
	uint8_t		*tc_buf;	/* RW: data buffer */
	size_t	 	 tc_pos;	/* RW: pos in tc_buf */
	boolean_t	 tc_freebuf;	/* W: we should free tc_buf */

};

struct tlv_state {
	struct tlv_context	*ts_root; /* top-level ctx spanning whole buf */
	struct tlv_context	*ts_now;  /* current tag ctx */
	boolean_t		 ts_debug;
};

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
	assert(ts->ts_now != NULL);
	tc->tc_next = ts->ts_now;
	tc->tc_depth = ts->ts_now->tc_depth + 1;
	ts->ts_now = tc;
}

static struct tlv_context *
tlv_ctx_pop(struct tlv_state *ts)
{
	struct tlv_context *tc = ts->ts_now;
	VERIFY(tc != NULL);
	VERIFY(tc != ts->ts_root);
	ts->ts_now = tc->tc_next;
	return (tc);
}

void
tlv_push(struct tlv_state *ts, uint tag)
{
	struct tlv_context *tc;
	struct tlv_context *p = ts->ts_now;
	assert(p != NULL);

	tc = calloc(1, sizeof (struct tlv_context));
	VERIFYN(tc);

	/* Write the tag into our parent buffer now */
	tlv_write_u8to32(ts, tag);

	/*
	 * Reserve enough space in the new context for the longest possible
	 * length
	 */
	tc->tc_end = p->tc_end - p->tc_pos - 4;

	tc->tc_buf = malloc(tc->tc_end);
	VERIFYN(tc->tc_buf);
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
tlv_peek_tag(struct tlv_state *ts, uint *ptag)
{
	struct tlv_context *p = ts->ts_now;
	const uint8_t *buf = p->tc_buf;
	uint8_t d;
	uint tag;
	size_t origin = p->tc_pos;
	errf_t *error;

	if (tlv_at_end(ts)) {
		error = errf("LengthError", NULL, "tlv_read_tag called "
		    "past end of context");
		__CPROVER_assume(error != NULL);
		return (error);
	}
	d = buf[p->tc_pos++];
	tag = d;

	if ((d & TLV_TAG_MASK) == TLV_TAG_CONT) {
		do {
			if (tlv_at_end(ts)) {
				error = errf("LengthError", NULL, "TLV tag "
				    "continued past end of context");
				__CPROVER_assume(error != NULL);
				p->tc_pos = origin;
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
		__CPROVER_assume(error != NULL);
		p->tc_pos = origin;
		return (error);
	}

	p->tc_pos = origin;
	*ptag = tag;
	return (ERRF_OK);
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
		__CPROVER_assume(error != NULL);
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
				__CPROVER_assume(error != NULL);
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
		__CPROVER_assume(error != NULL);
		free(tc);
		return (error);
	}
	d = buf[p->tc_pos++];
	if ((d & TLV_CONT) == TLV_CONT) {
		octs = d & (~TLV_CONT);
		if (octs < 1 || octs > 4) {
			error = errf("LengthError", NULL, "TLV tag had invalid "
			    "length indicator: %d octets", octs);
			__CPROVER_assume(error != NULL);
			free(tc);
			return (error);
		}
		len = 0;
		if (tlv_rem(ts) < octs) {
			error = errf("LengthError", NULL, "TLV tag length "
			    "bytes continued past end of context");
			__CPROVER_assume(error != NULL);
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
		__CPROVER_assume(error != NULL);
		free(tc);
		return (error);
	}
	if (tlv_rem(ts) < len) {
		error = errf("LengthError", NULL, "TLV tag length is too "
		    "long for enclosing tag: %zu", len);
		__CPROVER_assume(error != NULL);
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
	return (ERRF_OK);
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
	if (len == 0) {
		*pdata = NULL;
		*plen = 0;
		return (NULL);
	}
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
	struct tlv_context *tc;
	uint8_t *buf;
	uint32_t mask = 0xFFUL << 24;
	int shift = 24;
	uint32_t part;

	tc = ts->ts_now;
	assert(tc != NULL);
	buf = tc->tc_buf;
	assert(buf != NULL);

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

boolean_t
tlv_at_root_end(const struct tlv_state *ts)
{
	return (ts->ts_now->tc_pos >= ts->ts_root->tc_end);
}

boolean_t
tlv_at_end(const struct tlv_state *ts)
{
	return (tlv_at_root_end(ts) || ts->ts_now->tc_pos >= ts->ts_now->tc_end);
}

size_t
tlv_root_rem(const struct tlv_state *ts)
{
	return (ts->ts_root->tc_end - ts->ts_now->tc_pos);
}

size_t
tlv_rem(const struct tlv_state *ts)
{
	return (ts->ts_now->tc_end - ts->ts_now->tc_pos);
}

uint8_t *
tlv_buf(const struct tlv_state *ts)
{
	return (ts->ts_root->tc_buf);
}

uint8_t *
tlv_ptr(const struct tlv_state *ts)
{
	const struct tlv_context *tc = ts->ts_now;
	return (&tc->tc_buf[tc->tc_pos]);
}

size_t
tlv_len(const struct tlv_state *ts)
{
	return (ts->ts_root->tc_pos);
}

#if defined(__CPROVER) && __CPROVER_MAIN == __FILE_tlv_c

uint8_t nondet_uchar(void);

int
main(int argc, char *argv[])
{
	struct tlv_state *tlv;
	errf_t *err;
	uint tag;
	char *str;

	__CPROVER_assume(ERRF_NOMEM != NULL);

	tlv = tlv_init_write();
	VERIFYN(tlv);
	tlv_push(tlv, 0xabcd);
	tlv_push(tlv, 0xa2);
	tlv_write_u8to32(tlv, 0x12345678);
	tlv_pop(tlv);
	tlv_push(tlv, 0xa1);
	tlv_write_byte(tlv, 0x00);
	tlv_pop(tlv);
	tlv_pop(tlv);
	tlv_free(tlv);

	const uint8_t buf[] = { 0x01, 0x07, 0xa1, 0x01, 0x00, 0xa2, 0x02, 0xab,
	    0xcd };
	tlv = tlv_init(buf, 0, sizeof (buf));
	VERIFYN(tlv);

	err = tlv_read_tag(tlv, &tag);
	assert(err == NULL || err == ERRF_NOMEM);
	if (err != NULL)
		return (1);
	assert(tag == 0x01);

	err = tlv_read_tag(tlv, &tag);
	assert(err == NULL || err == ERRF_NOMEM);
	if (err != NULL)
		return (1);
	assert(tag == 0xa1);
	tlv_skip(tlv);

	err = tlv_read_tag(tlv, &tag);
	assert(err == NULL || err == ERRF_NOMEM);
	if (err != NULL)
		return (1);
	assert(tag == 0xa2);
	tlv_skip(tlv);

	tlv_end(tlv);
	tlv_free(tlv);

	const uint8_t buf2[] = { 0x01, 0x08, 0xa1, 0xff, 0x00, 0xa2, 0x02, 0xab,
	    0xcd };
	tlv = tlv_init(buf2, 0, sizeof (buf2));
	VERIFYN(tlv);

	err = tlv_read_tag(tlv, &tag);
	assert(err != NULL);

	tlv_abort(tlv);
	tlv_free(tlv);

	const uint8_t buf3[] = { 0x01, 0x05, 'h', 'e', 'l', 'l', 'o' };
	tlv = tlv_init(buf3, 0, sizeof (buf3));
	VERIFYN(tlv);
	err = tlv_read_tag(tlv, &tag);
	assert(err == NULL || err == ERRF_NOMEM);
	if (err != NULL)
		return (1);
	assert(tag == 0x01);
	err = tlv_read_string(tlv, &str);
	assert(err == NULL || err == ERRF_NOMEM);
	if (err != NULL)
		return (1);
	assert(strlen(str) == 5);
	assert(strcmp(str, "hello") == 0);
	tlv_abort(tlv);
	tlv_free(tlv);

	const uint8_t buf4[] = { nondet_uchar(), nondet_uchar(), nondet_uchar(),
	    nondet_uchar() };
	tlv = tlv_init(buf4, 0, sizeof (buf4));
	VERIFYN(tlv);
	err = tlv_read_tag(tlv, &tag);
	if (err == ERRF_OK) {
		assert(tlv_rem(tlv) <= 2);
		assert(tlv_ptr(tlv) >= &buf4[2]);
		assert(tlv_ptr(tlv) <= &buf4[3] ||
		    (tlv_ptr(tlv) == &buf4[4] && tlv_rem(tlv) == 0));

		err = tlv_read_tag(tlv, &tag);
		if (err == ERRF_OK) {
			/*
			 * only 4 bytes of data, it could be 2 zero-length tags
			 * but no more
			 */
			assert(tlv_rem(tlv) == 0);
			tlv_end(tlv);
		} else {
			errf_free(err);
		}
	} else {
		errf_free(err);
	}
	tlv_abort(tlv);
	tlv_free(tlv);

	const uint8_t buf5[] = { nondet_uchar(), nondet_uchar(), nondet_uchar(),
	    nondet_uchar(), nondet_uchar(), nondet_uchar(), nondet_uchar() };
	tlv = tlv_init(buf5, 0, sizeof (buf5));
	VERIFYN(tlv);
	err = tlv_read_tag(tlv, &tag);
	if (err == ERRF_OK) {
		err = tlv_read_tag(tlv, &tag);
		if (err == ERRF_OK) {
			err = tlv_read_tag(tlv, &tag);
			if (err == ERRF_OK) {
				assert(tlv_rem(tlv) <= 1);
				tlv_skip(tlv);
			}
			assert(tlv_rem(tlv) <= 3);
			tlv_skip(tlv);
		} else {
			errf_free(err);
		}
		assert(tlv_rem(tlv) <= 5);
		tlv_skip(tlv);
	} else {
		errf_free(err);
	}
	tlv_abort(tlv);
	tlv_free(tlv);

	return (0);
}
#endif
