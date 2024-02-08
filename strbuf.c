/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2024 The University of Queenslad
 * Author: Alex Wilson <alex@uq.edu.au>
 */

#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>

#include "utils.h"
#include "debug.h"
#include "errf.h"

struct strbuf {
	char	*sb_buf;
	size_t	 sb_len;
	size_t	 sb_max;
};

struct strbuf *
strbuf_new_init(size_t initial)
{
	struct strbuf *sb;
	sb = calloc(1, sizeof (struct strbuf));
	if (sb == NULL)
		return (NULL);
	sb->sb_max = initial;
	sb->sb_buf = malloc(sb->sb_max);
	if (sb->sb_buf == NULL) {
		strbuf_free(sb);
		return (NULL);
	}
	return (sb);
}

struct strbuf *
strbuf_new(void)
{
	return (strbuf_new_init(128));
}

struct strbuf *
strbuf_from(const char *cstr)
{
	struct strbuf *sb;
	sb = strbuf_new();
	if (sb == NULL)
		return (NULL);
	strbuf_append(sb, cstr);
	return (sb);
}

void
strbuf_free(struct strbuf *sb)
{
	if (sb == NULL)
		return;
	free(sb->sb_buf);
	free(sb);
}

void
strbuf_freezero(struct strbuf *sb)
{
	if (sb == NULL)
		return;
	explicit_bzero(sb->sb_buf, sb->sb_len);
	free(sb->sb_buf);
	free(sb);
}

void
strbuf_reset(struct strbuf *sb)
{
	explicit_bzero(sb->sb_buf, sb->sb_len);
	sb->sb_len = 0;
}

static void
strbuf_expand(struct strbuf *sb, size_t minfree)
{
	size_t minmax = sb->sb_len + minfree;
	size_t newmax = sb->sb_max;
	char *oldbuf = sb->sb_buf;
	if (newmax > minmax)
		return;
	while (newmax < minmax)
		newmax *= 2;
	sb->sb_buf = malloc(newmax);
	if (sb->sb_buf == NULL) {
		newmax = minmax;
		sb->sb_buf = malloc(newmax);
	}
	VERIFY(sb->sb_buf != NULL);
	__CPROVER_assume(sb->sb_buf != NULL);
	memcpy(sb->sb_buf, oldbuf, sb->sb_len);
	explicit_bzero(oldbuf, sb->sb_len);
	free(oldbuf);
	sb->sb_max = newmax;
}

void
strbuf_append(struct strbuf *sb, const char *cstr)
{
	size_t len;
	if (cstr == NULL)
		return;
	len = strlen(cstr);
	strbuf_expand(sb, len);
	VERIFY3U(sb->sb_len + len, <, sb->sb_max);
	memcpy(&sb->sb_buf[sb->sb_len], cstr, len);
	sb->sb_len += len;
}

void
strbuf_concat(struct strbuf *sb, const struct strbuf *osb)
{
	strbuf_expand(sb, osb->sb_len);
	VERIFY3U(sb->sb_len + osb->sb_len, <, sb->sb_max);
	memcpy(&sb->sb_buf[sb->sb_len], osb->sb_buf, osb->sb_len);
	sb->sb_len += osb->sb_len;
}

const char *
strbuf_cstr(struct strbuf *sb)
{
	strbuf_expand(sb, 1);
	sb->sb_buf[sb->sb_len] = '\0';
	return (sb->sb_buf);
}

size_t
strbuf_len(const struct strbuf *sb)
{
	return (sb->sb_len);
}

#if defined(__CPROVER) && __CPROVER_MAIN == __FILE_strbuf_c

char *
genstr(size_t minlen, size_t maxlen)
{
	size_t len, i;
	char *buf;
	__CPROVER_assume(len >= minlen);
	__CPROVER_assume(len <= maxlen);
	buf = malloc(len + 1);
	__CPROVER_assume(buf != NULL);
	for (i = 0; i < len; ++i) {
		char c;
		__CPROVER_assume(c != 0);
		buf[i] = c;
	}
	buf[len] = '\0';
	return (buf);
}

void
prove_strbuf(void)
{
	struct strbuf *sb;
	char *tmp;
	size_t len;

	sb = strbuf_new_init(8);
	__CPROVER_assume(sb != NULL);
	strbuf_append(sb, genstr(0, 10));
	strbuf_append(sb, genstr(1, 10));
	len = strbuf_len(sb);
	assert(len > 0);
	assert(len <= 20);
	assert(strlen(strbuf_cstr(sb)) == len);
	strbuf_free(sb);
}

int
main(int argc, char *argv[])
{
	__CPROVER_assume(ERRF_NOMEM != NULL);
	prove_strbuf();
	return (0);
}

#endif
