/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>

#include "utils.h"
#include "debug.h"

void
set_no_dump(void *ptr, size_t size)
{
#if defined(MADV_DONTDUMP)
	(void) madvise(ptr, size, MADV_DONTDUMP);
#endif
#if defined(MADV_NOCORE)
	(void) madvise(ptr, size, MADV_NOCORE);
#endif
	(void) mlock(ptr, size);
}

void *
malloc_conceal(size_t size)
{
	void *ptr = malloc(size);
	if (ptr != NULL)
		set_no_dump(ptr, size);
	return (ptr);
}

void *
calloc_conceal(size_t nmemb, size_t size)
{
	void *ptr = calloc(nmemb, size);
	if (ptr != NULL)
		set_no_dump(ptr, size);
	return (ptr);
}

#if !defined(__OpenBSD__) && !defined(__FreeBSD__) && !defined(__sun)
void
freezero(void *ptr, size_t sz)
{
	if (ptr != NULL && sz > 0)
		explicit_bzero(ptr, sz);
	free(ptr);
}
#endif

static char
nybble_to_hex(uint8_t nybble)
{
	if (nybble >= 0xA)
		return ('A' + (nybble - 0xA));
	else
		return ('0' + nybble);
}

char *
buf_to_hex(const uint8_t *buf, size_t len, boolean_t spaces)
{
	size_t i, j = 0;
	char *out = calloc(1, len * 3 + 1);
	uint8_t nybble;
	for (i = 0; i < len; ++i) {
		nybble = (buf[i] & 0xF0) >> 4;
		out[j++] = nybble_to_hex(nybble);
		nybble = (buf[i] & 0x0F);
		out[j++] = nybble_to_hex(nybble);
		if (spaces && i + 1 < len)
			out[j++] = ' ';
	}
	out[j] = 0;
	return (out);
}
