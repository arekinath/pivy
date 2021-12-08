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
#include "errf.h"

#include "openssh/sshbuf.h"
#include "openssh/ssherr.h"

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

#if !defined(__OpenBSD__) && !defined(__sun)
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

struct errf *
sshbuf_b16tod(const char *str, struct sshbuf *buf)
{
	const uint len = strlen(str);
	uint idx = 0;
	uint shift = 4;
	uint i;
	int rc;
	uint8_t v = 0;
	for (i = 0; i < len; ++i) {
		const char c = str[i];
		if (c >= '0' && c <= '9') {
			v |= (c - '0') << shift;
		} else if (c >= 'a' && c <= 'f') {
			v |= (c - 'a' + 0xa) << shift;
		} else if (c >= 'A' && c <= 'F') {
			v |= (c - 'A' + 0xA) << shift;
		} else if (c == ':' || c == ' ' || c == '\t' ||
		    c == '\n' || c == '\r') {
			continue;
		} else {
			return (errf("HexParseError", NULL,
			    "invalid hex digit: '%c'", c));
		}
		if (shift == 4) {
			shift = 0;
		} else if (shift == 0) {
			rc = sshbuf_put_u8(buf, v);
			if (rc != 0)
				return (ssherrf("sshbuf_put_u8", rc, NULL));
			v = 0;
			shift = 4;
		}
	}
	if (shift == 0) {
		return (errf("HexParseError", NULL, "odd number of hex digits "
		    "(incomplete)"));
	}
	return (ERRF_OK);
}

int
platform_sys_dir_uid(uid_t uid)
{
	if (uid == 0)
		return 1;
	return 0;
}

char *
sys_get_rdomain(int fd)
{
	return NULL;
}

int
sys_set_rdomain(int fd, const char *name)
{
	return -1;
}

int
sys_tun_open(int tun, int mode, char **ifname)
{
	return -1;
}
