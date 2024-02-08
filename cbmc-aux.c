/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2024 The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
 */

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "errf.h"

#if defined(__CPROVER)

/*
 * CBMC has no stdlib impl of strlcpy/strlcat since they're BSD-specific.
 * We'll provide the OpenBSD definitions of them here.
 */

/* License for strlcpy */
/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* OPENBSD ORIGINAL: lib/libc/string/strlcpy.c */
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = *s++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return(s - src - 1);	/* count does not include NUL */
}

/* License for strlcat */
/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* OPENBSD ORIGINAL: lib/libc/string/strlcat.c */
size_t
strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));	/* count does not include NUL */
}

#if __CPROVER_MAIN != __FILE_errf_c

/* Mocks for errf.c functions */

struct errf {
	const char *errf_name;
};

struct errf errf_nomem = {
	.errf_name = { "MemoryError" }
};

struct errf *ERRF_NOMEM = &errf_nomem;

struct errf *
_errf(const char *name, struct errf *cause, const char *func,
    const char *file, uint line, const char *fmt, ...)
{
	struct errf *err;
	err = calloc(1, sizeof (struct errf));
	if (err == NULL)
		return (ERRF_NOMEM);
	err->errf_name = name;
	return (err);
}

struct errf *
_errfno(const char *enofunc, int eno, const char *func,
    const char *file, uint line, const char *fmt, ...)
{
	struct errf *err;
	err = calloc(1, sizeof (struct errf));
	if (err == NULL)
		return (ERRF_NOMEM);
	err->errf_name = "SystemError";
	return (err);
}

const char *
errf_name(const struct errf *err)
{
	return (err->errf_name);
}

void
errf_free(struct errf *err)
{
	if (err == NULL)
		return;
	if (err == ERRF_NOMEM)
		return;
	free(err);
}

boolean_t
errf_caused_by(const struct errf *err, const char *name)
{
	return (strcmp(err->errf_name, name) == 0);
}

#endif	/* ! proving errf.c */

#if __CPROVER_MAIN != __FILE_utils_c
/* mocks of bcdbuf and bitbuf */

struct bitbuf {
	size_t b_bits;
};

struct bitbuf *
bitbuf_new(void)
{
	struct bitbuf *b;
	b = calloc(1, sizeof (struct bitbuf));
	if (b == NULL)
		return (NULL);
	return (b);
}

struct bitbuf *
bitbuf_from(const uint8_t *buf, size_t len)
{
	struct bitbuf *b;
	b = calloc(1, sizeof (struct bitbuf));
	if (b == NULL)
		return (NULL);
	b->b_bits = len * 8;
	return (b);
}

void
bitbuf_free(struct bitbuf *b)
{
	if (b == NULL)
		return;
	free(b);
}

size_t
bitbuf_rem(const struct bitbuf *b)
{
	return (b->b_bits);
}

size_t
bitbuf_len(const struct bitbuf *b)
{
	return (b->b_bits);
}

boolean_t
bitbuf_at_end(const struct bitbuf *b)
{
	return (b->b_bits == 0);
}

struct bcdbuf {
	size_t bcd_bits;
};

struct bcdbuf *
bcdbuf_new(void)
{
	struct bcdbuf *b;
	b = calloc(1, sizeof (struct bcdbuf));
	if (b == NULL)
		return (NULL);
	return (b);
}

struct bcdbuf *
bcdbuf_from(const uint8_t *buf, size_t len)
{
	struct bcdbuf *b;
	b = calloc(1, sizeof (struct bcdbuf));
	if (b == NULL)
		return (NULL);
	b->bcd_bits = len * 8;
	return (b);
}

void
bcdbuf_free(struct bcdbuf *b)
{
	if (b == NULL)
		return;
	free(b);
}

errf_t *
bcdbuf_read(struct bcdbuf *b, enum iso7811_bcd *out)
{
	int doerr;
	errf_t *err;
	enum iso7811_bcd v;

	if (b->bcd_bits < 5) {
		__CPROVER_assume(err != ERRF_OK && err != ERRF_NOMEM);
		return (err);
	}

	__CPROVER_assume(doerr == 0 || doerr == 1);
	if (doerr) {
		__CPROVER_assume(err != ERRF_OK && err != ERRF_NOMEM);
		return (err);
	}

	b->bcd_bits -= 5;
	__CPROVER_assume(v != ISO_BCD_NONE);
	*out = v;

	return (ERRF_OK);
}

errf_t *
bcdbuf_read_string(struct bcdbuf *b, size_t limit, char **pstr,
    enum iso7811_bcd *terminator)
{
	int doerr;
	errf_t *err;
	enum iso7811_bcd v;
	size_t len, i;
	char *str;

	if (b->bcd_bits < 5) {
		__CPROVER_assume(err != ERRF_OK && err != ERRF_NOMEM);
		return (err);
	}

	__CPROVER_assume(doerr == 0 || doerr == 1);
	if (doerr) {
		__CPROVER_assume(err != ERRF_OK && err != ERRF_NOMEM);
		return (err);
	}

	__CPROVER_assume(len <= limit);
	__CPROVER_assume((len + 1) * 5 <= b->bcd_bits);

	b->bcd_bits -= (len + 1) * 5;
	if (terminator != NULL) {
		__CPROVER_assume(v == ISO_BCD_ES || v == ISO_BCD_FS);
		*terminator = v;
	}

	str = malloc(len + 1);
	__CPROVER_assume(str != NULL);
	for (i = 0; i < len; ++i) {
		char c;
		__CPROVER_assume(c >= '0' && c <= '9');
		str[i] = c;
	}
	str[len] = '\0';
	*pstr = str;

	return (ERRF_OK);
}

errf_t *
bcdbuf_read_and_check_lrc(struct bcdbuf *b)
{
	int doerr;
	errf_t *err;

	if (b->bcd_bits < 5) {
		__CPROVER_assume(err != ERRF_OK && err != ERRF_NOMEM);
		return (err);
	}

	__CPROVER_assume(doerr == 0 || doerr == 1);
	if (doerr) {
		__CPROVER_assume(err != ERRF_OK && err != ERRF_NOMEM);
		return (err);
	}

	b->bcd_bits -= 5;
	return (ERRF_OK);
}

size_t
bcdbuf_rem(const struct bcdbuf *b)
{
	size_t nsyms = b->bcd_bits / 5;
	if (nsyms == 0)
		return (1);
	return (nsyms);
}

size_t
bcdbuf_len(const struct bcdbuf *b)
{
	return (b->bcd_bits / 5);
}

boolean_t
bcdbuf_at_end(const struct bcdbuf *b)
{
	return (b->bcd_bits == 0);
}

errf_t *
bcdbuf_write(struct bcdbuf *b, enum iso7811_bcd v)
{
	errf_t *err;

	if (b == ISO_BCD_NONE) {
		__CPROVER_assume(err != ERRF_OK && err != ERRF_NOMEM);
		return (err);
	}

	b->bcd_bits += 5;
	return (ERRF_OK);
}

errf_t *
bcdbuf_write_lrc(struct bcdbuf *b)
{
	b->bcd_bits += 5;
	return (ERRF_OK);
}

errf_t *
bcdbuf_write_string(struct bcdbuf *b, const char *str,
    enum iso7811_bcd terminator)
{
	size_t i, len;
	errf_t *err;

	len = strlen(str);
	for (i = 0; i < len; ++i) {
		if (!(str[i] >= '0' && str[i] <= '9')) {
			__CPROVER_assume(err != ERRF_OK && err != ERRF_NOMEM);
			return (err);
		}
		b->bcd_bits += 5;
	}

	if (terminator != ISO_BCD_NONE)
		b->bcd_bits += 5;

	return (ERRF_OK);
}

uint8_t *
bcdbuf_to_bytes(const struct bcdbuf *b, size_t *outlen)
{
	uint8_t *buf;
	size_t len;

	len = (b->bcd_bits + 7) / 8;

	buf = malloc(len);
	if (buf == NULL)
		return (NULL);

	*outlen = len;
	return (buf);
}

/*
 * Copy this one since it's pretty short and a mock wouldn't be useful
 * anyway.
 */
const char *
iso7811_to_str(enum iso7811_bcd b)
{
	switch (b) {
	case ISO_BCD_0: return ("0");
	case ISO_BCD_1: return ("1");
	case ISO_BCD_2: return ("2");
	case ISO_BCD_3: return ("3");
	case ISO_BCD_4: return ("4");
	case ISO_BCD_5: return ("5");
	case ISO_BCD_6: return ("6");
	case ISO_BCD_7: return ("7");
	case ISO_BCD_8: return ("8");
	case ISO_BCD_9: return ("9");
	case ISO_BCD_SS: return ("SS");
	case ISO_BCD_FS: return ("FS");
	case ISO_BCD_ES: return ("ES");
	default: return (NULL);
	}
}

#endif 	/* !proving utils.c */

#endif
