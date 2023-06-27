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
#include <errno.h>
#include <strings.h>

#include "utils.h"
#include "debug.h"
#include "errf.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "openssh/config.h"
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

enum bitbuf_mode {
	BITBUF_READ,
	BITBUF_WRITE
};

struct bitbuf {
	enum bitbuf_mode	 bb_mode;

	uint8_t			*bb_buf;
	size_t			 bb_len;

	size_t			 bb_byte;
	size_t			 bb_bit;
};

struct bitbuf *
bitbuf_new(void)
{
	struct bitbuf *b;

	b = calloc(1, sizeof (struct bitbuf));
	if (b == NULL)
		return (NULL);
	b->bb_mode = BITBUF_WRITE;
	b->bb_len = 128;
	b->bb_buf = calloc(1, b->bb_len);
	if (b->bb_buf == NULL) {
		free(b);
		return (NULL);
	}

	return (b);
}

struct bitbuf *
bitbuf_from(const uint8_t *buf, size_t len)
{
	struct bitbuf *b;

	b = calloc(1, sizeof (struct bitbuf));
	if (b == NULL)
		return (NULL);
	b->bb_mode = BITBUF_READ;
	b->bb_len = len;
	b->bb_buf = (uint8_t *)buf;

	return (b);
}

void
bitbuf_free(struct bitbuf *b)
{
	if (b == NULL)
		return;
	if (b->bb_mode == BITBUF_WRITE)
		free(b->bb_buf);
	free(b);
}

uint8_t *
bitbuf_to_bytes(const struct bitbuf *b, size_t *outlen)
{
	uint8_t *buf;

	*outlen = b->bb_byte + (b->bb_bit > 0 ? 1 : 0);
	buf = malloc(*outlen);
	if (buf == NULL)
		return (NULL);
	bcopy(b->bb_buf, buf, *outlen);

	return (buf);
}

errf_t *
bitbuf_expand(struct bitbuf *b)
{
	size_t nsz;
	uint8_t *nbuf;

	nsz = b->bb_len * 2;
	nbuf = calloc(1, nsz);
	if (nbuf == NULL)
		return (errfno("malloc", errno, NULL));
	bcopy(b->bb_buf, nbuf, b->bb_len);
	free(b->bb_buf);

	b->bb_buf = nbuf;
	b->bb_len = nsz;

	return (ERRF_OK);
}

errf_t *
bitbuf_write(struct bitbuf *b, uint32_t v, uint nbits)
{
	uint rem = nbits;
	errf_t *err;

	VERIFY(b->bb_mode == BITBUF_WRITE);

	while (rem > 0) {
		uint take = 8 - b->bb_bit;
		if (take > rem)
			take = rem;
		const uint32_t mask = (1 << take) - 1;
		const uint32_t vshift = (v >> (rem - take)) & mask;
		const uint32_t vor = vshift << (8 - take - b->bb_bit);
		b->bb_buf[b->bb_byte] |= vor;

		b->bb_bit += take;
		if (b->bb_bit >= 8) {
			b->bb_byte++;
			b->bb_bit = 0;
			if (b->bb_byte + 1 >= b->bb_len) {
				if ((err = bitbuf_expand(b)))
					return (err);
			}
		}

		rem -= take;
	}

	return (ERRF_OK);
}

errf_t *
bitbuf_read(struct bitbuf *b, uint nbits, uint32_t *out)
{
	uint rem = nbits;
	uint32_t final = 0;

	VERIFY(b->bb_mode == BITBUF_READ);

	while (rem > 0) {
		uint take = 8 - b->bb_bit;
		if (take > rem)
			take = rem;

		const uint32_t mask = (1 << take) - 1;
		const uint32_t v = b->bb_buf[b->bb_byte];
		const uint32_t vshift = (v >> (8 - take - b->bb_bit)) & mask;
		const uint32_t vor = vshift << (rem - take);
		final |= vor;

		rem -= take;

		b->bb_bit += take;
		if (b->bb_bit >= 8) {
			b->bb_byte++;
			b->bb_bit = 0;
			if (b->bb_byte >= b->bb_len && rem > 0) {
				return (errf("ShortBuffer", NULL, "Tried to "
				    "read %u bits from bitbuf with only "
				    "%u bits", nbits, nbits - rem));
			}
		}
	}

	*out = final;

	return (ERRF_OK);
}

errf_t *
parse_lifetime(char *lifetime, unsigned long *outp)
{
	unsigned long lifetime_secs;
	char *p;

	errno = 0;
	lifetime_secs = strtoul(lifetime, &p, 10);
	if (errno != 0) {
		return (errf("SyntaxError", errfno("strtoul", errno,
		    NULL), "Error parsing lifetime spec: '%s'", lifetime));
	}
	if (*p == 's' && *(p + 1) == '\0') {
		++p;
	} else if (*p == 'm' && *(p + 1) == '\0') {
		++p;
		lifetime_secs *= 60;
	} else if (*p == 'h' && *(p + 1) == '\0') {
		++p;
		lifetime_secs *= 3600;
	} else if (*p == 'd' && *(p + 1) == '\0') {
		++p;
		lifetime_secs *= 3600*24;
	} else if (*p == 'w' && *(p + 1) == '\0') {
		++p;
		lifetime_secs *= 3600*24*7;
	} else if (*p == 'y' && *(p + 1) == '\0') {
		++p;
		lifetime_secs *= 3600*24*365;
	}
	if (*p != '\0') {
		return (errf("SyntaxError", NULL, "Error parsing contents "
		    "of 'lifetime' certificate variable: trailing garbage '%s'",
		    p));
	}

	*outp = lifetime_secs;
	return (ERRF_OK);
}

char *
unparse_lifetime(unsigned long secs)
{
	struct sshbuf *buf = sshbuf_new();
	int rc;
	char *ret;
	VERIFY(buf != NULL);
	const char *unit = "s";

	if (secs >= 3600*24*365 && secs % 3600*24*365 == 0) {
		secs /= 3600*24*365;
		unit = "y";
	} else if (secs >= 3600*24*7 && secs % 3600*24*7 == 0) {
		secs /= 3600*24*7;
		unit = "w";
	} else if (secs >= 3600*24 && secs % 3600*24 == 0) {
		secs /= 3600*24;
		unit = "d";
	} else if (secs >= 3600 && secs % 3600 == 0) {
		secs /= 3600;
		unit = "h";
	} else if (secs >= 60 && secs % 60 == 0) {
		secs /= 60;
		unit = "m";
	}

	rc = sshbuf_putf(buf, "%lu%s", secs, unit);
	VERIFY(rc == 0);

	ret = sshbuf_dup_string(buf);
	sshbuf_free(buf);

	return (ret);
}

struct errf *
X509_to_der(X509 *cert, uint8_t **pbuf, size_t *plen)
{
	int rc;
	uint8_t *cbuf = NULL;
	errf_t *err;
	rc = i2d_X509(cert, &cbuf);
	if (rc < 0) {
		make_sslerrf(err, "i2d_X509", "converting X509 cert to DER");
		return (err);
	}
	*plen = rc;
	*pbuf = cbuf;
	return (ERRF_OK);
}

struct errf *
X509_REQ_to_der(X509_REQ *req, uint8_t **pbuf, size_t *plen)
{
	int rc;
	uint8_t *cbuf = NULL;
	errf_t *err;
	rc = i2d_X509_REQ(req, &cbuf);
	if (rc < 0) {
		make_sslerrf(err, "i2d_X509_REQ", "converting X509 req to DER");
		return (err);
	}
	*plen = rc;
	*pbuf = cbuf;
	return (ERRF_OK);
}

struct errf *
X509_CRL_to_der(X509_CRL *crl, uint8_t **pbuf, size_t *plen)
{
	int rc;
	uint8_t *cbuf = NULL;
	errf_t *err;
	rc = i2d_X509_CRL(crl, &cbuf);
	if (rc < 0) {
		make_sslerrf(err, "i2d_X509_CRL", "converting X509 CRL to DER");
		return (err);
	}
	*plen = rc;
	*pbuf = cbuf;
	return (ERRF_OK);
}

struct errf *
X509_from_der(const uint8_t *buf, size_t len, X509 **pcert)
{
	const unsigned char *p;
	X509 *x;
	errf_t *err;
	p = buf;
	x = d2i_X509(NULL, &p, len);
	if (x == NULL) {
		make_sslerrf(err, "d2i_X509", "parsing X509 certificate");
		return (err);
	}
	*pcert = x;
	return (ERRF_OK);
}

struct errf *
X509_REQ_from_der(const uint8_t *buf, size_t len, X509_REQ **preq)
{
	const unsigned char *p;
	X509_REQ *x;
	errf_t *err;
	p = buf;
	x = d2i_X509_REQ(NULL, &p, len);
	if (x == NULL) {
		make_sslerrf(err, "d2i_X509_REQ", "parsing X509 cert req");
		return (err);
	}
	*preq = x;
	return (ERRF_OK);
}

struct errf *
X509_CRL_from_der(const uint8_t *buf, size_t len, X509_CRL **pcrl)
{
	const unsigned char *p;
	X509_CRL *x;
	errf_t *err;
	p = buf;
	x = d2i_X509_CRL(NULL, &p, len);
	if (x == NULL) {
		make_sslerrf(err, "d2i_X509_CRL", "parsing X509 CRL");
		return (err);
	}
	*pcrl = x;
	return (ERRF_OK);
}
