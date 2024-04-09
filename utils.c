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
xstrlcat(char *buf, const char *str, size_t buflen)
{
	size_t rc;
	rc = strlcat(buf, str, buflen);
	VERIFY3U(rc, <, buflen);
}

void
xstrlcpy(char *buf, const char *str, size_t buflen)
{
	size_t rc;
	rc = strlcpy(buf, str, buflen);
	VERIFY3U(rc, <, buflen);
}

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

size_t
bitbuf_rem(const struct bitbuf *b)
{
	size_t nbits, ubits;
	VERIFY(b->bb_mode == BITBUF_READ);
	nbits = b->bb_len * 8;
	ubits = b->bb_byte * 8 + b->bb_bit;
	VERIFY3U(ubits, <=, nbits);
	return (nbits - ubits);
}

size_t
bitbuf_len(const struct bitbuf *b)
{
	if (b->bb_mode == BITBUF_READ)
		return (b->bb_len * 8);
	else
		return (b->bb_byte * 8 + b->bb_bit);
}

boolean_t
bitbuf_at_end(const struct bitbuf *b)
{
	return (b->bb_byte == b->bb_len);
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

	if (b->bb_byte >= b->bb_len) {
		return (errf("ShortBuffer", NULL, "Tried to read %u bits from "
		    "bitbuf with nothing left", nbits));
	}


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

struct bcdbuf {
	struct bitbuf 	*bcd_b;
	char	 	*bcd_sb;
	size_t		 bcd_sblen;
	uint8_t		 bcd_last;
	uint8_t		 bcd_lrc;
};

struct bcdbuf *
bcdbuf_new(void)
{
	struct bcdbuf *b = NULL;

	b = calloc(1, sizeof (*b));
	if (b == NULL)
		goto fail;

	b->bcd_b = bitbuf_new();
	if (b->bcd_b == NULL)
		goto fail;

	return (b);
fail:
	bcdbuf_free(b);
	return (NULL);
}

struct bcdbuf *
bcdbuf_from(const uint8_t *data, size_t len)
{
	struct bcdbuf *b = NULL;

	b = calloc(1, sizeof (*b));
	if (b == NULL)
		goto fail;

	b->bcd_b = bitbuf_from(data, len);
	if (b->bcd_b == NULL)
		goto fail;

	b->bcd_sblen = 30;
	b->bcd_sb = malloc(b->bcd_sblen);
	if (b->bcd_sb == NULL)
		goto fail;
	b->bcd_sb[0] = '\0';

	return (b);
fail:
	bcdbuf_free(b);
	return (NULL);
}

void
bcdbuf_free(struct bcdbuf *b)
{
	if (b == NULL)
		return;
	bitbuf_free(b->bcd_b);
	free(b->bcd_sb);
	free(b);
}

errf_t *
bcdbuf_write(struct bcdbuf *b, enum iso7811_bcd v)
{
	errf_t *err;

	VERIFY(b->bcd_b->bb_mode == BITBUF_WRITE);
	VERIFY(v != ISO_BCD_NONE);
	if ((err = bitbuf_write(b->bcd_b, v, 5)))
		return (err);
	b->bcd_last = v;
	b->bcd_lrc ^= (v & 0x1e);

	return (ERRF_OK);
}

errf_t *
bcdbuf_write_lrc(struct bcdbuf *b)
{
	errf_t *err;
	uint32_t v;

	VERIFY(b->bcd_b->bb_mode == BITBUF_WRITE);
	v = b->bcd_lrc;
	v |= ((v & (1<<4)) >> 4) ^ ((v & (1<<3)) >> 3) ^ ((v & (1<<2)) >> 2) ^
	    ((v & (1<<1)) >> 1) ^ 1;

	if ((err = bitbuf_write(b->bcd_b, v, 5))) {
		err = errf("ISO7811Error", err, "Failed to write LRC");
		return (err);
	}

	return (ERRF_OK);
}

errf_t *
bcdbuf_write_string(struct bcdbuf *b, const char *strval,
    enum iso7811_bcd terminator)
{
	enum iso7811_bcd v;
	errf_t *err;
	const char *p = strval;

	VERIFY(b->bcd_b->bb_mode == BITBUF_WRITE);
	while (*p != '\0') {
		switch (*p) {
		case '0':
			v = ISO_BCD_0;
			break;
		case '1':
			v = ISO_BCD_1;
			break;
		case '2':
			v = ISO_BCD_2;
			break;
		case '3':
			v = ISO_BCD_3;
			break;
		case '4':
			v = ISO_BCD_4;
			break;
		case '5':
			v = ISO_BCD_5;
			break;
		case '6':
			v = ISO_BCD_6;
			break;
		case '7':
			v = ISO_BCD_7;
			break;
		case '8':
			v = ISO_BCD_8;
			break;
		case '9':
			v = ISO_BCD_9;
			break;
		default:
			err = errf("ISO7811Error", NULL, "String data "
			    "contains invalid BCD char: '%c'", *p);
			return (err);
		}
		if ((err = bcdbuf_write(b, v)))
			return (err);
		p++;
	}

	if (terminator != ISO_BCD_NONE) {
		if ((err = bcdbuf_write(b, terminator)))
			return (err);
	}

	return (ERRF_OK);
}

errf_t *
bcdbuf_read(struct bcdbuf *b, enum iso7811_bcd *out)
{
	errf_t *err;
	uint32_t v;

	VERIFY(b->bcd_b->bb_mode == BITBUF_READ);
	if ((err = bitbuf_read(b->bcd_b, 5, &v)))
		return (err);
	b->bcd_last = v;
	b->bcd_lrc ^= (v & 0x1e);

	switch (v) {
	case ISO_BCD_0:
	case ISO_BCD_1:
	case ISO_BCD_2:
	case ISO_BCD_3:
	case ISO_BCD_4:
	case ISO_BCD_5:
	case ISO_BCD_6:
	case ISO_BCD_7:
	case ISO_BCD_8:
	case ISO_BCD_9:
	case ISO_BCD_SS:
	case ISO_BCD_FS:
	case ISO_BCD_ES:
		*out = v;
		return (ERRF_OK);

	default:
		return (errf("ISO7811Error", NULL, "Input data contains "
		    "illegal BCD symbol: %x at offset 0x%x(+%u bits)",
		    v, b->bcd_b->bb_byte, 8 - b->bcd_b->bb_bit));
	}
}

errf_t *
bcdbuf_read_and_check_lrc(struct bcdbuf *b)
{
	errf_t *err;
	uint32_t v;

	if ((err = bitbuf_read(b->bcd_b, 5, &v)))
		return (err);

	v &= 0x1e;

	if (v != b->bcd_lrc) {
		err = errf("ISO7811Error", NULL, "LRC mismatch");
		return (err);
	}

	return (ERRF_OK);
}

errf_t *
bcdbuf_read_string(struct bcdbuf *b, size_t limit, char **field,
    enum iso7811_bcd *terminator)
{
	enum iso7811_bcd v;
	const char *vstr;
	errf_t *err;
	size_t len;

	if (limit >= b->bcd_sblen) {
		b->bcd_sblen = limit * 2;
		free(b->bcd_sb);
		b->bcd_sb = malloc(b->bcd_sblen);
		__CPROVER_assume(b->bcd_sb != NULL);
		VERIFY(b->bcd_sb != NULL);
	}

	while (1) {
		err = bcdbuf_read(b, &v);
		if (err != ERRF_OK)
			return (err);
		if (v == ISO_BCD_SS) {
			err = errf("ISO7811Error", NULL, "Read SS at start "
			    "of string, expected valid BCD char");
			return (err);
		}
		if (v == ISO_BCD_FS || v == ISO_BCD_ES) {
			if (terminator)
				*terminator = v;
			break;
		}
		vstr = iso7811_to_str(v);
		VERIFY(vstr != NULL);
		len = strlcat(b->bcd_sb, vstr, b->bcd_sblen);
		if (limit != 0 && len >= limit) {
			if (terminator)
				*terminator = ISO_BCD_NONE;
			break;
		}
	}
	*field = strdup(b->bcd_sb);
	__CPROVER_assume(*field != NULL);
	VERIFY(*field != NULL);
	b->bcd_sb[0] = '\0';
	return (ERRF_OK);
}

uint8_t *
bcdbuf_to_bytes(const struct bcdbuf *b, size_t *outlen)
{
	VERIFY(b->bcd_b->bb_mode == BITBUF_WRITE);
	return (bitbuf_to_bytes(b->bcd_b, outlen));
}

size_t
bcdbuf_rem(const struct bcdbuf *b)
{
	size_t nbits = bitbuf_rem(b->bcd_b);
	size_t nsyms = nbits / 5;
	if (nsyms == 0 && nbits > 0)
		return (1);
	return (nsyms);
}

size_t
bcdbuf_len(const struct bcdbuf *b)
{
	size_t nbits = bitbuf_len(b->bcd_b);
	size_t nsyms = nbits / 5;
	if (nsyms == 0 && nbits > 0)
		return (1);
	return (nsyms);
}

boolean_t
bcdbuf_at_end(const struct bcdbuf *b)
{
	return (bitbuf_at_end(b->bcd_b));
}

#if defined(__CPROVER) && __CPROVER_MAIN == __FILE_utils_c

uint8_t nondet_u8(void);
uint32_t nondet_u32(void);
char nondet_char(void);

char
rbcdchar(void)
{
	char b = nondet_char();
	__CPROVER_assume(b >= '0' && b <= '9');
	return (b);
}

enum iso7811_bcd
rbcdenum(void)
{
	enum iso7811_bcd v;
	__CPROVER_assume(v >= ISO_BCD_0 && v <= ISO_BCD_9);
	return (v);
}

void
prove_bitbuf_read_uniform(uint nbits, uint minbpf, uint maxbpf)
{
	struct bitbuf *bit;
	uint32_t v32;
	struct errf *err;
	uint nfields, bpf, i;
	size_t len;
	uint8_t *buf;
	const uint nbytes = nbits / 8;

	__CPROVER_assume(bpf >= minbpf && bpf <= maxbpf);
	nfields = nbits / bpf;
	assert(nfields > 0 && nfields <= 4);

	uint8_t *data = malloc(nbytes);
	__CPROVER_assume(data != NULL);
	for (i = 0; i < nbytes; ++i)
		__CPROVER_assume(data[i] != 0);

	bit = bitbuf_from(data, nbytes);
	__CPROVER_assume(bit != NULL);

	for (i = 0; i < nfields; ++i) {
		err = bitbuf_read(bit, bpf, &v32);
		__CPROVER_assume(err != ERRF_NOMEM);
		assert(err == ERRF_OK);
		assert(v32 <= (1<<bpf));
	}

	err = bitbuf_read(bit, bpf, &v32);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err != ERRF_OK);
	assert(errf_caused_by(err, "ShortBuffer"));

	assert(bitbuf_rem(bit) <= bpf);

	bitbuf_free(bit);
}

void
prove_bitbuf_read_any(uint nbits, uint minbpf, uint maxbpf)
{
	struct bitbuf *bit;
	uint32_t v32;
	struct errf *err;
	size_t len;
	uint i;
	uint8_t *buf;
	const uint nbytes = nbits / 8;
	uint bitrem = nbits;

	uint8_t *data = malloc(nbytes);
	__CPROVER_assume(data != NULL);
	for (i = 0; i < nbytes; ++i)
		__CPROVER_assume(data[i] != 0);

	bit = bitbuf_from(data, nbytes);
	__CPROVER_assume(bit != NULL);

	while (bitrem > 0 && i < 4) {
		uint bpf;
		__CPROVER_assume(bpf >= minbpf && bpf <= maxbpf);
		__CPROVER_assume(bpf <= bitrem);

		err = bitbuf_read(bit, bpf, &v32);
		__CPROVER_assume(err != ERRF_NOMEM);
		assert(err == ERRF_OK);
		assert(v32 <= (1<<bpf));

		bitrem -= bpf;
		++i;
	}

	bitbuf_free(bit);
}

void
prove_bitbuf_write(void)
{
	struct bitbuf *bit;
	struct errf *err;
	uint nbits, nfields, i, nbytes;
	size_t len;
	uint8_t *buf;

	bit = bitbuf_new();
	__CPROVER_assume(bit != NULL);

	__CPROVER_assume(nfields > 0 && nfields < 3);
	nbits = 0;

	for (i = 0; i < nfields; ++i) {
		uint bpf;
		uint32_t v32;
		__CPROVER_assume(bpf >= 3 && bpf <= 16);
		__CPROVER_assume(v32 < (1<<bpf));

		err = bitbuf_write(bit, v32, bpf);
		__CPROVER_assume(err != ERRF_NOMEM);
		assert(err == ERRF_OK);

		nbits += bpf;
	}

	assert(bitbuf_len(bit) == nbits);
	nbytes = (nbits + 7) / 8;

	buf = bitbuf_to_bytes(bit, &len);
	__CPROVER_assume(buf != NULL);
	assert(len == nbytes);

	bitbuf_free(bit);
	free(buf);
}

void
prove_bitbuf(void)
{
	prove_bitbuf_read_uniform(16, 4, 8);
	prove_bitbuf_read_uniform(32, 8, 16);
	prove_bitbuf_read_any(8, 1, 4);
	prove_bitbuf_write();
}

void
prove_bcdbuf(void)
{
	struct bcdbuf *bcd;
	uint32_t v32;
	struct errf *err;
	uint nbits;
	size_t len;
	uint8_t *buf;
	char *str;
	enum iso7811_bcd bcdchar;

	const uint8_t bbuf0[] = { (ISO_BCD_SS << 3), nondet_u8(), nondet_u8(),
	    nondet_u8(), nondet_u8(), (ISO_BCD_ES << 3) };
	bcd = bcdbuf_from(bbuf0, sizeof (bbuf0));
	__CPROVER_assume(bcd != NULL);

	err = bcdbuf_read(bcd, &bcdchar);
	__CPROVER_assume(err == ERRF_OK);
	assert(bcdchar == ISO_BCD_SS);

	err = bcdbuf_read_string(bcd, 8, &str, &bcdchar);
	__CPROVER_assume(err != ERRF_NOMEM);
	if (err == ERRF_OK) {
		assert(str != NULL);
		assert(strlen(str) <= 8);
		assert(bcdchar == ISO_BCD_ES || bcdchar == ISO_BCD_FS);
	}

	bcdbuf_free(bcd);

	bcd = bcdbuf_new();
	__CPROVER_assume(bcd != NULL);

	const char bbuf1[] = { rbcdchar(), rbcdchar(), '\0' };
	err = bcdbuf_write_string(bcd, bbuf1, ISO_BCD_FS);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);
	err = bcdbuf_write_lrc(bcd);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);

	assert(bcdbuf_len(bcd) == 4);

	buf = bcdbuf_to_bytes(bcd, &len);
	__CPROVER_assume(buf != NULL);
	assert(len == 3);

	bcdbuf_free(bcd);
	free(buf);

	bcd = bcdbuf_new();
	__CPROVER_assume(bcd != NULL);

	const enum iso7811_bcd bcdbuf[] = { rbcdenum(), rbcdenum(),
	    ISO_BCD_ES };
	err = bcdbuf_write(bcd, bcdbuf[0]);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);
	err = bcdbuf_write(bcd, bcdbuf[1]);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);
	err = bcdbuf_write(bcd, bcdbuf[2]);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);
	err = bcdbuf_write_lrc(bcd);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);

	/*buf = bcdbuf_to_bytes(bcd, &len);
	__CPROVER_assume(buf != NULL);
	assert(len == 2);

	bcdbuf_free(bcd);

	bcd = bcdbuf_from(buf, len);
	__CPROVER_assume(bcd != NULL);

	err = bcdbuf_read(bcd, &bcdchar);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);
	assert(bcdchar == bcdbuf[0]);

	err = bcdbuf_read(bcd, &bcdchar);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);
	assert(bcdchar == bcdbuf[1]);

	err = bcdbuf_read(bcd, &bcdchar);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);
	assert(bcdchar == bcdbuf[2]);

	err = bcdbuf_read(bcd, &bcdchar);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err != ERRF_OK);

	err = bcdbuf_read_and_check_lrc(bcd);
	__CPROVER_assume(err != ERRF_NOMEM);
	assert(err == ERRF_OK);*/

	bcdbuf_free(bcd);
}

int
main(int argc, char *argv[])
{
	__CPROVER_assume(ERRF_NOMEM != NULL);
	prove_bitbuf();
	prove_bcdbuf();
	return (0);
}
#endif
