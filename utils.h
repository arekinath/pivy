/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#if !defined(_UTILS_H)
#define _UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <openssl/x509.h>

/* Can't use errf_t here (errf.h #includes this first) */
struct errf;

struct errf *X509_to_der(X509 *, uint8_t **, size_t *);
struct errf *X509_REQ_to_der(X509_REQ *, uint8_t **, size_t *);
struct errf *X509_CRL_to_der(X509_CRL *, uint8_t **, size_t *);
struct errf *X509_from_der(const uint8_t *, size_t, X509 **);
struct errf *X509_REQ_from_der(const uint8_t *, size_t, X509_REQ **);
struct errf *X509_CRL_from_der(const uint8_t *, size_t, X509_CRL **);

#if !defined(__APPLE__) && !defined(__sun)
typedef uint64_t uintmax_t;
#endif

#if !defined(USING_SPL) && !defined(__sun)
#define _MACH_MACHINE_BOOLEAN_H_
typedef enum { B_FALSE = 0, B_TRUE = 1 } boolean_t;
typedef unsigned int uint;
typedef unsigned int u_int;
#endif

#if defined(__sun)
/*
 * This is dumb.
 *
 * We build with _XOPEN_SOURCE=600 in order to get the void* version of mmap()
 * instead of the stupid caddr_t version from sys/mman.h
 *
 * But if we build with that, then sys/types.h doesn't give us B_TRUE/B_FALSE
 * because it ignores __EXTENSIONS__.
 *
 * This was all fixed around the r151040 era, so if we ever drop support for
 * r151038 and earlier, then we can get rid of this.
 *
 * Note that we have to #define these _after_ including sys/types.h, or else
 * the macro definition will mess up the enum definition in there that does
 * include B_TRUE/B_FALSE on newer versions.
 */
#define B_TRUE _B_TRUE
#define B_FALSE _B_FALSE
#endif

struct strbuf;
struct strbuf *strbuf_new(void);
struct strbuf *strbuf_new_init(size_t);
struct strbuf *strbuf_from(const char *);
void strbuf_free(struct strbuf *);
void strbuf_freezero(struct strbuf *);
void strbuf_reset(struct strbuf *);
void strbuf_append(struct strbuf *, const char *);
void strbuf_concat(struct strbuf *, const struct strbuf *);
const char *strbuf_cstr(struct strbuf *);
size_t strbuf_len(const struct strbuf *);

struct bitbuf;
struct bitbuf *bitbuf_new(void);
struct bitbuf *bitbuf_from(const uint8_t *, size_t len);
void bitbuf_free(struct bitbuf *);
struct errf *bitbuf_write(struct bitbuf *, uint32_t v, uint nbits);
struct errf *bitbuf_read(struct bitbuf *, uint nbits, uint32_t *v);
uint8_t *bitbuf_to_bytes(const struct bitbuf *, size_t *outlen);
size_t bitbuf_rem(const struct bitbuf *);
size_t bitbuf_len(const struct bitbuf *);
boolean_t bitbuf_at_end(const struct bitbuf *);

enum iso7811_bcd {
	/* used as a control char, never put on wire */
	ISO_BCD_NONE	= 0x00,

	/* ordinary BCD digits */
	ISO_BCD_0	= 0x01,
	ISO_BCD_1	= 0x10,
	ISO_BCD_2	= 0x08,
	ISO_BCD_3	= 0x19,
	ISO_BCD_4	= 0x04,
	ISO_BCD_5	= 0x15,
	ISO_BCD_6	= 0x0d,
	ISO_BCD_7	= 0x1c,
	ISO_BCD_8	= 0x02,
	ISO_BCD_9	= 0x13,

	/* control chars that go on the wire */
	ISO_BCD_SS	= 0x1a,
	ISO_BCD_FS	= 0x16,
	ISO_BCD_ES	= 0x1f
};
struct bcdbuf;
struct bcdbuf *bcdbuf_new(void);
struct bcdbuf *bcdbuf_from(const uint8_t *, size_t);
void bcdbuf_free(struct bcdbuf *);
const char *iso7811_to_str(enum iso7811_bcd);
struct errf *bcdbuf_write(struct bcdbuf *, enum iso7811_bcd);
struct errf *bcdbuf_write_lrc(struct bcdbuf *);
struct errf *bcdbuf_write_string(struct bcdbuf *, const char *str,
    enum iso7811_bcd terminator);
struct errf *bcdbuf_read(struct bcdbuf *, enum iso7811_bcd *out);
struct errf *bcdbuf_read_and_check_lrc(struct bcdbuf *);
struct errf *bcdbuf_read_string(struct bcdbuf *, size_t limit, char **pstr,
    enum iso7811_bcd *terminator);
uint8_t *bcdbuf_to_bytes(const struct bcdbuf *, size_t *outlen);
size_t bcdbuf_rem(const struct bcdbuf *);
size_t bcdbuf_len(const struct bcdbuf *);
boolean_t bcdbuf_at_end(const struct bcdbuf *);

void *malloc_conceal(size_t size) __attribute__((malloc));
void *calloc_conceal(size_t nmemb, size_t size) __attribute__((malloc));

void set_no_dump(void *ptr, size_t size);

#if !defined(__OpenBSD__) && !defined(__sun)
void freezero(void *ptr, size_t size);
#endif

void xstrlcat(char *, const char *, size_t);
void xstrlcpy(char *, const char *, size_t);

char *buf_to_hex(const uint8_t *buf, size_t len, boolean_t spaces);

#if defined(__bounded)
#undef __bounded
#endif

#if defined(HAVE_BOUNDED_ATTR)
#define __bounded(_what, ...) __attribute__((__bounded__(_what, __VA_ARG__)))
#else
#define __bounded(_what, ...)
#endif

#if defined(__APPLE__)
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"

void *reallocarray(void *, size_t, size_t);
void *recallocarray(void *, size_t, size_t, size_t);
void explicit_bzero(void *, size_t);

typedef unsigned char u_char;
#endif

struct sshbuf;
struct errf *sshbuf_b16tod(const char *str, struct sshbuf *buf);

int timingsafe_bcmp(const void *, const void *, size_t);

struct errf *parse_lifetime(char *, unsigned long *out);
char *unparse_lifetime(unsigned long);

#define	jsonerrf(func, ...)	\
    errf("JSONError", NULL, func " returned error: %s", \
    ##__VA_ARGS__, json_util_get_last_err())

#define	jtokerrf(func, jerr, ...)	\
    errf("JSONError", NULL, func " returned error: %s", \
    ##__VA_ARGS__, json_tokener_error_desc(jerr))

#if defined(__OpenBSD__)
#include <readpassphrase.h>
#else

#define RPP_ECHO_OFF    0x00		/* Turn off echo (default). */
#define RPP_ECHO_ON     0x01		/* Leave echo on. */
#define RPP_REQUIRE_TTY 0x02		/* Fail if there is no tty. */
#define RPP_FORCELOWER  0x04		/* Force input to lower case. */
#define RPP_FORCEUPPER  0x08		/* Force input to upper case. */
#define RPP_SEVENBIT    0x10		/* Strip the high bit from input. */
#define RPP_STDIN       0x20		/* Read from stdin, not /dev/tty */

char * readpassphrase(const char *, char *, size_t, int);

#endif /* defined(__OpenBSD__) */

#endif
