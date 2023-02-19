/*
 * Portions of this file are derived from assfail.c in illumos, under the
 * following license:
 *
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012, 2014 by Delphix. All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */

#include "utils.h"
#include "debug.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <errno.h>

#include "openssh/config.h"
#include "openssh/ssherr.h"

#if !defined(__sun)
static void
ultos(uint64_t n, int base, char *s)
{
	char lbuf[24];		/* 64 bits fits in 16 hex digits, 20 decimal */
	char *cp = lbuf;

	do {
		*cp++ = "0123456789abcdef"[n%base];
		n /= base;
	} while (n);
	if (base == 16) {
		*s++ = '0';
		*s++ = 'x';
	}
	do {
		*s++ = *--cp;
	} while (cp > lbuf);
	*s = '\0';
}

boolean_t
assfail(const char *assertion, const char *filename, int line_num)
{
	char buf[800];
	pid_t self;
	volatile int rc;

	buf[0] = 0;
	self = getpid();
	ultos((uint64_t)(uintptr_t)self, 16, buf + strlen(buf));
	(void) strcat(buf, ": ");
	(void) strcat(buf, assertion);

	if (filename != NULL) {
		(void) strcat(buf, ", file ");
		(void) strcat(buf, filename);
		(void) strcat(buf, ", line ");
		ultos((uint64_t)line_num, 10, buf + strlen(buf));
	}

	(void) strcat(buf, "\n");
	rc = write(2, buf, strlen(buf));
	(void)rc;
	abort();
	return (B_TRUE);
}

void
assfail3(const char *assertion, uintmax_t lv, const char *op, uintmax_t rv,
    const char *filename, int line_num)
{
	char buf[1000];
	buf[0] = 0;
	(void) strcpy(buf, assertion);
	(void) strcat(buf, " (");
	ultos((uint64_t)lv, 16, buf + strlen(buf));
	(void) strcat(buf, " ");
	(void) strcat(buf, op);
	(void) strcat(buf, " ");
	ultos((uint64_t)rv, 16, buf + strlen(buf));
	(void) strcat(buf, ")");
	assfail(buf, filename, line_num);
}
#endif

const char *
ssh_err(int n)
{
	switch (n) {
	case SSH_ERR_SUCCESS:
		return "success";
	case SSH_ERR_INTERNAL_ERROR:
		return "unexpected internal error";
	case SSH_ERR_ALLOC_FAIL:
		return "memory allocation failed";
	case SSH_ERR_MESSAGE_INCOMPLETE:
		return "incomplete message";
	case SSH_ERR_INVALID_FORMAT:
		return "invalid format";
	case SSH_ERR_BIGNUM_IS_NEGATIVE:
		return "bignum is negative";
	case SSH_ERR_STRING_TOO_LARGE:
		return "string is too large";
	case SSH_ERR_BIGNUM_TOO_LARGE:
		return "bignum is too large";
	case SSH_ERR_ECPOINT_TOO_LARGE:
		return "elliptic curve point is too large";
	case SSH_ERR_NO_BUFFER_SPACE:
		return "insufficient buffer space";
	case SSH_ERR_INVALID_ARGUMENT:
		return "invalid argument";
	case SSH_ERR_KEY_BITS_MISMATCH:
		return "key bits do not match";
	case SSH_ERR_EC_CURVE_INVALID:
		return "invalid elliptic curve";
	case SSH_ERR_KEY_TYPE_MISMATCH:
		return "key type does not match";
	case SSH_ERR_KEY_TYPE_UNKNOWN:
		return "unknown or unsupported key type";
	case SSH_ERR_EC_CURVE_MISMATCH:
		return "elliptic curve does not match";
	case SSH_ERR_EXPECTED_CERT:
		return "plain key provided where certificate required";
	case SSH_ERR_KEY_LACKS_CERTBLOB:
		return "key lacks certificate data";
	case SSH_ERR_KEY_CERT_UNKNOWN_TYPE:
		return "unknown/unsupported certificate type";
	case SSH_ERR_KEY_CERT_INVALID_SIGN_KEY:
		return "invalid certificate signing key";
	case SSH_ERR_KEY_INVALID_EC_VALUE:
		return "invalid elliptic curve value";
	case SSH_ERR_SIGNATURE_INVALID:
		return "incorrect signature";
	case SSH_ERR_LIBCRYPTO_ERROR:
		return "error in libcrypto";  /* XXX fetch and return */
	case SSH_ERR_UNEXPECTED_TRAILING_DATA:
		return "unexpected bytes remain after decoding";
	case SSH_ERR_SYSTEM_ERROR:
		return strerror(errno);
	case SSH_ERR_KEY_CERT_INVALID:
		return "invalid certificate";
	case SSH_ERR_AGENT_COMMUNICATION:
		return "communication with agent failed";
	case SSH_ERR_AGENT_FAILURE:
		return "agent refused operation";
	case SSH_ERR_DH_GEX_OUT_OF_RANGE:
		return "DH GEX group out of range";
	case SSH_ERR_DISCONNECTED:
		return "disconnected";
	case SSH_ERR_MAC_INVALID:
		return "message authentication code incorrect";
	case SSH_ERR_NO_CIPHER_ALG_MATCH:
		return "no matching cipher found";
	case SSH_ERR_NO_MAC_ALG_MATCH:
		return "no matching MAC found";
	case SSH_ERR_NO_COMPRESS_ALG_MATCH:
		return "no matching compression method found";
	case SSH_ERR_NO_KEX_ALG_MATCH:
		return "no matching key exchange method found";
	case SSH_ERR_NO_HOSTKEY_ALG_MATCH:
		return "no matching host key type found";
	case SSH_ERR_PROTOCOL_MISMATCH:
		return "protocol version mismatch";
	case SSH_ERR_NO_PROTOCOL_VERSION:
		return "could not read protocol version";
	case SSH_ERR_NO_HOSTKEY_LOADED:
		return "could not load host key";
	case SSH_ERR_NEED_REKEY:
		return "rekeying not supported by peer";
	case SSH_ERR_PASSPHRASE_TOO_SHORT:
		return "passphrase is too short (minimum five characters)";
	case SSH_ERR_FILE_CHANGED:
		return "file changed while reading";
	case SSH_ERR_KEY_UNKNOWN_CIPHER:
		return "key encrypted using unsupported cipher";
	case SSH_ERR_KEY_WRONG_PASSPHRASE:
		return "incorrect passphrase supplied to decrypt private key";
	case SSH_ERR_KEY_BAD_PERMISSIONS:
		return "bad permissions";
	case SSH_ERR_KEY_CERT_MISMATCH:
		return "certificate does not match key";
	case SSH_ERR_KEY_NOT_FOUND:
		return "key not found";
	case SSH_ERR_AGENT_NOT_PRESENT:
		return "agent not present";
	case SSH_ERR_AGENT_NO_IDENTITIES:
		return "agent contains no identities";
	case SSH_ERR_BUFFER_READ_ONLY:
		return "internal error: buffer is read-only";
	case SSH_ERR_KRL_BAD_MAGIC:
		return "KRL file has invalid magic number";
	case SSH_ERR_KEY_REVOKED:
		return "Key is revoked";
	case SSH_ERR_CONN_CLOSED:
		return "Connection closed";
	case SSH_ERR_CONN_TIMEOUT:
		return "Connection timed out";
	case SSH_ERR_CONN_CORRUPT:
		return "Connection corrupted";
	case SSH_ERR_PROTOCOL_ERROR:
		return "Protocol error";
	default:
		return "unknown error";
	}
}
