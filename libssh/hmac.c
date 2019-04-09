/* $OpenBSD: hmac.c,v 1.12 2015/03/24 20:03:44 markus Exp $ */
/*
 * Copyright (c) 2014 Markus Friedl.  All rights reserved.
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

#include <sys/types.h>
#include <string.h>

#include "sshbuf.h"
#include "digest.h"
#include "hmac.h"

struct ssh_hmac_ctx {
	int			 alg;
	struct ssh_digest_ctx	*ictx;
	struct ssh_digest_ctx	*octx;
	struct ssh_digest_ctx	*digest;
	u_char			*buf;
	size_t			 buf_len;
};

size_t
ssh_hmac_bytes(int alg)
{
	return ssh_digest_bytes(alg);
}

struct ssh_hmac_ctx *
ssh_hmac_start(int alg)
{
	struct ssh_hmac_ctx	*ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;
	ret->alg = alg;
	if ((ret->ictx = ssh_digest_start(alg)) == NULL ||
	    (ret->octx = ssh_digest_start(alg)) == NULL ||
	    (ret->digest = ssh_digest_start(alg)) == NULL)
		goto fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	if ((ret->buf = calloc(1, ret->buf_len)) == NULL)
		goto fail;
	return ret;
fail:
	ssh_hmac_free(ret);
	return NULL;
}

int
ssh_hmac_init(struct ssh_hmac_ctx *ctx, const void *key, size_t klen)
{
	size_t i;

	/* reset ictx and octx if no is key given */
	if (key != NULL) {
		/* truncate long keys */
		if (klen <= ctx->buf_len)
			memcpy(ctx->buf, key, klen);
		else if (ssh_digest_memory(ctx->alg, key, klen, ctx->buf,
		    ctx->buf_len) < 0)
			return -1;
		for (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		if (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			return -1;
		for (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		if (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			return -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	if (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		return -1;
	return 0;
}

int
ssh_hmac_update(struct ssh_hmac_ctx *ctx, const void *m, size_t mlen)
{
	return ssh_digest_update(ctx->digest, m, mlen);
}

int
ssh_hmac_update_buffer(struct ssh_hmac_ctx *ctx, const struct sshbuf *b)
{
	return ssh_digest_update_buffer(ctx->digest, b);
}

int
ssh_hmac_final(struct ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
{
	size_t len;

	len = ssh_digest_bytes(ctx->alg);
	if (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		return -1;
	/* switch to octx */
	if (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		return -1;
	return 0;
}

void
ssh_hmac_free(struct ssh_hmac_ctx *ctx)
{
	if (ctx != NULL) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		if (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			free(ctx->buf);
		}
		explicit_bzero(ctx, sizeof(*ctx));
		free(ctx);
	}
}

