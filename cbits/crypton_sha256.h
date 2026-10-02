/*
 * Copyright (C) 2006-2009 Vincent Hanquez <vincent@snarc.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef CRYPTOHASH_SHA256_H
#define CRYPTOHASH_SHA256_H

#include <stdint.h>

#define SHA256_BLOCK_SIZE 64

struct sha256_ctx
{
	uint64_t sz;
	uint8_t  buf[128];
	uint32_t h[8];
};

#define sha224_ctx 		sha256_ctx

#define SHA224_DIGEST_SIZE	28
#define SHA224_CTX_SIZE		sizeof(struct sha224_ctx)

#define SHA256_DIGEST_SIZE	32
#define SHA256_CTX_SIZE		sizeof(struct sha256_ctx)

void crypton_sha224_init(struct sha224_ctx *ctx);
void crypton_sha224_update(struct sha224_ctx *ctx, const uint8_t *data, uint32_t len);
void crypton_sha224_finalize(struct sha224_ctx *ctx, uint8_t *out);
void crypton_sha224_finalize_prefix(struct sha224_ctx *ctx, const uint8_t *data, uint32_t len, uint32_t n, uint8_t *out);

void crypton_sha256_init(struct sha256_ctx *ctx);
void crypton_sha256_update(struct sha256_ctx *ctx, const uint8_t *data, uint32_t len);
/* The pointers are all required to be non-null, which is said here so that
 * the compiler knows it too.  Both of these write their digest through a
 * loop -- store_be32(out + 4 * i, ...) -- where sha1 and md5 write theirs at
 * constant offsets, and that is the difference that makes gcc's
 * -Wstringop-overflow reason about out being null: with
 * -fsanitize=undefined, UndefinedBehaviorSanitizer inserts a null check
 * before memcpy, because glibc declares memcpy nonnull, and the check puts a
 * null path in front of the warning pass, which then reports writing into
 * "a region of size 0" at "address zero".  Saying the pointer is never null
 * removes the path rather than the warning.  It costs nothing: compiled as
 * the package compiles it, the assembly is identical with and without. */
__attribute__((nonnull))
void crypton_sha256_finalize(struct sha256_ctx *ctx, uint8_t *out);
void crypton_sha256_finalize_prefix(struct sha256_ctx *ctx, const uint8_t *data, uint32_t len, uint32_t n, uint8_t *out);

#endif
