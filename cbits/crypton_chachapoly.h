/*
 * Copyright (c) 2026 Kazu Yamamoto
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef CRYPTON_CHACHAPOLY_H
#define CRYPTON_CHACHAPOLY_H

#include <stdint.h>

/* ChaCha20-Poly1305 (RFC 8439) as one call.
 *
 * The pieces are the ChaCha20 and Poly1305 already here; what these do is
 * hold them together, which the Haskell above used to do at the cost of eight
 * foreign calls and the allocations between them.
 *
 * The nonce is the twelve bytes RFC 8439 defines.  taglen is at most 16.
 */

void crypton_chachapoly_encrypt(uint8_t *out, uint8_t *tag, uint32_t taglen,
                                const uint8_t *key,
                                const uint8_t *nonce, uint32_t noncelen,
                                const uint8_t *aad, uint32_t aadlen,
                                const uint8_t *input, uint32_t inlen);

/* Decrypt and compare, a byte at a time over the whole tag whichever way the
 * answer goes.  Returns non-zero when the tag matched. */
int crypton_chachapoly_decrypt(uint8_t *out,
                               const uint8_t *tag, uint32_t taglen,
                               const uint8_t *key,
                               const uint8_t *nonce, uint32_t noncelen,
                               const uint8_t *aad, uint32_t aadlen,
                               const uint8_t *input, uint32_t inlen);

/* Decrypt and hand the computed tag back rather than comparing it. */
void crypton_chachapoly_decrypt_tag(uint8_t *out, uint8_t *outtag,
                                    uint32_t taglen, const uint8_t *key,
                                    const uint8_t *nonce, uint32_t noncelen,
                                    const uint8_t *aad, uint32_t aadlen,
                                    const uint8_t *input, uint32_t inlen);

#endif
