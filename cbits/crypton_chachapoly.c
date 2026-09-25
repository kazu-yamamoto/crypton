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

#include <stdint.h>
#include <string.h>

#include "crypton_chacha.h"
#include "crypton_chachapoly.h"
#include "crypton_poly1305.h"

/* RFC 8439.  The one-time Poly1305 key is the first 32 bytes of the ChaCha20
 * keystream at counter 0; a whole 64-byte block is generated so the counter
 * lands on 1, which is where the message starts. */
static void chachapoly_start(crypton_chacha_context *cctx, poly1305_ctx *pctx,
                             const uint8_t *key,
                             const uint8_t *nonce, uint32_t noncelen)
{
	uint8_t block[64];

	crypton_chacha_init(cctx, 20, 32, key, noncelen, nonce);
	crypton_chacha_generate(block, cctx, sizeof(block));
	crypton_poly1305_init(pctx, (poly1305_key *) block);
	memset(block, 0, sizeof(block));
}

/* Poly1305 over an associated or encrypted part, then zeros up to the next
 * multiple of sixteen. */
static void absorb_padded(poly1305_ctx *pctx, const uint8_t *p, uint32_t len)
{
	static const uint8_t zeros[16] = {0};
	uint32_t rem;

	if (len)
		crypton_poly1305_update(pctx, (uint8_t *) p, len);
	rem = len % 16;
	if (rem)
		crypton_poly1305_update(pctx, (uint8_t *) zeros, 16 - rem);
}

/* The two lengths, little endian, eight bytes each, which is what the tag
 * ends on. */
static void absorb_lengths(poly1305_ctx *pctx, uint32_t aadlen, uint32_t inlen)
{
	uint8_t lens[16];
	int i;

	for (i = 0; i < 8; i++)
		lens[i] = (uint8_t) (((uint64_t) aadlen) >> (8 * i));
	for (i = 0; i < 8; i++)
		lens[8 + i] = (uint8_t) (((uint64_t) inlen) >> (8 * i));
	crypton_poly1305_update(pctx, lens, sizeof(lens));
}

void crypton_chachapoly_encrypt(uint8_t *out, uint8_t *tag, uint32_t taglen,
                                const uint8_t *key,
                                const uint8_t *nonce, uint32_t noncelen,
                                const uint8_t *aad, uint32_t aadlen,
                                const uint8_t *input, uint32_t inlen)
{
	crypton_chacha_context cctx;
	poly1305_ctx pctx;
	poly1305_mac mac;

	chachapoly_start(&cctx, &pctx, key, nonce, noncelen);
	absorb_padded(&pctx, aad, aadlen);
	if (inlen)
		crypton_chacha_combine(out, &cctx, input, inlen);
	/* what the tag covers is the ciphertext, which is now in out */
	absorb_padded(&pctx, out, inlen);
	absorb_lengths(&pctx, aadlen, inlen);
	crypton_poly1305_finalize(mac, &pctx);
	memcpy(tag, mac, taglen);

	memset(&cctx, 0, sizeof(cctx));
	memset(&pctx, 0, sizeof(pctx));
}

/* Shared by the two decrypting entry points: with outtag NULL the tag is
 * compared here and the answer returned, otherwise it is written there. */
static int chachapoly_decrypt(uint8_t *out, const uint8_t *tag, uint32_t taglen,
                              uint8_t *outtag, const uint8_t *key,
                              const uint8_t *nonce, uint32_t noncelen,
                              const uint8_t *aad, uint32_t aadlen,
                              const uint8_t *input, uint32_t inlen)
{
	crypton_chacha_context cctx;
	poly1305_ctx pctx;
	poly1305_mac mac;
	uint8_t diff = 0;
	uint32_t i;

	chachapoly_start(&cctx, &pctx, key, nonce, noncelen);
	absorb_padded(&pctx, aad, aadlen);
	/* here the ciphertext is the input, so the tag can be taken before the
	 * plaintext is written and out may alias input */
	absorb_padded(&pctx, input, inlen);
	absorb_lengths(&pctx, aadlen, inlen);
	crypton_poly1305_finalize(mac, &pctx);

	if (inlen)
		crypton_chacha_combine(out, &cctx, input, inlen);

	memset(&cctx, 0, sizeof(cctx));
	memset(&pctx, 0, sizeof(pctx));

	if (outtag) {
		memcpy(outtag, mac, taglen);
		return 1;
	}
	for (i = 0; i < taglen; i++)
		diff |= (uint8_t) (mac[i] ^ tag[i]);
	return diff == 0;
}

int crypton_chachapoly_decrypt(uint8_t *out,
                               const uint8_t *tag, uint32_t taglen,
                               const uint8_t *key,
                               const uint8_t *nonce, uint32_t noncelen,
                               const uint8_t *aad, uint32_t aadlen,
                               const uint8_t *input, uint32_t inlen)
{
	return chachapoly_decrypt(out, tag, taglen, NULL, key, nonce, noncelen,
	                          aad, aadlen, input, inlen);
}

void crypton_chachapoly_decrypt_tag(uint8_t *out, uint8_t *outtag,
                                    uint32_t taglen, const uint8_t *key,
                                    const uint8_t *nonce, uint32_t noncelen,
                                    const uint8_t *aad, uint32_t aadlen,
                                    const uint8_t *input, uint32_t inlen)
{
	(void) chachapoly_decrypt(out, NULL, taglen, outtag, key, nonce,
	                          noncelen, aad, aadlen, input, inlen);
}
