/*
 * Copyright (c) 2014 Vincent Hanquez <vincent@snarc.org>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of his contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef CRYPTON_POLY1305_H
# define CRYPTON_POLY1305_H

/*
 * Either the 26-bit limbs the C implementation works in, or the state the
 * assembly keeps: its accumulator, in whichever base it is using at the
 * time, the clamped key, and the powers of that laid out for the four-way
 * vector loop, which together come to exactly 192 bytes -- OpenSSL allots
 * the same for the same thing.
 *
 * size = 192+16+4+16 = 228, 232 with the alignment the union asks for
 */
typedef struct
{
	union {
		struct {
			uint32_t r[5];
			uint32_t h[5];
		} limb;
		uint64_t opaque[24];
	} st;
	uint32_t pad[4];
	uint32_t index;
	uint8_t buf[16]; /* previous partial block */
} poly1305_ctx;

typedef uint8_t poly1305_mac[16];
typedef uint8_t poly1305_key[32];

void crypton_poly1305_init(poly1305_ctx *ctx, poly1305_key *key);
void crypton_poly1305_update(poly1305_ctx *ctx, uint8_t *data, uint32_t length);
void crypton_poly1305_finalize(poly1305_mac mac, poly1305_ctx *ctx);

#endif
