/*
 * Copyright (c) 2026 Kazu Yamamoto <kazu@iij.ad.jp>
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
 *
 * What the stitched AES-GCM assembly in cbits/asm needs in order to be
 * called: the two pieces of state it reads are laid out the way OpenSSL
 * lays them out, which is not the way crypton does, and neither is worth
 * changing the rest of the library for.  Both are built here, per message,
 * from the key schedule and the H that crypton already has.
 */

#include "crypton_cpu.h"

#ifdef WITH_X86_GCM_ASM

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>
#include <crypton_aes.h>
#include <aes/gcm_x86_asm.h>

#ifdef WITH_TARGET_ATTRIBUTES
#define TARGET_PCLMUL __attribute__((target("sse4.1,pclmul")))
#else
#define TARGET_PCLMUL
#endif

#define ALIGNMENT(n) __attribute__((aligned(n)))

/*
 * cbits/asm/aesni-gcm-x86_64-*.S.  Both answer how many bytes they got
 * through, which is a multiple of six blocks and is zero if the message is
 * shorter than they are willing to start on.
 */
size_t crypton_gcm_asm_encrypt(const void *in, void *out, size_t len,
                               const void *key, uint8_t ivec[16], void *Xi);
size_t crypton_gcm_asm_decrypt(const void *in, void *out, size_t len,
                               const void *key, uint8_t ivec[16], void *Xi);

/*
 * The key schedule as the assembly reads it: the encryption round keys,
 * and at offset 240 the number of rounds less one, which is the count
 * OpenSSL's AES-NI key setup leaves there -- 9, 11 and 13 -- and what the
 * assembly compares against to tell the three key sizes apart.
 */
struct asm_key {
	uint8_t rd_key[240];
	uint32_t rounds;
};

/*
 * The assembly reads the running tag from the front of this and the powers
 * of H from 32 bytes in, which is where they sit in OpenSSL's GCM context
 * -- the 16 bytes between them hold H itself there and nothing here.
 * Powers up to the sixth are used, since the loop takes six blocks at a
 * time, and each pair of them is followed by the halves the Karatsuba
 * multiplication would otherwise have to add up again.
 */
struct asm_gcm {
	block128 xi;
	block128 unused;
	block128 htable[9];
};

/*
 * H, and every power of it, is kept shifted up by one bit: GCM numbers the
 * bits of a field element the other way round from the way the carry-less
 * multiply does, and pre-shifting the operand is what saves the correction
 * after each multiply.  The bit that falls off the top is the one that the
 * polynomial reduces.
 */
TARGET_PCLMUL
static __m128i twist(__m128i h)
{
	const __m128i poly = _mm_set_epi64x(0xc200000000000000ULL, 1);
	__m128i carried = _mm_slli_si128(_mm_srli_epi64(h, 63), 8);
	__m128i top = _mm_shuffle_epi32(h, 0xff);
	__m128i reduce = _mm_cmpgt_epi32(_mm_setzero_si128(), top);

	h = _mm_or_si128(_mm_slli_epi64(h, 1), carried);
	return _mm_xor_si128(h, _mm_and_si128(reduce, poly));
}

/* the two halves of a value added together, which is the term Karatsuba
 * needs and which does not depend on what it is multiplied by */
TARGET_PCLMUL
static __m128i fold(__m128i a)
{
	return _mm_xor_si128(a, _mm_unpackhi_epi64(a, a));
}

/*
 * The table the assembly reads: the first six powers of H, each shifted up
 * by one, and after each pair the two halves of both of them added
 * together, which is the term the Karatsuba multiplication would otherwise
 * work out for itself every time.
 *
 * The powers are not computed here.  crypton's own table already holds
 * H^1 to H^8, in the byte order the multiply wants and unshifted, so
 * twisting each one is the whole of the work -- which is why this is worth
 * doing per message rather than keeping a second table in the context.
 */
TARGET_PCLMUL
static void init_htable(struct asm_gcm *st, const aes_gcm *gcm)
{
	int i;

	for (i = 0; i < 3; i++) {
		__m128i odd = twist(_mm_loadu_si128(
		    (const __m128i *) &gcm->htable[2 * i]));
		__m128i even = twist(_mm_loadu_si128(
		    (const __m128i *) &gcm->htable[2 * i + 1]));

		_mm_storeu_si128((__m128i *) &st->htable[3 * i + 0], odd);
		_mm_storeu_si128((__m128i *) &st->htable[3 * i + 1], even);
		_mm_storeu_si128((__m128i *) &st->htable[3 * i + 2],
		                 _mm_unpacklo_epi64(fold(odd), fold(even)));
	}
}

/*
 * The counter block, whose bottom 32 bits are what counts, as GCM has it.
 * crypton keeps the value it last used and the assembly wants the one it
 * is to use next, so this steps between the two conventions at each end.
 */
static void ctr32_bump(uint8_t ivec[16], uint32_t delta)
{
	uint32_t c = ((uint32_t) ivec[12] << 24) | ((uint32_t) ivec[13] << 16)
	           | ((uint32_t) ivec[14] << 8) | (uint32_t) ivec[15];

	c += delta;
	ivec[12] = (uint8_t) (c >> 24);
	ivec[13] = (uint8_t) (c >> 16);
	ivec[14] = (uint8_t) (c >> 8);
	ivec[15] = (uint8_t) c;
}

/*
 * How much of the message to hand over.  The assembly works in groups of
 * six blocks, and what it leaves behind goes to a loop that works in groups
 * of eight and then one at a time.  Handing over every group it could take
 * often leaves two or four blocks to go through one at a time, which at a
 * multiply apiece costs more than the three groups it takes to line the
 * remainder up on eight.  So the length is rounded down to whichever number
 * of six-block groups within reach leaves the least behind, modulo eight.
 */
static uint32_t handover(uint32_t blocks)
{
	uint32_t groups = blocks / 6;
	uint32_t best = groups;
	uint32_t least = (blocks - 6 * groups) % 8;
	uint32_t i;

	for (i = 1; i <= 3 && groups >= i; i++) {
		uint32_t left = (blocks - 6 * (groups - i)) % 8;

		if (left < least) {
			least = left;
			best = groups - i;
		}
	}
	return best * 6 * 16;
}

int crypton_gcm_asm_usable(void)
{
	static int resolved = 0;
	static int usable = 0;

	if (!resolved) {
		const uint32_t need = CRYPTON_X86_AVX | CRYPTON_X86_MOVBE
		                    | CRYPTON_X86_PCLMUL;

		usable = (crypton_x86_simd_features() & need) == need;
		resolved = 1;
	}
	return usable;
}

TARGET_PCLMUL
static uint32_t bulk(int encrypt, uint8_t *output, aes_gcm *gcm, aes_key *key,
                     const uint8_t *input, uint32_t length)
{
	struct asm_gcm st ALIGNMENT(16);
	struct asm_key k ALIGNMENT(16);
	uint8_t ivec[16] ALIGNMENT(16);
	uint32_t hand;
	size_t done;

	if (!crypton_gcm_asm_usable())
		return 0;

	/* below its own minimum the assembly does nothing, so in that case
	 * give it everything and let it decide */
	hand = handover(length / 16);
	if (hand < (encrypt ? 0x60 * 3 : 0x60))
		hand = length;

	memcpy(k.rd_key, key->data, 16 * (size_t) (key->nbr + 1));
	k.rounds = (uint32_t) key->nbr - 1;
	memcpy(&st.xi, &gcm->tag, 16);
	memcpy(ivec, &gcm->civ, 16);
	ctr32_bump(ivec, 1);
	init_htable(&st, gcm);

	done = encrypt
	     ? crypton_gcm_asm_encrypt(input, output, hand, &k, ivec, &st.xi)
	     : crypton_gcm_asm_decrypt(input, output, hand, &k, ivec, &st.xi);

	if (done > 0) {
		ctr32_bump(ivec, 0xffffffff);
		memcpy(&gcm->tag, &st.xi, 16);
		memcpy(&gcm->civ, ivec, 16);
	}
	return (uint32_t) done;
}

uint32_t crypton_gcm_asm_bulk_encrypt(uint8_t *output, aes_gcm *gcm, aes_key *key,
                                      const uint8_t *input, uint32_t length)
{
	return bulk(1, output, gcm, key, input, length);
}

uint32_t crypton_gcm_asm_bulk_decrypt(uint8_t *output, aes_gcm *gcm, aes_key *key,
                                      const uint8_t *input, uint32_t length)
{
	return bulk(0, output, gcm, key, input, length);
}

#endif
