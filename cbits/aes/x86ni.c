/*
 * Copyright (c) 2012-2013 Vincent Hanquez <vincent@snarc.org>
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

#ifdef WITH_AESNI

#include <wmmintrin.h>
#include <tmmintrin.h>
#include <string.h>
#include <crypton_aes.h>
#include <crypton_cpu.h>
#include <aes/gf.h>
#include <aes/x86ni.h>
#include <aes/gcm_vaes_x86.h>
#include <aes/block128.h>
#include <aes/gcm_x86_asm.h>

#ifdef ARCH_X86
#define ALIGN_UP(addr, size) (((addr) + ((size) - 1)) & (~((size) - 1)))
#define ALIGNMENT(n) __attribute__((aligned(n)))

/* old GCC version doesn't cope with the shuffle parameters, that can take 2 values (0xff and 0xaa)
 * in our case, passed as argument despite being a immediate 8 bits constant anyway.
 * un-factorise aes_128_key_expansion into 2 version that have the shuffle parameter explicitly set */
TARGET_AESNI
static __m128i aes_128_key_expansion_ff(__m128i key, __m128i keygened)
{
	keygened = _mm_shuffle_epi32(keygened, 0xff);
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}

/*
 * SubWord(RotWord(w)), which is the one part of a key schedule that would
 * otherwise want the S-box out of a table.  AESKEYGENASSIST computes it for
 * the words in lanes 1 and 3 and exclusive-ors the round constant into the
 * result; the constant is an immediate, so it is left at zero here and
 * applied by the caller, which keeps the 192-bit schedule a loop.
 */
TARGET_AESNI
static uint32_t key_sub_rot(uint32_t w)
{
	const __m128i t =
	    _mm_aeskeygenassist_si128(_mm_setr_epi32(0, (int) w, 0, 0), 0x00);

	return (uint32_t) _mm_cvtsi128_si32(_mm_srli_si128(t, 4));
}

TARGET_AESNI
static __m128i aes_128_key_expansion_aa(__m128i key, __m128i keygened)
{
	keygened = _mm_shuffle_epi32(keygened, 0xaa);
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}

TARGET_AESNI
void crypton_aesni_init(aes_key *key, uint8_t *ikey, uint8_t size)
{
	__m128i k[28];
	uint64_t *out = (uint64_t *) key->data;
	int i;

	switch (size) {
	case 16:
		k[0] = _mm_loadu_si128((const __m128i*) ikey);

		#define AES_128_key_exp(K, RCON) aes_128_key_expansion_ff(K, _mm_aeskeygenassist_si128(K, RCON))
		k[1]  = AES_128_key_exp(k[0], 0x01);
		k[2]  = AES_128_key_exp(k[1], 0x02);
		k[3]  = AES_128_key_exp(k[2], 0x04);
		k[4]  = AES_128_key_exp(k[3], 0x08);
		k[5]  = AES_128_key_exp(k[4], 0x10);
		k[6]  = AES_128_key_exp(k[5], 0x20);
		k[7]  = AES_128_key_exp(k[6], 0x40);
		k[8]  = AES_128_key_exp(k[7], 0x80);
		k[9]  = AES_128_key_exp(k[8], 0x1B);
		k[10] = AES_128_key_exp(k[9], 0x36);

		/* generate decryption keys in reverse order.
		 * k[10] is shared by last encryption and first decryption rounds
		 * k[20] is shared by first encryption round (and is the original user key) */
		k[11] = _mm_aesimc_si128(k[9]);
		k[12] = _mm_aesimc_si128(k[8]);
		k[13] = _mm_aesimc_si128(k[7]);
		k[14] = _mm_aesimc_si128(k[6]);
		k[15] = _mm_aesimc_si128(k[5]);
		k[16] = _mm_aesimc_si128(k[4]);
		k[17] = _mm_aesimc_si128(k[3]);
		k[18] = _mm_aesimc_si128(k[2]);
		k[19] = _mm_aesimc_si128(k[1]);

		for (i = 0; i < 20; i++)
			_mm_storeu_si128(((__m128i *) out) + i, k[i]);
		break;
	case 24: {
		/*
		 * The 192-bit schedule takes six words at a time where a round
		 * key is four, so it does not fall into 128-bit pieces the way
		 * the other two do; it is built a word at a time instead.
		 * Thirteen round keys, then the eleven inverted ones.
		 */
		static const uint32_t rcon[8] = {
			0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
		};
		uint32_t w[52];

		memcpy(w, ikey, 24);
		for (i = 6; i < 52; i++) {
			uint32_t t = w[i - 1];

			if (i % 6 == 0)
				t = key_sub_rot(t) ^ rcon[i / 6 - 1];
			w[i] = w[i - 6] ^ t;
		}
		memcpy(out, w, sizeof(w));

		for (i = 1; i < 12; i++)
			_mm_storeu_si128(((__m128i *) out) + 12 + i,
			    _mm_aesimc_si128(_mm_loadu_si128(
			        ((const __m128i *) w) + (12 - i))));
		break;
	}
	case 32:
#define AES_256_key_exp_1(K1, K2, RCON) aes_128_key_expansion_ff(K1, _mm_aeskeygenassist_si128(K2, RCON))
#define AES_256_key_exp_2(K1, K2)       aes_128_key_expansion_aa(K1, _mm_aeskeygenassist_si128(K2, 0x00))
		k[0]  = _mm_loadu_si128((const __m128i*) ikey);
		k[1]  = _mm_loadu_si128((const __m128i*) (ikey+16));
		k[2]  = AES_256_key_exp_1(k[0], k[1], 0x01);
		k[3]  = AES_256_key_exp_2(k[1], k[2]);
		k[4]  = AES_256_key_exp_1(k[2], k[3], 0x02);
		k[5]  = AES_256_key_exp_2(k[3], k[4]);
		k[6]  = AES_256_key_exp_1(k[4], k[5], 0x04);
		k[7]  = AES_256_key_exp_2(k[5], k[6]);
		k[8]  = AES_256_key_exp_1(k[6], k[7], 0x08);
		k[9]  = AES_256_key_exp_2(k[7], k[8]);
		k[10] = AES_256_key_exp_1(k[8], k[9], 0x10);
		k[11] = AES_256_key_exp_2(k[9], k[10]);
		k[12] = AES_256_key_exp_1(k[10], k[11], 0x20);
		k[13] = AES_256_key_exp_2(k[11], k[12]);
		k[14] = AES_256_key_exp_1(k[12], k[13], 0x40);

		k[15] = _mm_aesimc_si128(k[13]);
		k[16] = _mm_aesimc_si128(k[12]);
		k[17] = _mm_aesimc_si128(k[11]);
		k[18] = _mm_aesimc_si128(k[10]);
		k[19] = _mm_aesimc_si128(k[9]);
		k[20] = _mm_aesimc_si128(k[8]);
		k[21] = _mm_aesimc_si128(k[7]);
		k[22] = _mm_aesimc_si128(k[6]);
		k[23] = _mm_aesimc_si128(k[5]);
		k[24] = _mm_aesimc_si128(k[4]);
		k[25] = _mm_aesimc_si128(k[3]);
		k[26] = _mm_aesimc_si128(k[2]);
		k[27] = _mm_aesimc_si128(k[1]);
		for (i = 0; i < 28; i++)
			_mm_storeu_si128(((__m128i *) out) + i, k[i]);
		break;
	default:
		break;
	}
}

/* TO OPTIMISE: use pcmulqdq... or some faster code.
 * this is the lamest way of doing it, but i'm out of time.
 * this is basically a copy of gf_mulx in gf.c */
TARGET_AESNI
static __m128i gfmulx(__m128i v)
{
	uint64_t v_[2] ALIGNMENT(16);
	const uint64_t gf_mask = 0x8000000000000000;

	_mm_store_si128((__m128i *) v_, v);
	uint64_t r = ((v_[1] & gf_mask) ? 0x87 : 0);
	v_[1] = (v_[1] << 1) | (v_[0] & gf_mask ? 1 : 0);
	v_[0] = (v_[0] << 1) ^ r;
	v = _mm_load_si128((__m128i *) v_);
	return v;
}

TARGET_AESNI
static __m128i gfmul_generic(__m128i tag, const table_4bit htable)
{
	aes_block _t ALIGNMENT(16);
	_mm_store_si128((__m128i *) &_t, tag);
	crypton_aes_generic_gf_mul(&_t, htable);
	tag = _mm_load_si128((__m128i *) &_t);
	return tag;
}

/* Four or eight GHASH steps.  The table-driven multiply gains nothing from
 * seeing them together; the PCLMUL versions below fold them into one
 * reduction. */
TARGET_AESNI
static __m128i gfmul4_generic(__m128i tag, const table_4bit htable, const __m128i *m)
{
	int i;

	for (i = 0; i < 4; i++)
		tag = gfmul_generic(_mm_xor_si128(tag, m[i]), htable);
	return tag;
}

TARGET_AESNI
static __m128i gfmul8_generic(__m128i tag, const table_4bit htable, const __m128i *m)
{
	int i;

	for (i = 0; i < 8; i++)
		tag = gfmul_generic(_mm_xor_si128(tag, m[i]), htable);
	return tag;
}

#ifdef WITH_PCLMUL

__m128i (*crypton_gfmul_branch_ptr)(__m128i a, const table_4bit t) = gfmul_generic;
#define gfmul(a,t) ((*crypton_gfmul_branch_ptr)(a,t))

__m128i (*crypton_gfmul4_branch_ptr)(__m128i a, const table_4bit t, const __m128i *m) = gfmul4_generic;
#define gfmul4(a,t,m) ((*crypton_gfmul4_branch_ptr)(a,t,m))

__m128i (*crypton_gfmul8_branch_ptr)(__m128i a, const table_4bit t, const __m128i *m) = gfmul8_generic;
#define gfmul8(a,t,m) ((*crypton_gfmul8_branch_ptr)(a,t,m))

/* See Intel carry-less-multiplication-instruction-in-gcm-mode-paper.pdf
 *
 * Adapted from figure 5, with additional byte swapping so that interface
 * is simimar to crypton_aes_generic_gf_mul.
 */
/*
 * The 256-bit carry-less product, before the reflection fixup and the
 * reduction.  Split out from the reduction because both of those are linear
 * over XOR: several products can be added together and fixed up just once,
 * which is what gf_mul4 below does.
 */
TARGET_AESNI_PCLMUL
static inline void clmul_pclmuldq(__m128i a, __m128i b, __m128i *lo, __m128i *hi)
{
	__m128i tmp3, tmp4, tmp5, tmp6;
	__m128i bswap_mask = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);

	a = _mm_shuffle_epi8(a, bswap_mask);

	/*
	 * Karatsuba: the middle term of the product is
	 * (a0^a1)(b0^b1) ^ a0b0 ^ a1b1, which is one carry-less multiply
	 * where the direct form needs two.  Three PCLMULQDQ rather than
	 * four, at the cost of a few shuffles and exclusive ors -- worth it
	 * wherever the multiply is the narrower port, which is every part
	 * this has been measured on.
	 */
	tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
	tmp6 = _mm_clmulepi64_si128(a, b, 0x11);
	tmp4 = _mm_clmulepi64_si128(_mm_xor_si128(a, _mm_shuffle_epi32(a, 0x4e)),
	                            _mm_xor_si128(b, _mm_shuffle_epi32(b, 0x4e)),
	                            0x00);
	tmp4 = _mm_xor_si128(tmp4, _mm_xor_si128(tmp3, tmp6));

	tmp5 = _mm_slli_si128(tmp4, 8);
	tmp4 = _mm_srli_si128(tmp4, 8);

	*lo = _mm_xor_si128(tmp3, tmp5);
	*hi = _mm_xor_si128(tmp6, tmp4);
}

/* Shift the 256-bit product left by one to undo GCM's bit reflection, then
 * reduce modulo the GCM polynomial.  This is the expensive half. */
TARGET_AESNI_PCLMUL
static inline __m128i gfred_pclmuldq(__m128i tmp3, __m128i tmp6)
{
	__m128i tmp2, tmp4, tmp5, tmp7, tmp8, tmp9;
	__m128i bswap_mask = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);

	tmp7 = _mm_srli_epi32(tmp3, 31);
	tmp8 = _mm_srli_epi32(tmp6, 31);
	tmp3 = _mm_slli_epi32(tmp3, 1);
	tmp6 = _mm_slli_epi32(tmp6, 1);

	tmp9 = _mm_srli_si128(tmp7, 12);
	tmp8 = _mm_slli_si128(tmp8, 4);
	tmp7 = _mm_slli_si128(tmp7, 4);
	tmp3 = _mm_or_si128(tmp3, tmp7);
	tmp6 = _mm_or_si128(tmp6, tmp8);
	tmp6 = _mm_or_si128(tmp6, tmp9);

	tmp7 = _mm_slli_epi32(tmp3, 31);
	tmp8 = _mm_slli_epi32(tmp3, 30);
	tmp9 = _mm_slli_epi32(tmp3, 25);

	tmp7 = _mm_xor_si128(tmp7, tmp8);
	tmp7 = _mm_xor_si128(tmp7, tmp9);
	tmp8 = _mm_srli_si128(tmp7, 4);
	tmp7 = _mm_slli_si128(tmp7, 12);
	tmp3 = _mm_xor_si128(tmp3, tmp7);

	tmp2 = _mm_srli_epi32(tmp3, 1);
	tmp4 = _mm_srli_epi32(tmp3, 2);
	tmp5 = _mm_srli_epi32(tmp3, 7);
	tmp2 = _mm_xor_si128(tmp2, tmp4);
	tmp2 = _mm_xor_si128(tmp2, tmp5);
	tmp2 = _mm_xor_si128(tmp2, tmp8);
	tmp3 = _mm_xor_si128(tmp3, tmp2);
	tmp6 = _mm_xor_si128(tmp6, tmp3);

	return _mm_shuffle_epi8(tmp6, bswap_mask);
}

TARGET_AESNI_PCLMUL
static __m128i gfmul_pclmuldq(__m128i a, const table_4bit htable)
{
	__m128i lo, hi;

	clmul_pclmuldq(a, _mm_loadu_si128((__m128i *) htable), &lo, &hi);
	return gfred_pclmuldq(lo, hi);
}

TARGET_AESNI_PCLMUL
void crypton_aesni_hinit_pclmul(table_4bit htable, const block128 *h)
{
	__m128i bswap_mask = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
	__m128i p;
	int i;

	/* When pclmul is active we don't need to fill the table.  Instead we just
	 * store H at index 0.  It is written in reverse order, so function
	 * gfmul_pclmuldq will not byte-swap this value.
	 */
	htable[0].q[0] = bitfn_swap64(h->q[1]);
	htable[0].q[1] = bitfn_swap64(h->q[0]);

	/* Indices 1..15 get H^2 .. H^16, which is what lets a group of blocks
	 * fold into one reduction: gf_mul4 uses the first four, the 128-bit
	 * GCM loop eight, and the 256-bit one all sixteen.  The table has
	 * sixteen slots and now they are all used.  Filling the upper half
	 * costs eight multiplies once per key, which is nothing beside a
	 * message. */
	p = _mm_loadu_si128((const __m128i *) h);
	for (i = 1; i < 16; i++) {
		p = gfmul_pclmuldq(p, htable);
		_mm_storeu_si128((__m128i *) &htable[i],
		                 _mm_shuffle_epi8(p, bswap_mask));
	}
}

TARGET_AESNI_PCLMUL
void crypton_aesni_gf_mul_pclmul(block128 *a, const table_4bit htable)
{
	__m128i _a, _b;
	_a = _mm_loadu_si128((__m128i *) a);
	_b = gfmul_pclmuldq(_a, htable);
	_mm_storeu_si128((__m128i *) a, _b);
}

/*
 * Four GHASH steps -- ((((a^b0)H ^ b1)H ^ b2)H ^ b3)H -- with a single
 * reduction.  Expanded that is (a^b0)H^4 ^ b1*H^3 ^ b2*H^2 ^ b3*H, so the
 * four products can be summed first and reduced once, which is where the
 * time goes.  Aggregated reduction, from the Intel GCM paper.
 */
TARGET_AESNI_PCLMUL
static __m128i gfmul4_pclmul(__m128i tag, const table_4bit htable, const __m128i *m)
{
	__m128i lo, hi, l, h;
	int i;

	clmul_pclmuldq(_mm_xor_si128(tag, m[0]),
	               _mm_loadu_si128((const __m128i *) &htable[3]), &lo, &hi);

	for (i = 1; i < 4; i++) {
		clmul_pclmuldq(m[i], _mm_loadu_si128((const __m128i *) &htable[3 - i]),
		               &l, &h);
		lo = _mm_xor_si128(lo, l);
		hi = _mm_xor_si128(hi, h);
	}

	return gfred_pclmuldq(lo, hi);
}

TARGET_AESNI_PCLMUL
static __m128i gfmul8_pclmul(__m128i tag, const table_4bit htable, const __m128i *m)
{
	__m128i lo, hi, l, h;
	int i;

	clmul_pclmuldq(_mm_xor_si128(tag, m[0]),
	               _mm_loadu_si128((const __m128i *) &htable[7]), &lo, &hi);

	for (i = 1; i < 8; i++) {
		clmul_pclmuldq(m[i], _mm_loadu_si128((const __m128i *) &htable[7 - i]),
		               &l, &h);
		lo = _mm_xor_si128(lo, l);
		hi = _mm_xor_si128(hi, h);
	}

	return gfred_pclmuldq(lo, hi);
}

TARGET_AESNI_PCLMUL
void crypton_aesni_gf_mul4_pclmul(block128 *a, const block128 *blocks, const table_4bit htable)
{
	__m128i m[4];
	int i;

	for (i = 0; i < 4; i++)
		m[i] = _mm_loadu_si128((const __m128i *) &blocks[i]);

	_mm_storeu_si128((__m128i *) a,
	                 gfmul4_pclmul(_mm_loadu_si128((const __m128i *) a), htable, m));
}

void crypton_aesni_init_pclmul(void)
{
	crypton_gfmul_branch_ptr = gfmul_pclmuldq;
	crypton_gfmul4_branch_ptr = gfmul4_pclmul;
	crypton_gfmul8_branch_ptr = gfmul8_pclmul;
}

#else
#define gfmul(a,t) (gfmul_generic(a,t))
#define gfmul4(a,t,m) (gfmul4_generic(a,t,m))
#define gfmul8(a,t,m) (gfmul8_generic(a,t,m))
#endif

TARGET_AESNI
static inline __m128i ghash_add(__m128i tag, const table_4bit htable, __m128i m)
{
	tag = _mm_xor_si128(tag, m);
	return gfmul(tag, htable);
}

TARGET_AESNI
static inline __m128i ghash_add4(__m128i tag, const table_4bit htable, const __m128i *m)
{
	return gfmul4(tag, htable, m);
}

TARGET_AESNI
static inline __m128i ghash_add8(__m128i tag, const table_4bit htable, const __m128i *m)
{
	return gfmul8(tag, htable, m);
}

/*
 * Eight blocks through the rounds with the round keys read from memory rather
 * than held in registers.
 *
 * There are sixteen vector registers.  Eight blocks and eleven to fifteen
 * round keys do not fit in them, and when the GCM loop preloaded the keys the
 * compiler spilled: ninety-six stack accesses around a hundred AESENCs, which
 * cost more than half the loop's throughput.  AESENC takes a memory operand,
 * and the round keys are in L1 from one group to the next, so reading them
 * each round costs nothing and leaves the registers for the blocks.
 */
/*
 * Eight blocks through the rounds with the round keys read from memory rather
 * than held in registers.
 *
 * There are sixteen vector registers.  Eight blocks and eleven to fifteen
 * round keys do not fit in them, and when the GCM loop preloaded the keys the
 * compiler spilled: ninety-six stack accesses around a hundred AESENCs.
 * AESENC takes a memory operand and the round keys stay in L1 from one group
 * to the next, so reading them costs nothing and leaves the registers for the
 * blocks.
 *
 * The rounds are written out rather than looped: the loop cost a fifth of the
 * throughput, which is what -funroll-loops was recovering.
 */
#define K_(r) _mm_loadu_si128(k_ + (r))

/* the rounds beyond the tenth, which only a longer key has */
#define ROUNDS8_EXTRA_128
#define ROUNDS8_EXTRA_192 AESENC8(K_(10)) AESENC8(K_(11))
#define ROUNDS8_EXTRA_256 \
	AESENC8(K_(10)) AESENC8(K_(11)) AESENC8(K_(12)) AESENC8(K_(13))

#define DO_ENC_BLOCK8_MEM(m, k, nbr, EXTRA)                                  \
	do {                                                                 \
		const __m128i *k_ = (const __m128i *) (k);                   \
		XOR8(K_(0))                                                  \
		AESENC8(K_(1)) AESENC8(K_(2)) AESENC8(K_(3))                 \
		AESENC8(K_(4)) AESENC8(K_(5)) AESENC8(K_(6))                 \
		AESENC8(K_(7)) AESENC8(K_(8)) AESENC8(K_(9))                 \
		EXTRA                                                        \
		AESENCLAST8(K_(nbr))                                         \
	} while (0)

#define DO_ENC_BLOCK_MEM(m, k, nbr)                                          \
	do {                                                                 \
		const __m128i *k_ = (const __m128i *) (k);                   \
		int r_;                                                      \
		m = _mm_xor_si128(m, K_(0));                                 \
		for (r_ = 1; r_ < (nbr); r_++)                               \
			m = _mm_aesenc_si128(m, K_(r_));                     \
		m = _mm_aesenclast_si128(m, K_(nbr));                        \
	} while (0)

/*
 * GCM's GHASH, called directly rather than through the branch pointer the
 * other callers use: the pointer is a call the compiler cannot see through,
 * and these want to be scheduled against the rounds around them.  The cost is
 * that the GCM loops are compiled with the instruction and so may only be
 * installed where the processor has it, which crypton_aes.c sees to, as it
 * already does for the AArch64 ones.
 */
#ifdef WITH_PCLMUL

#define GCM_TARGET TARGET_AESNI_PCLMUL

TARGET_AESNI_PCLMUL
static inline __m128i gcm_ghash_add(__m128i tag, const table_4bit htable, __m128i m)
{
	return gfmul_pclmuldq(_mm_xor_si128(tag, m), htable);
}

TARGET_AESNI_PCLMUL
static inline __m128i gcm_ghash_add8(__m128i tag, const table_4bit htable, const __m128i *m)
{
	return gfmul8_pclmul(tag, htable, m);
}

/*
 * One block's carry-less multiply, accumulated rather than reduced, so that
 * the eight of a group can be spread between the rounds of the next group's
 * AES.
 */
TARGET_AESNI_PCLMUL
static inline void ghash_fold(__m128i *lo, __m128i *hi, __m128i b,
                              const table_4bit htable, int i)
{
	__m128i l, h;

	clmul_pclmuldq(b, _mm_loadu_si128((const __m128i *) &htable[i]), &l, &h);
	*lo = _mm_xor_si128(*lo, l);
	*hi = _mm_xor_si128(*hi, h);
}

#else

#define GCM_TARGET TARGET_AESNI
#define gcm_ghash_add(t, h, m)  ghash_add((t), (h), (m))
#define gcm_ghash_add8(t, h, m) ghash_add8((t), (h), (m))

#endif

/*
 * A group of eight encrypted, with the previous group's GHASH folded in
 * between the rounds where the build has the carry-less multiply: GH(j) after
 * round j + 1, and the reduction after round nine, which every key size
 * reaches.  The names are the ones the GCM loops use.
 */
#ifdef WITH_PCLMUL

#define GCM_GH(j)                                                            \
	ghash_fold(&glo_, &ghi_,                                             \
	           (j) == 0 ? _mm_xor_si128(tag, pending[0]) : pending[j],   \
	           gcm->htable, 7 - (j));

#define GCM_GHRED tag = gfred_pclmuldq(glo_, ghi_);

#define GCM_GROUP8(m, k, nbr, EXTRA)                                         \
	do {                                                                 \
		const __m128i *k_ = (const __m128i *) (k);                   \
		__m128i glo_ = _mm_setzero_si128();                          \
		__m128i ghi_ = _mm_setzero_si128();                          \
		XOR8(K_(0))                                                  \
		AESENC8(K_(1)) GCM_GH(0)                                     \
		AESENC8(K_(2)) GCM_GH(1)                                     \
		AESENC8(K_(3)) GCM_GH(2)                                     \
		AESENC8(K_(4)) GCM_GH(3)                                     \
		AESENC8(K_(5)) GCM_GH(4)                                     \
		AESENC8(K_(6)) GCM_GH(5)                                     \
		AESENC8(K_(7)) GCM_GH(6)                                     \
		AESENC8(K_(8)) GCM_GH(7)                                     \
		AESENC8(K_(9)) GCM_GHRED                                     \
		EXTRA                                                        \
		AESENCLAST8(K_(nbr))                                         \
	} while (0)

#else

#define GCM_GROUP8(m, k, nbr, EXTRA)                                         \
	do {                                                                 \
		DO_ENC_BLOCK8_MEM(m, k, nbr, EXTRA);                         \
		tag = ghash_add8(tag, gcm->htable, pending);                 \
	} while (0)

#endif

#define PRELOAD_ENC_KEYS128(k) \
	__m128i K0  = _mm_loadu_si128(((__m128i *) k)+0); \
	__m128i K1  = _mm_loadu_si128(((__m128i *) k)+1); \
	__m128i K2  = _mm_loadu_si128(((__m128i *) k)+2); \
	__m128i K3  = _mm_loadu_si128(((__m128i *) k)+3); \
	__m128i K4  = _mm_loadu_si128(((__m128i *) k)+4); \
	__m128i K5  = _mm_loadu_si128(((__m128i *) k)+5); \
	__m128i K6  = _mm_loadu_si128(((__m128i *) k)+6); \
	__m128i K7  = _mm_loadu_si128(((__m128i *) k)+7); \
	__m128i K8  = _mm_loadu_si128(((__m128i *) k)+8); \
	__m128i K9  = _mm_loadu_si128(((__m128i *) k)+9); \
	__m128i K10 = _mm_loadu_si128(((__m128i *) k)+10);

#define PRELOAD_ENC_KEYS192(k) \
	PRELOAD_ENC_KEYS128(k) \
	__m128i K11 = _mm_loadu_si128(((__m128i *) k)+11); \
	__m128i K12 = _mm_loadu_si128(((__m128i *) k)+12);

#define PRELOAD_ENC_KEYS256(k) \
	PRELOAD_ENC_KEYS128(k) \
	__m128i K11 = _mm_loadu_si128(((__m128i *) k)+11); \
	__m128i K12 = _mm_loadu_si128(((__m128i *) k)+12); \
	__m128i K13 = _mm_loadu_si128(((__m128i *) k)+13); \
	__m128i K14 = _mm_loadu_si128(((__m128i *) k)+14);

#define DO_ENC_BLOCK128(m) \
	m = _mm_xor_si128(m, K0); \
	m = _mm_aesenc_si128(m, K1); \
	m = _mm_aesenc_si128(m, K2); \
	m = _mm_aesenc_si128(m, K3); \
	m = _mm_aesenc_si128(m, K4); \
	m = _mm_aesenc_si128(m, K5); \
	m = _mm_aesenc_si128(m, K6); \
	m = _mm_aesenc_si128(m, K7); \
	m = _mm_aesenc_si128(m, K8); \
	m = _mm_aesenc_si128(m, K9); \
	m = _mm_aesenclast_si128(m, K10);

#define DO_ENC_BLOCK192(m) \
	m = _mm_xor_si128(m, K0); \
	m = _mm_aesenc_si128(m, K1); \
	m = _mm_aesenc_si128(m, K2); \
	m = _mm_aesenc_si128(m, K3); \
	m = _mm_aesenc_si128(m, K4); \
	m = _mm_aesenc_si128(m, K5); \
	m = _mm_aesenc_si128(m, K6); \
	m = _mm_aesenc_si128(m, K7); \
	m = _mm_aesenc_si128(m, K8); \
	m = _mm_aesenc_si128(m, K9); \
	m = _mm_aesenc_si128(m, K10); \
	m = _mm_aesenc_si128(m, K11); \
	m = _mm_aesenclast_si128(m, K12);

#define DO_ENC_BLOCK256(m) \
	m = _mm_xor_si128(m, K0); \
	m = _mm_aesenc_si128(m, K1); \
	m = _mm_aesenc_si128(m, K2); \
	m = _mm_aesenc_si128(m, K3); \
	m = _mm_aesenc_si128(m, K4); \
	m = _mm_aesenc_si128(m, K5); \
	m = _mm_aesenc_si128(m, K6); \
	m = _mm_aesenc_si128(m, K7); \
	m = _mm_aesenc_si128(m, K8); \
	m = _mm_aesenc_si128(m, K9); \
	m = _mm_aesenc_si128(m, K10); \
	m = _mm_aesenc_si128(m, K11); \
	m = _mm_aesenc_si128(m, K12); \
	m = _mm_aesenc_si128(m, K13); \
	m = _mm_aesenclast_si128(m, K14);

/* load K0 at K9 from index 'at' */
#define PRELOAD_DEC_KEYS_AT(k, at) \
	__m128i K0  = _mm_loadu_si128(((__m128i *) k)+at+0); \
	__m128i K1  = _mm_loadu_si128(((__m128i *) k)+at+1); \
	__m128i K2  = _mm_loadu_si128(((__m128i *) k)+at+2); \
	__m128i K3  = _mm_loadu_si128(((__m128i *) k)+at+3); \
	__m128i K4  = _mm_loadu_si128(((__m128i *) k)+at+4); \
	__m128i K5  = _mm_loadu_si128(((__m128i *) k)+at+5); \
	__m128i K6  = _mm_loadu_si128(((__m128i *) k)+at+6); \
	__m128i K7  = _mm_loadu_si128(((__m128i *) k)+at+7); \
	__m128i K8  = _mm_loadu_si128(((__m128i *) k)+at+8); \
	__m128i K9  = _mm_loadu_si128(((__m128i *) k)+at+9); \

/*
 * Eight blocks through the rounds together, which is what covers the
 * latency of AESENC.  Written out one line per block rather than left to a
 * loop over m[i]: a loop is only as good as the compiler's willingness to
 * unroll it, and when it declines the blocks go to the stack and each
 * round becomes a load and a store.
 */
#define XOR8(KK) \
	m[0] = _mm_xor_si128(m[0], KK); m[1] = _mm_xor_si128(m[1], KK); \
	m[2] = _mm_xor_si128(m[2], KK); m[3] = _mm_xor_si128(m[3], KK); \
	m[4] = _mm_xor_si128(m[4], KK); m[5] = _mm_xor_si128(m[5], KK); \
	m[6] = _mm_xor_si128(m[6], KK); m[7] = _mm_xor_si128(m[7], KK);

#define AESENC8(KK) \
	m[0] = _mm_aesenc_si128(m[0], KK); m[1] = _mm_aesenc_si128(m[1], KK); \
	m[2] = _mm_aesenc_si128(m[2], KK); m[3] = _mm_aesenc_si128(m[3], KK); \
	m[4] = _mm_aesenc_si128(m[4], KK); m[5] = _mm_aesenc_si128(m[5], KK); \
	m[6] = _mm_aesenc_si128(m[6], KK); m[7] = _mm_aesenc_si128(m[7], KK);

#define AESENCLAST8(KK) \
	m[0] = _mm_aesenclast_si128(m[0], KK); m[1] = _mm_aesenclast_si128(m[1], KK); \
	m[2] = _mm_aesenclast_si128(m[2], KK); m[3] = _mm_aesenclast_si128(m[3], KK); \
	m[4] = _mm_aesenclast_si128(m[4], KK); m[5] = _mm_aesenclast_si128(m[5], KK); \
	m[6] = _mm_aesenclast_si128(m[6], KK); m[7] = _mm_aesenclast_si128(m[7], KK);

#define DO_ENC_BLOCK8_128(m) \
	XOR8(K0) AESENC8(K1) AESENC8(K2) AESENC8(K3) AESENC8(K4) AESENC8(K5) \
	AESENC8(K6) AESENC8(K7) AESENC8(K8) AESENC8(K9) AESENCLAST8(K10)

#define DO_ENC_BLOCK8_192(m) \
	XOR8(K0) AESENC8(K1) AESENC8(K2) AESENC8(K3) AESENC8(K4) AESENC8(K5) \
	AESENC8(K6) AESENC8(K7) AESENC8(K8) AESENC8(K9) AESENC8(K10) \
	AESENC8(K11) AESENCLAST8(K12)

#define DO_ENC_BLOCK8_256(m) \
	XOR8(K0) AESENC8(K1) AESENC8(K2) AESENC8(K3) AESENC8(K4) AESENC8(K5) \
	AESENC8(K6) AESENC8(K7) AESENC8(K8) AESENC8(K9) AESENC8(K10) \
	AESENC8(K11) AESENC8(K12) AESENC8(K13) AESENCLAST8(K14)

#define PRELOAD_DEC_KEYS128(k) \
	PRELOAD_DEC_KEYS_AT(k, 10) \
	__m128i K10 = _mm_loadu_si128(((__m128i *) k)+0);

#define PRELOAD_DEC_KEYS192(k) \
	PRELOAD_DEC_KEYS_AT(k, 12) \
	__m128i K10 = _mm_loadu_si128(((__m128i *) k)+12+10); \
	__m128i K11 = _mm_loadu_si128(((__m128i *) k)+12+11); \
	__m128i K12 = _mm_loadu_si128(((__m128i *) k)+0);

#define PRELOAD_DEC_KEYS256(k) \
	PRELOAD_DEC_KEYS_AT(k, 14) \
	__m128i K10 = _mm_loadu_si128(((__m128i *) k)+14+10); \
	__m128i K11 = _mm_loadu_si128(((__m128i *) k)+14+11); \
	__m128i K12 = _mm_loadu_si128(((__m128i *) k)+14+12); \
	__m128i K13 = _mm_loadu_si128(((__m128i *) k)+14+13); \
	__m128i K14 = _mm_loadu_si128(((__m128i *) k)+0);

#define AESDEC8(KK) \
	m[0] = _mm_aesdec_si128(m[0], KK); m[1] = _mm_aesdec_si128(m[1], KK); \
	m[2] = _mm_aesdec_si128(m[2], KK); m[3] = _mm_aesdec_si128(m[3], KK); \
	m[4] = _mm_aesdec_si128(m[4], KK); m[5] = _mm_aesdec_si128(m[5], KK); \
	m[6] = _mm_aesdec_si128(m[6], KK); m[7] = _mm_aesdec_si128(m[7], KK);

#define AESDECLAST8(KK) \
	m[0] = _mm_aesdeclast_si128(m[0], KK); m[1] = _mm_aesdeclast_si128(m[1], KK); \
	m[2] = _mm_aesdeclast_si128(m[2], KK); m[3] = _mm_aesdeclast_si128(m[3], KK); \
	m[4] = _mm_aesdeclast_si128(m[4], KK); m[5] = _mm_aesdeclast_si128(m[5], KK); \
	m[6] = _mm_aesdeclast_si128(m[6], KK); m[7] = _mm_aesdeclast_si128(m[7], KK);

#define DO_DEC_BLOCK8_128(m) \
	XOR8(K0) AESDEC8(K1) AESDEC8(K2) AESDEC8(K3) AESDEC8(K4) AESDEC8(K5) \
	AESDEC8(K6) AESDEC8(K7) AESDEC8(K8) AESDEC8(K9) AESDECLAST8(K10)

#define DO_DEC_BLOCK8_192(m) \
	XOR8(K0) AESDEC8(K1) AESDEC8(K2) AESDEC8(K3) AESDEC8(K4) AESDEC8(K5) \
	AESDEC8(K6) AESDEC8(K7) AESDEC8(K8) AESDEC8(K9) AESDEC8(K10) \
	AESDEC8(K11) AESDECLAST8(K12)

#define DO_DEC_BLOCK8_256(m) \
	XOR8(K0) AESDEC8(K1) AESDEC8(K2) AESDEC8(K3) AESDEC8(K4) AESDEC8(K5) \
	AESDEC8(K6) AESDEC8(K7) AESDEC8(K8) AESDEC8(K9) AESDEC8(K10) \
	AESDEC8(K11) AESDEC8(K12) AESDEC8(K13) AESDECLAST8(K14)

/*
 * The XTS tweak advances by doubling in GF(2^128).  gfmulx above does that
 * through memory; this keeps it in a register, which matters once eight
 * tweaks are wanted per group.  The block is little-endian, so the low
 * 64-bit half is first.
 */
TARGET_AESNI
static inline __m128i gfmulx_sse(__m128i v)
{
	const __m128i poly = _mm_set_epi64x(0, 0x87);
	const __m128i carry = _mm_srli_epi64(v, 63);
	/* the low half's carry becomes the high half's bit 0 */
	const __m128i into_hi = _mm_slli_si128(carry, 8);
	/* and the high half's becomes all ones, or nothing, in the low half */
	const __m128i out = _mm_sub_epi64(_mm_setzero_si128(), _mm_srli_si128(carry, 8));

	return _mm_xor_si128(_mm_or_si128(_mm_slli_epi64(v, 1), into_hi),
	                     _mm_and_si128(out, poly));
}

/*
 * The tweak doubles in a pair of general-purpose registers and is moved
 * into a vector one per block.  The doubling is three integer operations,
 * and the integer units have nothing else to do here, where there are only
 * sixteen vector registers and the rounds want as many of them as they can
 * get: done in vector registers, which is what this did, the eight
 * doublings of a group both lengthen the critical path and push the round
 * keys out to memory.
 */
#define XTS_TWEAK_STEP(lo, hi) do {                                          \
	const uint64_t _c = (hi) >> 63;                                      \
	(hi) = ((hi) << 1) | ((lo) >> 63);                                   \
	(lo) = ((lo) << 1) ^ (_c ? 0x87 : 0);                                \
} while (0)

/* the eight tweaks a group needs, from the one it starts at */
#define XTS_TWEAKS8(dst, lo, hi) do {                                        \
	int _i;                                                              \
	for (_i = 0; _i < 8; _i++) {                                         \
		(dst)[_i] = _mm_set_epi64x((long long) (hi), (long long) (lo)); \
		XTS_TWEAK_STEP(lo, hi);                                      \
	}                                                                    \
} while (0)

#define DO_DEC_BLOCK128(m) \
	m = _mm_xor_si128(m, K0); \
	m = _mm_aesdec_si128(m, K1); \
	m = _mm_aesdec_si128(m, K2); \
	m = _mm_aesdec_si128(m, K3); \
	m = _mm_aesdec_si128(m, K4); \
	m = _mm_aesdec_si128(m, K5); \
	m = _mm_aesdec_si128(m, K6); \
	m = _mm_aesdec_si128(m, K7); \
	m = _mm_aesdec_si128(m, K8); \
	m = _mm_aesdec_si128(m, K9); \
	m = _mm_aesdeclast_si128(m, K10);

#define DO_DEC_BLOCK192(m) \
	m = _mm_xor_si128(m, K0); \
	m = _mm_aesdec_si128(m, K1); \
	m = _mm_aesdec_si128(m, K2); \
	m = _mm_aesdec_si128(m, K3); \
	m = _mm_aesdec_si128(m, K4); \
	m = _mm_aesdec_si128(m, K5); \
	m = _mm_aesdec_si128(m, K6); \
	m = _mm_aesdec_si128(m, K7); \
	m = _mm_aesdec_si128(m, K8); \
	m = _mm_aesdec_si128(m, K9); \
	m = _mm_aesdec_si128(m, K10); \
	m = _mm_aesdec_si128(m, K11); \
	m = _mm_aesdeclast_si128(m, K12);

#define DO_DEC_BLOCK256(m) \
	m = _mm_xor_si128(m, K0); \
	m = _mm_aesdec_si128(m, K1); \
	m = _mm_aesdec_si128(m, K2); \
	m = _mm_aesdec_si128(m, K3); \
	m = _mm_aesdec_si128(m, K4); \
	m = _mm_aesdec_si128(m, K5); \
	m = _mm_aesdec_si128(m, K6); \
	m = _mm_aesdec_si128(m, K7); \
	m = _mm_aesdec_si128(m, K8); \
	m = _mm_aesdec_si128(m, K9); \
	m = _mm_aesdec_si128(m, K10); \
	m = _mm_aesdec_si128(m, K11); \
	m = _mm_aesdec_si128(m, K12); \
	m = _mm_aesdec_si128(m, K13); \
	m = _mm_aesdeclast_si128(m, K14);

#define SIZE 128
#define NBR 10
#define ROUNDS8_EXTRA ROUNDS8_EXTRA_128
#define SIZED(m) m##128
#define PRELOAD_ENC PRELOAD_ENC_KEYS128
#define DO_ENC_BLOCK DO_ENC_BLOCK128
#define DO_ENC_BLOCK8 DO_ENC_BLOCK8_128
#define PRELOAD_DEC PRELOAD_DEC_KEYS128
#define DO_DEC_BLOCK DO_DEC_BLOCK128
#define DO_DEC_BLOCK8 DO_DEC_BLOCK8_128
#include <aes/x86ni_impl.c>

#undef SIZE
#undef NBR
#undef ROUNDS8_EXTRA
#undef SIZED
#undef PRELOAD_ENC
#undef PRELOAD_DEC
#undef DO_ENC_BLOCK
#undef DO_ENC_BLOCK8
#undef DO_DEC_BLOCK
#undef DO_DEC_BLOCK8

#define SIZED(m) m##192
#define SIZE 192
#define NBR 12
#define ROUNDS8_EXTRA ROUNDS8_EXTRA_192
#define PRELOAD_ENC PRELOAD_ENC_KEYS192
#define DO_ENC_BLOCK DO_ENC_BLOCK192
#define DO_ENC_BLOCK8 DO_ENC_BLOCK8_192
#define PRELOAD_DEC PRELOAD_DEC_KEYS192
#define DO_DEC_BLOCK DO_DEC_BLOCK192
#define DO_DEC_BLOCK8 DO_DEC_BLOCK8_192
#include <aes/x86ni_impl.c>

#undef SIZE
#undef NBR
#undef ROUNDS8_EXTRA
#undef SIZED
#undef PRELOAD_ENC
#undef PRELOAD_DEC
#undef DO_ENC_BLOCK
#undef DO_ENC_BLOCK8
#undef DO_DEC_BLOCK
#undef DO_DEC_BLOCK8

#define SIZED(m) m##256
#define SIZE 256
#define NBR 14
#define ROUNDS8_EXTRA ROUNDS8_EXTRA_256
#define PRELOAD_ENC PRELOAD_ENC_KEYS256
#define DO_ENC_BLOCK DO_ENC_BLOCK256
#define DO_ENC_BLOCK8 DO_ENC_BLOCK8_256
#define PRELOAD_DEC PRELOAD_DEC_KEYS256
#define DO_DEC_BLOCK DO_DEC_BLOCK256
#define DO_DEC_BLOCK8 DO_DEC_BLOCK8_256
#include <aes/x86ni_impl.c>

#undef SIZE
#undef NBR
#undef ROUNDS8_EXTRA
#undef SIZED
#undef PRELOAD_ENC
#undef PRELOAD_DEC
#undef DO_ENC_BLOCK
#undef DO_ENC_BLOCK8
#undef DO_DEC_BLOCK
#undef DO_DEC_BLOCK8

#endif

#endif
