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
#include <aes/block128.h>

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

	/* Indices 1..7 get H^2 .. H^8, which is what lets a group of blocks
	 * fold into one reduction: gf_mul4 uses the first four, the GCM loop
	 * all eight.  The table has sixteen slots. */
	p = _mm_loadu_si128((const __m128i *) h);
	for (i = 1; i < 8; i++) {
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

#define DO_ENC_BLOCK8_256(m) \
	XOR8(K0) AESENC8(K1) AESENC8(K2) AESENC8(K3) AESENC8(K4) AESENC8(K5) \
	AESENC8(K6) AESENC8(K7) AESENC8(K8) AESENC8(K9) AESENC8(K10) \
	AESENC8(K11) AESENC8(K12) AESENC8(K13) AESENCLAST8(K14)

#define PRELOAD_DEC_KEYS128(k) \
	PRELOAD_DEC_KEYS_AT(k, 10) \
	__m128i K10 = _mm_loadu_si128(((__m128i *) k)+0);

#define PRELOAD_DEC_KEYS256(k) \
	PRELOAD_DEC_KEYS_AT(k, 14) \
	__m128i K10 = _mm_loadu_si128(((__m128i *) k)+14+10); \
	__m128i K11 = _mm_loadu_si128(((__m128i *) k)+14+11); \
	__m128i K12 = _mm_loadu_si128(((__m128i *) k)+14+12); \
	__m128i K13 = _mm_loadu_si128(((__m128i *) k)+14+13); \
	__m128i K14 = _mm_loadu_si128(((__m128i *) k)+0);

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
#define SIZED(m) m##128
#define PRELOAD_ENC PRELOAD_ENC_KEYS128
#define DO_ENC_BLOCK DO_ENC_BLOCK128
#define DO_ENC_BLOCK8 DO_ENC_BLOCK8_128
#define PRELOAD_DEC PRELOAD_DEC_KEYS128
#define DO_DEC_BLOCK DO_DEC_BLOCK128
#include <aes/x86ni_impl.c>

#undef SIZE
#undef SIZED
#undef PRELOAD_ENC
#undef PRELOAD_DEC
#undef DO_ENC_BLOCK
#undef DO_ENC_BLOCK8
#undef DO_DEC_BLOCK

#define SIZED(m) m##256
#define SIZE 256
#define PRELOAD_ENC PRELOAD_ENC_KEYS256
#define DO_ENC_BLOCK DO_ENC_BLOCK256
#define DO_ENC_BLOCK8 DO_ENC_BLOCK8_256
#define PRELOAD_DEC PRELOAD_DEC_KEYS256
#define DO_DEC_BLOCK DO_DEC_BLOCK256
#include <aes/x86ni_impl.c>

#undef SIZE
#undef SIZED
#undef PRELOAD_ENC
#undef PRELOAD_DEC
#undef DO_ENC_BLOCK
#undef DO_ENC_BLOCK8
#undef DO_DEC_BLOCK

#endif

#endif
