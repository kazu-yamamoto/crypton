/*
 * AES-GCM through VAES and VPCLMULQDQ in their 512-bit form, which takes
 * four blocks where the 256-bit form in cbits/aes/gcm_vaes_x86.c takes two
 * and the 128-bit one takes one.  The instruction rate is the same, so the
 * work per group halves again.
 *
 * This is that file widened and nothing else: the same group of sixteen
 * blocks, the same descending powers of H sharing one reduction, the same
 * round keys read from memory rather than held in registers.  Four blocks to
 * a register means the group fills four of them rather than eight, which is
 * what leaves room for the group's own ciphertext to be kept for the GHASH
 * when encrypting.
 *
 * Nothing here is borrowed.  OpenSSL's and BoringSSL's AVX-512 AES-GCM is
 * Apache-2.0 and s2n-bignum has no GCM at all.
 *
 * The reduction at the end is a copy of the one in gcm_vaes_x86.c rather
 * than a call to it: the two files are compiled for different instruction
 * sets, and a function compiled for one cannot be inlined into the other.
 */
#include "aes/gcm_vaes512_x86.h"

#ifdef WITH_GCM_VAES512

#include <string.h>
#include <immintrin.h>

#include <aes/gf.h>
#include <aes/block128.h>

#if defined(__clang__) || defined(__GNUC__)
#define V512_TARGET \
	__attribute__((target("avx512f,avx512bw,avx512vl,aes,pclmul,vaes,vpclmulqdq")))
#else
#define V512_TARGET
#endif

/*
 * Thirty-two blocks to a group, four to a register, so eight registers are
 * in flight.  The number of registers is what matters as much as the blocks
 * per instruction: AES-NI has a latency of four cycles against a throughput
 * of one, so it takes eight independent chains to keep two ports busy.  Four
 * registers of four blocks was written first and measured *slower* than the
 * 256-bit path -- the blocks per instruction had doubled and the chains had
 * halved.
 *
 * The table holds sixteen powers of H, so the GHASH of a group is two passes
 * of sixteen blocks, the second picking up the tag the first leaves.
 */
#define V512WIDE 8
#define V512HALF 4
#define V512BYTES 512

/*
 * The 128-bit multiply of cbits/aes/x86ni.c, done in all four lanes at once.
 * Every shuffle and shift here works inside its own 128-bit lane, so the
 * four products never mix: what comes out is four independent carry-less
 * products, accumulated by the caller and reduced together at the end.
 */
V512_TARGET
static inline void clmul512(__m512i a, __m512i b, __m512i *lo, __m512i *hi)
{
	const __m512i bswap = _mm512_set4_epi32(
		0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
	__m512i t3, t4, t5, t6;

	a = _mm512_shuffle_epi8(a, bswap);

	/* Karatsuba, as in the 128-bit one: three multiplies, not four */
	t3 = _mm512_clmulepi64_epi128(a, b, 0x00);
	t6 = _mm512_clmulepi64_epi128(a, b, 0x11);
	t4 = _mm512_clmulepi64_epi128(
		_mm512_xor_si512(a, _mm512_shuffle_epi32(a, _MM_PERM_BADC)),
		_mm512_xor_si512(b, _mm512_shuffle_epi32(b, _MM_PERM_BADC)),
		0x00);
	t4 = _mm512_xor_si512(t4, _mm512_xor_si512(t3, t6));

	t5 = _mm512_bslli_epi128(t4, 8);
	t4 = _mm512_bsrli_epi128(t4, 8);

	*lo = _mm512_xor_si512(t3, t5);
	*hi = _mm512_xor_si512(t6, t4);
}

/*
 * The reduction of cbits/aes/x86ni.c.  By the time it runs the four lanes
 * have been folded into one, so there is one 256-bit product to reduce.
 */
V512_TARGET
static inline __m128i gfred512(__m128i t3, __m128i t6)
{
	const __m128i bswap = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
	__m128i t2, t4, t5, t7, t8, t9;

	t7 = _mm_srli_epi32(t3, 31);
	t8 = _mm_srli_epi32(t6, 31);
	t3 = _mm_slli_epi32(t3, 1);
	t6 = _mm_slli_epi32(t6, 1);

	t9 = _mm_srli_si128(t7, 12);
	t8 = _mm_slli_si128(t8, 4);
	t7 = _mm_slli_si128(t7, 4);
	t3 = _mm_or_si128(t3, t7);
	t6 = _mm_or_si128(t6, t8);
	t6 = _mm_or_si128(t6, t9);

	t7 = _mm_slli_epi32(t3, 31);
	t8 = _mm_slli_epi32(t3, 30);
	t9 = _mm_slli_epi32(t3, 25);

	t7 = _mm_xor_si128(t7, t8);
	t7 = _mm_xor_si128(t7, t9);
	t8 = _mm_srli_si128(t7, 4);
	t7 = _mm_slli_si128(t7, 12);
	t3 = _mm_xor_si128(t3, t7);

	t2 = _mm_srli_epi32(t3, 1);
	t4 = _mm_srli_epi32(t3, 2);
	t5 = _mm_srli_epi32(t3, 7);
	t2 = _mm_xor_si128(t2, t4);
	t2 = _mm_xor_si128(t2, t5);
	t2 = _mm_xor_si128(t2, t8);
	t3 = _mm_xor_si128(t3, t2);
	t6 = _mm_xor_si128(t6, t3);

	return _mm_shuffle_epi8(t6, bswap);
}

/* the four 128-bit lanes of a register added together */
V512_TARGET
static inline __m128i fold512(__m512i v)
{
	__m256i h = _mm256_xor_si256(_mm512_castsi512_si256(v),
	                             _mm512_extracti64x4_epi64(v, 1));

	return _mm_xor_si128(_mm256_castsi256_si128(h),
	                     _mm256_extracti128_si256(h, 1));
}

/*
 * Sixteen blocks against H^16 .. H^1, one reduction.  v[j] holds blocks 4j
 * to 4j+3 in its four lanes, so the powers for it are H^(16-4j) down to
 * H^(13-4j) -- the table's own order the other way round, hence the four
 * 128-bit loads rather than one 512-bit one.
 */
V512_TARGET
static inline __m128i ghash16(__m128i tag, const table_4bit htable,
                              const __m512i *v, int fromwire)
{
	__m512i lo = _mm512_setzero_si512(), hi = _mm512_setzero_si512();
	__m512i l, h, b;
	int j;

	for (j = 0; j < V512HALF; j++) {
		const __m128i p0 =
			_mm_loadu_si128((const __m128i *) &htable[15 - 4 * j]);
		const __m128i p1 =
			_mm_loadu_si128((const __m128i *) &htable[14 - 4 * j]);
		const __m128i p2 =
			_mm_loadu_si128((const __m128i *) &htable[13 - 4 * j]);
		const __m128i p3 =
			_mm_loadu_si128((const __m128i *) &htable[12 - 4 * j]);
		__m512i hp = _mm512_castsi128_si512(p0);

		hp = _mm512_inserti32x4(hp, p1, 1);
		hp = _mm512_inserti32x4(hp, p2, 2);
		hp = _mm512_inserti32x4(hp, p3, 3);

		b = fromwire ? _mm512_loadu_si512(v + j) : v[j];
		if (j == 0) /* the running tag joins the first block */
			b = _mm512_xor_si512(
				b, _mm512_inserti32x4(
					_mm512_setzero_si512(), tag, 0));
		clmul512(b, hp, &l, &h);
		lo = _mm512_xor_si512(lo, l);
		hi = _mm512_xor_si512(hi, h);
	}

	/* the four lanes are independent products of the same sum: fold them */
	return gfred512(fold512(lo), fold512(hi));
}

#define KK512(r) _mm512_broadcast_i32x4(_mm_loadu_si128(k_ + (r)))

#define AESENC32(K)                                                         \
	do {                                                                \
		const __m512i rk = (K);                                     \
		v[0] = _mm512_aesenc_epi128(v[0], rk);                      \
		v[1] = _mm512_aesenc_epi128(v[1], rk);                      \
		v[2] = _mm512_aesenc_epi128(v[2], rk);                      \
		v[3] = _mm512_aesenc_epi128(v[3], rk);                      \
		v[4] = _mm512_aesenc_epi128(v[4], rk);                      \
		v[5] = _mm512_aesenc_epi128(v[5], rk);                      \
		v[6] = _mm512_aesenc_epi128(v[6], rk);                      \
		v[7] = _mm512_aesenc_epi128(v[7], rk);                      \
	} while (0)

#define AESLAST32(K)                                                        \
	do {                                                                \
		const __m512i rk = (K);                                     \
		v[0] = _mm512_aesenclast_epi128(v[0], rk);                  \
		v[1] = _mm512_aesenclast_epi128(v[1], rk);                  \
		v[2] = _mm512_aesenclast_epi128(v[2], rk);                  \
		v[3] = _mm512_aesenclast_epi128(v[3], rk);                  \
		v[4] = _mm512_aesenclast_epi128(v[4], rk);                  \
		v[5] = _mm512_aesenclast_epi128(v[5], rk);                  \
		v[6] = _mm512_aesenclast_epi128(v[6], rk);                  \
		v[7] = _mm512_aesenclast_epi128(v[7], rk);                  \
	} while (0)

#define XOR32(K)                                                            \
	do {                                                                \
		const __m512i rk = (K);                                     \
		v[0] = _mm512_xor_si512(v[0], rk);                          \
		v[1] = _mm512_xor_si512(v[1], rk);                          \
		v[2] = _mm512_xor_si512(v[2], rk);                          \
		v[3] = _mm512_xor_si512(v[3], rk);                          \
		v[4] = _mm512_xor_si512(v[4], rk);                          \
		v[5] = _mm512_xor_si512(v[5], rk);                          \
		v[6] = _mm512_xor_si512(v[6], rk);                          \
		v[7] = _mm512_xor_si512(v[7], rk);                          \
	} while (0)

/*
 * The rounds are written out rather than looped for the reason the 128-bit
 * loop gives: the count is a value in the key, and a loop over it leaves the
 * round key reached through an index the compiler cannot fold.
 */
V512_TARGET
static inline __attribute__((always_inline)) void
rounds32(__m512i *v, const uint8_t *k, const int nbr)
{
	const __m128i *k_ = (const __m128i *) k;

	XOR32(KK512(0));
	AESENC32(KK512(1)); AESENC32(KK512(2)); AESENC32(KK512(3));
	AESENC32(KK512(4)); AESENC32(KK512(5)); AESENC32(KK512(6));
	AESENC32(KK512(7)); AESENC32(KK512(8)); AESENC32(KK512(9));
	if (nbr > 10) {
		AESENC32(KK512(10)); AESENC32(KK512(11));
		if (nbr > 12) {
			AESENC32(KK512(12)); AESENC32(KK512(13));
		}
	}
	AESLAST32(_mm512_broadcast_i32x4(_mm_loadu_si128(k_ + nbr)));
}

/* sixteen consecutive counters, four to a register.  GCM counts in the low
 * thirty-two bits and wraps there, which is what _mm_add_epi32 does. */
V512_TARGET
static inline __m128i counters32(__m512i *v, __m128i iv, __m128i one,
                                 __m128i bswap)
{
	int j;

	for (j = 0; j < V512WIDE; j++) {
		__m128i c0, c1, c2, c3;
		__m512i c;

		iv = _mm_add_epi32(iv, one);
		c0 = _mm_shuffle_epi8(iv, bswap);
		iv = _mm_add_epi32(iv, one);
		c1 = _mm_shuffle_epi8(iv, bswap);
		iv = _mm_add_epi32(iv, one);
		c2 = _mm_shuffle_epi8(iv, bswap);
		iv = _mm_add_epi32(iv, one);
		c3 = _mm_shuffle_epi8(iv, bswap);

		c = _mm512_castsi128_si512(c0);
		c = _mm512_inserti32x4(c, c1, 1);
		c = _mm512_inserti32x4(c, c2, 2);
		c = _mm512_inserti32x4(c, c3, 3);
		v[j] = c;
	}
	return iv;
}

/*
 * Inlined into three callers with the round count a constant in each, which
 * folds away the tests inside the group loop -- the same reason the 256-bit
 * file gives, where without it AES-256 lost what AES-128 gained.
 */
V512_TARGET
static inline __attribute__((always_inline)) uint32_t
bulk_n(uint8_t *output, aes_gcm *gcm, const aes_key *key,
       const uint8_t *input, uint32_t length, int decrypt, const int nbr)
{
	const __m128i bswap = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
	const __m128i one = _mm_set_epi32(0, 1, 0, 0);
	__m512i v[V512WIDE];
	__m128i iv, tag;
	uint32_t groups = length / V512BYTES;
	uint32_t done = 0;
	uint32_t g;
	int j;

	if (groups == 0)
		return 0;

	iv = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) &gcm->civ), bswap);
	tag = _mm_loadu_si128((const __m128i *) &gcm->tag);

	for (g = 0; g < groups; g++, input += V512BYTES, output += V512BYTES,
	     done += V512BYTES) {
		iv = counters32(v, iv, one, bswap);
		rounds32(v, key->data, nbr);

		for (j = 0; j < V512WIDE; j++) {
			const __m512i in =
				_mm512_loadu_si512((const __m512i *) (input + 64 * j));

			v[j] = _mm512_xor_si512(v[j], in);
			_mm512_storeu_si512((__m512i *) (output + 64 * j), v[j]);
		}
		/* sixteen blocks to a pass, since that is how many powers of
		 * H the table holds; the second picks up the tag the first
		 * leaves */
		tag = ghash16(tag, gcm->htable,
		              decrypt ? (const __m512i *) input : v,
		              decrypt);
		tag = ghash16(tag, gcm->htable,
		              decrypt ? (const __m512i *) (input + 256)
		                      : v + V512HALF,
		              decrypt);
	}

	_mm_storeu_si128((__m128i *) &gcm->civ, _mm_shuffle_epi8(iv, bswap));
	_mm_storeu_si128((__m128i *) &gcm->tag, tag);
	return done;
}

V512_TARGET
static uint32_t bulk(uint8_t *output, aes_gcm *gcm, const aes_key *key,
                     const uint8_t *input, uint32_t length, int decrypt)
{
	switch (key->nbr) {
	case 10:
		return bulk_n(output, gcm, key, input, length, decrypt, 10);
	case 12:
		return bulk_n(output, gcm, key, input, length, decrypt, 12);
	case 14:
		return bulk_n(output, gcm, key, input, length, decrypt, 14);
	default:
		return 0; /* not a key length AES has */
	}
}

uint32_t crypton_gcm_vaes512_bulk_encrypt(uint8_t *output, aes_gcm *gcm,
                                          const aes_key *key,
                                          const uint8_t *input,
                                          uint32_t length)
{
	return bulk(output, gcm, key, input, length, 0);
}

uint32_t crypton_gcm_vaes512_bulk_decrypt(uint8_t *output, aes_gcm *gcm,
                                          const aes_key *key,
                                          const uint8_t *input,
                                          uint32_t length)
{
	return bulk(output, gcm, key, input, length, 1);
}

#endif
