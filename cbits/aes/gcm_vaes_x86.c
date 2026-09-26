/*
 * AES-GCM through VAES and VPCLMULQDQ: the same AES and carry-less multiply
 * instructions the rest of this directory uses, in their 256-bit form, which
 * takes two blocks where the 128-bit form takes one.  The instruction rate is
 * the same, so the throughput is twice -- measured at 2.00 on an EPYC 9V74,
 * for both halves, with nothing else in the loop.
 *
 * Nothing here is borrowed.  OpenSSL's and BoringSSL's wide AES-GCM is
 * Apache-2.0, s2n-bignum has no GCM at all, and the CRYPTOGAMS assembly in
 * cbits/asm is 128-bit throughout -- its `vaesenc` is the VEX encoding of
 * AESENC on XMM, not the VAES extension.  So this is the 128-bit loop in
 * cbits/aes/x86ni_impl.c widened, and it keeps that loop's shape: a group of
 * counters through the rounds together, the round keys read from memory
 * rather than held in registers, and the group's GHASH folded against
 * descending powers of H so that sixteen blocks share one reduction.
 *
 * The powers come from the table crypton_aesni_hinit_pclmul fills.  It has
 * sixteen slots and the 128-bit loop uses eight of them; this uses all
 * sixteen, which is why that function now fills them.
 */
#include "aes/gcm_vaes_x86.h"

#ifdef WITH_GCM_VAES

#include <string.h>
#include <immintrin.h>

#include <aes/gf.h>
#include <aes/block128.h>

#if defined(__clang__) || defined(__GNUC__)
#define VAES_TARGET __attribute__((target("avx2,aes,pclmul,vaes,vpclmulqdq")))
#else
#define VAES_TARGET
#endif

/* sixteen blocks to a group, two to a register */
#define VWIDE 8

/*
 * The 128-bit multiply of cbits/aes/x86ni.c, done in both lanes at once.
 * Every shuffle and shift here works inside its own 128-bit half, so the two
 * products never mix: what comes out is two independent carry-less products,
 * accumulated by the caller and reduced together at the end.
 */
VAES_TARGET
static inline void clmul256(__m256i a, __m256i b, __m256i *lo, __m256i *hi)
{
	const __m256i bswap = _mm256_setr_epi8(
		15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,
		15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
	__m256i t3, t4, t5, t6;

	a = _mm256_shuffle_epi8(a, bswap);

	/* Karatsuba, as in the 128-bit one: three multiplies, not four */
	t3 = _mm256_clmulepi64_epi128(a, b, 0x00);
	t6 = _mm256_clmulepi64_epi128(a, b, 0x11);
	t4 = _mm256_clmulepi64_epi128(
		_mm256_xor_si256(a, _mm256_shuffle_epi32(a, 0x4e)),
		_mm256_xor_si256(b, _mm256_shuffle_epi32(b, 0x4e)), 0x00);
	t4 = _mm256_xor_si256(t4, _mm256_xor_si256(t3, t6));

	t5 = _mm256_slli_si256(t4, 8);
	t4 = _mm256_srli_si256(t4, 8);

	*lo = _mm256_xor_si256(t3, t5);
	*hi = _mm256_xor_si256(t6, t4);
}

/*
 * The reduction of cbits/aes/x86ni.c, unchanged: by the time it runs the two
 * lanes have been folded into one, so there is one 256-bit product to reduce
 * and no reason to do it twice.
 */
VAES_TARGET
static inline __m128i gfred(__m128i t3, __m128i t6)
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

/*
 * Sixteen blocks against H^16 .. H^1, one reduction.  v[j] holds blocks 2j
 * and 2j+1 in its low and high halves, so the powers for it are H^(16-2j)
 * low and H^(15-2j) high -- the table's own order the other way round, hence
 * the pair of 128-bit loads rather than one 256-bit one.
 */
VAES_TARGET
static inline __m128i ghash16(__m128i tag, const table_4bit htable,
                              const __m256i *v, int fromwire)
{
	__m256i lo = _mm256_setzero_si256(), hi = _mm256_setzero_si256();
	__m256i l, h, b;
	int j;

	for (j = 0; j < VWIDE; j++) {
		const __m256i hp = _mm256_set_m128i(
			_mm_loadu_si128((const __m128i *) &htable[14 - 2 * j]),
			_mm_loadu_si128((const __m128i *) &htable[15 - 2 * j]));

		b = fromwire ? _mm256_loadu_si256(v + j) : v[j];
		if (j == 0) /* the running tag joins the first block */
			b = _mm256_xor_si256(
				b, _mm256_inserti128_si256(
					_mm256_setzero_si256(), tag, 0));
		clmul256(b, hp, &l, &h);
		lo = _mm256_xor_si256(lo, l);
		hi = _mm256_xor_si256(hi, h);
	}

	/* the two lanes are independent products of the same sum: fold them */
	return gfred(_mm_xor_si128(_mm256_castsi256_si128(lo),
	                           _mm256_extracti128_si256(lo, 1)),
	             _mm_xor_si128(_mm256_castsi256_si128(hi),
	                           _mm256_extracti128_si256(hi, 1)));
}

#define KK(r) _mm256_broadcastsi128_si256(_mm_loadu_si128(k_ + (r)))

#define AESENC16(K)                                                          \
	do {                                                                 \
		const __m256i rk = (K);                                      \
		v[0] = _mm256_aesenc_epi128(v[0], rk);                       \
		v[1] = _mm256_aesenc_epi128(v[1], rk);                       \
		v[2] = _mm256_aesenc_epi128(v[2], rk);                       \
		v[3] = _mm256_aesenc_epi128(v[3], rk);                       \
		v[4] = _mm256_aesenc_epi128(v[4], rk);                       \
		v[5] = _mm256_aesenc_epi128(v[5], rk);                       \
		v[6] = _mm256_aesenc_epi128(v[6], rk);                       \
		v[7] = _mm256_aesenc_epi128(v[7], rk);                       \
	} while (0)

#define AESLAST16(K)                                                         \
	do {                                                                 \
		const __m256i rk = (K);                                      \
		v[0] = _mm256_aesenclast_epi128(v[0], rk);                   \
		v[1] = _mm256_aesenclast_epi128(v[1], rk);                   \
		v[2] = _mm256_aesenclast_epi128(v[2], rk);                   \
		v[3] = _mm256_aesenclast_epi128(v[3], rk);                   \
		v[4] = _mm256_aesenclast_epi128(v[4], rk);                   \
		v[5] = _mm256_aesenclast_epi128(v[5], rk);                   \
		v[6] = _mm256_aesenclast_epi128(v[6], rk);                   \
		v[7] = _mm256_aesenclast_epi128(v[7], rk);                   \
	} while (0)

#define XOR16(K)                                                             \
	do {                                                                 \
		const __m256i rk = (K);                                      \
		v[0] = _mm256_xor_si256(v[0], rk);                           \
		v[1] = _mm256_xor_si256(v[1], rk);                           \
		v[2] = _mm256_xor_si256(v[2], rk);                           \
		v[3] = _mm256_xor_si256(v[3], rk);                           \
		v[4] = _mm256_xor_si256(v[4], rk);                           \
		v[5] = _mm256_xor_si256(v[5], rk);                           \
		v[6] = _mm256_xor_si256(v[6], rk);                           \
		v[7] = _mm256_xor_si256(v[7], rk);                           \
	} while (0)

/*
 * The rounds are written out rather than looped for the reason the 128-bit
 * loop gives: the count is a value in the key, and a loop over it leaves the
 * round key reached through an index the compiler cannot fold.
 */
VAES_TARGET
static inline __attribute__((always_inline)) void
rounds16(__m256i *v, const uint8_t *k, const int nbr)
{
	const __m128i *k_ = (const __m128i *) k;

	XOR16(KK(0));
	AESENC16(KK(1)); AESENC16(KK(2)); AESENC16(KK(3));
	AESENC16(KK(4)); AESENC16(KK(5)); AESENC16(KK(6));
	AESENC16(KK(7)); AESENC16(KK(8)); AESENC16(KK(9));
	if (nbr > 10) {
		AESENC16(KK(10)); AESENC16(KK(11));
		if (nbr > 12) {
			AESENC16(KK(12)); AESENC16(KK(13));
		}
	}
	AESLAST16(_mm256_broadcastsi128_si256(_mm_loadu_si128(k_ + nbr)));
}

/* sixteen consecutive counters, two to a register.  GCM counts in the low
 * thirty-two bits and wraps there, which is what _mm_add_epi32 does. */
VAES_TARGET
static inline __m128i counters16(__m256i *v, __m128i iv, __m128i one,
                                 __m128i bswap)
{
	int j;

	for (j = 0; j < VWIDE; j++) {
		__m128i c0, c1;

		iv = _mm_add_epi32(iv, one);
		c0 = _mm_shuffle_epi8(iv, bswap);
		iv = _mm_add_epi32(iv, one);
		c1 = _mm_shuffle_epi8(iv, bswap);
		v[j] = _mm256_set_m128i(c1, c0);
	}
	return iv;
}

/*
 * The round count is a value in the key, and a test on it inside the group
 * loop is a branch the 128-bit path does not have: that one compiles a
 * separate function for each key length through the SIZED macro.  This does
 * the same thing by being inlined into three callers with the count a
 * constant in each, which folds the tests away.  Without it AES-256 lost
 * what AES-128 gained.
 */
VAES_TARGET
static inline __attribute__((always_inline)) uint32_t
bulk_n(uint8_t *output, aes_gcm *gcm, const aes_key *key,
       const uint8_t *input, uint32_t length, int decrypt, const int nbr)
{
	const __m128i bswap = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
	const __m128i one = _mm_set_epi32(0, 1, 0, 0);
	__m256i v[VWIDE];
	__m128i iv, tag;
	uint32_t groups = length / 256;
	uint32_t done = 0;
	uint32_t g;
	int j;

	if (groups == 0)
		return 0;

	iv = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) &gcm->civ), bswap);
	tag = _mm_loadu_si128((const __m128i *) &gcm->tag);

	for (g = 0; g < groups; g++, input += 256, output += 256, done += 256) {
		iv = counters16(v, iv, one, bswap);
		rounds16(v, key->data, nbr);

		/*
		 * The ciphertext is what the tag is taken over, and after
		 * this exclusive or it is in v itself when encrypting.  When
		 * decrypting it is the input, which the GHASH below reads
		 * again rather than keeping: there are sixteen vector
		 * registers, the group fills eight of them, and a second
		 * eight held aside is what makes the compiler spill.  The
		 * input is in L1 from the load a moment ago.
		 */
		for (j = 0; j < VWIDE; j++) {
			const __m256i in =
				_mm256_loadu_si256((const __m256i *) (input + 32 * j));

			v[j] = _mm256_xor_si256(v[j], in);
			_mm256_storeu_si256((__m256i *) (output + 32 * j), v[j]);
		}
		tag = ghash16(tag, gcm->htable,
		              decrypt ? (const __m256i *) input : v,
		              decrypt);
	}

	_mm_storeu_si128((__m128i *) &gcm->civ, _mm_shuffle_epi8(iv, bswap));
	_mm_storeu_si128((__m128i *) &gcm->tag, tag);
	return done;
}

VAES_TARGET
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

uint32_t crypton_gcm_vaes_bulk_encrypt(uint8_t *output, aes_gcm *gcm,
                                       const aes_key *key,
                                       const uint8_t *input, uint32_t length)
{
	return bulk(output, gcm, key, input, length, 0);
}

uint32_t crypton_gcm_vaes_bulk_decrypt(uint8_t *output, aes_gcm *gcm,
                                       const aes_key *key,
                                       const uint8_t *input, uint32_t length)
{
	return bulk(output, gcm, key, input, length, 1);
}

#endif
