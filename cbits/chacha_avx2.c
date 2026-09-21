/*
 * ChaCha with AVX2, eight blocks at a time.
 *
 * The same arrangement as the SSE and NEON versions, twice as wide: word i
 * of eight blocks goes in lane i of one 256-bit register.  Eight blocks is
 * where the register file stops being the constraint -- sixteen registers
 * hold the working state either way, so the wider ones are free.
 *
 * AVX2 is not part of any baseline, so this is reached only after
 * crypton_x86_simd_features() has said the CPU has it and the OS saves the
 * wider registers.  It is compiled into a translation unit that is
 * otherwise baseline, through a function attribute, so nothing here can be
 * emitted anywhere else.
 */

#include <stdint.h>
#include <immintrin.h>
#include "crypton_chacha.h"

#ifdef WITH_TARGET_ATTRIBUTES

#define TARGET __attribute__((target("avx2")))

/* rotating a 32-bit lane by sixteen or eight is a byte shuffle, which AVX2
 * does within each 128-bit half -- which is all this needs */
static const int8_t rot16_tbl[32] = {
	2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13,
	2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13,
};
static const int8_t rot8_tbl[32] = {
	3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14,
	3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14,
};

#define ROL(x, n)                                                            \
	((n) == 16 ? _mm256_shuffle_epi8((x), _mm256_loadu_si256((const __m256i *) rot16_tbl)) \
	 : (n) == 8 ? _mm256_shuffle_epi8((x), _mm256_loadu_si256((const __m256i *) rot8_tbl)) \
	 : _mm256_or_si256(_mm256_slli_epi32((x), (n)), _mm256_srli_epi32((x), 32 - (n))))

TARGET
static inline void core8(int rounds, const crypton_chacha_state *in,
                         const uint8_t *src, uint8_t *dst, int combine)
{
	__m256i v0, v1, v2, v3, v4, v5, v6, v7;
	__m256i v8, v9, v10, v11, v12, v13, v14, v15;
	const uint32_t c = in->d[12];
	const __m256i ctr = _mm256_setr_epi32((int) c, (int) (c + 1), (int) (c + 2),
	                                      (int) (c + 3), (int) (c + 4), (int) (c + 5),
	                                      (int) (c + 6), (int) (c + 7));
	int i;

#define SET(n) v##n = _mm256_set1_epi32((int) in->d[n])
	SET(0);  SET(1);  SET(2);  SET(3);
	SET(4);  SET(5);  SET(6);  SET(7);
	SET(8);  SET(9);  SET(10); SET(11);
	         SET(13); SET(14); SET(15);
#undef SET
	v12 = ctr;

#define QR(a, b, cc, d)                                                  \
	a = _mm256_add_epi32(a, b); d = ROL(_mm256_xor_si256(d, a), 16);  \
	cc = _mm256_add_epi32(cc, d); b = ROL(_mm256_xor_si256(b, cc), 12); \
	a = _mm256_add_epi32(a, b); d = ROL(_mm256_xor_si256(d, a),  8);  \
	cc = _mm256_add_epi32(cc, d); b = ROL(_mm256_xor_si256(b, cc),  7)

	for (i = rounds; i > 0; i -= 2) {
		QR(v0, v4, v8,  v12);
		QR(v1, v5, v9,  v13);
		QR(v2, v6, v10, v14);
		QR(v3, v7, v11, v15);

		QR(v0, v5, v10, v15);
		QR(v1, v6, v11, v12);
		QR(v2, v7, v8,  v13);
		QR(v3, v4, v9,  v14);
	}
#undef QR

#define ADD(n) v##n = _mm256_add_epi32(v##n, _mm256_set1_epi32((int) in->d[n]))
	ADD(0);  ADD(1);  ADD(2);  ADD(3);
	ADD(4);  ADD(5);  ADD(6);  ADD(7);
	ADD(8);  ADD(9);  ADD(10); ADD(11);
	         ADD(13); ADD(14); ADD(15);
#undef ADD
	v12 = _mm256_add_epi32(v12, ctr);

	/*
	 * The interleave works within each 128-bit half, so four registers
	 * holding word w of blocks 0..7 come apart into words w..w+3 of
	 * blocks 0..3 in the low halves and of blocks 4..7 in the high ones.
	 *
	 * Each piece is exclusive-ored with the input and stored where it
	 * belongs as it comes out.  Writing the keystream to a buffer and
	 * reading it back to combine it cost a pass over every byte, which is
	 * a tenth of what this loop does.
	 */
#define OUT(j, g, v)                                                         \
	do {                                                                 \
		__m128i o_ = (v);                                            \
		if (combine)                                                 \
			o_ = _mm_xor_si128(o_, _mm_loadu_si128(              \
			    (const __m128i *) (src + 64 * (j) + 4 * (g))));  \
		_mm_storeu_si128((__m128i *) (dst + 64 * (j) + 4 * (g)), o_);\
	} while (0)

#define GROUP(g, qa, qb, qc, qd)                                             \
	do {                                                                 \
		__m256i t0_ = _mm256_unpacklo_epi32(qa, qb);                 \
		__m256i t1_ = _mm256_unpackhi_epi32(qa, qb);                 \
		__m256i t2_ = _mm256_unpacklo_epi32(qc, qd);                 \
		__m256i t3_ = _mm256_unpackhi_epi32(qc, qd);                 \
		__m256i u0_ = _mm256_unpacklo_epi64(t0_, t2_);               \
		__m256i u1_ = _mm256_unpackhi_epi64(t0_, t2_);               \
		__m256i u2_ = _mm256_unpacklo_epi64(t1_, t3_);               \
		__m256i u3_ = _mm256_unpackhi_epi64(t1_, t3_);               \
		OUT(0, (g), _mm256_castsi256_si128(u0_));                    \
		OUT(1, (g), _mm256_castsi256_si128(u1_));                    \
		OUT(2, (g), _mm256_castsi256_si128(u2_));                    \
		OUT(3, (g), _mm256_castsi256_si128(u3_));                    \
		OUT(4, (g), _mm256_extracti128_si256(u0_, 1));               \
		OUT(5, (g), _mm256_extracti128_si256(u1_, 1));               \
		OUT(6, (g), _mm256_extracti128_si256(u2_, 1));               \
		OUT(7, (g), _mm256_extracti128_si256(u3_, 1));               \
	} while (0)
	GROUP(0,  v0,  v1,  v2,  v3);
	GROUP(4,  v4,  v5,  v6,  v7);
	GROUP(8,  v8,  v9,  v10, v11);
	GROUP(12, v12, v13, v14, v15);
#undef GROUP
#undef OUT
}

TARGET
void crypton_chacha_avx2_combine(int rounds, uint8_t *dst, const uint8_t *src,
                                 const crypton_chacha_state *in)
{
	core8(rounds, in, src, dst, 1);
}

TARGET
void crypton_chacha_avx2_generate(int rounds, uint8_t *dst, const crypton_chacha_state *in)
{
	core8(rounds, in, NULL, dst, 0);
}

#endif /* WITH_TARGET_ATTRIBUTES */
