/*
 * Poly1305 with AVX2, four blocks at a time.
 *
 * The scalar code carries the accumulator as five 26-bit limbs and, for each
 * block, adds the block and multiplies by r.  Four blocks at a time works the
 * same way with the limbs spread across four lanes: lane j carries the blocks
 * at positions congruent to j, every step multiplies all four by r^4, and at
 * the end the lanes are folded back together weighted by r^4, r^3, r^2 and r.
 *
 *     h = (h + m1) r^4 + m2 r^3 + m3 r^2 + m4 r
 *
 * which is the same value the scalar loop would have reached.
 *
 * AVX2 is not part of any baseline, so this is reached only after
 * crypton_x86_simd_features() has said the CPU has it and the OS saves the
 * wider registers.  It sits in a translation unit that is otherwise baseline,
 * through a function attribute.
 *
 * Nothing here calls _mm256_zeroupper().  The compiler emits VZEROUPPER at
 * the boundaries of a function it compiled for AVX, and an explicit one in
 * the middle of such a function is something it schedules around rather than
 * respects: with one before the scalar tail below, GCC at -O3 produced the
 * wrong tag, and at -O2 the right one.
 */

#include <stdint.h>
#include <string.h>
#include <immintrin.h>
#include "crypton_poly1305.h"

#ifdef WITH_TARGET_ATTRIBUTES

#define TARGET __attribute__((target("avx2")))

#define MASK26 0x3ffffffU

/* r^(n+1) = r^n * r, in the same five 26-bit limbs the context uses */
static void mul_limbs(uint32_t out[5], const uint32_t a[5], const uint32_t b[5])
{
	uint64_t d[5];
	uint32_t s[5];
	uint32_t c;
	int i;

	for (i = 1; i < 5; i++)
		s[i] = b[i] * 5;

	d[0] = (uint64_t) a[0] * b[0] + (uint64_t) a[1] * s[4]
	     + (uint64_t) a[2] * s[3] + (uint64_t) a[3] * s[2] + (uint64_t) a[4] * s[1];
	d[1] = (uint64_t) a[0] * b[1] + (uint64_t) a[1] * b[0]
	     + (uint64_t) a[2] * s[4] + (uint64_t) a[3] * s[3] + (uint64_t) a[4] * s[2];
	d[2] = (uint64_t) a[0] * b[2] + (uint64_t) a[1] * b[1]
	     + (uint64_t) a[2] * b[0] + (uint64_t) a[3] * s[4] + (uint64_t) a[4] * s[3];
	d[3] = (uint64_t) a[0] * b[3] + (uint64_t) a[1] * b[2]
	     + (uint64_t) a[2] * b[1] + (uint64_t) a[3] * b[0] + (uint64_t) a[4] * s[4];
	d[4] = (uint64_t) a[0] * b[4] + (uint64_t) a[1] * b[3]
	     + (uint64_t) a[2] * b[2] + (uint64_t) a[3] * b[1] + (uint64_t) a[4] * b[0];

	c = (uint32_t) (d[0] >> 26); out[0] = (uint32_t) d[0] & MASK26;
	d[1] += c; c = (uint32_t) (d[1] >> 26); out[1] = (uint32_t) d[1] & MASK26;
	d[2] += c; c = (uint32_t) (d[2] >> 26); out[2] = (uint32_t) d[2] & MASK26;
	d[3] += c; c = (uint32_t) (d[3] >> 26); out[3] = (uint32_t) d[3] & MASK26;
	d[4] += c; c = (uint32_t) (d[4] >> 26); out[4] = (uint32_t) d[4] & MASK26;
	out[0] += c * 5; c = out[0] >> 26; out[0] &= MASK26;
	out[1] += c;
}

/* One multiply by the five limbs in r[], with the reduction that follows. */
#define MULRED(a0, a1, a2, a3, a4, r0, r1, r2, r3, r4, s1, s2, s3, s4)        \
	do {                                                                  \
		__m256i d0_, d1_, d2_, d3_, d4_, c_;                          \
		const __m256i m26_ = _mm256_set1_epi64x(MASK26);              \
		d0_ = _mm256_add_epi64(                                       \
		    _mm256_add_epi64(_mm256_mul_epu32(a0, r0), _mm256_mul_epu32(a1, s4)), \
		    _mm256_add_epi64(                                         \
		        _mm256_add_epi64(_mm256_mul_epu32(a2, s3), _mm256_mul_epu32(a3, s2)), \
		        _mm256_mul_epu32(a4, s1)));                           \
		d1_ = _mm256_add_epi64(                                       \
		    _mm256_add_epi64(_mm256_mul_epu32(a0, r1), _mm256_mul_epu32(a1, r0)), \
		    _mm256_add_epi64(                                         \
		        _mm256_add_epi64(_mm256_mul_epu32(a2, s4), _mm256_mul_epu32(a3, s3)), \
		        _mm256_mul_epu32(a4, s2)));                           \
		d2_ = _mm256_add_epi64(                                       \
		    _mm256_add_epi64(_mm256_mul_epu32(a0, r2), _mm256_mul_epu32(a1, r1)), \
		    _mm256_add_epi64(                                         \
		        _mm256_add_epi64(_mm256_mul_epu32(a2, r0), _mm256_mul_epu32(a3, s4)), \
		        _mm256_mul_epu32(a4, s3)));                           \
		d3_ = _mm256_add_epi64(                                       \
		    _mm256_add_epi64(_mm256_mul_epu32(a0, r3), _mm256_mul_epu32(a1, r2)), \
		    _mm256_add_epi64(                                         \
		        _mm256_add_epi64(_mm256_mul_epu32(a2, r1), _mm256_mul_epu32(a3, r0)), \
		        _mm256_mul_epu32(a4, s4)));                           \
		d4_ = _mm256_add_epi64(                                       \
		    _mm256_add_epi64(_mm256_mul_epu32(a0, r4), _mm256_mul_epu32(a1, r3)), \
		    _mm256_add_epi64(                                         \
		        _mm256_add_epi64(_mm256_mul_epu32(a2, r2), _mm256_mul_epu32(a3, r1)), \
		        _mm256_mul_epu32(a4, r0)));                           \
                                                                              \
		c_ = _mm256_srli_epi64(d0_, 26); a0 = _mm256_and_si256(d0_, m26_); \
		d1_ = _mm256_add_epi64(d1_, c_);                              \
		c_ = _mm256_srli_epi64(d1_, 26); a1 = _mm256_and_si256(d1_, m26_); \
		d2_ = _mm256_add_epi64(d2_, c_);                              \
		c_ = _mm256_srli_epi64(d2_, 26); a2 = _mm256_and_si256(d2_, m26_); \
		d3_ = _mm256_add_epi64(d3_, c_);                              \
		c_ = _mm256_srli_epi64(d3_, 26); a3 = _mm256_and_si256(d3_, m26_); \
		d4_ = _mm256_add_epi64(d4_, c_);                              \
		c_ = _mm256_srli_epi64(d4_, 26); a4 = _mm256_and_si256(d4_, m26_); \
		/* what leaves the top limb comes back multiplied by five */  \
		a0 = _mm256_add_epi64(                                        \
		    a0, _mm256_add_epi64(_mm256_slli_epi64(c_, 2), c_));      \
		c_ = _mm256_srli_epi64(a0, 26); a0 = _mm256_and_si256(a0, m26_); \
		a1 = _mm256_add_epi64(a1, c_);                                \
	} while (0)

/*
 * Four blocks from data into the five limb vectors, lane i holding block i.
 * The two loads give (m0.lo, m0.hi, m1.lo, m1.hi) and the same for m2 and m3;
 * the unpacks gather the low halves and the high halves, in the lane order
 * 0, 2, 1, 3, and the permute puts that straight.
 */
#define LOAD4(dst0, dst1, dst2, dst3, dst4, data, hibit)                      \
	do {                                                                  \
		__m256i t0_ = _mm256_loadu_si256((const __m256i *) (data));   \
		__m256i t1_ = _mm256_loadu_si256((const __m256i *) ((data) + 32)); \
		__m256i lo_ = _mm256_permute4x64_epi64(                       \
		    _mm256_unpacklo_epi64(t0_, t1_), 0xd8);                   \
		__m256i hi_ = _mm256_permute4x64_epi64(                       \
		    _mm256_unpackhi_epi64(t0_, t1_), 0xd8);                   \
		const __m256i m26b_ = _mm256_set1_epi64x(MASK26);             \
		dst0 = _mm256_and_si256(lo_, m26b_);                          \
		dst1 = _mm256_and_si256(_mm256_srli_epi64(lo_, 26), m26b_);   \
		dst2 = _mm256_and_si256(                                      \
		    _mm256_or_si256(_mm256_srli_epi64(lo_, 52),               \
		                    _mm256_slli_epi64(hi_, 12)), m26b_);      \
		dst3 = _mm256_and_si256(_mm256_srli_epi64(hi_, 14), m26b_);   \
		dst4 = _mm256_or_si256(_mm256_srli_epi64(hi_, 40), hibit);    \
	} while (0)

/*
 * Whole groups of four blocks.  The caller keeps anything left over for the
 * scalar loop, and only calls this with the high bit set, which is every
 * block but the last of a message.
 */
TARGET
void crypton_poly1305_avx2_blocks(poly1305_ctx *ctx, const uint8_t *data, uint32_t groups)
{
	uint32_t r1[5], r2[5], r3[5], r4[5];
	__m256i a0, a1, a2, a3, a4;
	__m256i R0, R1, R2, R3, R4, S1, S2, S3, S4;
	const __m256i hibit = _mm256_set1_epi64x(1 << 24);
	uint64_t lane[4];
	uint32_t h[5];
	uint32_t c;
	int i;

	memcpy(r1, ctx->r, sizeof r1);
	mul_limbs(r2, r1, r1);
	mul_limbs(r3, r2, r1);
	mul_limbs(r4, r3, r1);

	/* the first group takes the accumulator in with its first block */
	LOAD4(a0, a1, a2, a3, a4, data, hibit);
	a0 = _mm256_add_epi64(a0, _mm256_set_epi64x(0, 0, 0, ctx->h[0]));
	a1 = _mm256_add_epi64(a1, _mm256_set_epi64x(0, 0, 0, ctx->h[1]));
	a2 = _mm256_add_epi64(a2, _mm256_set_epi64x(0, 0, 0, ctx->h[2]));
	a3 = _mm256_add_epi64(a3, _mm256_set_epi64x(0, 0, 0, ctx->h[3]));
	a4 = _mm256_add_epi64(a4, _mm256_set_epi64x(0, 0, 0, ctx->h[4]));
	data += 64;

#define BROADCAST(v, src) v = _mm256_set1_epi64x(src)
	BROADCAST(R0, r4[0]); BROADCAST(R1, r4[1]); BROADCAST(R2, r4[2]);
	BROADCAST(R3, r4[3]); BROADCAST(R4, r4[4]);
	BROADCAST(S1, r4[1] * 5); BROADCAST(S2, r4[2] * 5);
	BROADCAST(S3, r4[3] * 5); BROADCAST(S4, r4[4] * 5);
#undef BROADCAST

	for (groups--; groups > 0; groups--, data += 64) {
		__m256i m0, m1, m2, m3, m4;

		MULRED(a0, a1, a2, a3, a4, R0, R1, R2, R3, R4, S1, S2, S3, S4);
		LOAD4(m0, m1, m2, m3, m4, data, hibit);
		a0 = _mm256_add_epi64(a0, m0);
		a1 = _mm256_add_epi64(a1, m1);
		a2 = _mm256_add_epi64(a2, m2);
		a3 = _mm256_add_epi64(a3, m3);
		a4 = _mm256_add_epi64(a4, m4);
	}

	/* fold the lanes back together, weighted r^4, r^3, r^2, r */
#define WEIGHTS(v, i) v = _mm256_set_epi64x(r1[i], r2[i], r3[i], r4[i])
	WEIGHTS(R0, 0); WEIGHTS(R1, 1); WEIGHTS(R2, 2);
	WEIGHTS(R3, 3); WEIGHTS(R4, 4);
#undef WEIGHTS
	S1 = _mm256_add_epi64(_mm256_slli_epi64(R1, 2), R1);
	S2 = _mm256_add_epi64(_mm256_slli_epi64(R2, 2), R2);
	S3 = _mm256_add_epi64(_mm256_slli_epi64(R3, 2), R3);
	S4 = _mm256_add_epi64(_mm256_slli_epi64(R4, 2), R4);
	MULRED(a0, a1, a2, a3, a4, R0, R1, R2, R3, R4, S1, S2, S3, S4);

#define SUMLANES(v, out)                                             \
	do {                                                         \
		_mm256_storeu_si256((__m256i *) lane, v);            \
		out = (uint32_t) (lane[0] + lane[1] + lane[2] + lane[3]); \
	} while (0)
	SUMLANES(a0, h[0]); SUMLANES(a1, h[1]); SUMLANES(a2, h[2]);
	SUMLANES(a3, h[3]); SUMLANES(a4, h[4]);
#undef SUMLANES

	/* each limb is at most four times 26 bits, so one pass settles it */
	for (i = 0; i < 4; i++) {
		c = h[i] >> 26;
		h[i] &= MASK26;
		h[i + 1] += c;
	}
	c = h[4] >> 26;
	h[4] &= MASK26;
	h[0] += c * 5;
	c = h[0] >> 26;
	h[0] &= MASK26;
	h[1] += c;

	memcpy(ctx->h, h, sizeof h);
}

#endif /* WITH_TARGET_ATTRIBUTES */
