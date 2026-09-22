/*
 * Poly1305 with NEON, four blocks at a time.
 *
 * This is a transliteration of poly1305_avx2.c rather than a fresh
 * formulation: that code is already pinned by the known-answer tests, and the
 * arithmetic is the same -- the accumulator's five 26-bit limbs spread across
 * four lanes, every step multiplying all four by r^4, and the lanes folded
 * back together weighted by r^4, r^3, r^2 and r.  See it for why that gives
 * what the scalar loop would have reached.
 *
 * What differs is the width.  AVX2 holds four 64-bit products in one
 * register; NEON holds two, so each of the five products becomes a pair, and
 * the limbs are packed back into four 32-bit lanes before the next
 * multiplication.
 *
 *   _mm256_mul_epu32           ->  vmull_u32 and vmull_high_u32
 *   _mm256_add_epi64           ->  vaddq_u64
 *   _mm256_srli_epi64          ->  vshrq_n_u64
 *   _mm256_and_si256 with 2^26 ->  vandq_u64
 *   _mm256_permute4x64_epi64   ->  vuzp1q_u64 and vuzp2q_u64
 */

#include <stdint.h>
#include <string.h>
#include <arm_neon.h>
#include "crypton_poly1305.h"

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

/* one product of a limb by a broadcast r, as a pair of pairs */
#define MUL(dl, dh, a, r)                                                    \
	do {                                                                 \
		(dl) = vmull_u32(vget_low_u32(a), vget_low_u32(r));          \
		(dh) = vmull_high_u32((a), (r));                             \
	} while (0)

#define MLA(dl, dh, a, r)                                                    \
	do {                                                                 \
		(dl) = vmlal_u32((dl), vget_low_u32(a), vget_low_u32(r));    \
		(dh) = vmlal_high_u32((dh), (a), (r));                       \
	} while (0)

/* the carry chain of poly1305_avx2.c, on both halves at once */
#define CARRY(d0l, d0h, d1l, d1h, d2l, d2h, d3l, d3h, d4l, d4h,              \
              a0, a1, a2, a3, a4)                                            \
	do {                                                                 \
		const uint64x2_t m_ = vdupq_n_u64(MASK26);                   \
		uint64x2_t xl_, xh_, yl_, yh_;                               \
		                                                             \
		xl_ = vshrq_n_u64(d0l, 26); d0l = vandq_u64(d0l, m_);        \
		xh_ = vshrq_n_u64(d0h, 26); d0h = vandq_u64(d0h, m_);        \
		yl_ = vshrq_n_u64(d3l, 26); d3l = vandq_u64(d3l, m_);        \
		yh_ = vshrq_n_u64(d3h, 26); d3h = vandq_u64(d3h, m_);        \
		d1l = vaddq_u64(d1l, xl_); d1h = vaddq_u64(d1h, xh_);        \
		d4l = vaddq_u64(d4l, yl_); d4h = vaddq_u64(d4h, yh_);        \
		                                                             \
		xl_ = vshrq_n_u64(d1l, 26); d1l = vandq_u64(d1l, m_);        \
		xh_ = vshrq_n_u64(d1h, 26); d1h = vandq_u64(d1h, m_);        \
		yl_ = vshrq_n_u64(d4l, 26); d4l = vandq_u64(d4l, m_);        \
		yh_ = vshrq_n_u64(d4h, 26); d4h = vandq_u64(d4h, m_);        \
		d2l = vaddq_u64(d2l, xl_); d2h = vaddq_u64(d2h, xh_);        \
		/* what leaves the top limb comes back multiplied by five */ \
		d0l = vaddq_u64(d0l, vaddq_u64(vshlq_n_u64(yl_, 2), yl_));   \
		d0h = vaddq_u64(d0h, vaddq_u64(vshlq_n_u64(yh_, 2), yh_));   \
		                                                             \
		xl_ = vshrq_n_u64(d2l, 26); d2l = vandq_u64(d2l, m_);        \
		xh_ = vshrq_n_u64(d2h, 26); d2h = vandq_u64(d2h, m_);        \
		yl_ = vshrq_n_u64(d0l, 26); d0l = vandq_u64(d0l, m_);        \
		yh_ = vshrq_n_u64(d0h, 26); d0h = vandq_u64(d0h, m_);        \
		d3l = vaddq_u64(d3l, xl_); d3h = vaddq_u64(d3h, xh_);        \
		d1l = vaddq_u64(d1l, yl_); d1h = vaddq_u64(d1h, yh_);        \
		                                                             \
		xl_ = vshrq_n_u64(d3l, 26); d3l = vandq_u64(d3l, m_);        \
		xh_ = vshrq_n_u64(d3h, 26); d3h = vandq_u64(d3h, m_);        \
		d4l = vaddq_u64(d4l, xl_); d4h = vaddq_u64(d4h, xh_);        \
		                                                             \
		(a0) = vcombine_u32(vmovn_u64(d0l), vmovn_u64(d0h));         \
		(a1) = vcombine_u32(vmovn_u64(d1l), vmovn_u64(d1h));         \
		(a2) = vcombine_u32(vmovn_u64(d2l), vmovn_u64(d2h));         \
		(a3) = vcombine_u32(vmovn_u64(d3l), vmovn_u64(d3h));         \
		(a4) = vcombine_u32(vmovn_u64(d4l), vmovn_u64(d4h));         \
	} while (0)

/*
 * Four blocks from data, added into the five limb vectors, lane i holding
 * block i.  The loads give each block's two halves; the unzips gather the low
 * halves of blocks 0 and 1, then of 2 and 3, and the same for the high ones.
 */
#define LOAD4_ADD(a0, a1, a2, a3, a4, data)                                  \
	do {                                                                 \
		const uint64x2_t m_ = vdupq_n_u64(MASK26);                   \
		const uint64x2_t hi_ = vdupq_n_u64((uint64_t) 1 << 24);      \
		uint64x2_t t0_ = vld1q_u64((const uint64_t *) (data));       \
		uint64x2_t t1_ = vld1q_u64((const uint64_t *) ((data) + 16)); \
		uint64x2_t t2_ = vld1q_u64((const uint64_t *) ((data) + 32)); \
		uint64x2_t t3_ = vld1q_u64((const uint64_t *) ((data) + 48)); \
		uint64x2_t la_ = vuzp1q_u64(t0_, t1_);                       \
		uint64x2_t ha_ = vuzp2q_u64(t0_, t1_);                       \
		uint64x2_t lb_ = vuzp1q_u64(t2_, t3_);                       \
		uint64x2_t hb_ = vuzp2q_u64(t2_, t3_);                       \
		uint64x2_t xa_, xb_;                                         \
		                                                             \
		xa_ = vandq_u64(la_, m_);                                    \
		xb_ = vandq_u64(lb_, m_);                                    \
		(a0) = vaddq_u32((a0),                                       \
		    vcombine_u32(vmovn_u64(xa_), vmovn_u64(xb_)));           \
		xa_ = vandq_u64(vshrq_n_u64(la_, 26), m_);                   \
		xb_ = vandq_u64(vshrq_n_u64(lb_, 26), m_);                   \
		(a1) = vaddq_u32((a1),                                       \
		    vcombine_u32(vmovn_u64(xa_), vmovn_u64(xb_)));           \
		xa_ = vandq_u64(vorrq_u64(vshrq_n_u64(la_, 52),              \
		                          vshlq_n_u64(ha_, 12)), m_);        \
		xb_ = vandq_u64(vorrq_u64(vshrq_n_u64(lb_, 52),              \
		                          vshlq_n_u64(hb_, 12)), m_);        \
		(a2) = vaddq_u32((a2),                                       \
		    vcombine_u32(vmovn_u64(xa_), vmovn_u64(xb_)));           \
		xa_ = vandq_u64(vshrq_n_u64(ha_, 14), m_);                   \
		xb_ = vandq_u64(vshrq_n_u64(hb_, 14), m_);                   \
		(a3) = vaddq_u32((a3),                                       \
		    vcombine_u32(vmovn_u64(xa_), vmovn_u64(xb_)));           \
		xa_ = vorrq_u64(vshrq_n_u64(ha_, 40), hi_);                  \
		xb_ = vorrq_u64(vshrq_n_u64(hb_, 40), hi_);                  \
		(a4) = vaddq_u32((a4),                                       \
		    vcombine_u32(vmovn_u64(xa_), vmovn_u64(xb_)));           \
	} while (0)

/*
 * Whole groups of four blocks.  The caller keeps anything left over for the
 * scalar loop, and only calls this with the high bit set, which is every
 * block but the last of a message.
 */
void crypton_poly1305_neon_blocks(poly1305_ctx *ctx, const uint8_t *data, uint32_t groups)
{
	uint32_t r1[5], r2[5], r3[5], r4[5];
	uint32x4_t a0, a1, a2, a3, a4;
	uint32x4_t rv[9];
	uint64x2_t d0l, d0h, d1l, d1h, d2l, d2h, d3l, d3h, d4l, d4h;
	uint32_t h[5];
	uint32_t c;
	int i;

	memcpy(r1, ctx->r, sizeof r1);
	mul_limbs(r2, r1, r1);
	mul_limbs(r3, r2, r1);
	mul_limbs(r4, r3, r1);

	/* the first group takes the accumulator in with its first block */
	a0 = vsetq_lane_u32(ctx->h[0], vdupq_n_u32(0), 0);
	a1 = vsetq_lane_u32(ctx->h[1], vdupq_n_u32(0), 0);
	a2 = vsetq_lane_u32(ctx->h[2], vdupq_n_u32(0), 0);
	a3 = vsetq_lane_u32(ctx->h[3], vdupq_n_u32(0), 0);
	a4 = vsetq_lane_u32(ctx->h[4], vdupq_n_u32(0), 0);
	LOAD4_ADD(a0, a1, a2, a3, a4, data);
	data += 64;

	for (i = 0; i < 5; i++)
		rv[i] = vdupq_n_u32(r4[i]);
	for (i = 1; i < 5; i++)
		rv[4 + i] = vdupq_n_u32(r4[i] * 5);

	for (groups--; groups > 0; groups--, data += 64) {
		MUL(d0l, d0h, a0, rv[0]);
		MLA(d0l, d0h, a1, rv[8]);
		MLA(d0l, d0h, a2, rv[7]);
		MLA(d0l, d0h, a3, rv[6]);
		MLA(d0l, d0h, a4, rv[5]);

		MUL(d1l, d1h, a0, rv[1]);
		MLA(d1l, d1h, a1, rv[0]);
		MLA(d1l, d1h, a2, rv[8]);
		MLA(d1l, d1h, a3, rv[7]);
		MLA(d1l, d1h, a4, rv[6]);

		MUL(d2l, d2h, a0, rv[2]);
		MLA(d2l, d2h, a1, rv[1]);
		MLA(d2l, d2h, a2, rv[0]);
		MLA(d2l, d2h, a3, rv[8]);
		MLA(d2l, d2h, a4, rv[7]);

		MUL(d3l, d3h, a0, rv[3]);
		MLA(d3l, d3h, a1, rv[2]);
		MLA(d3l, d3h, a2, rv[1]);
		MLA(d3l, d3h, a3, rv[0]);
		MLA(d3l, d3h, a4, rv[8]);

		MUL(d4l, d4h, a0, rv[4]);
		MLA(d4l, d4h, a1, rv[3]);
		MLA(d4l, d4h, a2, rv[2]);
		MLA(d4l, d4h, a3, rv[1]);
		MLA(d4l, d4h, a4, rv[0]);

		CARRY(d0l, d0h, d1l, d1h, d2l, d2h, d3l, d3h, d4l, d4h,
		      a0, a1, a2, a3, a4);
		LOAD4_ADD(a0, a1, a2, a3, a4, data);
	}

	/* fold the lanes back together, weighted r^4, r^3, r^2, r */
	for (i = 0; i < 5; i++) {
		const uint32_t w[4] = { r4[i], r3[i], r2[i], r1[i] };

		rv[i] = vld1q_u32(w);
	}
	for (i = 1; i < 5; i++)
		rv[4 + i] = vaddq_u32(vshlq_n_u32(rv[i], 2), rv[i]);

	MUL(d0l, d0h, a0, rv[0]);
	MLA(d0l, d0h, a1, rv[8]);
	MLA(d0l, d0h, a2, rv[7]);
	MLA(d0l, d0h, a3, rv[6]);
	MLA(d0l, d0h, a4, rv[5]);

	MUL(d1l, d1h, a0, rv[1]);
	MLA(d1l, d1h, a1, rv[0]);
	MLA(d1l, d1h, a2, rv[8]);
	MLA(d1l, d1h, a3, rv[7]);
	MLA(d1l, d1h, a4, rv[6]);

	MUL(d2l, d2h, a0, rv[2]);
	MLA(d2l, d2h, a1, rv[1]);
	MLA(d2l, d2h, a2, rv[0]);
	MLA(d2l, d2h, a3, rv[8]);
	MLA(d2l, d2h, a4, rv[7]);

	MUL(d3l, d3h, a0, rv[3]);
	MLA(d3l, d3h, a1, rv[2]);
	MLA(d3l, d3h, a2, rv[1]);
	MLA(d3l, d3h, a3, rv[0]);
	MLA(d3l, d3h, a4, rv[8]);

	MUL(d4l, d4h, a0, rv[4]);
	MLA(d4l, d4h, a1, rv[3]);
	MLA(d4l, d4h, a2, rv[2]);
	MLA(d4l, d4h, a3, rv[1]);
	MLA(d4l, d4h, a4, rv[0]);

	CARRY(d0l, d0h, d1l, d1h, d2l, d2h, d3l, d3h, d4l, d4h,
	      a0, a1, a2, a3, a4);

	/* the four lanes of each limb summed, which the tail below carries:
	 * each lane is under 2^26 after the reduction above, so the sum of
	 * four of them is under 2^28 */
	h[0] = vaddvq_u32(a0);
	h[1] = vaddvq_u32(a1);
	h[2] = vaddvq_u32(a2);
	h[3] = vaddvq_u32(a3);
	h[4] = vaddvq_u32(a4);

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
