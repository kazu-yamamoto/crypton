/*
 * SHA-1 using the ARMv8-A cryptographic extensions.
 *
 * crypton_sha1.c computes the compression function a round at a time in plain
 * C.  AArch64 has instructions for it -- SHA1C, SHA1P, SHA1M, SHA1H, SHA1SU0
 * and SHA1SU1 -- which do four rounds at a time and most of the message
 * schedule alongside.  They come with the SHA-256 ones this tree already uses,
 * under the same optional feature, so anything that has those has these.
 *
 * SHA-1 is not a hash to choose today, but it is still what a number of
 * protocols and file formats ask for.
 */

#include <stdint.h>
#include <arm_neon.h>
#if defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

/*
 * The instructions are an extension, so a translation unit compiled for
 * baseline ARMv8-A may not use them; see sha256_armv8.c for the whole of that
 * argument.
 */
#ifdef WITH_TARGET_ATTRIBUTES
#define TARGET_ARMV8_CRYPTO __attribute__((target("+crypto")))
#else
#define TARGET_ARMV8_CRYPTO
#endif

/*
 * A group of four rounds, and the schedule that goes with it.
 *
 * SHA1C, SHA1P and SHA1M each do four rounds with one of the three round
 * functions -- choose, parity and majority -- taking the four state words in
 * a register, E in a general one, and the four message words with their round
 * constant already added.  SHA1H is the rotation of A by thirty that carries
 * E from one group to the next.
 *
 * The schedule is the exclusive or of four earlier words rotated left by one.
 * SHA1SU0 does the three terms that reach furthest back and SHA1SU1 the last
 * one, together with the rotation and the dependency inside the group.
 */
#define GROUP(f, ecur, enext, wk_cur, wk_next, kk, w0, w1, w2, w3)           \
	do {                                                                 \
		enext = vsha1h_u32(vgetq_lane_u32(abcd, 0));                 \
		abcd = f(abcd, ecur, wk_cur);                                \
		wk_next = vaddq_u32(w2, kk);                                 \
		w0 = vsha1su0q_u32(w0, w1, w2);                              \
		w3 = vsha1su1q_u32(w3, w2);                                  \
	} while (0)

/*
 * One 64-byte block.  `state` is the five words of chaining value in host
 * order, `buf` the block as it arrived, which SHA-1 reads big-endian.
 */
TARGET_ARMV8_CRYPTO
void crypton_sha1_armv8_do_chunk(uint32_t state[5], const uint32_t buf[16])
{
	const uint32x4_t k0 = vdupq_n_u32(0x5a827999);
	const uint32x4_t k1 = vdupq_n_u32(0x6ed9eba1);
	const uint32x4_t k2 = vdupq_n_u32(0x8f1bbcdc);
	const uint32x4_t k3 = vdupq_n_u32(0xca62c1d6);
	uint32x4_t abcd, abcd_prev;
	uint32x4_t m0, m1, m2, m3;
	uint32x4_t wk0, wk1;
	uint32_t e0, e1, e_prev;

	abcd = vld1q_u32(state);
	e0 = state[4];
	abcd_prev = abcd;
	e_prev = e0;

	m0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(buf))));
	m1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(buf + 4))));
	m2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(buf + 8))));
	m3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(buf + 12))));

	wk0 = vaddq_u32(m0, k0);
	wk1 = vaddq_u32(m1, k0);

	/* rounds 0 to 15, where the schedule has less to do each group until
	 * it is running a whole group ahead */
	e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
	abcd = vsha1cq_u32(abcd, e0, wk0);
	wk0 = vaddq_u32(m2, k0);
	m0 = vsha1su0q_u32(m0, m1, m2);

	e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
	abcd = vsha1cq_u32(abcd, e1, wk1);
	wk1 = vaddq_u32(m3, k0);
	m1 = vsha1su0q_u32(m1, m2, m3);
	m0 = vsha1su1q_u32(m0, m3);

	e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
	abcd = vsha1cq_u32(abcd, e0, wk0);
	wk0 = vaddq_u32(m0, k0);
	m2 = vsha1su0q_u32(m2, m3, m0);
	m1 = vsha1su1q_u32(m1, m0);

	e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
	abcd = vsha1cq_u32(abcd, e1, wk1);
	wk1 = vaddq_u32(m1, k1);
	m3 = vsha1su0q_u32(m3, m0, m1);
	m2 = vsha1su1q_u32(m2, m1);

	/* rounds 16 to 19, still the choose function, and then twenty of each
	 * of the others; the message registers come back to the same roles
	 * every fourth group */
	GROUP(vsha1cq_u32, e0, e1, wk0, wk0, k1, m0, m1, m2, m3);
	GROUP(vsha1pq_u32, e1, e0, wk1, wk1, k1, m1, m2, m3, m0);
	GROUP(vsha1pq_u32, e0, e1, wk0, wk0, k1, m2, m3, m0, m1);
	GROUP(vsha1pq_u32, e1, e0, wk1, wk1, k1, m3, m0, m1, m2);
	GROUP(vsha1pq_u32, e0, e1, wk0, wk0, k2, m0, m1, m2, m3);
	GROUP(vsha1pq_u32, e1, e0, wk1, wk1, k2, m1, m2, m3, m0);
	GROUP(vsha1mq_u32, e0, e1, wk0, wk0, k2, m2, m3, m0, m1);
	GROUP(vsha1mq_u32, e1, e0, wk1, wk1, k2, m3, m0, m1, m2);
	GROUP(vsha1mq_u32, e0, e1, wk0, wk0, k2, m0, m1, m2, m3);
	GROUP(vsha1mq_u32, e1, e0, wk1, wk1, k3, m1, m2, m3, m0);
	GROUP(vsha1mq_u32, e0, e1, wk0, wk0, k3, m2, m3, m0, m1);
	GROUP(vsha1pq_u32, e1, e0, wk1, wk1, k3, m3, m0, m1, m2);

	/* rounds 64 to 79, where the schedule runs out a piece at a time */
	e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
	abcd = vsha1pq_u32(abcd, e0, wk0);
	wk0 = vaddq_u32(m2, k3);
	m3 = vsha1su1q_u32(m3, m2);

	e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
	abcd = vsha1pq_u32(abcd, e1, wk1);
	wk1 = vaddq_u32(m3, k3);

	e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
	abcd = vsha1pq_u32(abcd, e0, wk0);

	e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
	abcd = vsha1pq_u32(abcd, e1, wk1);

	vst1q_u32(state, vaddq_u32(abcd, abcd_prev));
	state[4] = e0 + e_prev;
}

/*
 * The SHA-1 instructions are optional in ARMv8.0, and arrive with the SHA-256
 * ones.  They are always there on Apple silicon; elsewhere the kernel reports
 * them.
 */
int crypton_sha1_armv8_available(void)
{
#if defined(__APPLE__)
	return 1;
#elif defined(__linux__)
	return (getauxval(AT_HWCAP) & HWCAP_SHA1) != 0;
#else
	return 0;
#endif
}
