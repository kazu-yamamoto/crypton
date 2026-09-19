/*
 * ChaCha with NEON, four blocks at a time.
 *
 * The state is sixteen 32-bit words and the quarter rounds touch four of
 * them at once, so a single block vectorises only by shuffling lanes
 * between the column and diagonal rounds.  Four blocks vectorise without
 * any shuffling at all: word i of the four blocks goes in lane i of one
 * register, every quarter round is then the same operation on whole
 * registers, and the blocks are independent because only the counter
 * differs between them.
 *
 * NEON is part of the AArch64 baseline, so unlike the AES, PMULL and SHA
 * work there is nothing to ask about at runtime and no target attribute
 * to attach.
 */

#include <stdint.h>
#include <arm_neon.h>
#include "crypton_chacha.h"

/* rotate each 32-bit lane left by n */
#define ROL(x, n) vsriq_n_u32(vshlq_n_u32((x), (n)), (x), 32 - (n))
/* by 16 it is a halfword swap, and by 8 a byte shuffle; both beat the pair
 * of shifts */
#define ROL16(x) vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))
#define ROL8(x)  vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), rot8))

#define QR(a, b, c, d)                          \
	a = vaddq_u32(a, b); d = ROL16(veorq_u32(d, a)); \
	c = vaddq_u32(c, d); b = ROL(veorq_u32(b, c), 12); \
	a = vaddq_u32(a, b); d = ROL8(veorq_u32(d, a));  \
	c = vaddq_u32(c, d); b = ROL(veorq_u32(b, c), 7)

/*
 * Turn four registers holding word w of blocks 0..3 into four holding
 * words w..w+3 of one block each, which is the order they are written in.
 */
#define TRANSPOSE(a, b, c, d)                                          \
	do {                                                           \
		uint32x4x2_t t0_ = vtrnq_u32((a), (b));                \
		uint32x4x2_t t1_ = vtrnq_u32((c), (d));                \
		(a) = vcombine_u32(vget_low_u32(t0_.val[0]),           \
		                   vget_low_u32(t1_.val[0]));          \
		(b) = vcombine_u32(vget_low_u32(t0_.val[1]),           \
		                   vget_low_u32(t1_.val[1]));          \
		(c) = vcombine_u32(vget_high_u32(t0_.val[0]),          \
		                   vget_high_u32(t1_.val[0]));         \
		(d) = vcombine_u32(vget_high_u32(t0_.val[1]),          \
		                   vget_high_u32(t1_.val[1]));         \
	} while (0)

/*
 * Four blocks with counters d[12], d[12]+1, d[12]+2 and d[12]+3.  The
 * caller keeps the state's counter, and only calls this when those four
 * do not carry into d[13].
 */
static void core4(int rounds, block out[4], const crypton_chacha_state *in)
{
	static const uint8_t rot8_tbl[16] =
		{ 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14 };
	const uint8x16_t rot8 = vld1q_u8(rot8_tbl);
	uint32x4_t v0, v1, v2, v3, v4, v5, v6, v7;
	uint32x4_t v8, v9, v10, v11, v12, v13, v14, v15;
	const uint32_t c = in->d[12];
	const uint32_t ctr4[4] = { c, c + 1, c + 2, c + 3 };
	int i;

	/*
	 * Only the working state is kept in registers.  The initial state has
	 * to be added back at the end, but holding a second copy of it would
	 * want thirty-two registers for that alone, and the machine has
	 * thirty-two in total; read it again instead, from memory that is
	 * certainly warm.
	 */
#define SET(n) v##n = vdupq_n_u32(in->d[n])
	SET(0);  SET(1);  SET(2);  SET(3);
	SET(4);  SET(5);  SET(6);  SET(7);
	SET(8);  SET(9);  SET(10); SET(11);
	         SET(13); SET(14); SET(15);
#undef SET
	v12 = vld1q_u32(ctr4);

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

#define ADD(n) v##n = vaddq_u32(v##n, vdupq_n_u32(in->d[n]))
	ADD(0);  ADD(1);  ADD(2);  ADD(3);
	ADD(4);  ADD(5);  ADD(6);  ADD(7);
	ADD(8);  ADD(9);  ADD(10); ADD(11);
	         ADD(13); ADD(14); ADD(15);
#undef ADD
	v12 = vaddq_u32(v12, vld1q_u32(ctr4));

	TRANSPOSE(v0,  v1,  v2,  v3);
	TRANSPOSE(v4,  v5,  v6,  v7);
	TRANSPOSE(v8,  v9,  v10, v11);
	TRANSPOSE(v12, v13, v14, v15);

	vst1q_u32(out[0].d + 0,  v0);
	vst1q_u32(out[1].d + 0,  v1);
	vst1q_u32(out[2].d + 0,  v2);
	vst1q_u32(out[3].d + 0,  v3);
	vst1q_u32(out[0].d + 4,  v4);
	vst1q_u32(out[1].d + 4,  v5);
	vst1q_u32(out[2].d + 4,  v6);
	vst1q_u32(out[3].d + 4,  v7);
	vst1q_u32(out[0].d + 8,  v8);
	vst1q_u32(out[1].d + 8,  v9);
	vst1q_u32(out[2].d + 8,  v10);
	vst1q_u32(out[3].d + 8,  v11);
	vst1q_u32(out[0].d + 12, v12);
	vst1q_u32(out[1].d + 12, v13);
	vst1q_u32(out[2].d + 12, v14);
	vst1q_u32(out[3].d + 12, v15);
}

/*
 * The four blocks land in one contiguous 256-byte run, so the exclusive or
 * with the plaintext is sixteen more vector operations rather than a loop
 * over bytes.
 */
void crypton_chacha_simd_combine(int rounds, uint8_t *dst, const uint8_t *src,
                                  const crypton_chacha_state *in)
{
	block k[4];
	const uint8_t *ks = (const uint8_t *) k;
	int i;

	core4(rounds, k, in);
	for (i = 0; i < 256; i += 16)
		vst1q_u8(dst + i, veorq_u8(vld1q_u8(src + i), vld1q_u8(ks + i)));
}

void crypton_chacha_simd_generate(int rounds, uint8_t *dst, const crypton_chacha_state *in)
{
	block k[4];
	const uint8_t *ks = (const uint8_t *) k;
	int i;

	core4(rounds, k, in);
	for (i = 0; i < 256; i += 16)
		vst1q_u8(dst + i, vld1q_u8(ks + i));
}

/* NEON has no wider sibling to choose between, so the answer is fixed. */
int crypton_chacha_simd_width(void)
{
	return 4;
}
