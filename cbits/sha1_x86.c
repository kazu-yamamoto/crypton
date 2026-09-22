/*
 * SHA-1 using the Intel SHA extensions.
 *
 * crypton_sha1.c computes the compression function a round at a time in plain
 * C.  The same extension that carries SHA256RNDS2 carries four instructions
 * for this one -- SHA1RNDS4, SHA1NEXTE, SHA1MSG1 and SHA1MSG2 -- which do four
 * rounds at a time and most of the message schedule alongside.
 *
 * SHA-1 is not a hash to choose today, but it is still what a number of
 * protocols and file formats ask for, and the instructions are already there
 * on any processor that has the SHA-256 ones.
 */

#include <stdint.h>
#include <immintrin.h>
#include "crypton_cpu.h"

/*
 * The instructions are an extension, so a translation unit compiled for the
 * x86-64 baseline may not use them; see cbits/sha256_x86.c for the whole of
 * that argument.  SSE4.1 and SSSE3 come along for the same reasons there.
 */
#ifdef WITH_TARGET_ATTRIBUTES
#define TARGET_X86_SHA __attribute__((target("sha,sse4.1,ssse3")))
#else
#define TARGET_X86_SHA
#endif

/*
 * A group of four rounds, and the schedule that goes with it.
 *
 * SHA1RNDS4 takes the four state words in one register -- A in the top lane,
 * which is why both the state and each block are loaded reversed -- and the
 * four message words with E already added into the first, which is what
 * SHA1NEXTE produces from the state as it stood four rounds ago.  The round
 * function and constant come from the immediate: 0 for rounds 0 to 19, then
 * one per twenty.
 *
 * The schedule is the exclusive or of four earlier words rotated left by one.
 * SHA1MSG1 does the part that reaches furthest back, the exclusive or with
 * the word eight before is an ordinary one, and SHA1MSG2 does the last part
 * together with the rotation and the dependency inside the group of four.
 */
#define GROUP(imm, ecur, enext, w0, w1, w2, w3)                              \
	do {                                                                 \
		ecur = _mm_sha1nexte_epu32(ecur, w0);                        \
		enext = abcd;                                                \
		w1 = _mm_sha1msg2_epu32(w1, w0);                             \
		abcd = _mm_sha1rnds4_epu32(abcd, ecur, imm);                 \
		w3 = _mm_sha1msg1_epu32(w3, w0);                             \
		w2 = _mm_xor_si128(w2, w0);                                  \
	} while (0)

/* the same without the part of the schedule that has run out */
#define GROUP_NOMSG1(imm, ecur, enext, w0, w1, w2)                           \
	do {                                                                 \
		ecur = _mm_sha1nexte_epu32(ecur, w0);                        \
		enext = abcd;                                                \
		w1 = _mm_sha1msg2_epu32(w1, w0);                             \
		abcd = _mm_sha1rnds4_epu32(abcd, ecur, imm);                 \
		w2 = _mm_xor_si128(w2, w0);                                  \
	} while (0)

#define GROUP_MSG2(imm, ecur, enext, w0, w1)                                 \
	do {                                                                 \
		ecur = _mm_sha1nexte_epu32(ecur, w0);                        \
		enext = abcd;                                                \
		w1 = _mm_sha1msg2_epu32(w1, w0);                             \
		abcd = _mm_sha1rnds4_epu32(abcd, ecur, imm);                 \
	} while (0)

#define GROUP_ROUNDS(imm, ecur, enext, w0)                                   \
	do {                                                                 \
		ecur = _mm_sha1nexte_epu32(ecur, w0);                        \
		enext = abcd;                                                \
		abcd = _mm_sha1rnds4_epu32(abcd, ecur, imm);                 \
	} while (0)

/*
 * One 64-byte block.  `state` is the five words of chaining value in host
 * order, `buf` the block as it arrived, which SHA-1 reads big-endian.
 */
TARGET_X86_SHA
void crypton_sha1_x86_do_chunk(uint32_t state[5], const uint32_t buf[16])
{
	/* the whole register reversed, which byte-swaps each word and puts
	 * the first of them in the top lane */
	const __m128i bswap = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8,
	                                    7, 6, 5, 4, 3, 2, 1, 0);
	__m128i abcd, e0, e1, abcd_prev, e_prev;
	__m128i m0, m1, m2, m3;

	abcd = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *) state), 0x1b);
	e0 = _mm_set_epi32((int) state[4], 0, 0, 0);
	abcd_prev = abcd;
	e_prev = e0;

	m0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) buf), bswap);
	m1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) (buf + 4)), bswap);
	m2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) (buf + 8)), bswap);
	m3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) (buf + 12)), bswap);

	/* rounds 0 to 15, where the schedule has nothing to extend yet: the
	 * first group takes E by an ordinary addition rather than SHA1NEXTE,
	 * there being no state from four rounds ago */
	e0 = _mm_add_epi32(e0, m0);
	e1 = abcd;
	abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);

	e1 = _mm_sha1nexte_epu32(e1, m1);
	e0 = abcd;
	abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
	m0 = _mm_sha1msg1_epu32(m0, m1);

	e0 = _mm_sha1nexte_epu32(e0, m2);
	e1 = abcd;
	abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
	m1 = _mm_sha1msg1_epu32(m1, m2);
	m0 = _mm_xor_si128(m0, m2);

	GROUP(0, e1, e0, m3, m0, m1, m2);

	/* rounds 16 to 63, where every group both hashes and schedules; the
	 * four message registers come back to the same roles every fourth
	 * group, and the round function changes every twentieth round */
	GROUP(0, e0, e1, m0, m1, m2, m3);
	GROUP(1, e1, e0, m1, m2, m3, m0);
	GROUP(1, e0, e1, m2, m3, m0, m1);
	GROUP(1, e1, e0, m3, m0, m1, m2);
	GROUP(1, e0, e1, m0, m1, m2, m3);
	GROUP(1, e1, e0, m1, m2, m3, m0);
	GROUP(2, e0, e1, m2, m3, m0, m1);
	GROUP(2, e1, e0, m3, m0, m1, m2);
	GROUP(2, e0, e1, m0, m1, m2, m3);
	GROUP(2, e1, e0, m1, m2, m3, m0);
	GROUP(2, e0, e1, m2, m3, m0, m1);
	GROUP(3, e1, e0, m3, m0, m1, m2);

	/* rounds 64 to 79, where the schedule runs out a piece at a time.  The
	 * first of these still extends: the part of the last four words that
	 * reaches sixteen back is taken here, three groups before they are
	 * finished */
	GROUP(3, e0, e1, m0, m1, m2, m3);
	GROUP_NOMSG1(3, e1, e0, m1, m2, m3);
	GROUP_MSG2(3, e0, e1, m2, m3);
	GROUP_ROUNDS(3, e1, e0, m3);

	/* and the chaining value, E through the same instruction that would
	 * have carried it into a fifth round */
	e0 = _mm_sha1nexte_epu32(e0, e_prev);
	abcd = _mm_add_epi32(abcd, abcd_prev);

	_mm_storeu_si128((__m128i *) state, _mm_shuffle_epi32(abcd, 0x1b));
	state[4] = (uint32_t) _mm_extract_epi32(e0, 3);
}
