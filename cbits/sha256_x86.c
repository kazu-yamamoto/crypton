/*
 * SHA-256 using the Intel SHA extensions.
 *
 * crypton_sha256.c computes the compression function a round at a time in
 * plain C.  x86 has instructions for it -- SHA256RNDS2, SHA256MSG1 and
 * SHA256MSG2 -- which do two rounds at a time and help with the message
 * schedule alongside.  This provides that version; crypton_sha256.c picks
 * between the two at runtime.
 *
 * SHA-224 shares the compression function, so it comes along for free.
 *
 * The extensions arrived with Goldmont and Ice Lake at Intel and with Zen at
 * AMD, so they are a good deal less universal than the AES ones: a processor
 * without them is ordinary, not ancient, and the plain C has to stay.
 */

#include <stdint.h>
#include <immintrin.h>
#include "crypton_cpu.h"

/*
 * The instructions are an extension, so a translation unit compiled for the
 * x86-64 baseline may not use them.  Mark the function that does, the way
 * cbits/aes/x86ni.h marks its counterparts, rather than raising the baseline
 * for every file in the library: the flag use_target_attributes picks between
 * the two, and with it set -- which is the default -- nothing else enables
 * the extensions.
 *
 * SSE4.1 comes along for the blend that splits the state, and SSSE3 for the
 * byte shuffle that swaps the block into big-endian order.  Every processor
 * with the SHA extensions has both, but the compiler still has to be told.
 */
#ifdef WITH_TARGET_ATTRIBUTES
#define TARGET_X86_SHA __attribute__((target("sha,sse4.1,ssse3")))
#else
#define TARGET_X86_SHA
#endif

/* 2^32 times the cube root of the first 64 primes, as crypton_sha256.c has
 * them, read four at a time */
static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/*
 * SHA256RNDS2 takes the eight words of state as two registers holding ABEF
 * and CDGH -- not the order they are kept in -- and each instruction does two
 * rounds, so a group of four is two of them with the second pair of round
 * constants shuffled down.
 */
#define ROUNDS4(w, ki)                                                       \
	do {                                                                 \
		__m128i wk = _mm_add_epi32(                                  \
		    (w), _mm_loadu_si128((const __m128i *) &K[ki]));          \
		cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);                \
		wk = _mm_shuffle_epi32(wk, 0x0e);                            \
		abef = _mm_sha256rnds2_epu32(abef, cdgh, wk);                \
	} while (0)

/*
 * The schedule for four rounds sixteen ahead.  SHA256MSG1 does the part that
 * depends on the older words, SHA256MSG2 the part that depends on the two
 * just before -- which is why `prev` is read for the first and written for
 * the second, one group behind `w`.
 */
#define SCHEDULE(w, next, prev)                                              \
	do {                                                                 \
		__m128i lo = _mm_alignr_epi8((w), (prev), 4);                \
		(next) =                                                     \
		    _mm_sha256msg2_epu32(_mm_add_epi32((next), lo), (w));    \
	} while (0)

#define EXTEND(w, prev) (prev) = _mm_sha256msg1_epu32((prev), (w))

/* four rounds and the schedule that goes with them */
#define GROUP(w, next, prev, ki)                                             \
	do {                                                                 \
		ROUNDS4((w), (ki));                                          \
		SCHEDULE((w), (next), (prev));                               \
		EXTEND((w), (prev));                                         \
	} while (0)

/*
 * One 64-byte block.  `state` is the eight words of chaining value in host
 * order, `buf` the block as it arrived, which SHA-256 reads big-endian.
 */
TARGET_X86_SHA
void crypton_sha256_x86_do_chunk(uint32_t state[8], const uint32_t buf[16])
{
	const __m128i bswap = _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4,
	                                    11, 10, 9, 8, 15, 14, 13, 12);
	__m128i abef, cdgh, abef_prev, cdgh_prev, t;
	__m128i m0, m1, m2, m3;
	int i;

	/* state is held as DCBA and HGFE; the instructions want ABEF and CDGH */
	t = _mm_loadu_si128((const __m128i *) state);
	cdgh = _mm_loadu_si128((const __m128i *) (state + 4));
	t = _mm_shuffle_epi32(t, 0xb1);
	cdgh = _mm_shuffle_epi32(cdgh, 0x1b);
	abef = _mm_alignr_epi8(t, cdgh, 8);
	cdgh = _mm_blend_epi16(cdgh, t, 0xf0);

	abef_prev = abef;
	cdgh_prev = cdgh;

	m0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) buf), bswap);
	m1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) (buf + 4)), bswap);
	m2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) (buf + 8)), bswap);
	m3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) (buf + 12)), bswap);

	/* the sixteen rounds the block itself covers: nothing to schedule for
	 * the first two groups, and the first word of schedule falls due in
	 * the fourth */
	ROUNDS4(m0, 0);
	ROUNDS4(m1, 4);
	EXTEND(m1, m0);
	ROUNDS4(m2, 8);
	EXTEND(m2, m1);
	GROUP(m3, m0, m2, 12);

	/* rounds 16 to 47, where every group both hashes and schedules; the
	 * four registers come back to the same roles every fourth group */
	for (i = 16; i < 48; i += 16) {
		GROUP(m0, m1, m3, i);
		GROUP(m1, m2, m0, i + 4);
		GROUP(m2, m3, m1, i + 8);
		GROUP(m3, m0, m2, i + 12);
	}

	/* rounds 48 to 63, where the schedule runs out: the last four words
	 * are extended in the first group here and finished in the third, and
	 * after that there is only hashing left */
	GROUP(m0, m1, m3, 48);
	ROUNDS4(m1, 52);
	SCHEDULE(m1, m2, m0);
	ROUNDS4(m2, 56);
	SCHEDULE(m2, m3, m1);
	ROUNDS4(m3, 60);

	abef = _mm_add_epi32(abef, abef_prev);
	cdgh = _mm_add_epi32(cdgh, cdgh_prev);

	/* and back into the order the context keeps */
	t = _mm_shuffle_epi32(abef, 0x1b);
	cdgh = _mm_shuffle_epi32(cdgh, 0xb1);
	_mm_storeu_si128((__m128i *) state, _mm_blend_epi16(t, cdgh, 0xf0));
	_mm_storeu_si128((__m128i *) (state + 4), _mm_alignr_epi8(cdgh, t, 8));
}
