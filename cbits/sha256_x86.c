/*
 * SHA-256's x86 paths: the Intel SHA extensions where the processor has them,
 * and the message schedule in SSE registers where it does not.
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
#define TARGET_X86_SSSE3 __attribute__((target("ssse3")))
#else
#define TARGET_X86_SHA
#define TARGET_X86_SSSE3
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

/*
 * The same hash on a processor without the extensions, which is an ordinary
 * one: they arrived with Goldmont and Ice Lake at Intel and with Zen at AMD,
 * and the Ice Lake and Cascade Lake server parts do not have them at all.
 *
 * The rounds are a chain and stay scalar.  The message schedule is not: it is
 * a quarter of the work, four words of it can be computed at a time, and
 * nothing in it depends on the chaining value, so it goes into the SSE
 * registers and runs alongside rounds that need the general ones.  Computing
 * four words per four rounds, sixteen rounds ahead of where they are read, is
 * the arrangement OpenSSL's assembly uses.
 */
#define ROR32V(x, n)                                                         \
	_mm_or_si128(_mm_srli_epi32((x), (n)), _mm_slli_epi32((x), 32 - (n)))

#define SIGMA0V(x)                                                           \
	_mm_xor_si128(_mm_xor_si128(ROR32V((x), 7), ROR32V((x), 18)),        \
	              _mm_srli_epi32((x), 3))

#define SIGMA1V(x)                                                           \
	_mm_xor_si128(_mm_xor_si128(ROR32V((x), 17), ROR32V((x), 19)),       \
	              _mm_srli_epi32((x), 10))

/*
 * The four words after the sixteen in x0 .. x3, which is
 *
 *   W[i] = W[i-16] + s0(W[i-15]) + W[i-7] + s1(W[i-2])
 *
 * with x0 holding W[i-16] .. W[i-13].  Everything but the last term is a
 * lane-wise sum; that one reaches back two words, so the first two of the four
 * take it from x3 and the other two from the two just computed.
 */
TARGET_X86_SSSE3
static inline __m128i schedule4(__m128i x0, __m128i x1, __m128i x2, __m128i x3)
{
	const __m128i zero = _mm_setzero_si128();
	__m128i p, t;

	p = _mm_add_epi32(x0, SIGMA0V(_mm_alignr_epi8(x1, x0, 4)));
	p = _mm_add_epi32(p, _mm_alignr_epi8(x3, x2, 4));

	/* s1 of W[i-2] and W[i-1], into the first two words */
	t = SIGMA1V(_mm_shuffle_epi32(x3, 0xfa));
	t = _mm_shuffle_epi32(t, 0x88);
	p = _mm_add_epi32(p, _mm_unpacklo_epi64(t, zero));

	/* and of those two words, into the other two */
	t = SIGMA1V(_mm_shuffle_epi32(p, 0x50));
	t = _mm_shuffle_epi32(t, 0x88);
	return _mm_add_epi32(p, _mm_unpacklo_epi64(zero, t));
}

static inline uint32_t ror32_(uint32_t x, unsigned n)
{
	return (x >> n) | (x << (32 - n));
}

#define e0(x) (ror32_(x, 2) ^ ror32_(x, 13) ^ ror32_(x, 22))
#define e1(x) (ror32_(x, 6) ^ ror32_(x, 11) ^ ror32_(x, 25))

/* one round, as crypton_sha256.c writes it */
#define R(a, b, c, d, e, f, g, h, i)                                         \
	t1 = h + e1(e) + (g ^ (e & (f ^ g))) + K[i] + w[i];                  \
	t2 = e0(a) + ((a & b) | (c & (a | b)));                              \
	d += t1;                                                             \
	h = t1 + t2

/* eight rounds from index i, after which the eight working words are back in
 * the roles their names give them */
#define R8(i)                                                                \
	do {                                                                 \
		R(a, b, c, d, e, f, g, h, (i) + 0);                          \
		R(h, a, b, c, d, e, f, g, (i) + 1);                          \
		R(g, h, a, b, c, d, e, f, (i) + 2);                          \
		R(f, g, h, a, b, c, d, e, (i) + 3);                          \
		R(e, f, g, h, a, b, c, d, (i) + 4);                          \
		R(d, e, f, g, h, a, b, c, (i) + 5);                          \
		R(c, d, e, f, g, h, a, b, (i) + 6);                          \
		R(b, c, d, e, f, g, h, a, (i) + 7);                          \
	} while (0)

TARGET_X86_SSSE3
void crypton_sha256_ssse3_do_chunk(uint32_t state[8], const uint32_t buf[16])
{
	const __m128i bswap = _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4,
	                                    11, 10, 9, 8, 15, 14, 13, 12);
	uint32_t w[64];
	uint32_t a, b, c, d, e, f, g, h, t1, t2;
	__m128i x0, x1, x2, x3;
	int i;

	x0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) buf), bswap);
	x1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) (buf + 4)), bswap);
	x2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) (buf + 8)), bswap);
	x3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) (buf + 12)), bswap);
	_mm_storeu_si128((__m128i *) w, x0);
	_mm_storeu_si128((__m128i *) (w + 4), x1);
	_mm_storeu_si128((__m128i *) (w + 8), x2);
	_mm_storeu_si128((__m128i *) (w + 12), x3);

	a = state[0]; b = state[1]; c = state[2]; d = state[3];
	e = state[4]; f = state[5]; g = state[6]; h = state[7];

	/* eight words of schedule per eight rounds, sixteen rounds behind */
	for (i = 16; i < 64; i += 8) {
		__m128i n0 = schedule4(x0, x1, x2, x3);
		__m128i n1 = schedule4(x1, x2, x3, n0);

		_mm_storeu_si128((__m128i *) (w + i), n0);
		_mm_storeu_si128((__m128i *) (w + i + 4), n1);
		x0 = x2; x1 = x3; x2 = n0; x3 = n1;

		R8(i - 16);
	}

	/* and the sixteen rounds the schedule ran ahead of */
	R8(48);
	R8(56);

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}
