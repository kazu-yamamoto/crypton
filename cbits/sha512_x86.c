/*
 * SHA-512's message schedule with AVX2, computed alongside the rounds.
 *
 * x86 has no instruction for the SHA-512 compression function the way it now
 * has one for SHA-256, and the rounds are a chain that cannot be spread over
 * lanes: each one waits for the one before it.  The schedule is a different
 * matter.  It is a quarter of the work, four words of it can be computed at a
 * time, and nothing in it depends on the chaining value -- so it can go into
 * the vector registers and run alongside rounds that need the scalar ones.
 *
 * Removing the schedule entirely, which gives the wrong answer but says what
 * there is to win, took 352.8 MB/s to 496.4 on the machine measured.
 *
 * The shape is the one OpenSSL's assembly uses: four schedule words computed
 * per four rounds, sixteen rounds behind, so that a word is ready well before
 * the round that reads it.
 */

#include <stdint.h>
#include <string.h>
#include <immintrin.h>
#include "crypton_cpu.h"

/*
 * AVX2 is not part of any baseline, so this is reached only after
 * crypton_x86_simd_features() has said the CPU has it and the operating
 * system saves the wider registers.  As with cbits/chacha_avx2.c, it is here
 * only when the compiler will take the attribute; without it the file is
 * empty and the generic schedule stands.
 */
#ifdef WITH_TARGET_ATTRIBUTES

#define TARGET_AVX2 __attribute__((target("avx2")))

/* 2^64 times the fractional part of the cube roots of the first 80 primes, as
 * crypton_sha512.c has them */
static const uint64_t K[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
	0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
	0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
	0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
	0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
	0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
	0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
	0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
	0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
	0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
	0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
	0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
	0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
	0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

#define ROR64V(x, n)                                                         \
	_mm256_or_si256(_mm256_srli_epi64((x), (n)),                         \
	                _mm256_slli_epi64((x), 64 - (n)))

#define SIGMA0V(x)                                                           \
	_mm256_xor_si256(_mm256_xor_si256(ROR64V((x), 1), ROR64V((x), 8)),   \
	                 _mm256_srli_epi64((x), 7))

#define SIGMA1V(x)                                                           \
	_mm256_xor_si256(_mm256_xor_si256(ROR64V((x), 19), ROR64V((x), 61)), \
	                 _mm256_srli_epi64((x), 6))

/*
 * {a1, a2, a3, b0}: the four words starting one past a.  AVX2's byte-wise
 * shift works inside each 128-bit half, so the halves have to be brought
 * together first.
 */
TARGET_AVX2
static inline __m256i step_one(__m256i a, __m256i b)
{
	return _mm256_alignr_epi8(_mm256_permute2x128_si256(a, b, 0x21), a, 8);
}

/*
 * The four words after the sixteen in x0 .. x3, which is
 *
 *   W[i] = W[i-16] + s0(W[i-15]) + W[i-7] + s1(W[i-2])
 *
 * with x0 holding W[i-16] .. W[i-13].  Everything but the last term is a
 * lane-wise sum; the last one reaches back two words, so the first two of the
 * four take it from x3 and the other two from the two just computed.
 */
TARGET_AVX2
static inline __m256i schedule4(__m256i x0, __m256i x1, __m256i x2, __m256i x3)
{
	const __m256i zero = _mm256_setzero_si256();
	__m256i p, t;

	p = _mm256_add_epi64(x0, SIGMA0V(step_one(x0, x1)));
	p = _mm256_add_epi64(p, step_one(x2, x3));

	/* s1 of W[i-2] and W[i-1], into the first two words */
	t = SIGMA1V(_mm256_permute4x64_epi64(x3, 0xfa));
	t = _mm256_permute4x64_epi64(t, 0x88);
	p = _mm256_add_epi64(p, _mm256_blend_epi32(zero, t, 0x0f));

	/* and of those two words, into the other two */
	t = SIGMA1V(_mm256_permute4x64_epi64(p, 0x50));
	t = _mm256_permute4x64_epi64(t, 0x88);
	return _mm256_add_epi64(p, _mm256_blend_epi32(zero, t, 0xf0));
}

#define e0(x) (ror64_(x, 28) ^ ror64_(x, 34) ^ ror64_(x, 39))
#define e1(x) (ror64_(x, 14) ^ ror64_(x, 18) ^ ror64_(x, 41))

static inline uint64_t ror64_(uint64_t x, unsigned n)
{
	return (x >> n) | (x << (64 - n));
}

/* one round, as crypton_sha512.c writes it */
#define R(a, b, c, d, e, f, g, h, i)                                         \
	t1 = h + e1(e) + (g ^ (e & (f ^ g))) + K[i] + w[i];                  \
	t2 = e0(a) + ((a & b) | (c & (a | b)));                              \
	d += t1;                                                             \
	h = t1 + t2

/* eight rounds from index i, after which the eight working words are back
 * in the roles their names give them */
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

/*
 * One 128-byte block.  `state` is the eight words of chaining value in host
 * order, `buf` the block as it arrived, which SHA-512 reads big-endian.
 */
TARGET_AVX2
void crypton_sha512_avx2_do_chunk(uint64_t state[8], const uint64_t buf[16])
{
	const __m256i bswap = _mm256_setr_epi8(
	    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
	    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
	uint64_t w[80];
	uint64_t a, b, c, d, e, f, g, h, t1, t2;
	__m256i x0, x1, x2, x3;
	int i;

	x0 = _mm256_shuffle_epi8(
	    _mm256_loadu_si256((const __m256i *) buf), bswap);
	x1 = _mm256_shuffle_epi8(
	    _mm256_loadu_si256((const __m256i *) (buf + 4)), bswap);
	x2 = _mm256_shuffle_epi8(
	    _mm256_loadu_si256((const __m256i *) (buf + 8)), bswap);
	x3 = _mm256_shuffle_epi8(
	    _mm256_loadu_si256((const __m256i *) (buf + 12)), bswap);
	_mm256_storeu_si256((__m256i *) w, x0);
	_mm256_storeu_si256((__m256i *) (w + 4), x1);
	_mm256_storeu_si256((__m256i *) (w + 8), x2);
	_mm256_storeu_si256((__m256i *) (w + 12), x3);

	a = state[0]; b = state[1]; c = state[2]; d = state[3];
	e = state[4]; f = state[5]; g = state[6]; h = state[7];

	/* eight words of schedule per eight rounds, sixteen rounds behind */
	for (i = 16; i < 80; i += 8) {
		__m256i n0 = schedule4(x0, x1, x2, x3);
		__m256i n1 = schedule4(x1, x2, x3, n0);

		_mm256_storeu_si256((__m256i *) (w + i), n0);
		_mm256_storeu_si256((__m256i *) (w + i + 4), n1);
		x0 = x2; x1 = x3; x2 = n0; x3 = n1;

		R8(i - 16);
	}

	/* and the sixteen rounds the schedule ran ahead of */
	R8(64);
	R8(72);

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

#endif /* WITH_TARGET_ATTRIBUTES */
