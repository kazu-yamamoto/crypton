/*
 * SHA-512 using the ARMv8.2 SHA-512 extension.
 *
 * The same idea as sha256_armv8.c: SHA512H, SHA512H2, SHA512SU0 and
 * SHA512SU1 do two rounds at a time and compute the message schedule
 * alongside.  This extension is a good deal less common than the SHA-256
 * one -- it arrived in ARMv8.2 and is optional there -- so the runtime
 * check matters more here, and it is asked rather than assumed even on
 * Apple, where the SHA-256 one is taken for granted.
 *
 * SHA-384 and the truncated SHA-512/t variants share the compression
 * function, so they come along.
 */

#include <stdint.h>
#include <arm_neon.h>
#if defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif
#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <string.h>
#endif

/*
 * The instructions are an extension, so a translation unit compiled for
 * baseline ARMv8-A may not use them; mark the function that does.  The
 * SHA-512 instructions live behind "+sha3" in both GCC and clang.
 */
#ifdef WITH_TARGET_ATTRIBUTES
#define TARGET_ARMV8_SHA3 __attribute__((target("+sha3")))
#else
#define TARGET_ARMV8_SHA3
#endif

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

/*
 * One 128-byte block.  `state` is the eight words of chaining value in host
 * order, `buf` the block as it arrived, which SHA-512 reads big-endian.
 *
 * ab, cd, ef and gh hold the working variables in pairs.  Each step covers
 * two rounds and rotates which pair plays which part, so four steps return
 * to the start; a group of eight steps is one pass over the schedule.
 */
TARGET_ARMV8_SHA3
void crypton_sha512_armv8_do_chunk(uint64_t state[8], const uint64_t buf[16])
{
	uint64x2_t ab, cd, ef, gh, ab0, cd0, ef0, gh0;
	uint64x2_t s[8];
	int i;

	ab0 = ab = vld1q_u64(state);
	cd0 = cd = vld1q_u64(state + 2);
	ef0 = ef = vld1q_u64(state + 4);
	gh0 = gh = vld1q_u64(state + 6);

	for (i = 0; i < 8; i++)
		s[i] = vreinterpretq_u64_u8(vrev64q_u8(
		    vld1q_u8((const uint8_t *) (buf + 2 * i))));

/* two rounds; A, B, C, D is a rotation of gh, ef, cd, ab */
#define RND(A, B, C, D, sv, ki)                                             \
	do {                                                                \
		uint64x2_t is_ = vaddq_u64((sv), vld1q_u64(&K[ki]));        \
		uint64x2_t sum_ = vaddq_u64(vextq_u64(is_, is_, 1), (A));   \
		uint64x2_t im_ = vsha512hq_u64(sum_, vextq_u64((B), (A), 1),\
		                               vextq_u64((C), (B), 1));     \
		(A) = vsha512h2q_u64(im_, (C), (D));                        \
		(C) = vaddq_u64((C), im_);                                  \
	} while (0)

/* extend the schedule in place, for the next sixteen rounds */
#define SCHED(j)                                                            \
	s[j] = vsha512su1q_u64(vsha512su0q_u64(s[j], s[((j) + 1) & 7]),     \
	                       s[((j) + 7) & 7],                            \
	                       vextq_u64(s[((j) + 4) & 7], s[((j) + 5) & 7], 1))

#define PASS(base)                                       \
	SCHED(0); RND(gh, ef, cd, ab, s[0], (base) +  0); \
	SCHED(1); RND(ef, cd, ab, gh, s[1], (base) +  2); \
	SCHED(2); RND(cd, ab, gh, ef, s[2], (base) +  4); \
	SCHED(3); RND(ab, gh, ef, cd, s[3], (base) +  6); \
	SCHED(4); RND(gh, ef, cd, ab, s[4], (base) +  8); \
	SCHED(5); RND(ef, cd, ab, gh, s[5], (base) + 10); \
	SCHED(6); RND(cd, ab, gh, ef, s[6], (base) + 12); \
	SCHED(7); RND(ab, gh, ef, cd, s[7], (base) + 14)

	/* rounds 0..15 run straight off the message */
	RND(gh, ef, cd, ab, s[0],  0);
	RND(ef, cd, ab, gh, s[1],  2);
	RND(cd, ab, gh, ef, s[2],  4);
	RND(ab, gh, ef, cd, s[3],  6);
	RND(gh, ef, cd, ab, s[4],  8);
	RND(ef, cd, ab, gh, s[5], 10);
	RND(cd, ab, gh, ef, s[6], 12);
	RND(ab, gh, ef, cd, s[7], 14);

	PASS(16);
	PASS(32);
	PASS(48);
	PASS(64);

#undef PASS
#undef SCHED
#undef RND

	vst1q_u64(state,     vaddq_u64(ab, ab0));
	vst1q_u64(state + 2, vaddq_u64(cd, cd0));
	vst1q_u64(state + 4, vaddq_u64(ef, ef0));
	vst1q_u64(state + 6, vaddq_u64(gh, gh0));
}

/*
 * Whether the extension is there.  Unlike the SHA-256 one this is not
 * something to take for granted anywhere, so both platforms are asked.
 */
int crypton_sha512_armv8_available(void)
{
#if defined(__APPLE__)
	int v = 0;
	size_t n = sizeof(v);

	if (sysctlbyname("hw.optional.arm.FEAT_SHA512", &v, &n, NULL, 0) != 0)
		return 0;
	return v != 0;
#elif defined(__linux__)
	return (getauxval(AT_HWCAP) & HWCAP_SHA512) != 0;
#else
	return 0;
#endif
}
