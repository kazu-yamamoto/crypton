/*
 * Keccak-f[1600] using the ARMv8.2 SHA-3 instructions.
 *
 * crypton_sha3.c runs the permutation in plain C, a round at a time over a
 * table of rotation amounts and lane positions.  AArch64 has four
 * instructions that exist for exactly this:
 *
 *   EOR3  a ^ b ^ c            the column parities of theta
 *   RAX1  a ^ ROL(b, 1)        the rest of theta
 *   XAR   ROR(a ^ b, n)        theta's exclusive or and rho's rotation at once
 *   BCAX  a ^ (b & ~c)         chi
 *
 * They work on 128-bit registers and the permutation has twenty-five 64-bit
 * lanes, so each lane sits in the low half of a register and the high half
 * goes unused.  Rho and pi move one lane of every row into every other row,
 * so the round cannot be done in place: the twenty-five rotated words are
 * computed first and chi then writes the state from them.
 *
 * The body is generated from the definitions in FIPS 202 rather than copied
 * in: the rotation amounts are the triangular numbers modulo 64, pi sends
 * lane (x, y) to (y, 2x + 3y), and the script that worked those out checked
 * the result against the published digests of the empty string and of "abc"
 * before emitting any of this.
 */

#include <stdint.h>
#include <arm_neon.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

/*
 * The SHA-3 instructions are an ARMv8.2 extension, so a translation unit
 * compiled for the baseline may not use them; see sha256_armv8.c for the whole
 * of that argument.  The flag for a build without attributes already asks for
 * "+sha3", which the SHA-512 path needed.
 */
#ifdef WITH_TARGET_ATTRIBUTES
#define TARGET_ARMV8_SHA3 __attribute__((target("+sha3")))
#else
#define TARGET_ARMV8_SHA3
#endif

static const uint64_t rc[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

#define ROUND(k)                                                             \
	do {                                                                 \
	/* theta: the parity of each column, and what it adds */           \
	c[0] = veor3q_u64(a[0], a[5], a[10]);                              \
	c[0] = veor3q_u64(c[0], a[15], a[20]);                             \
	c[1] = veor3q_u64(a[1], a[6], a[11]);                              \
	c[1] = veor3q_u64(c[1], a[16], a[21]);                             \
	c[2] = veor3q_u64(a[2], a[7], a[12]);                              \
	c[2] = veor3q_u64(c[2], a[17], a[22]);                             \
	c[3] = veor3q_u64(a[3], a[8], a[13]);                              \
	c[3] = veor3q_u64(c[3], a[18], a[23]);                             \
	c[4] = veor3q_u64(a[4], a[9], a[14]);                              \
	c[4] = veor3q_u64(c[4], a[19], a[24]);                             \
	d[0] = vrax1q_u64(c[4], c[1]);                                     \
	d[1] = vrax1q_u64(c[0], c[2]);                                     \
	d[2] = vrax1q_u64(c[1], c[3]);                                     \
	d[3] = vrax1q_u64(c[2], c[4]);                                     \
	d[4] = vrax1q_u64(c[3], c[0]);                                     \
	/* theta's exclusive or, rho's rotation and pi's move, in one */   \
	b[0 ] = veorq_u64(a[0 ], d[0]);                                    \
	b[1 ] = vxarq_u64(a[6 ], d[1], 20);                                \
	b[2 ] = vxarq_u64(a[12], d[2], 21);                                \
	b[3 ] = vxarq_u64(a[18], d[3], 43);                                \
	b[4 ] = vxarq_u64(a[24], d[4], 50);                                \
	b[5 ] = vxarq_u64(a[3 ], d[3], 36);                                \
	b[6 ] = vxarq_u64(a[9 ], d[4], 44);                                \
	b[7 ] = vxarq_u64(a[10], d[0], 61);                                \
	b[8 ] = vxarq_u64(a[16], d[1], 19);                                \
	b[9 ] = vxarq_u64(a[22], d[2],  3);                                \
	b[10] = vxarq_u64(a[1 ], d[1], 63);                                \
	b[11] = vxarq_u64(a[7 ], d[2], 58);                                \
	b[12] = vxarq_u64(a[13], d[3], 39);                                \
	b[13] = vxarq_u64(a[19], d[4], 56);                                \
	b[14] = vxarq_u64(a[20], d[0], 46);                                \
	b[15] = vxarq_u64(a[4 ], d[4], 37);                                \
	b[16] = vxarq_u64(a[5 ], d[0], 28);                                \
	b[17] = vxarq_u64(a[11], d[1], 54);                                \
	b[18] = vxarq_u64(a[17], d[2], 49);                                \
	b[19] = vxarq_u64(a[23], d[3],  8);                                \
	b[20] = vxarq_u64(a[2 ], d[2],  2);                                \
	b[21] = vxarq_u64(a[8 ], d[3],  9);                                \
	b[22] = vxarq_u64(a[14], d[4], 25);                                \
	b[23] = vxarq_u64(a[15], d[0], 23);                                \
	b[24] = vxarq_u64(a[21], d[1], 62);                                \
	/* chi, along each row */                                          \
	a[0 ] = vbcaxq_u64(b[0 ], b[2 ], b[1 ]);                           \
	a[1 ] = vbcaxq_u64(b[1 ], b[3 ], b[2 ]);                           \
	a[2 ] = vbcaxq_u64(b[2 ], b[4 ], b[3 ]);                           \
	a[3 ] = vbcaxq_u64(b[3 ], b[0 ], b[4 ]);                           \
	a[4 ] = vbcaxq_u64(b[4 ], b[1 ], b[0 ]);                           \
	a[5 ] = vbcaxq_u64(b[5 ], b[7 ], b[6 ]);                           \
	a[6 ] = vbcaxq_u64(b[6 ], b[8 ], b[7 ]);                           \
	a[7 ] = vbcaxq_u64(b[7 ], b[9 ], b[8 ]);                           \
	a[8 ] = vbcaxq_u64(b[8 ], b[5 ], b[9 ]);                           \
	a[9 ] = vbcaxq_u64(b[9 ], b[6 ], b[5 ]);                           \
	a[10] = vbcaxq_u64(b[10], b[12], b[11]);                           \
	a[11] = vbcaxq_u64(b[11], b[13], b[12]);                           \
	a[12] = vbcaxq_u64(b[12], b[14], b[13]);                           \
	a[13] = vbcaxq_u64(b[13], b[10], b[14]);                           \
	a[14] = vbcaxq_u64(b[14], b[11], b[10]);                           \
	a[15] = vbcaxq_u64(b[15], b[17], b[16]);                           \
	a[16] = vbcaxq_u64(b[16], b[18], b[17]);                           \
	a[17] = vbcaxq_u64(b[17], b[19], b[18]);                           \
	a[18] = vbcaxq_u64(b[18], b[15], b[19]);                           \
	a[19] = vbcaxq_u64(b[19], b[16], b[15]);                           \
	a[20] = vbcaxq_u64(b[20], b[22], b[21]);                           \
	a[21] = vbcaxq_u64(b[21], b[23], b[22]);                           \
	a[22] = vbcaxq_u64(b[22], b[24], b[23]);                           \
	a[23] = vbcaxq_u64(b[23], b[20], b[24]);                           \
	a[24] = vbcaxq_u64(b[24], b[21], b[20]);                           \
	/* iota */                                                         \
		a[0] = veorq_u64(a[0], vld1q_dup_u64(&rc[k]));                \
	} while (0)

/* the twenty-four rounds over the state, in place */
TARGET_ARMV8_SHA3
void crypton_sha3_armv8_permute(uint64_t state[25])
{
	uint64x2_t a[25], b[25], c[5], d[5];
	int i, round;

	for (i = 0; i < 25; i++)
		a[i] = vld1q_dup_u64(&state[i]);

	/* four rounds to an iteration: a round is a chain -- the column
	 * parities wait for the last chi of the round before -- so giving the
	 * processor more than one of them to look at is worth something.  One
	 * round an iteration measured 802 MB/s of SHA3-256, two 949 and four
	 * 991, against 551 for the plain C */
	for (round = 0; round < 24; round += 4) {
		ROUND(round);
		ROUND(round + 1);
		ROUND(round + 2);
		ROUND(round + 3);
	}

	for (i = 0; i < 25; i++)
		state[i] = vgetq_lane_u64(a[i], 0);
}

/*
 * Whether the extension is there.  It is on Apple silicon; elsewhere the
 * kernel reports it.
 */
int crypton_sha3_armv8_available(void)
{
#if defined(__APPLE__)
	int v = 0;
	size_t n = sizeof(v);

	if (sysctlbyname("hw.optional.arm.FEAT_SHA3", &v, &n, NULL, 0) != 0)
		return 0;
	return v != 0;
#elif defined(__linux__)
	return (getauxval(AT_HWCAP) & HWCAP_SHA3) != 0;
#else
	return 0;
#endif
}
