/*
 * SHA-256 using the ARMv8-A cryptographic extensions.
 *
 * crypton_sha256.c computes the compression function a round at a time in
 * plain C.  AArch64 has instructions for it -- SHA256H, SHA256H2, SHA256SU0
 * and SHA256SU1 -- which do four rounds at a time and compute the message
 * schedule alongside.  This provides that version; crypton_sha256.c picks
 * between the two at runtime.
 *
 * SHA-224 shares the compression function, so it comes along for free.
 */

#include <stdint.h>
#include <arm_neon.h>
#if defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

/*
 * The SHA-2 instructions are an extension, so a translation unit compiled for
 * baseline ARMv8-A may not use them.  Mark the function that does, the way
 * cbits/aes/x86ni.h marks its x86 counterparts, rather than raising
 * -march for every file in the library: the flag use_target_attributes picks
 * between the two, and with it set -- which is the default -- nothing else
 * enables the extensions, so without these the file does not compile at all on
 * a toolchain whose baseline lacks them.  Apple's does not lack them, which is
 * why only Linux noticed.
 *
 * "+crypto" rather than "crypto": GCC rejects the latter.
 */
#ifdef WITH_TARGET_ATTRIBUTES
#define TARGET_ARMV8_CRYPTO __attribute__((target("+crypto")))
#else
#define TARGET_ARMV8_CRYPTO
#endif

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
 * One 64-byte block.  `state` is the eight words of chaining value in host
 * order, `buf` the block as it arrived, which SHA-256 reads big-endian.
 */
TARGET_ARMV8_CRYPTO
void crypton_sha256_armv8_do_chunk(uint32_t state[8], const uint32_t buf[16])
{
	uint32x4_t abcd, efgh, abcd_prev, efgh_prev, abcd_save, tmp;
	uint32x4_t m0, m1, m2, m3;
	int i;

	abcd_prev = abcd = vld1q_u32(state);
	efgh_prev = efgh = vld1q_u32(state + 4);

	m0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(buf))));
	m1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(buf + 4))));
	m2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(buf + 8))));
	m3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(buf + 12))));

	/* twelve groups of four rounds that also extend the schedule ... */
	for (i = 0; i < 48; i += 16) {
		uint32x4_t n0, n1, n2, n3;

		n0 = vsha256su1q_u32(vsha256su0q_u32(m0, m1), m2, m3);
		tmp = vaddq_u32(m0, vld1q_u32(&K[i]));
		abcd_save = abcd;
		abcd = vsha256hq_u32(abcd, efgh, tmp);
		efgh = vsha256h2q_u32(efgh, abcd_save, tmp);

		n1 = vsha256su1q_u32(vsha256su0q_u32(m1, m2), m3, n0);
		tmp = vaddq_u32(m1, vld1q_u32(&K[i + 4]));
		abcd_save = abcd;
		abcd = vsha256hq_u32(abcd, efgh, tmp);
		efgh = vsha256h2q_u32(efgh, abcd_save, tmp);

		n2 = vsha256su1q_u32(vsha256su0q_u32(m2, m3), n0, n1);
		tmp = vaddq_u32(m2, vld1q_u32(&K[i + 8]));
		abcd_save = abcd;
		abcd = vsha256hq_u32(abcd, efgh, tmp);
		efgh = vsha256h2q_u32(efgh, abcd_save, tmp);

		n3 = vsha256su1q_u32(vsha256su0q_u32(m3, n0), n1, n2);
		tmp = vaddq_u32(m3, vld1q_u32(&K[i + 12]));
		abcd_save = abcd;
		abcd = vsha256hq_u32(abcd, efgh, tmp);
		efgh = vsha256h2q_u32(efgh, abcd_save, tmp);

		m0 = n0; m1 = n1; m2 = n2; m3 = n3;
	}

	/* ... and the last four, where there is no more schedule to extend */
	tmp = vaddq_u32(m0, vld1q_u32(&K[48]));
	abcd_save = abcd;
	abcd = vsha256hq_u32(abcd, efgh, tmp);
	efgh = vsha256h2q_u32(efgh, abcd_save, tmp);

	tmp = vaddq_u32(m1, vld1q_u32(&K[52]));
	abcd_save = abcd;
	abcd = vsha256hq_u32(abcd, efgh, tmp);
	efgh = vsha256h2q_u32(efgh, abcd_save, tmp);

	tmp = vaddq_u32(m2, vld1q_u32(&K[56]));
	abcd_save = abcd;
	abcd = vsha256hq_u32(abcd, efgh, tmp);
	efgh = vsha256h2q_u32(efgh, abcd_save, tmp);

	tmp = vaddq_u32(m3, vld1q_u32(&K[60]));
	abcd_save = abcd;
	abcd = vsha256hq_u32(abcd, efgh, tmp);
	efgh = vsha256h2q_u32(efgh, abcd_save, tmp);

	vst1q_u32(state, vaddq_u32(abcd, abcd_prev));
	vst1q_u32(state + 4, vaddq_u32(efgh, efgh_prev));
}

/*
 * The SHA-2 instructions are optional in ARMv8.0.  They are always there on
 * Apple silicon; elsewhere the kernel reports them.
 */
int crypton_sha256_armv8_available(void)
{
#if defined(__APPLE__)
	return 1;
#elif defined(__linux__)
	return (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
#else
	return 0;
#endif
}
