/*
 * Ed25519's base point multiplication through the vendored s2n-bignum.
 *
 * Signing does this twice: once for the nonce's point R, and once for the
 * public key, which crypton derives from the secret key at every signature
 * rather than trusting the one it is handed.  Both go through here, so both
 * halves of a signature move at once.
 *
 * Measured on an Apple M4, one multiplication with the encoding:
 * ed25519-donna 7.5 us against s2n-bignum 3.5.
 */
#include <string.h>

#include "ed25519/ed25519_s2n.h"

#if defined(CRYPTON_S2N_BIGNUM) && defined(__BYTE_ORDER__) \
    && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define CRYPTON_ED25519_S2N 1
#include "crypton_cpu.h"

extern void edwards25519_scalarmulbase(uint64_t res[8],
                                       const uint64_t scalar[4]);
extern void edwards25519_scalarmulbase_alt(uint64_t res[8],
                                           const uint64_t scalar[4]);
extern void edwards25519_encode(uint8_t z[32], const uint64_t p[8]);

/* The same question as everywhere else in cbits/s2n: a microarchitecture one
 * on ARM that no feature bit answers, and exactly a feature bit on x86-64. */
static int use_alt(void)
{
#if defined(__aarch64__) || defined(__arm64__)
#ifdef __APPLE__
	return 1;
#else
	return 0;
#endif
#else
	return (crypton_x86_simd_features() & CRYPTON_X86_ADX) == 0;
#endif
}
#endif

int crypton_ed25519_base_mult(uint8_t out[32], const uint8_t scalar[32])
{
#ifdef CRYPTON_ED25519_S2N
	/* the assembly takes four little-endian 64-bit words, which is the
	 * same bits as the 32 little-endian bytes the scalar is kept in */
	uint64_t s[4], p[8];

	memcpy(s, scalar, 32);
	if (use_alt())
		edwards25519_scalarmulbase_alt(p, s);
	else
		edwards25519_scalarmulbase(p, s);
	edwards25519_encode(out, p);

	memset(s, 0, sizeof s);
	memset(p, 0, sizeof p);
	return 1;
#else
	(void) out;
	(void) scalar;
	return 0;
#endif
}
