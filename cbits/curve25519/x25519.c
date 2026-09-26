/*
 * X25519 through the vendored s2n-bignum where it is built, and through
 * curve25519-donna where it is not.
 *
 * The fixed-base routine is the interesting half: crypton had none, and asked
 * for the public key by multiplying the base point 9 the general way.  With a
 * table it is four to five times less work, and a TLS handshake generates a
 * key every time.  Measured on an Apple M4:
 *
 *                     donna     s2n
 *     shared secret   18.15 us  12.35
 *     key generation  18.15     3.65
 *
 * and on an x86-64, 41.19 to 26.96 and 41.18 to 8.54.
 */
#include <string.h>

#include "curve25519/x25519.h"

void crypton_curve25519_donna(uint8_t *mypublic, const uint8_t *secret,
                              const uint8_t *basepoint);

/* The assembly takes four little-endian 64-bit words, which is the same bits
 * as the 32 little-endian bytes RFC 7748 sends, so the two cross by copying
 * -- on a little-endian machine, which is the only kind s2n-bignum is for. */
#if defined(CRYPTON_S2N_BIGNUM) && defined(__BYTE_ORDER__) \
    && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define CRYPTON_X25519_S2N 1
#include "crypton_cpu.h"

extern void curve25519_x25519(uint64_t res[4], const uint64_t scalar[4],
                              const uint64_t point[4]);
extern void curve25519_x25519_alt(uint64_t res[4], const uint64_t scalar[4],
                                  const uint64_t point[4]);
extern void curve25519_x25519base(uint64_t res[4], const uint64_t scalar[4]);
extern void curve25519_x25519base_alt(uint64_t res[4], const uint64_t scalar[4]);

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

void crypton_x25519(uint8_t out[32], const uint8_t secret[32],
                    const uint8_t point[32])
{
#ifdef CRYPTON_X25519_S2N
	uint64_t r[4], s[4], p[4];

	memcpy(s, secret, 32);
	memcpy(p, point, 32);
	if (use_alt())
		curve25519_x25519_alt(r, s, p);
	else
		curve25519_x25519(r, s, p);
	memcpy(out, r, 32);
#else
	crypton_curve25519_donna(out, secret, point);
#endif
}

void crypton_x25519_base(uint8_t out[32], const uint8_t secret[32])
{
#ifdef CRYPTON_X25519_S2N
	uint64_t r[4], s[4];

	memcpy(s, secret, 32);
	if (use_alt())
		curve25519_x25519base_alt(r, s);
	else
		curve25519_x25519base(r, s);
	memcpy(out, r, 32);
#else
	static const uint8_t nine[32] = {9};

	crypton_curve25519_donna(out, secret, nine);
#endif
}
