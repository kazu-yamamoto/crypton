/*
 * Inversion modulo an odd number through s2n-bignum, whose routine takes a
 * fixed number of division steps rather than an exponentiation: twenty to
 * thirty times less work than Fermat's little theorem at the sizes here.
 * Measured on an Apple M4, inverting modulo a curve order:
 *
 *              Fermat     this
 *     P-256    6.02 us    0.80
 *     P-384    31.3       1.20
 *     P-521    63.2       2.05
 *
 * It uses no instruction beyond the base architecture on either x86-64 or
 * AArch64, so unlike the rest of the vendored assembly there is nothing to
 * ask the processor first.
 */
#include <string.h>

#include "crypton_modinv.h"

#ifdef CRYPTON_S2N_BIGNUM

extern void bignum_modinv(uint64_t k, uint64_t *z, const uint64_t *a,
                          const uint64_t *b, uint64_t *t);

/* 4096 bits and no more, which covers every modulus that reaches here -- the
 * order of a curve, or a prime factor of an RSA modulus -- and keeps the
 * working space on the stack.  Anything larger is handed back. */
#define MODINV_MAXWORDS 64

int crypton_modinv_sec(uint8_t *z, const uint8_t *a, const uint8_t *m,
                       uint32_t len)
{
	uint64_t aw[MODINV_MAXWORDS], mw[MODINV_MAXWORDS];
	uint64_t zw[MODINV_MAXWORDS], t[3 * MODINV_MAXWORDS];
	uint32_t k = (len + 7) / 8;
	uint32_t i;

	/* An even modulus is the one case it answers without saying it
	 * cannot: it returns a number that is not an inverse rather than
	 * failing, so keep it away from here.  Every caller's modulus is odd. */
	if (len == 0 || k > MODINV_MAXWORDS || (m[len - 1] & 1) == 0)
		return 1;

	for (i = 0; i < k; i++) {
		aw[i] = 0;
		mw[i] = 0;
	}
	for (i = 0; i < len; i++) {
		uint32_t pos = len - 1 - i;

		aw[pos / 8] |= (uint64_t)a[i] << (8 * (pos % 8));
		mw[pos / 8] |= (uint64_t)m[i] << (8 * (pos % 8));
	}

	bignum_modinv(k, zw, aw, mw, t);

	for (i = 0; i < len; i++)
		z[len - 1 - i] = (uint8_t)(zw[i / 8] >> (8 * (i % 8)));
	return 0;
}

#else

int crypton_modinv_sec(uint8_t *z, const uint8_t *a, const uint8_t *m,
                       uint32_t len)
{
	(void)z;
	(void)a;
	(void)m;
	(void)len;
	return 1;
}

#endif
