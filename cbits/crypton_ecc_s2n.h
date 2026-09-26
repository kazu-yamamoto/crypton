/*
 * P-384 and P-521 through the vendored s2n-bignum assembly, for the two
 * curves it knows among the ones crypton_ecc_mul is asked about.
 *
 * s2n-bignum has no affine wrapper for these two -- only a scalar
 * multiplication on Jacobian points, Montgomery-domain for P-384 and plain
 * for P-521 -- so the conversions in and out are built here out of its own
 * field operations.  See cbits/s2n/README.md.
 */
#ifndef CRYPTON_ECC_S2N_H
#define CRYPTON_ECC_S2N_H

#include <stdint.h>

/*
 * Returns 1 if this was a curve it knows and it answered, with *ret set to
 * what crypton_ecc_mul should return -- 0 and the point in outx and outy, 1
 * for the point at infinity, or -1 for arguments it will not take.  Returns
 * 0 if the curve is not one of its two and nothing was written.
 */
int crypton_s2n_ecc_mul(int *ret, uint8_t *outx, uint8_t *outy,
                        const uint8_t *px, const uint8_t *py,
                        const uint8_t *k, uint32_t klen,
                        const uint8_t *a, const uint8_t *b,
                        const uint8_t *p, uint32_t plen);

#endif
