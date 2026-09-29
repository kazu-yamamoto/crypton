#ifndef CRYPTON_P256_VERIFY_H
#define CRYPTON_P256_VERIFY_H

#include <stdint.h>

/*
 * n1*G + n2*Q, in variable time, as a Jacobian triple in the plain domain.
 *
 * Returns 1 when the answer is in `out`, and 0 when the walk met the one
 * case s2n-bignum's point addition does not cover -- adding a point to
 * itself -- in which case the caller works the answer out the constant-time
 * way instead.  Nothing here is secret: it is all in the signature and the
 * public key.
 */
int crypton_p256_verify_mul(uint64_t out[12], const uint64_t n1[4],
                            const uint64_t n2[4], const uint64_t qx[4],
                            const uint64_t qy[4]);

#endif
