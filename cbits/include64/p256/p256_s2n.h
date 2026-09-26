/*
 * The vendored s2n-bignum assembly, behind one call that picks the variant
 * the machine wants.  See cbits/s2n/README.md for which and why.
 *
 * Only declared in the 64-bit field build: s2n-bignum is x86-64 and AArch64
 * only, and this interface is the four little-endian 64-bit words those
 * architectures give crypton_p256_int anyway.
 */
#ifndef CRYPTON_P256_S2N_H
#define CRYPTON_P256_S2N_H

#include <stdint.h>

/* res = scalar * point, all of them affine and not in Montgomery form:
 * point is x then y, four words each, and res the same.  The point at
 * infinity goes in and comes out as (0, 0). */
void crypton_s2n_p256_scalarmul(uint64_t res[8], const uint64_t scalar[4],
                                const uint64_t point[8]);

#endif
