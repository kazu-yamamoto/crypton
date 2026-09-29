#ifndef CRYPTON_ED25519_S2N_H
#define CRYPTON_ED25519_S2N_H

#include <stdint.h>

/* The base point multiplied by a scalar, packed into Ed25519's 32-byte
 * encoding.  The scalar is 32 little-endian bytes, already reduced.
 *
 * Returns 1 when the vendored s2n-bignum did the work and 0 when it is not
 * built, in which case the caller multiplies the base point itself.
 */
int crypton_ed25519_base_mult(uint8_t out[32], const uint8_t scalar[32]);

#endif
