#ifndef CRYPTON_MODINV_H
#define CRYPTON_MODINV_H

#include <stdint.h>

/* z = a^-1 mod m, all three big-endian byte strings of len bytes.
 *
 * Returns 0 with the answer in z, and 1 without touching z when it will not
 * do this one: the assembly it needs is not built, the modulus is even, or
 * the numbers are larger than it keeps room for.  A 1 is not an error, it is
 * "ask something else".
 *
 * The answer is not checked here.  When a has no inverse the routine
 * underneath returns something that is not one rather than saying so, so the
 * caller has to multiply out and look -- which is what Crypto.Number.
 * ModArithmetic.inverseSafe already did for the exponentiation this
 * replaces.
 */
int crypton_modinv_sec(uint8_t *z, const uint8_t *a, const uint8_t *m,
                       uint32_t len);

#endif
