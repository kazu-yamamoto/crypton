#ifndef CRYPTON_POWM_H
#define CRYPTON_POWM_H

#include <stdint.h>

/* Modular exponentiation whose work does not depend on the exponent's bits.
 *
 * All three numbers are big-endian byte strings.  The modulus has to be odd
 * and at least one byte, and the base has to be smaller than it: the caller
 * reduces, which it can do in whatever way it likes, because in this library
 * the base is always a public value.
 *
 * The result is written to out, which holds modlen bytes.
 *
 * Returns 0 on success, and nonzero if the modulus is even or memory ran out,
 * in which case out is untouched.
 */
int crypton_powm_sec(uint8_t *out,
                     const uint8_t *base, uint32_t baselen,
                     const uint8_t *exp, uint32_t explen,
                     const uint8_t *mod, uint32_t modlen);

#endif
