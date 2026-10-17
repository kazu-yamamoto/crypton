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

/* The same, for an exponent that is not a secret: it reads the exponent's
 * bits and branches on them.  Nothing in this library may call it with a
 * secret exponent.
 *
 * It declines -- returning 1 with out untouched -- whenever it is not the
 * faster of the two things the caller could do: for an exponent of more
 * than eight bytes, where a windowed walk is the better algorithm, and
 * everywhere the vendored assembly's Montgomery multiplication does not
 * run.  So a caller must have something to fall back to.
 */
int crypton_powm_pub(uint8_t *out,
                     const uint8_t *base, uint32_t baselen,
                     const uint8_t *exp, uint32_t explen,
                     const uint8_t *mod, uint32_t modlen);

/* The window the secure exponentiation walks the exponent in, so that a
 * build which did not take -DPOWM_WINDOW_BITS cannot pass for one that
 * did. */
int crypton_powm_window_bits(void);

#endif
