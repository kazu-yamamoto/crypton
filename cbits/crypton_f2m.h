#ifndef CRYPTON_F2M_H
#define CRYPTON_F2M_H

#include <stdint.h>

/* Multiply a point of a curve over a binary field by a scalar, doing the same
 * work whatever the scalar is.
 *
 * The curve is y^2 + x*y = x^3 + a*x^2 + b over the field of the polynomial
 * fx, and a does not come into it: the ladder carries the x coordinates of
 * two consecutive multiples, and what it takes to add them is b alone.  The
 * point has to be on the curve and to have an x that is not zero -- the one
 * point with none is its own negation, and the caller sees to it.
 *
 * Every number is a big-endian byte string.  The coordinates and b are flen
 * bytes, and fx is the whole polynomial, x^m included, in fxlen.
 *
 * The scalar is walked over every bit of the klen bytes it is given, so its
 * value is hidden but its length is not.
 *
 * Returns 0 with the answer in outx and outy, 1 if the answer is the point at
 * infinity, and -1 for arguments it cannot work with or memory it could not
 * have.
 */
int crypton_f2m_mul(uint8_t *outx, uint8_t *outy,
                    const uint8_t *px, const uint8_t *py,
                    const uint8_t *k, uint32_t klen,
                    const uint8_t *b, uint32_t flen,
                    const uint8_t *fx, uint32_t fxlen);

#endif
