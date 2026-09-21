#ifndef CRYPTON_ECC_H
#define CRYPTON_ECC_H

#include <stdint.h>

/* Multiply a point of a curve over a prime field by a scalar, doing the same
 * work whatever the scalar is.
 *
 * The curve is y^2 = x^3 + a*x + b over the field of p, which has to be an
 * odd prime; the point has to be on it and not the point at infinity, and its
 * coordinates, a and b have to be below p.  Every number is a big-endian byte
 * string, and the coordinates, a, b and p are all plen bytes.
 *
 * The scalar is walked four bits at a time over every one of the klen bytes
 * it is given, so its value is hidden but its length is not.
 *
 * Returns 0 with the answer in outx and outy, 1 if the answer is the point at
 * infinity, which has no coordinates, and -1 if the arguments are not ones it
 * can work with or memory ran out.
 */
int crypton_ecc_mul(uint8_t *outx, uint8_t *outy,
                    const uint8_t *px, const uint8_t *py,
                    const uint8_t *k, uint32_t klen,
                    const uint8_t *a, const uint8_t *b,
                    const uint8_t *p, uint32_t plen);

/* How many bytes a table for a base point takes, for a prime of plen bytes
 * and scalars of klen.  Zero if those sizes are not ones it can work with. */
uint32_t crypton_ecc_table_size(uint32_t plen, uint32_t klen);

/* Fill that many bytes with the multiples of a point that
 * crypton_ecc_table_mul wants: for every four bits of a scalar, the sixteen
 * points that those bits can call for.  The buffer has to be aligned as a
 * pointer is, which is what an allocator gives.
 *
 * The point, a, b and p are as for crypton_ecc_mul.  Returns 0, or -1 for
 * arguments it cannot work with or memory it could not have.
 */
int crypton_ecc_table_build(uint8_t *table,
                            const uint8_t *gx, const uint8_t *gy,
                            uint32_t klen,
                            const uint8_t *a, const uint8_t *b,
                            const uint8_t *p, uint32_t plen);

/* Multiply the point that table was built for by a scalar of klen bytes,
 * which has to be the klen the table was built for.  One addition for every
 * four bits and no doublings, since the table holds what the doublings would
 * work out.
 *
 * Returns what crypton_ecc_mul returns.
 */
int crypton_ecc_table_mul(uint8_t *outx, uint8_t *outy, const uint8_t *table,
                          const uint8_t *k, uint32_t klen,
                          const uint8_t *a, const uint8_t *b,
                          const uint8_t *p, uint32_t plen);

#endif
