#ifndef CRYPTON_X25519_H
#define CRYPTON_X25519_H

#include <stdint.h>

/* out = secret * point, the X25519 of RFC 7748: three 32-byte little-endian
 * strings as they go over the wire. */
void crypton_x25519(uint8_t out[32], const uint8_t secret[32],
                    const uint8_t point[32]);

/* out = secret * G, which is the same thing with the base point 9 -- but
 * where the assembly is built this reads a table instead and is four to five
 * times faster, which is what a key generation costs. */
void crypton_x25519_base(uint8_t out[32], const uint8_t secret[32]);

#endif
