/*
 * dst = a xor b.
 *
 * Data.ByteArray's xor walks a byte at a time through an IO applicative, and
 * that allocates: fifty bytes of heap for every byte exclusive-ored, which in
 * counter mode cost more than the cipher did.  This is the same operation in
 * one pass of words.
 */

#include <stdint.h>
#include <string.h>

#include "crypton_memxor.h"

void crypton_memxor(uint8_t *dst, const uint8_t *a, const uint8_t *b, uint32_t len)
{
	uint32_t i = 0;

	for (; i + 8 <= len; i += 8) {
		uint64_t x, y;

		memcpy(&x, a + i, 8);
		memcpy(&y, b + i, 8);
		x ^= y;
		memcpy(dst + i, &x, 8);
	}
	for (; i < len; i++)
		dst[i] = a[i] ^ b[i];
}
