#ifndef CRYPTON_DES_H
#define CRYPTON_DES_H

#include <stdint.h>

/* the sixteen round keys, as eight six-bit values each */
typedef struct {
	uint8_t sk[16 * 8];
} crypton_des_key;

/* Build a schedule from an eight byte key.  The parity bits are ignored, as
 * FIPS 46-3 says.  With reverse set, the rounds come out in the order that
 * decrypts. */
void crypton_des_init(crypton_des_key *ks, const uint8_t *key, int reverse);

/* Apply nkeys schedules in order to each of nblocks eight byte blocks. */
void crypton_des_ecb(uint8_t *out, const crypton_des_key *ks, uint32_t nkeys,
                     const uint8_t *in, uint32_t nblocks);

#endif
