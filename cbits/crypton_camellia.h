#ifndef CRYPTON_CAMELLIA_H
#define CRYPTON_CAMELLIA_H

#include <stdint.h>

/* the subkeys of RFC 3713 section 2.2, for a 128-bit key */
typedef struct {
	uint64_t kw[4];
	uint64_t k[18];
	uint64_t ke[4];
} crypton_camellia_key;

void crypton_camellia_init(crypton_camellia_key *ks, const uint8_t *key);

void crypton_camellia_encrypt(uint8_t *out, const crypton_camellia_key *ks,
                              const uint8_t *in, uint32_t nblocks);

void crypton_camellia_decrypt(uint8_t *out, const crypton_camellia_key *ks,
                              const uint8_t *in, uint32_t nblocks);

#endif
