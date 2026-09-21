#ifndef CRYPTON_BLOWFISH_H
#define CRYPTON_BLOWFISH_H

#include <stdint.h>

/* The key schedule: the P array and the four S boxes, which is all the state
 * Blowfish has.  The caller keeps it; nothing here allocates. */
typedef struct {
	uint32_t p[18];
	uint32_t s[4][256];
} crypton_blowfish_ctx;

/* Set a schedule up from a key of keylen bytes, which has to be 1 to 56. */
void crypton_blowfish_init(crypton_blowfish_ctx *ctx, const uint8_t *key,
                           uint32_t keylen);

/* Encrypt or decrypt whole blocks: len has to be a multiple of eight, and out
 * may be in. */
void crypton_blowfish_encrypt(const crypton_blowfish_ctx *ctx, uint8_t *out,
                              const uint8_t *in, uint32_t len);
void crypton_blowfish_decrypt(const crypton_blowfish_ctx *ctx, uint8_t *out,
                              const uint8_t *in, uint32_t len);

/* The whole of what bcrypt does with Blowfish: the key setup that costs what
 * the cost says, and then the sixty-four encryptions.  Writes 24 bytes, of
 * which bcrypt keeps 23.  The salt is 16 bytes and the key is the password
 * with its terminating zero, 1 to 72 bytes of it.
 *
 * Returns 0, or -1 for a cost or a length it will not take.
 */
int crypton_bcrypt(uint8_t out[24], uint32_t cost, const uint8_t salt[16],
                   const uint8_t *key, uint32_t keylen);

/* What bcrypt_pbkdf does with Blowfish: the same key setup, sixty-four times
 * over, and then the four blocks of its own magic.  Writes 32 bytes.  The two
 * hashes it is given are 64 bytes each in the only caller there is.
 *
 * Returns 0, or -1 for a length it will not take.
 */
int crypton_bcrypt_pbkdf_hash(uint8_t out[32], const uint8_t *pass,
                              uint32_t passlen, const uint8_t *salt,
                              uint32_t saltlen);

#endif
