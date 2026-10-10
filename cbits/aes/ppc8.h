/*
 * AES and GHASH on PowerISA 2.07, as implemented by cbits/aes/ppc8.c over
 * the CRYPTOGAMS assembly.  crypton_aes.c installs these when
 * crypton_aes_ppc8_available says the processor has the instructions.
 */
#ifndef CRYPTON_AES_PPC8_H
#define CRYPTON_AES_PPC8_H

#include "crypton_aes.h"
#include "aes/gf.h"
#include "crypton_cpu.h"

int  crypton_aes_ppc8_available(void);

void crypton_aes_ppc8_init(aes_key *key, uint8_t *origkey, uint8_t size);
void crypton_aes_ppc8_encrypt_block(aes_block *output, aes_key *key, aes_block *input);
void crypton_aes_ppc8_decrypt_block(aes_block *output, aes_key *key, aes_block *input);
void crypton_aes_ppc8_encrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks);
void crypton_aes_ppc8_decrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks);
void crypton_aes_ppc8_encrypt_cbc(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks);
void crypton_aes_ppc8_decrypt_cbc(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks);
void crypton_aes_ppc8_encrypt_ctr(uint8_t *output, aes_key *key, aes_block *iv, uint8_t *input, uint32_t len);
void crypton_aes_ppc8_encrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit, uint32_t spoint, aes_block *input, uint32_t nb_blocks);
void crypton_aes_ppc8_decrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit, uint32_t spoint, aes_block *input, uint32_t nb_blocks);
void crypton_aes_ppc8_hinit(table_4bit htable, const block128 *h);
void crypton_aes_ppc8_gf_mul(block128 *a, const table_4bit htable);
void crypton_aes_ppc8_gf_mul4(block128 *a, const block128 *blocks, const table_4bit htable);

#endif
