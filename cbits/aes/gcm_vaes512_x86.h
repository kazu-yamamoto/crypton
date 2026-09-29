/*
 * AES-GCM in the 512-bit form of the AES and carry-less multiply
 * instructions, which do four blocks where the 128-bit ones do one and the
 * 256-bit ones in cbits/aes/gcm_vaes_x86.c do two.
 */
#ifndef CRYPTON_GCM_VAES512_X86_H
#define CRYPTON_GCM_VAES512_X86_H

#include <crypton_cpu.h>

#if defined(ARCH_X86) && defined(__x86_64__) && defined(WITH_AESNI) \
    && defined(WITH_PCLMUL)
#define WITH_GCM_VAES512
#endif

#ifdef WITH_GCM_VAES512

#include <stdint.h>
#include <crypton_aes.h>

/* The same contract as the 256-bit pair: whole groups off the front, the
 * counter left in gcm->civ and the running tag in gcm->tag, and the number
 * of bytes taken returned, a multiple of 512 and possibly zero. */
uint32_t crypton_gcm_vaes512_bulk_encrypt(uint8_t *output, aes_gcm *gcm,
                                          const aes_key *key,
                                          const uint8_t *input,
                                          uint32_t length);
uint32_t crypton_gcm_vaes512_bulk_decrypt(uint8_t *output, aes_gcm *gcm,
                                          const aes_key *key,
                                          const uint8_t *input,
                                          uint32_t length);

/* Thirty-two blocks is the least it will start on. */
#define GCM_VAES512_MIN_BLOCKS 32

#endif
#endif
