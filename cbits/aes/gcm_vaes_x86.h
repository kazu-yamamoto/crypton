/*
 * AES-GCM in the 256-bit form of the AES and carry-less multiply
 * instructions, which do two blocks where the 128-bit ones do one.
 */
#ifndef CRYPTON_GCM_VAES_X86_H
#define CRYPTON_GCM_VAES_X86_H

#include <crypton_cpu.h>

#if defined(ARCH_X86) && defined(__x86_64__) && defined(WITH_AESNI) \
    && defined(WITH_PCLMUL)
#define WITH_GCM_VAES
#endif

#ifdef WITH_GCM_VAES

#include <stdint.h>
#include <crypton_aes.h>

/* The bulk of a message in whole groups of sixteen blocks, leaving the
 * counter in gcm->civ and the running tag in gcm->tag where the caller's own
 * loop expects to find them.  Returns the number of bytes taken, which is a
 * multiple of 256 and may be zero. */
uint32_t crypton_gcm_vaes_bulk_encrypt(uint8_t *output, aes_gcm *gcm,
                                       const aes_key *key,
                                       const uint8_t *input, uint32_t length);
uint32_t crypton_gcm_vaes_bulk_decrypt(uint8_t *output, aes_gcm *gcm,
                                       const aes_key *key,
                                       const uint8_t *input, uint32_t length);

/* Sixteen blocks is the least it will start on. */
#define GCM_VAES_MIN_BLOCKS 16

#endif
#endif
