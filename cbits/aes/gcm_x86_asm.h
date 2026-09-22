/*
 * Copyright (c) 2026 Kazu Yamamoto <kazu@iij.ad.jp>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of his contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef CRYPTON_AES_GCM_X86_ASM_H
#define CRYPTON_AES_GCM_X86_ASM_H

#ifdef WITH_X86_GCM_ASM

#include <stdint.h>
#include <crypton_aes.h>

/*
 * How long a message has to be before it is handed over.  The assembly
 * needs the powers of H in a layout of its own, and what does not fill six
 * blocks is left to the loop that would otherwise have taken eight at a
 * time, so a short message pays for the setup and for a tail that goes
 * through one block at a time.  Encryption also spends its first twelve
 * blocks in plain counter mode before the stitched loop starts, which is
 * why it has to be given a good deal more before it comes out ahead.
 *
 * Measured on a Haswell-generation x86-64: decryption is ahead from 288
 * bytes up, by 5 to 20 per cent, and below that loses by about as much.
 * Encryption between 288 and
 * 1024 bytes is a wash -- it swings either way by up to ten per cent
 * depending on how the length divides into groups -- and from 1152 bytes it
 * is ahead by 9 per cent or more, reaching 25 to 40 per cent once the
 * message is a few kilobytes.
 */
#define GCM_ASM_MIN_BLOCKS_ENC 72
#define GCM_ASM_MIN_BLOCKS_DEC 18

/* whether the processor has what cbits/asm/aesni-gcm-x86_64-*.S needs */
int crypton_gcm_asm_usable(void);

/*
 * Encrypt or decrypt from the front of the message, hashing as it goes, and
 * answer how much was done -- a multiple of 96 bytes, possibly none of it.
 * The counter and the running tag in *gcm are brought forward by that much.
 */
uint32_t crypton_gcm_asm_bulk_encrypt(uint8_t *output, aes_gcm *gcm, aes_key *key,
                                      const uint8_t *input, uint32_t length);
uint32_t crypton_gcm_asm_bulk_decrypt(uint8_t *output, aes_gcm *gcm, aes_key *key,
                                      const uint8_t *input, uint32_t length);

#endif

#endif
