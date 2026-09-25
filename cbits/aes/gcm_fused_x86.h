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

#ifndef CRYPTON_GCM_FUSED_X86_H
#define CRYPTON_GCM_FUSED_X86_H

#include <stdint.h>
#include <stddef.h>
#include <crypton_aes.h>

void crypton_gcm_fused_key_init(aes_gcm_fused *fk, const aes_key *key);

void crypton_gcm_fused_encrypt(uint8_t *out, const aes_gcm_fused *fk,
                               const aes_key *key,
                               const uint8_t *nonce,
                               const uint8_t *aad, size_t aadlen,
                               const uint8_t *in, size_t inlen, size_t taglen,
                               const aes_key *hpkey, size_t sampleoff,
                               uint8_t *mask);

int crypton_gcm_fused_decrypt(uint8_t *out, const aes_gcm_fused *fk,
                              const aes_key *key, const uint8_t *nonce,
                              const uint8_t *aad, size_t aadlen,
                              const uint8_t *in, size_t inlen,
                              const uint8_t *tag, size_t taglen,
                              uint8_t *outtag);

#endif
