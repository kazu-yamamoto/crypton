/*
 * Copyright (c) 2012 Vincent Hanquez <vincent@snarc.org>
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
#include "crypton_aes.h"

void crypton_aes_generic_encrypt_block(aes_block *output, aes_key *key, aes_block *input);
void crypton_aes_generic_decrypt_block(aes_block *output, aes_key *key, aes_block *input);
void crypton_aes_generic_init(aes_key *key, uint8_t *origkey, uint8_t size);

/*
 * The bitsliced core takes four blocks at a time, and the schedule it reads
 * is the expanded one rather than the compressed form the aes_key holds.
 * Expanding costs about what a block costs, so a mode with more than one
 * block to do expands once, here, and hands the result to every group.
 */
typedef struct {
	uint64_t sk_exp[120];
	unsigned nbr;
} aes_sched;

void crypton_aes_generic_schedule(aes_sched *sched, const aes_key *key);

/* nb_blocks of them, four at a pass; decrypt selects the direction */
void crypton_aes_generic_blocks(uint8_t *output, const uint8_t *input,
                                uint32_t nb_blocks, const aes_sched *sched,
                                int decrypt);

/*
 * CTR with the two counters crypton uses.  These are not the generic
 * entries: those go through the branch table for the block itself and so
 * run on accelerated machines too, where the key holds a different
 * schedule.  crypton_aes.c installs these only when nothing was
 * accelerated.
 */
void crypton_aes_bitsliced_encrypt_ctr(uint8_t *output, aes_key *key,
                                       aes_block *iv, uint8_t *input,
                                       uint32_t len);
void crypton_aes_bitsliced_encrypt_c32(uint8_t *output, aes_key *key,
                                       aes_block *iv, uint8_t *input,
                                       uint32_t len);
