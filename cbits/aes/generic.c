/*
 * Copyright (C) 2008 Vincent Hanquez <vincent@snarc.org>
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
 *
 * AES, portable, for machines whose processor has no AES instructions or
 * whose build was not given them.
 *
 * This was a table-driven implementation: an S-box indexed by a byte of the
 * state, in every round and in the key expansion, which is what made it fast
 * and what made it variable-time.  It is now BearSSL's bitsliced aes_ct64,
 * which holds four blocks interleaved across eight 64-bit words and computes
 * the S-box as boolean algebra -- no table, and so no address derived from a
 * secret.  See cbits/bearssl/README.md.
 *
 * What is here is only the glue.  Nothing in this file branches or indexes on
 * the key or the data.
 */

#include <stdint.h>
#include <string.h>
#include <crypton_aes.h>
#include "bearssl/inner.h"
#include "aes/block128.h"
#include "aes/generic.h"

/*
 * The schedule is kept in its compressed form, 30 words of it, inside the
 * aes_key the caller already has -- comfortably inside the 448 bytes that
 * held the round keys before.  br_aes_ct64_skey_expand blows it up to 120
 * words on the stack once per call, which is how BearSSL's own CTR and CBC
 * use it.
 *
 * It travels through memcpy rather than a cast because aes_key is all
 * uint8_t and so carries no alignment of its own, whatever the allocator
 * happens to give it.
 */
#define COMP_SKEY_WORDS 30

void crypton_aes_generic_schedule(aes_sched *sched, const aes_key *key)
{
	uint64_t comp_skey[COMP_SKEY_WORDS];

	memcpy(comp_skey, key->data, sizeof comp_skey);
	sched->nbr = key->nbr;
	br_aes_ct64_skey_expand(sched->sk_exp, sched->nbr, comp_skey);
}

/*
 * Up to four blocks through the bitsliced core at once.  Fewer than four is
 * the same work as four -- the lanes are there whether anything is in them
 * -- so a caller with four to offer gets them for what one used to cost.
 */
static void pass(uint8_t *output, const uint8_t *input, unsigned n,
                 const aes_sched *sched, int decrypt)
{
	uint32_t w[16];
	uint64_t q[8];
	unsigned i;

	memset(w, 0, sizeof w);
	for (i = 0; i < n; i++) {
		w[4 * i]     = br_dec32le(input + 16 * i);
		w[4 * i + 1] = br_dec32le(input + 16 * i + 4);
		w[4 * i + 2] = br_dec32le(input + 16 * i + 8);
		w[4 * i + 3] = br_dec32le(input + 16 * i + 12);
	}

	for (i = 0; i < 4; i++)
		br_aes_ct64_interleave_in(&q[i], &q[i + 4], w + 4 * i);
	br_aes_ct64_ortho(q);
	if (decrypt)
		br_aes_ct64_bitslice_decrypt(sched->nbr, sched->sk_exp, q);
	else
		br_aes_ct64_bitslice_encrypt(sched->nbr, sched->sk_exp, q);
	br_aes_ct64_ortho(q);
	for (i = 0; i < 4; i++)
		br_aes_ct64_interleave_out(w + 4 * i, q[i], q[i + 4]);

	for (i = 0; i < n; i++) {
		br_enc32le(output + 16 * i,      w[4 * i]);
		br_enc32le(output + 16 * i + 4,  w[4 * i + 1]);
		br_enc32le(output + 16 * i + 8,  w[4 * i + 2]);
		br_enc32le(output + 16 * i + 12, w[4 * i + 3]);
	}
}

void crypton_aes_generic_blocks(uint8_t *output, const uint8_t *input,
                                uint32_t nb_blocks, const aes_sched *sched,
                                int decrypt)
{
	while (nb_blocks >= 4) {
		pass(output, input, 4, sched, decrypt);
		output += 64;
		input += 64;
		nb_blocks -= 4;
	}
	if (nb_blocks > 0)
		pass(output, input, (unsigned) nb_blocks, sched, decrypt);
}

static void one(aes_block *output, aes_key *key, aes_block *input, int decrypt)
{
	aes_sched sched;

	crypton_aes_generic_schedule(&sched, key);
	crypton_aes_generic_blocks((uint8_t *) output, (const uint8_t *) input,
	                           1, &sched, decrypt);
}

void crypton_aes_generic_encrypt_block(aes_block *output, aes_key *key, aes_block *input)
{
	one(output, key, input, 0);
}

void crypton_aes_generic_decrypt_block(aes_block *output, aes_key *key, aes_block *input)
{
	one(output, key, input, 1);
}

void crypton_aes_generic_init(aes_key *key, uint8_t *origkey, uint8_t size)
{
	uint64_t comp_skey[COMP_SKEY_WORDS];
	unsigned nbr;

	/* 0 for a key length that is not 16, 24 or 32; the old code returned
	 * without touching the key in that case and so does this */
	nbr = br_aes_ct64_keysched(comp_skey, origkey, size);
	if (nbr == 0)
		return;

	key->nbr = (uint8_t) nbr;
	memcpy(key->data, comp_skey, sizeof comp_skey);
}

/*
 * CTR, four counter blocks at a time.  The counter itself is serial, but
 * nothing about it depends on the keystream, so the four blocks it will
 * reach next can be written down before any of them is encrypted.
 */
static void ctr(uint8_t *output, aes_key *key, aes_block *iv,
                uint8_t *input, uint32_t len, int c32)
{
	aes_sched sched;
	aes_block counter;
	uint8_t ks[64];
	uint32_t nb_blocks = len / 16;
	uint32_t tail = len % 16;
	uint32_t i;

	crypton_aes_generic_schedule(&sched, key);
	block128_copy(&counter, iv);

	while (nb_blocks > 0) {
		uint32_t n = nb_blocks < 4 ? nb_blocks : 4;

		for (i = 0; i < n; i++) {
			block128_copy((block128 *) (ks + 16 * i), &counter);
			if (c32)
				block128_inc32_le(&counter);
			else
				block128_inc_be(&counter);
		}
		crypton_aes_generic_blocks(ks, ks, n, &sched, 0);
		for (i = 0; i < n * 16; i++)
			output[i] = ks[i] ^ input[i];

		output += n * 16;
		input += n * 16;
		nb_blocks -= n;
	}

	if (tail != 0) {
		block128_copy((block128 *) ks, &counter);
		crypton_aes_generic_blocks(ks, ks, 1, &sched, 0);
		for (i = 0; i < tail; i++)
			output[i] = ks[i] ^ input[i];
	}
}

void crypton_aes_bitsliced_encrypt_ctr(uint8_t *output, aes_key *key,
                                       aes_block *iv, uint8_t *input,
                                       uint32_t len)
{
	ctr(output, key, iv, input, len, 0);
}

void crypton_aes_bitsliced_encrypt_c32(uint8_t *output, aes_key *key,
                                       aes_block *iv, uint8_t *input,
                                       uint32_t len)
{
	ctr(output, key, iv, input, len, 1);
}
