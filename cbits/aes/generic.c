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
#define SKEY_WORDS      120

static void expand(uint64_t *sk_exp, const aes_key *key)
{
	uint64_t comp_skey[COMP_SKEY_WORDS];

	memcpy(comp_skey, key->data, sizeof comp_skey);
	br_aes_ct64_skey_expand(sk_exp, key->nbr, comp_skey);
}

static void one_block(aes_block *output, aes_key *key, aes_block *input,
                      int decrypt)
{
	uint64_t sk_exp[SKEY_WORDS];
	const uint8_t *in = (const uint8_t *) input;
	uint8_t *out = (uint8_t *) output;
	uint32_t w[4];
	uint64_t q[8];

	expand(sk_exp, key);

	w[0] = br_dec32le(in);
	w[1] = br_dec32le(in + 4);
	w[2] = br_dec32le(in + 8);
	w[3] = br_dec32le(in + 12);

	/* three of the four lanes go unused: a caller with four blocks to
	 * offer reaches the wide entry points instead */
	memset(q, 0, sizeof q);
	br_aes_ct64_interleave_in(&q[0], &q[4], w);
	br_aes_ct64_ortho(q);
	if (decrypt)
		br_aes_ct64_bitslice_decrypt(key->nbr, sk_exp, q);
	else
		br_aes_ct64_bitslice_encrypt(key->nbr, sk_exp, q);
	br_aes_ct64_ortho(q);
	br_aes_ct64_interleave_out(w, q[0], q[4]);

	br_enc32le(out, w[0]);
	br_enc32le(out + 4, w[1]);
	br_enc32le(out + 8, w[2]);
	br_enc32le(out + 12, w[3]);
}

void crypton_aes_generic_encrypt_block(aes_block *output, aes_key *key, aes_block *input)
{
	one_block(output, key, input, 0);
}

void crypton_aes_generic_decrypt_block(aes_block *output, aes_key *key, aes_block *input)
{
	one_block(output, key, input, 1);
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
