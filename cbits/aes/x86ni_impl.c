/*
 * Copyright (c) 2012-2013 Vincent Hanquez <vincent@snarc.org>
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

TARGET_AESNI
void SIZED(crypton_aesni_encrypt_block)(aes_block *out, aes_key *key, aes_block *in)
{
	__m128i *k = (__m128i *) key->data;
	PRELOAD_ENC(k);
	__m128i m = _mm_loadu_si128((__m128i *) in);
	DO_ENC_BLOCK(m);
	_mm_storeu_si128((__m128i *) out, m);
}

TARGET_AESNI
void SIZED(crypton_aesni_decrypt_block)(aes_block *out, aes_key *key, aes_block *in)
{
	__m128i *k = (__m128i *) key->data;
	PRELOAD_DEC(k);
	__m128i m = _mm_loadu_si128((__m128i *) in);
	DO_DEC_BLOCK(m);
	_mm_storeu_si128((__m128i *) out, m);
}

TARGET_AESNI
void SIZED(crypton_aesni_encrypt_ecb)(aes_block *out, aes_key *key, aes_block *in, uint32_t blocks)
{
	__m128i *k = (__m128i *) key->data;

	PRELOAD_ENC(k);
	for (; blocks-- > 0; in += 1, out += 1) {
		__m128i m = _mm_loadu_si128((__m128i *) in);
		DO_ENC_BLOCK(m);
		_mm_storeu_si128((__m128i *) out, m);
	}
}

TARGET_AESNI
void SIZED(crypton_aesni_decrypt_ecb)(aes_block *out, aes_key *key, aes_block *in, uint32_t blocks)
{
	__m128i *k = (__m128i *) key->data;

	PRELOAD_DEC(k);

	for (; blocks-- > 0; in += 1, out += 1) {
		__m128i m = _mm_loadu_si128((__m128i *) in);
		DO_DEC_BLOCK(m);
		_mm_storeu_si128((__m128i *) out, m);
	}
}

TARGET_AESNI
void SIZED(crypton_aesni_encrypt_cbc)(aes_block *out, aes_key *key, aes_block *_iv, aes_block *in, uint32_t blocks)
{
	__m128i *k = (__m128i *) key->data;
	__m128i iv = _mm_loadu_si128((__m128i *) _iv);

	PRELOAD_ENC(k);

	for (; blocks-- > 0; in += 1, out += 1) {
		__m128i m = _mm_loadu_si128((__m128i *) in);
		m = _mm_xor_si128(m, iv);
		DO_ENC_BLOCK(m);
		iv = m;
		_mm_storeu_si128((__m128i *) out, m);
	}
}

TARGET_AESNI
void SIZED(crypton_aesni_decrypt_cbc)(aes_block *out, aes_key *key, aes_block *_iv, aes_block *in, uint32_t blocks)
{
	__m128i *k = (__m128i *) key->data;
	__m128i iv = _mm_loadu_si128((__m128i *) _iv);

	PRELOAD_DEC(k);

	for (; blocks-- > 0; in += 1, out += 1) {
		__m128i m = _mm_loadu_si128((__m128i *) in);
		__m128i ivnext = m;

		DO_DEC_BLOCK(m);
		m = _mm_xor_si128(m, iv);

		_mm_storeu_si128((__m128i *) out, m);
		iv = ivnext;
	}
}

TARGET_AESNI
void SIZED(crypton_aesni_encrypt_ctr)(uint8_t *output, aes_key *key, aes_block *_iv, uint8_t *input, uint32_t len)
{
	__m128i *k = (__m128i *) key->data;
	__m128i bswap_mask = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
	__m128i one        = _mm_set_epi32(0,1,0,0);
	uint32_t nb_blocks = len / 16;
	uint32_t part_block_len = len % 16;

	/* get the IV in little endian format */
	__m128i iv = _mm_loadu_si128((__m128i *) _iv);
	iv = _mm_shuffle_epi8(iv, bswap_mask);

	PRELOAD_ENC(k);

	for (; nb_blocks-- > 0; output += 16, input += 16) {
		/* put back the iv in big endian mode,
		 * encrypt it and and xor it the input block
		 */
		__m128i tmp = _mm_shuffle_epi8(iv, bswap_mask);
		DO_ENC_BLOCK(tmp);
		__m128i m = _mm_loadu_si128((__m128i *) input);
		m = _mm_xor_si128(m, tmp);

		_mm_storeu_si128((__m128i *) output, m);
		/* iv += 1 */
		iv = _mm_add_epi64(iv, one);
	}

	if (part_block_len != 0) {
		aes_block block;
		memset(&block.b, 0, 16);
		memcpy(&block.b, input, part_block_len);

		__m128i m = _mm_loadu_si128((__m128i *) &block);
		__m128i tmp = _mm_shuffle_epi8(iv, bswap_mask);

		DO_ENC_BLOCK(tmp);
		m = _mm_xor_si128(m, tmp);
		_mm_storeu_si128((__m128i *) &block.b, m);
		memcpy(output, &block.b, part_block_len);
	}

	return ;
}

TARGET_AESNI
void SIZED(crypton_aesni_encrypt_c32_)(uint8_t *output, aes_key *key, aes_block *_iv, uint8_t *input, uint32_t len)
{
	__m128i *k = (__m128i *) key->data;
	__m128i one        = _mm_set_epi32(0,0,0,1);
	uint32_t nb_blocks = len / 16;
	uint32_t part_block_len = len % 16;

	/* get the IV */
	__m128i iv = _mm_loadu_si128((__m128i *) _iv);

	PRELOAD_ENC(k);

	for (; nb_blocks-- > 0; output += 16, input += 16) {
		/* encrypt the iv and and xor it the input block */
		__m128i tmp = iv;
		DO_ENC_BLOCK(tmp);
		__m128i m = _mm_loadu_si128((__m128i *) input);
		m = _mm_xor_si128(m, tmp);

		_mm_storeu_si128((__m128i *) output, m);
		/* iv += 1 */
		iv = _mm_add_epi32(iv, one);
	}

	if (part_block_len != 0) {
		aes_block block;
		memset(&block.b, 0, 16);
		memcpy(&block.b, input, part_block_len);

		__m128i m = _mm_loadu_si128((__m128i *) &block);
		__m128i tmp = iv;

		DO_ENC_BLOCK(tmp);
		m = _mm_xor_si128(m, tmp);
		_mm_storeu_si128((__m128i *) &block.b, m);
		memcpy(output, &block.b, part_block_len);
	}

	return ;
}

TARGET_AESNI
void SIZED(crypton_aesni_encrypt_xts)(aes_block *out, aes_key *key1, aes_key *key2,
                               aes_block *_tweak, uint32_t spoint, aes_block *in, uint32_t blocks)
{
	uint64_t tlo, thi;

	do {
		__m128i *k2 = (__m128i *) key2->data;
		__m128i tweak = _mm_loadu_si128((__m128i *) _tweak);
		aes_block first ALIGNMENT(16);

		PRELOAD_ENC(k2);
		DO_ENC_BLOCK(tweak);
		_mm_storeu_si128((__m128i *) &first, tweak);
		tlo = first.q[0];
		thi = first.q[1];

		while (spoint-- > 0)
			XTS_TWEAK_STEP(tlo, thi);
	} while (0) ;

	do {
		__m128i *k1 = (__m128i *) key1->data;

		/*
		 * Eight at a time.  The eight tweaks are kept from one group
		 * to the next and each is advanced by eight doublings at
		 * once, which is a single multiplication and does not wait
		 * for the other seven; doubling along the group instead,
		 * which is what this did, puts a chain of eight in front of
		 * every set of rounds, and on a processor whose AES is fast
		 * that chain is most of the block.
		 */
		for ( ; blocks >= 8; blocks -= 8, in += 8, out += 8) {
			__m128i m[8], t[8];
			int i;

			XTS_TWEAKS8(t, tlo, thi);
			for (i = 0; i < 8; i++)
				m[i] = _mm_xor_si128(
				    _mm_loadu_si128((__m128i *) (in + i)), t[i]);
			DO_ENC_BLOCK8_MEM(m, k1, NBR, ROUNDS8_EXTRA);
			for (i = 0; i < 8; i++)
				_mm_storeu_si128((__m128i *) (out + i),
				                 _mm_xor_si128(m[i], t[i]));
		}
		for ( ; blocks-- > 0; in += 1, out += 1) {
			const __m128i tweak =
			    _mm_set_epi64x((long long) thi, (long long) tlo);
			__m128i m = _mm_loadu_si128((__m128i *) in);

			m = _mm_xor_si128(m, tweak);
			DO_ENC_BLOCK_MEM(m, k1, NBR);
			m = _mm_xor_si128(m, tweak);

			_mm_storeu_si128((__m128i *) out, m);
			XTS_TWEAK_STEP(tlo, thi);
		}
	} while (0);
}

/*
 * XTS the other way, which until now fell to the generic loop -- and which
 * nothing reached at all, since crypton_aes_decrypt_xts called the generic
 * function directly rather than through the branch table.  The tweak is
 * enciphered whichever way the data goes; only the data is deciphered.
 */
TARGET_AESNI
void SIZED(crypton_aesni_decrypt_xts)(aes_block *out, aes_key *key1, aes_key *key2,
                               aes_block *_tweak, uint32_t spoint, aes_block *in, uint32_t blocks)
{
	uint64_t tlo, thi;

	do {
		__m128i *k2 = (__m128i *) key2->data;
		__m128i tweak = _mm_loadu_si128((__m128i *) _tweak);
		aes_block first ALIGNMENT(16);

		PRELOAD_ENC(k2);
		DO_ENC_BLOCK(tweak);
		_mm_storeu_si128((__m128i *) &first, tweak);
		tlo = first.q[0];
		thi = first.q[1];

		while (spoint-- > 0)
			XTS_TWEAK_STEP(tlo, thi);
	} while (0) ;

	do {
		__m128i *k1 = (__m128i *) key1->data;
		PRELOAD_DEC(k1);

		/* the tweaks kept and advanced, as encryption has them */
		for ( ; blocks >= 8; blocks -= 8, in += 8, out += 8) {
			__m128i m[8], t[8];
			int i;

			XTS_TWEAKS8(t, tlo, thi);
			for (i = 0; i < 8; i++)
				m[i] = _mm_xor_si128(
				    _mm_loadu_si128((__m128i *) (in + i)), t[i]);
			DO_DEC_BLOCK8(m);
			for (i = 0; i < 8; i++)
				_mm_storeu_si128((__m128i *) (out + i),
				                 _mm_xor_si128(m[i], t[i]));
		}
		for ( ; blocks-- > 0; in += 1, out += 1) {
			const __m128i tweak =
			    _mm_set_epi64x((long long) thi, (long long) tlo);
			__m128i m = _mm_loadu_si128((__m128i *) in);

			m = _mm_xor_si128(m, tweak);
			DO_DEC_BLOCK(m);
			m = _mm_xor_si128(m, tweak);

			_mm_storeu_si128((__m128i *) out, m);
			XTS_TWEAK_STEP(tlo, thi);
		}
	} while (0);
}

GCM_TARGET
void SIZED(crypton_aesni_gcm_encrypt)(uint8_t *output, aes_gcm *gcm, aes_key *key, uint8_t *input, uint32_t length)
{
	__m128i *k = (__m128i *) key->data;
	__m128i bswap_mask = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
	__m128i one        = _mm_set_epi32(0,1,0,0);
	uint32_t nb_blocks = length / 16;
	uint32_t part_block_len = length % 16;
	/* the group of ciphertext whose GHASH has not been taken yet */
	__m128i pending[8];
	int held = 0;

	gcm->length_input += length;

#ifdef WITH_GCM_VAES
	/*
	 * The 256-bit instructions first where the processor has them: they
	 * take two blocks where the ones below take one, and the assembly
	 * that follows is 128-bit throughout.  Same contract -- whole groups
	 * off the front, the counter and the tag left behind.
	 */
	if (nb_blocks >= GCM_VAES_MIN_BLOCKS
	    && (crypton_x86_simd_features() & CRYPTON_X86_VAES)) {
		uint32_t done = crypton_gcm_vaes_bulk_encrypt(output, gcm, key,
		                                              input,
		                                              nb_blocks * 16);

		output += done;
		input += done;
		nb_blocks -= done / 16;
	}
#endif
#if defined(WITH_X86_GCM_ASM) && defined(WITH_PCLMUL)
	/*
	 * The stitched assembly next, which takes whole groups of six
	 * blocks off the front of the message and leaves the counter and the
	 * running tag where the loop below expects to find them.  It wants
	 * eighteen blocks before it will start, and answers with what it did.
	 */
	if (nb_blocks >= GCM_ASM_MIN_BLOCKS_ENC) {
		uint32_t done = crypton_gcm_asm_bulk_encrypt(output, gcm, key,
		                                             input, nb_blocks * 16);

		output += done;
		input += done;
		nb_blocks -= done / 16;
	}
#endif

	__m128i tag = _mm_loadu_si128((__m128i *) &gcm->tag);
	__m128i iv = _mm_loadu_si128((__m128i *) &gcm->civ);
	iv = _mm_shuffle_epi8(iv, bswap_mask);


	/*
	 * Eight blocks at a time: the counters go through the rounds together
	 * so the pipeline has something to do while AESENC is in flight, and
	 * their GHASH folds into one reduction against H^8 .. H^1 rather than
	 * eight.
	 *
	 * The GHASH is of the group before, not this one.  Taken in step the
	 * two halves cannot overlap at all: the multiply of a block waits for
	 * the rounds that produced it, and on this processor they do not even
	 * want the same port -- AESENC and PCLMULQDQ issue to different ones,
	 * so held a group apart they run through each other.  It costs one
	 * group's worth of ciphertext kept aside and a last GHASH after the
	 * loop.
	 */
	for (; nb_blocks >= 8; nb_blocks -= 8, output += 128, input += 128) {
		__m128i m[8];
		int i;

		for (i = 0; i < 8; i++) {
			/* iv += 1, put back in big endian */
			iv = _mm_add_epi32(iv, one);
			m[i] = _mm_shuffle_epi8(iv, bswap_mask);
		}
		if (held)
			GCM_GROUP8(m, k, NBR, ROUNDS8_EXTRA);
		else
			DO_ENC_BLOCK8_MEM(m, k, NBR, ROUNDS8_EXTRA);

		for (i = 0; i < 8; i++) {
			m[i] = _mm_xor_si128(m[i],
			                     _mm_loadu_si128((__m128i *) (input + 16 * i)));
			_mm_storeu_si128((__m128i *) (output + 16 * i), m[i]);
		}
		for (i = 0; i < 8; i++)
			pending[i] = m[i];
		held = 1;
	}
	if (held)
		tag = gcm_ghash_add8(tag, gcm->htable, pending);
	for (; nb_blocks-- > 0; output += 16, input += 16) {
		/* iv += 1 */
		iv = _mm_add_epi32(iv, one);

		/* put back iv in big endian, encrypt it,
		 * and xor it to input */
		__m128i tmp = _mm_shuffle_epi8(iv, bswap_mask);
		DO_ENC_BLOCK_MEM(tmp, k, NBR);
		__m128i m = _mm_loadu_si128((__m128i *) input);
		m = _mm_xor_si128(m, tmp);

		tag = gcm_ghash_add(tag, gcm->htable, m);

		/* store it out */
		_mm_storeu_si128((__m128i *) output, m);
	}
	if (part_block_len > 0) {
		__m128i mask;
		aes_block block;
		/* FIXME could do something a bit more clever (slli & sub & and maybe) ... */
		switch (part_block_len) {
		case 1: mask = _mm_setr_epi8(0,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80); break;
		case 2: mask = _mm_setr_epi8(0,1,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80); break;
		case 3: mask = _mm_setr_epi8(0,1,2,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80); break;
		case 4: mask = _mm_setr_epi8(0,1,2,3,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80); break;
		case 5: mask = _mm_setr_epi8(0,1,2,3,4,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80); break;
		case 6: mask = _mm_setr_epi8(0,1,2,3,4,5,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80); break;
		case 7: mask = _mm_setr_epi8(0,1,2,3,4,5,6,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80); break;
		case 8: mask = _mm_setr_epi8(0,1,2,3,4,5,6,7,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80); break;
		case 9: mask = _mm_setr_epi8(0,1,2,3,4,5,6,7,8,0x80,0x80,0x80,0x80,0x80,0x80,0x80); break;
		case 10: mask = _mm_setr_epi8(0,1,2,3,4,5,6,7,8,9,0x80,0x80,0x80,0x80,0x80,0x80); break;
		case 11: mask = _mm_setr_epi8(0,1,2,3,4,5,6,7,8,9,10,0x80,0x80,0x80,0x80,0x80); break;
		case 12: mask = _mm_setr_epi8(0,1,2,3,4,5,6,7,8,9,10,11,0x80,0x80,0x80,0x80); break;
		case 13: mask = _mm_setr_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,0x80,0x80,0x80); break;
		case 14: mask = _mm_setr_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,0x80,0x80); break;
		case 15: mask = _mm_setr_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,0x80); break;
		default: mask = _mm_setr_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15); break;
		}
		block128_zero(&block);
		block128_copy_bytes(&block, input, part_block_len);

		/* iv += 1 */
		iv = _mm_add_epi32(iv, one);

		/* put back iv in big endian mode, encrypt it and xor it with input */
		__m128i tmp = _mm_shuffle_epi8(iv, bswap_mask);
		DO_ENC_BLOCK_MEM(tmp, k, NBR);

		__m128i m = _mm_loadu_si128((__m128i *) &block);
		m = _mm_xor_si128(m, tmp);
		m = _mm_shuffle_epi8(m, mask);

		tag = gcm_ghash_add(tag, gcm->htable, m);

		/* make output */
		_mm_storeu_si128((__m128i *) &block.b, m);
		memcpy(output, &block.b, part_block_len);
	}
	/* store back IV & tag */
	__m128i tmp = _mm_shuffle_epi8(iv, bswap_mask);
	_mm_storeu_si128((__m128i *) &gcm->civ, tmp);
	_mm_storeu_si128((__m128i *) &gcm->tag, tag);
}

/*
 * GCM decryption, which until now fell to the generic loop: that advances
 * the counter and calls the block function once per block through the
 * branch table, and measured a quarter the speed of encryption on the same
 * machine.  The shape is the encryption loop with two differences -- the
 * tag is taken over the ciphertext, which is the input rather than the
 * output, and the ciphertext is read before anything is written, since
 * output may be input.
 */
GCM_TARGET
void SIZED(crypton_aesni_gcm_decrypt)(uint8_t *output, aes_gcm *gcm, aes_key *key, uint8_t *input, uint32_t length)
{
	__m128i *k = (__m128i *) key->data;
	__m128i bswap_mask = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
	__m128i one        = _mm_set_epi32(0,1,0,0);
	uint32_t nb_blocks = length / 16;
	uint32_t part_block_len = length % 16;
	/* the group of ciphertext whose GHASH has not been taken yet */
	__m128i pending[8];
	int held = 0;

	gcm->length_input += length;

#ifdef WITH_GCM_VAES
	/* as in encryption; the tag is taken over the input here */
	if (nb_blocks >= GCM_VAES_MIN_BLOCKS
	    && (crypton_x86_simd_features() & CRYPTON_X86_VAES)) {
		uint32_t done = crypton_gcm_vaes_bulk_decrypt(output, gcm, key,
		                                              input,
		                                              nb_blocks * 16);

		output += done;
		input += done;
		nb_blocks -= done / 16;
	}
#endif
#if defined(WITH_X86_GCM_ASM) && defined(WITH_PCLMUL)
	/* the same as encryption, except that decryption has nothing to
	 * hold back and so will start on six blocks */
	if (nb_blocks >= GCM_ASM_MIN_BLOCKS_DEC) {
		uint32_t done = crypton_gcm_asm_bulk_decrypt(output, gcm, key,
		                                             input, nb_blocks * 16);

		output += done;
		input += done;
		nb_blocks -= done / 16;
	}
#endif

	__m128i tag = _mm_loadu_si128((__m128i *) &gcm->tag);
	__m128i iv = _mm_loadu_si128((__m128i *) &gcm->civ);
	iv = _mm_shuffle_epi8(iv, bswap_mask);


	/* the group before's GHASH, alongside this group's rounds, as
	 * encryption does it */
	for (; nb_blocks >= 8; nb_blocks -= 8, output += 128, input += 128) {
		__m128i m[8], c[8];
		int i;

		for (i = 0; i < 8; i++) {
			/* iv += 1, put back in big endian */
			iv = _mm_add_epi32(iv, one);
			m[i] = _mm_shuffle_epi8(iv, bswap_mask);
		}
		for (i = 0; i < 8; i++)
			c[i] = _mm_loadu_si128((__m128i *) (input + 16 * i));
		if (held)
			GCM_GROUP8(m, k, NBR, ROUNDS8_EXTRA);
		else
			DO_ENC_BLOCK8_MEM(m, k, NBR, ROUNDS8_EXTRA);

		for (i = 0; i < 8; i++)
			_mm_storeu_si128((__m128i *) (output + 16 * i),
			                 _mm_xor_si128(m[i], c[i]));
		for (i = 0; i < 8; i++)
			pending[i] = c[i];
		held = 1;
	}
	if (held)
		tag = gcm_ghash_add8(tag, gcm->htable, pending);
	for (; nb_blocks-- > 0; output += 16, input += 16) {
		__m128i c = _mm_loadu_si128((__m128i *) input);

		iv = _mm_add_epi32(iv, one);
		__m128i tmp = _mm_shuffle_epi8(iv, bswap_mask);
		DO_ENC_BLOCK_MEM(tmp, k, NBR);

		tag = gcm_ghash_add(tag, gcm->htable, c);
		_mm_storeu_si128((__m128i *) output, _mm_xor_si128(tmp, c));
	}
	if (part_block_len > 0) {
		aes_block block;

		/* the ciphertext padded with zeros is what the tag is taken
		 * over, so no mask is needed the way encryption needs one */
		block128_zero(&block);
		block128_copy_bytes(&block, input, part_block_len);
		__m128i c = _mm_loadu_si128((__m128i *) &block);

		/* iv += 1 */
		iv = _mm_add_epi32(iv, one);

		__m128i tmp = _mm_shuffle_epi8(iv, bswap_mask);
		DO_ENC_BLOCK_MEM(tmp, k, NBR);

		tag = gcm_ghash_add(tag, gcm->htable, c);

		_mm_storeu_si128((__m128i *) &block.b, _mm_xor_si128(tmp, c));
		memcpy(output, &block.b, part_block_len);
	}
	/* store back IV & tag */
	__m128i tmp = _mm_shuffle_epi8(iv, bswap_mask);
	_mm_storeu_si128((__m128i *) &gcm->civ, tmp);
	_mm_storeu_si128((__m128i *) &gcm->tag, tag);
}
