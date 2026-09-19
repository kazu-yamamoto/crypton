/*
 * Included from armv8.c once per key size, with NBR set to the number of
 * rounds and SIZED() naming the functions.  This mirrors x86ni_impl.c.
 *
 * Two things here want compile-time constants, and both are worth having.
 * With the round count fixed the compiler keeps the round keys scheduled
 * instead of reloading them against a count read out of the key.  With the
 * blocks in flight fixed it interleaves that many independent chains, which
 * is what covers the latency of AESE and AESMC -- one block at a time leaves
 * the pipeline waiting on itself.  On Apple silicon the two together are
 * worth about four times a loop that does one block with a round count from
 * memory.
 *
 * The blocks are named by constant index throughout, and every step is
 * written out one per block rather than left to a loop over s[i].  Such a
 * loop is only as good as the compiler's willingness to unroll it, and GCC
 * at -O2 declines: s[] then lives on the stack and each round turns into a
 * load and a store, which measured slower than the one-block code this
 * replaces.  Spelling the steps out costs nothing and leaves nothing to
 * decide.
 */

/* Eight chains is where the return flattens out on the cores measured. */
#define WAY 8

#define EACH1(m) m(0)
#define EACH8(m) m(0) m(1) m(2) m(3) m(4) m(5) m(6) m(7)

#define LOAD_IN(i)   s[i] = vld1q_u8((const uint8_t *) (input + (i)));
#define STORE_OUT(i) vst1q_u8((uint8_t *) (output + (i)), s[i]);

#define ENC_STEP(i)  s[i] = vaesmcq_u8(vaeseq_u8(s[i], k_));
#define ENC_LAST(i)  s[i] = veorq_u8(vaeseq_u8(s[i], k_), l_);
#define DEC_STEP(i)  s[i] = vaesimcq_u8(vaesdq_u8(s[i], k_));
#define DEC_LAST(i)  s[i] = veorq_u8(vaesdq_u8(s[i], k_), l_);

/* Encrypt the blocks EACH names, in place in s[].  rk must be in scope. */
#define ENC_ROUNDS(EACH)                                                     \
	do {                                                                 \
		int r_;                                                      \
		for (r_ = 0; r_ < NBR - 1; r_++) {                           \
			const uint8x16_t k_ = vld1q_u8(rk + 16 * r_);        \
			EACH(ENC_STEP)                                       \
		}                                                            \
		{                                                            \
			const uint8x16_t k_ = vld1q_u8(rk + 16 * (NBR - 1)); \
			const uint8x16_t l_ = vld1q_u8(rk + 16 * NBR);       \
			EACH(ENC_LAST)                                       \
		}                                                            \
	} while (0)

/*
 * Decrypt them.  fwd and inv must be in scope: the schedule is k[nbr],
 * imc(k[nbr-1]) .. imc(k[1]), k[0], so the two ends come from the forward
 * keys and the middle from the inverted ones.
 */
#define DEC_ROUNDS(EACH)                                                     \
	do {                                                                 \
		int r_;                                                      \
		{                                                            \
			const uint8x16_t k_ = vld1q_u8(fwd + 16 * NBR);      \
			EACH(DEC_STEP)                                       \
		}                                                            \
		for (r_ = 0; r_ < NBR - 2; r_++) {                           \
			const uint8x16_t k_ = vld1q_u8(inv + 16 * r_);       \
			EACH(DEC_STEP)                                       \
		}                                                            \
		{                                                            \
			const uint8x16_t k_ = vld1q_u8(inv + 16 * (NBR - 2));\
			const uint8x16_t l_ = vld1q_u8(fwd);                 \
			EACH(DEC_LAST)                                       \
		}                                                            \
	} while (0)

TARGET_ARMV8_CRYPTO
void SIZED(crypton_aes_armv8_encrypt_block)(aes_block *output, aes_key *key, aes_block *input)
{
	const uint8_t *rk = FWD(key);
	uint8x16_t s[1];

	EACH1(LOAD_IN);
	ENC_ROUNDS(EACH1);
	EACH1(STORE_OUT);
}

TARGET_ARMV8_CRYPTO
void SIZED(crypton_aes_armv8_decrypt_block)(aes_block *output, aes_key *key, aes_block *input)
{
	const uint8_t *fwd = FWD(key);
	const uint8_t *inv = INV(key);
	uint8x16_t s[1];

	EACH1(LOAD_IN);
	DEC_ROUNDS(EACH1);
	EACH1(STORE_OUT);
}

TARGET_ARMV8_CRYPTO
void SIZED(crypton_aes_armv8_encrypt_ecb)(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	const uint8_t *rk = FWD(key);
	uint8x16_t s[WAY];

	for (; nb_blocks >= WAY; nb_blocks -= WAY, input += WAY, output += WAY) {
		EACH8(LOAD_IN);
		ENC_ROUNDS(EACH8);
		EACH8(STORE_OUT);
	}
	for (; nb_blocks > 0; nb_blocks--, input++, output++) {
		EACH1(LOAD_IN);
		ENC_ROUNDS(EACH1);
		EACH1(STORE_OUT);
	}
}

TARGET_ARMV8_CRYPTO
void SIZED(crypton_aes_armv8_decrypt_ecb)(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	const uint8_t *fwd = FWD(key);
	const uint8_t *inv = INV(key);
	uint8x16_t s[WAY];

	for (; nb_blocks >= WAY; nb_blocks -= WAY, input += WAY, output += WAY) {
		EACH8(LOAD_IN);
		DEC_ROUNDS(EACH8);
		EACH8(STORE_OUT);
	}
	for (; nb_blocks > 0; nb_blocks--, input++, output++) {
		EACH1(LOAD_IN);
		DEC_ROUNDS(EACH1);
		EACH1(STORE_OUT);
	}
}

/* CBC encryption chains, so there is nothing to interleave.  It still gains
 * the round keys staying put. */
TARGET_ARMV8_CRYPTO
void SIZED(crypton_aes_armv8_encrypt_cbc)(aes_block *output, aes_key *key, aes_block *_iv, aes_block *input, uint32_t nb_blocks)
{
	const uint8_t *rk = FWD(key);
	uint8x16_t iv = vld1q_u8((const uint8_t *) _iv);
	uint8x16_t s[1];

	for (; nb_blocks-- > 0; input++, output++) {
		s[0] = veorq_u8(iv, vld1q_u8((const uint8_t *) input));
		ENC_ROUNDS(EACH1);
		iv = s[0];
		EACH1(STORE_OUT);
	}
}

/* Decryption does not chain: each block is deciphered on its own and then
 * XORed with the ciphertext before it, so it interleaves like ECB. */
/* c[] holds the previous block at index 0 and this group's ciphertext after
 * it, so block i is XORed with c[i] and the next group starts from c[WAY]. */
#define CBC_KEEP(i)  c[(i) + 1] = s[i];
#define CBC_XOR(i)   vst1q_u8((uint8_t *) (output + (i)), veorq_u8(s[i], c[i]));

TARGET_ARMV8_CRYPTO
void SIZED(crypton_aes_armv8_decrypt_cbc)(aes_block *output, aes_key *key, aes_block *_iv, aes_block *input, uint32_t nb_blocks)
{
	const uint8_t *fwd = FWD(key);
	const uint8_t *inv = INV(key);
	uint8x16_t iv = vld1q_u8((const uint8_t *) _iv);
	uint8x16_t s[WAY], c[WAY + 1];

	for (; nb_blocks >= WAY; nb_blocks -= WAY, input += WAY, output += WAY) {
		EACH8(LOAD_IN);
		c[0] = iv;
		EACH8(CBC_KEEP);
		DEC_ROUNDS(EACH8);
		EACH8(CBC_XOR);
		iv = c[WAY];
	}
	for (; nb_blocks > 0; nb_blocks--, input++, output++) {
		EACH1(LOAD_IN);
		c[1] = s[0];
		DEC_ROUNDS(EACH1);
		vst1q_u8((uint8_t *) output, veorq_u8(s[0], iv));
		iv = c[1];
	}
}

/*
 * CTR counts the whole 128 bits big-endian, with the carry crossing the
 * halves.  The arithmetic is kept identical to
 * crypton_aes_generic_encrypt_ctr, which also leaves the caller's IV alone.
 */
#define CTR_SET(i)  s[i] = vreinterpretq_u8_u64(vsetq_lane_u64(cpu_to_be64(lo + (i)), base, 1));
#define CTR_XOR(i)  vst1q_u8(output + 16 * (i), \
                             veorq_u8(s[i], vld1q_u8(input + 16 * (i))));

TARGET_ARMV8_CRYPTO
void SIZED(crypton_aes_armv8_encrypt_ctr)(uint8_t *output, aes_key *key, aes_block *iv, uint8_t *input, uint32_t len)
{
	const uint8_t *rk = FWD(key);
	uint32_t nb_blocks = len / 16;
	uint32_t remaining = len % 16;
	aes_block ctr;
	uint8x16_t s[WAY];
	uint32_t i;

	block128_copy(&ctr, iv);

	/*
	 * The counter goes through memory only when its low half is about to
	 * wrap.  Otherwise it stays in registers: the top eight bytes do not
	 * change and the bottom eight are one add away.  That matters -- with
	 * a store and a reload for every block, CTR ran at the same speed for
	 * 128-bit and 256-bit keys, which is the giveaway that the cipher was
	 * not what it was waiting for.
	 */
	for (; nb_blocks >= WAY; nb_blocks -= WAY, input += 16 * WAY, output += 16 * WAY) {
		uint64_t lo = be64_to_cpu(ctr.q[1]);

		if (lo + (WAY - 1) < lo) {
			/* a block in this group carries into the top half;
			 * let the scalar increment deal with it */
			for (i = 0; i < WAY; i++, block128_inc_be(&ctr))
				s[i] = vld1q_u8((const uint8_t *) &ctr);
		} else {
			const uint64x2_t base =
			    vreinterpretq_u64_u8(vld1q_u8((const uint8_t *) &ctr));

			EACH8(CTR_SET);

			/* no block above needed a carry, but the counter left
			 * for the next group still can */
			ctr.q[1] = cpu_to_be64(lo + WAY);
			if (lo + WAY < lo)
				ctr.q[0] = cpu_to_be64(be64_to_cpu(ctr.q[0]) + 1);
		}
		ENC_ROUNDS(EACH8);
		EACH8(CTR_XOR);
	}
	for (; nb_blocks > 0; nb_blocks--, input += 16, output += 16) {
		s[0] = vld1q_u8((const uint8_t *) &ctr);
		block128_inc_be(&ctr);
		ENC_ROUNDS(EACH1);
		vst1q_u8(output, veorq_u8(s[0], vld1q_u8(input)));
	}
	if (remaining) {
		aes_block o;

		s[0] = vld1q_u8((const uint8_t *) &ctr);
		ENC_ROUNDS(EACH1);
		vst1q_u8((uint8_t *) &o, s[0]);
		for (i = 0; i < remaining; i++)
			output[i] = o.b[i] ^ input[i];
	}
}

#undef WAY
#undef EACH1
#undef EACH8
#undef LOAD_IN
#undef STORE_OUT
#undef ENC_STEP
#undef ENC_LAST
#undef DEC_STEP
#undef DEC_LAST
#undef ENC_ROUNDS
#undef DEC_ROUNDS
#undef CBC_KEEP
#undef CBC_XOR
#undef CTR_SET
#undef CTR_XOR
