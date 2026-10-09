/*
 * Stands in for BearSSL's own src/inner.h.
 *
 * The five .c files beside this one are upstream's, byte for byte, and each
 * of them opens with #include "inner.h".  Upstream's is some two thousand
 * lines and declares the whole library; these five want six things from it.
 * So this header gives those six and nothing else, and the upstream files
 * stay unmodified -- which is what makes `diff` against a new BearSSL
 * release readable.  See README.md.
 *
 * The byte-order helpers are written here rather than copied, in their plain
 * portable form without upstream's unaligned-access fast paths, so that they
 * carry no platform configuration with them.  cbits/tests/bearssl_diff.c
 * checks the whole thing against crypton's existing implementation.
 */
#ifndef CRYPTON_BEARSSL_INNER_H
#define CRYPTON_BEARSSL_INNER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline uint32_t
br_dec32le(const void *src)
{
	const unsigned char *b = src;

	return (uint32_t)b[0]
	    | ((uint32_t)b[1] << 8)
	    | ((uint32_t)b[2] << 16)
	    | ((uint32_t)b[3] << 24);
}

static inline void
br_enc32le(void *dst, uint32_t x)
{
	unsigned char *b = dst;

	b[0] = (unsigned char)x;
	b[1] = (unsigned char)(x >> 8);
	b[2] = (unsigned char)(x >> 16);
	b[3] = (unsigned char)(x >> 24);
}

static inline uint64_t
br_dec64be(const void *src)
{
	const unsigned char *b = src;
	uint64_t x = 0;
	int i;

	for (i = 0; i < 8; i++)
		x = (x << 8) | (uint64_t)b[i];
	return x;
}

static inline void
br_enc64be(void *dst, uint64_t x)
{
	unsigned char *b = dst;
	int i;

	for (i = 7; i >= 0; i--) {
		b[i] = (unsigned char)(x & 0xff);
		x >>= 8;
	}
}

/* dec32le.c */
void br_range_dec32le(uint32_t *v, size_t num, const void *src);

/* aes_ct64.c */
void br_aes_ct64_bitslice_Sbox(uint64_t *q);
void br_aes_ct64_ortho(uint64_t *q);
void br_aes_ct64_interleave_in(uint64_t *q0, uint64_t *q1, const uint32_t *w);
void br_aes_ct64_interleave_out(uint32_t *w, uint64_t q0, uint64_t q1);
unsigned br_aes_ct64_keysched(uint64_t *comp_skey, const void *key,
	size_t key_len);
void br_aes_ct64_skey_expand(uint64_t *skey, unsigned num_rounds,
	const uint64_t *comp_skey);

/* aes_ct64_enc.c, aes_ct64_dec.c */
void br_aes_ct64_bitslice_encrypt(unsigned num_rounds, const uint64_t *skey,
	uint64_t *q);
void br_aes_ct64_bitslice_invSbox(uint64_t *q);
void br_aes_ct64_bitslice_decrypt(unsigned num_rounds, const uint64_t *skey,
	uint64_t *q);

/* ghash_ctmul64.c */
void br_ghash_ctmul64(void *y, const void *h, const void *data, size_t len);

#endif
