/*
 * Does the vendored BearSSL agree with the implementation it would replace?
 *
 * Two anchors.  FIPS-197's own vectors say the new code computes AES, and
 * not merely something both sides compute the same way.  Then a long run of
 * random keys and blocks says the two agree everywhere the vectors do not
 * reach, which is what a replacement has to show before the old code goes.
 *
 * Run with an argument to corrupt one byte on purpose and see the comparison
 * notice: a differential test that cannot fail has said nothing.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "bearssl/inner.h"
#include "crypton_aes.h"
#include "aes/generic.h"
#include "aes/gf.h"

/* ---- the vendored code, one block at a time, as aes_ct64_cbcenc.c does ---- */

static void bear_key(uint64_t *comp_skey, unsigned *nr,
                     const uint8_t *key, size_t len)
{
	*nr = br_aes_ct64_keysched(comp_skey, key, len);
}

static void bear_block(uint8_t *out, const uint64_t *comp_skey, unsigned nr,
                       const uint8_t *in, int decrypt)
{
	uint64_t sk_exp[120];
	uint32_t w[4];
	uint64_t q[8];

	br_aes_ct64_skey_expand(sk_exp, nr, comp_skey);
	w[0] = br_dec32le(in);
	w[1] = br_dec32le(in + 4);
	w[2] = br_dec32le(in + 8);
	w[3] = br_dec32le(in + 12);
	memset(q, 0, sizeof q);
	br_aes_ct64_interleave_in(&q[0], &q[4], w);
	br_aes_ct64_ortho(q);
	if (decrypt)
		br_aes_ct64_bitslice_decrypt(nr, sk_exp, q);
	else
		br_aes_ct64_bitslice_encrypt(nr, sk_exp, q);
	br_aes_ct64_ortho(q);
	br_aes_ct64_interleave_out(w, q[0], q[4]);
	br_enc32le(out, w[0]);
	br_enc32le(out + 4, w[1]);
	br_enc32le(out + 8, w[2]);
	br_enc32le(out + 12, w[3]);
}

/* ---- crypton's GHASH, driven the way crypton_aes.c drives it ---- */

static void crypton_ghash(uint8_t *y, const uint8_t *h,
                          const uint8_t *data, size_t len)
{
	table_4bit ht;
	block128 acc;
	size_t i;

	crypton_aes_generic_hinit(ht, (const block128 *) h);
	block128_zero(&acc);
	for (i = 0; i < len; i += 16) {
		block128_xor_bytes(&acc, data + i, 16);
		crypton_aes_generic_gf_mul(&acc, ht);
	}
	memcpy(y, &acc, 16);
}

/* ---- the comparison ---- */

static int failures;
static int sabotage;

static void same(const char *what, const uint8_t *a, const uint8_t *b, size_t n)
{
	if (memcmp(a, b, n) != 0) {
		size_t i;

		printf("  MISMATCH %s\n    bearssl ", what);
		for (i = 0; i < n; i++) printf("%02x", a[i]);
		printf("\n    crypton ");
		for (i = 0; i < n; i++) printf("%02x", b[i]);
		printf("\n");
		failures++;
	}
}

static uint32_t rnd_state = 1;
static uint8_t rnd(void)
{
	rnd_state = rnd_state * 1103515245u + 12345u;
	return (uint8_t)(rnd_state >> 16);
}
static void rnd_fill(uint8_t *p, size_t n)
{
	while (n--) *p++ = rnd();
}

int main(int argc, char **argv)
{
	/* FIPS-197 C.1, C.2, C.3 */
	static const uint8_t pt[16] = {
		0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
		0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
	static const uint8_t k128[16] = {
		0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
	static const uint8_t k192[24] = {
		0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 };
	static const uint8_t k256[32] = {
		0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
		16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 };
	static const uint8_t c128[16] = {
		0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
		0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a };
	static const uint8_t c192[16] = {
		0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,
		0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91 };
	static const uint8_t c256[16] = {
		0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
		0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89 };
	const uint8_t *keys[3] = { k128, k192, k256 };
	const uint8_t *cts[3]  = { c128, c192, c256 };
	size_t klens[3] = { 16, 24, 32 };
	uint64_t comp[30];
	unsigned nr;
	uint8_t a[16], b[16];
	int i, round;

	sabotage = argc > 1;
	printf("== FIPS-197, so that agreement means AES ==\n");
	for (i = 0; i < 3; i++) {
		bear_key(comp, &nr, keys[i], klens[i]);
		bear_block(a, comp, nr, pt, 0);
		if (sabotage && i == 1) a[0] ^= 1;
		same("bearssl vs FIPS-197", a, cts[i], 16);
		bear_block(b, comp, nr, cts[i], 1);
		same("bearssl decrypt vs plaintext", b, pt, 16);
	}

	printf("== bearssl vs crypton's generic, 2000 random keys and blocks ==\n");
	for (round = 0; round < 2000; round++) {
		uint8_t key[32], in[16], e1[16], e2[16], d1[16], d2[16];
		size_t kl = klens[round % 3];
		aes_key ck;

		rnd_fill(key, kl);
		rnd_fill(in, 16);

		bear_key(comp, &nr, key, kl);
		bear_block(e1, comp, nr, in, 0);
		bear_block(d1, comp, nr, in, 1);

		crypton_aes_generic_init(&ck, key, (uint8_t) kl);
		crypton_aes_generic_encrypt_block((aes_block *) e2, &ck,
		                                  (aes_block *) in);
		crypton_aes_generic_decrypt_block((aes_block *) d2, &ck,
		                                  (aes_block *) in);
		if (sabotage && round == 7) e1[3] ^= 0x10;
		same("encrypt", e1, e2, 16);
		same("decrypt", d1, d2, 16);
	}

	printf("== GHASH: ghash_ctmul64 vs the 4-bit table, 500 messages ==\n");
	for (round = 0; round < 500; round++) {
		uint8_t h[16], data[256], y1[16], y2[16];
		size_t len = 16u * (size_t)(1 + (round % 16));

		rnd_fill(h, 16);
		rnd_fill(data, len);

		memset(y1, 0, 16);
		br_ghash_ctmul64(y1, h, data, len);
		crypton_ghash(y2, h, data, len);
		if (sabotage && round == 3) y1[15] ^= 0x80;
		same("ghash", y1, y2, 16);
	}

	printf("%s: %d mismatch(es)%s\n",
	       failures ? "FAIL" : "ok", failures,
	       sabotage ? "  (sabotage was asked for)" : "");
	return failures != 0;
}
