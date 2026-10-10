/*
 * crypton's portable AES and GHASH against the BearSSL they are written on.
 *
 * This began as the migration check: for one commit, cbits/aes/generic.c and
 * cbits/aes/gf.c were still the table-driven implementations, and this said
 * the vendored code computed what they computed before they were replaced.
 *
 * Since the replacement the two sides are no longer independent, and what is
 * left is still worth checking: everything in generic.c and gf.c is now
 * crypton's own glue -- a schedule kept compressed and carried through
 * memcpy, the interleave-and-ortho idiom around a single block, three of four
 * lanes left idle, and a GHASH entry that reaches the same multiply by handing
 * it a block of zeros.  Each of those is somewhere a mistake would live, and
 * each is compared here against calling BearSSL directly.
 *
 * FIPS-197's own vectors come first either way, so that agreement means AES
 * rather than two callers agreeing on something that is not.
 *
 * Run with an argument to corrupt results on purpose and see the comparison
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
#include "aes/block128.h"

/*
 * crypton_aes.c's table, which is a global, and the three key sizes of the
 * two CTR entries this looks for in it.  Searching rather than indexing
 * because the index is an enum private to that file.
 */
#define BRANCH_TABLE_SEARCH 64
extern void *crypton_aes_branch_table[];

/* the two GCM implementations, which crypton_aes.c declares but no header
 * does: in this build the generic one reaches the portable block function
 * too, so the two have to agree exactly, tag and all */
void crypton_aes_generic_gcm_encrypt(uint8_t *, aes_gcm *, aes_key *, uint8_t *, uint32_t);
void crypton_aes_generic_gcm_decrypt(uint8_t *, aes_gcm *, aes_key *, uint8_t *, uint32_t);
void crypton_aes_bitsliced_gcm_encrypt(uint8_t *, aes_gcm *, aes_key *, uint8_t *, uint32_t);
void crypton_aes_bitsliced_gcm_decrypt(uint8_t *, aes_gcm *, aes_key *, uint8_t *, uint32_t);

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

	printf("== crypton's glue vs BearSSL direct, 2000 random keys and blocks ==\n");
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

	printf("== GHASH: crypton's entries vs br_ghash_ctmul64, 500 messages ==\n");
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

	printf("== gf_mul4: the four-block entry against the same four blocks ==\n");
	for (round = 0; round < 500; round++) {
		uint8_t h[16], data[64], y1[16];
		table_4bit ht;
		block128 acc;

		rnd_fill(h, 16);
		rnd_fill(data, sizeof data);

		memset(y1, 0, 16);
		br_ghash_ctmul64(y1, h, data, sizeof data);

		crypton_aes_generic_hinit(ht, (const block128 *) h);
		block128_zero(&acc);
		crypton_aes_generic_gf_mul4(&acc, (const block128 *) data, ht);
		if (sabotage && round == 11) y1[0] ^= 0x40;
		same("gf_mul4", y1, (const uint8_t *) &acc, 16);
	}

	/*
	 * And that the wide entries are the ones installed.  Nothing else
	 * here would notice if they were not: the entries they replace are
	 * correct too, just a block at a time, so every answer above would
	 * be the same and only the speed would be gone.
	 */
	/*
	 * The Haskell suite reaches the four-block pass, but thinly: its
	 * vectors are mostly a block or three long, and breaking that pass
	 * alone fails sixteen of its examples where breaking every pass
	 * fails seven hundred.  So the lane logic and the counter are
	 * covered here instead, where the lengths can be chosen.
	 */
	printf("== many blocks at a pass against one at a time ==\n");
	for (round = 0; round < 200; round++) {
		uint8_t key[32], in[16 * 9], wide[16 * 9], single[16 * 9];
		size_t kl = klens[round % 3];
		uint32_t nb = 1 + (round % 9);
		aes_sched sched;
		aes_key ck;
		uint32_t i;
		int dec = round & 1;

		rnd_fill(key, kl);
		rnd_fill(in, nb * 16);
		crypton_aes_generic_init(&ck, key, (uint8_t) kl);

		crypton_aes_generic_schedule(&sched, &ck);
		crypton_aes_generic_blocks(wide, in, nb, &sched, dec);

		for (i = 0; i < nb; i++) {
			if (dec)
				crypton_aes_generic_decrypt_block(
				    (aes_block *) (single + 16 * i), &ck,
				    (aes_block *) (in + 16 * i));
			else
				crypton_aes_generic_encrypt_block(
				    (aes_block *) (single + 16 * i), &ck,
				    (aes_block *) (in + 16 * i));
		}
		if (sabotage && round == 5) wide[16] ^= 2;
		same("wide pass", wide, single, nb * 16);
	}

	printf("== the four-block CTR against one block at a time ==\n");
	for (round = 0; round < 200; round++) {
		uint8_t key[32], iv[16], in[200], got[200], want[200];
		size_t kl = klens[round % 3];
		/* lengths that land on, before and after a group of four */
		uint32_t len = 1 + (round % 200);
		aes_key ck;
		aes_block counter, ks;
		uint32_t done, n, i;
		int c32 = round & 1;

		rnd_fill(key, kl);
		rnd_fill(iv, 16);
		rnd_fill(in, len);
		crypton_aes_generic_init(&ck, key, (uint8_t) kl);

		if (c32)
			crypton_aes_bitsliced_encrypt_c32(got, &ck,
			    (aes_block *) iv, in, len);
		else
			crypton_aes_bitsliced_encrypt_ctr(got, &ck,
			    (aes_block *) iv, in, len);

		block128_copy(&counter, (block128 *) iv);
		for (done = 0; done < len; done += 16) {
			crypton_aes_generic_encrypt_block(&ks, &ck, &counter);
			n = len - done < 16 ? len - done : 16;
			for (i = 0; i < n; i++)
				want[done + i] = ((uint8_t *) &ks)[i]
				               ^ in[done + i];
			if (c32)
				block128_inc32_le(&counter);
			else
				block128_inc_be(&counter);
		}
		if (sabotage && round == 9) got[len - 1] ^= 4;
		same("ctr", got, want, len);
	}

	printf("== the four-block GCM against the one-block GCM ==\n");
	for (round = 0; round < 200; round++) {
		uint8_t key[32], iv[12], in[300], ga[300], gb[300];
		size_t kl = klens[round % 3];
		uint32_t len = 1 + (round % 300);
		aes_key ck;
		aes_gcm g1, g2;
		int dec = round & 1;

		rnd_fill(key, kl);
		rnd_fill(iv, sizeof iv);
		rnd_fill(in, len);
		crypton_aes_initkey(&ck, key, (uint8_t) kl);
		crypton_aes_gcm_init(&g1, &ck, iv, sizeof iv);
		memcpy(&g2, &g1, sizeof g1);

		if (dec) {
			crypton_aes_generic_gcm_decrypt(ga, &g1, &ck, in, len);
			crypton_aes_bitsliced_gcm_decrypt(gb, &g2, &ck, in, len);
		} else {
			crypton_aes_generic_gcm_encrypt(ga, &g1, &ck, in, len);
			crypton_aes_bitsliced_gcm_encrypt(gb, &g2, &ck, in, len);
		}
		if (sabotage && round == 13) gb[0] ^= 1;
		same("gcm text", ga, gb, len);
		/* the running GHASH and counter, which the tag is made from */
		same("gcm state", (const uint8_t *) &g1, (const uint8_t *) &g2,
		     sizeof g1);
	}

	printf("== which implementation the build chose ==\n");
#if !defined(WITH_AESNI) && !defined(WITH_ARMV8_CRYPTO)
	/*
	 * With no accelerator compiled in, crypton_aes.c does not read the
	 * branch table at all -- its GET_ macros name the portable entries
	 * directly -- so there is nothing here to look at, and which
	 * implementation runs is settled by the preprocessor.  Scanning the
	 * table in this build was a check that passed while telling nothing,
	 * which is how the four-block CTR came to be written, installed, and
	 * never called.
	 */
	printf("  named at compile time; the table is not read in this build\n");
	(void) crypton_aes_branch_table;
	if (sabotage) { /* nothing to corrupt here */ }
#else
	{
		int i, ctr = 0, c32 = 0;

		for (i = 0; i < BRANCH_TABLE_SEARCH; i++) {
			if (crypton_aes_branch_table[i] ==
			    (void *) crypton_aes_bitsliced_encrypt_ctr)
				ctr++;
			if (crypton_aes_branch_table[i] ==
			    (void *) crypton_aes_bitsliced_encrypt_c32)
				c32++;
		}
		printf("  CTR entries %d, C32 entries %d\n", ctr, c32);
		if (sabotage) { ctr = 0; }
		if (ctr != 3 || c32 != 3) {
			printf("  MISMATCH the portable CTR entries were not installed\n");
			failures++;
		}
	}
#endif

	printf("%s: %d mismatch(es)%s\n",
	       failures ? "FAIL" : "ok", failures,
	       sabotage ? "  (sabotage was asked for)" : "");
	return failures != 0;
}
