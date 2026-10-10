/*
 * The POWER8 path against the portable one.
 *
 * crypton's own test suite exercises whichever implementation the machine
 * installed, so on a POWER8 it never runs the portable code and nothing
 * compares the two.  CI has no POWER8 either.  This does the comparison in
 * one process, with both compiled in, and runs under qemu-ppc64le.
 *
 *     powerpc64le-linux-gnu-gcc -O2 -static -Icbits -Icbits/aes \
 *         -DWITH_PPC8_CRYPTO -o ppc8_diff \
 *         cbits/tests/ppc8_diff.c cbits/crypton_aes.c cbits/aes/generic.c \
 *         cbits/aes/gf.c cbits/aes/ppc8.c cbits/crypton_cpu.c \
 *         cbits/asm/aesp8-ppc-linux64le.S cbits/asm/ghashp8-ppc-linux64le.S \
 *         cbits/bearssl/*.c
 *     qemu-ppc64le-static ./ppc8_diff
 *
 * Given any argument it corrupts a result in each section, so that the
 * comparison can be seen to notice: one that cannot fail has said nothing.
 *
 * One trap in writing this, worth naming because it looks like a crash in
 * the code under test.  Several of the generic mode loops reach the block
 * function through the branch table, which in this process holds the POWER8
 * entries -- so calling them as the reference hands a portable key to the
 * POWER8 block function.  The references below are therefore the entries
 * that reach cbits/aes/generic.c directly, and XTS, whose generic loop takes
 * its tweak through the table, is written out here instead.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "crypton_aes.h"
#include "aes/generic.h"
#include "aes/gf.h"
#include "aes/block128.h"
#include "aes/ppc8.h"

/* the portable CTR, which reaches generic.c rather than the branch table */
void crypton_aes_bitsliced_encrypt_ctr(uint8_t *output, aes_key *key,
                                       aes_block *iv, uint8_t *input,
                                       uint32_t len);

static int failures;
static int sabotage;

static void same(const char *what, const uint8_t *a, const uint8_t *b, size_t n)
{
	size_t i;

	if (memcmp(a, b, n) == 0)
		return;
	printf("  MISMATCH %s\n    ppc8     ", what);
	for (i = 0; i < n && i < 32; i++) printf("%02x", a[i]);
	printf("\n    portable ");
	for (i = 0; i < n && i < 32; i++) printf("%02x", b[i]);
	printf("\n");
	failures++;
}

static uint32_t rnd_state = 1;
static uint8_t rnd(void)
{
	rnd_state = rnd_state * 1103515245u + 12345u;
	return (uint8_t) (rnd_state >> 16);
}
static void rnd_fill(uint8_t *p, size_t n)
{
	while (n--) *p++ = rnd();
}

/*
 * XTS with the portable block function, written out because the generic
 * loop takes its tweak through the branch table.
 */
static void xts_reference(uint8_t *out, aes_key *k1, aes_key *k2,
                          const uint8_t *dataunit, uint32_t spoint,
                          const uint8_t *in, uint32_t nb, int decrypt)
{
	block128 tweak, t;
	uint32_t i;

	memcpy(&tweak, dataunit, 16);
	crypton_aes_generic_encrypt_block(&tweak, k2, &tweak);
	while (spoint-- > 0)
		crypton_aes_generic_gf_mulx(&tweak);

	for (i = 0; i < nb; i++) {
		block128_vxor(&t, (const block128 *) (in + 16 * i), &tweak);
		if (decrypt)
			crypton_aes_generic_decrypt_block(&t, k1, &t);
		else
			crypton_aes_generic_encrypt_block(&t, k1, &t);
		block128_vxor((block128 *) (out + 16 * i), &t, &tweak);
		crypton_aes_generic_gf_mulx(&tweak);
	}
}

/* the two inits write different things into the same aes_key, so each side
 * gets its own */
static void keys(aes_key *p8, aes_key *gen, const uint8_t *k, uint8_t len)
{
	memset(p8, 0, sizeof *p8);
	memset(gen, 0, sizeof *gen);
	p8->nbr = gen->nbr = len == 16 ? 10 : len == 24 ? 12 : 14;
	crypton_aes_ppc8_init(p8, (uint8_t *) k, len);
	crypton_aes_generic_init(gen, (uint8_t *) k, len);
}

int main(int argc, char **argv)
{
	static const uint8_t klens[3] = { 16, 24, 32 };
	int round;

	setvbuf(stdout, NULL, _IONBF, 0);   /* so a crash does not eat the section it was in */
	sabotage = argc > 1;

	printf("== the dispatch would take: aes=%d ==\n",
	       crypton_aes_ppc8_available());

	printf("== ECB and CBC, both directions ==\n");
	for (round = 0; round < 300; round++) {
		uint8_t key[32], in[16 * 9], a[16 * 9], b[16 * 9], iv[16];
		uint8_t len = klens[round % 3];
		uint32_t nb = 1 + (round % 9);
		aes_key kp, kg;

		rnd_fill(key, len);
		rnd_fill(in, nb * 16);
		rnd_fill(iv, 16);
		keys(&kp, &kg, key, len);

		crypton_aes_ppc8_encrypt_ecb((aes_block *) a, &kp, (aes_block *) in, nb);
		crypton_aes_generic_encrypt_ecb((aes_block *) b, &kg, (aes_block *) in, nb);
		if (sabotage && round == 3) a[0] ^= 1;
		same("ecb encrypt", a, b, nb * 16);

		crypton_aes_ppc8_decrypt_ecb((aes_block *) a, &kp, (aes_block *) in, nb);
		crypton_aes_generic_decrypt_ecb((aes_block *) b, &kg, (aes_block *) in, nb);
		same("ecb decrypt", a, b, nb * 16);

		{
			aes_block iv1, iv2;
			memcpy(&iv1, iv, 16); memcpy(&iv2, iv, 16);
			crypton_aes_ppc8_encrypt_cbc((aes_block *) a, &kp, &iv1, (aes_block *) in, nb);
			crypton_aes_generic_encrypt_cbc((aes_block *) b, &kg, &iv2, (aes_block *) in, nb);
			same("cbc encrypt", a, b, nb * 16);

			memcpy(&iv1, iv, 16); memcpy(&iv2, iv, 16);
			crypton_aes_ppc8_decrypt_cbc((aes_block *) a, &kp, &iv1, (aes_block *) in, nb);
			crypton_aes_generic_decrypt_cbc((aes_block *) b, &kg, &iv2, (aes_block *) in, nb);
			same("cbc decrypt", a, b, nb * 16);
		}
	}

	/*
	 * CTR, and the one place the two counters have to be reconciled by
	 * hand.  crypton counts over all 128 bits and the assembly over the
	 * low 32, so the work is handed over in runs that stop where that word
	 * wraps.  A buffer that never reaches the wrap exercises none of that,
	 * so the IV here is placed a few blocks before it on purpose.
	 */
	printf("== CTR, including the 32-bit counter wrapping ==\n");
	for (round = 0; round < 200; round++) {
		uint8_t key[32], in[600], a[600], b[600], iv[16];
		uint8_t len = klens[round % 3];
		uint32_t n = 1 + (round % 600);
		aes_key kp, kg;
		aes_block iv1, iv2;
		uint32_t before = round % 5;   /* blocks left before the wrap */

		rnd_fill(key, len);
		rnd_fill(in, n);
		rnd_fill(iv, 16);
		/* put the low word within a few blocks of wrapping, and for a
		 * third of the rounds exactly on it */
		iv[12] = 0xff; iv[13] = 0xff; iv[14] = 0xff;
		iv[15] = (uint8_t) (0x100 - before - 1);
		keys(&kp, &kg, key, len);

		memcpy(&iv1, iv, 16); memcpy(&iv2, iv, 16);
		crypton_aes_ppc8_encrypt_ctr(a, &kp, &iv1, in, n);
		crypton_aes_bitsliced_encrypt_ctr(b, &kg, &iv2, in, n);
		if (sabotage && round == 7) a[n - 1] ^= 2;
		same("ctr across the wrap", a, b, n);
	}

	printf("== XTS, both directions and a starting point ==\n");
	for (round = 0; round < 200; round++) {
		uint8_t k1[32], k2[32], in[16 * 11], a[16 * 11], b[16 * 11], du[16];
		uint8_t len = klens[round % 3];
		uint32_t nb = 1 + (round % 11);
		uint32_t spoint = round % 4;
		aes_key p1, g1, p2, g2;
		aes_block d1;

		rnd_fill(k1, len);
		rnd_fill(k2, len);
		rnd_fill(in, nb * 16);
		rnd_fill(du, 16);
		keys(&p1, &g1, k1, len);
		keys(&p2, &g2, k2, len);

		memcpy(&d1, du, 16);
		crypton_aes_ppc8_encrypt_xts((aes_block *) a, &p1, &p2, &d1, spoint,
		                             (aes_block *) in, nb);
		xts_reference(b, &g1, &g2, du, spoint, in, nb, 0);
		/* a[0], not a further block: at this round nb is 1 and anything
		 * past the first block is outside what same() is given */
		if (sabotage && round == 11) a[0] ^= 4;
		same("xts encrypt", a, b, nb * 16);

		memcpy(&d1, du, 16);
		crypton_aes_ppc8_decrypt_xts((aes_block *) a, &p1, &p2, &d1, spoint,
		                             (aes_block *) in, nb);
		xts_reference(b, &g1, &g2, du, spoint, in, nb, 1);
		same("xts decrypt", a, b, nb * 16);
	}

	/*
	 * GHASH, where the two arguments do not take the same convention and
	 * ppc8.c has to swap one of them.  Two different H and a non-zero
	 * accumulator, because a symmetric H or a zero start can hide a wrong
	 * convention.
	 */
	printf("== GHASH ==\n");
	for (round = 0; round < 300; round++) {
		uint8_t h[16], data[64], start[16];
		table_4bit tp, tg;
		block128 ap, ag;

		rnd_fill(h, 16);
		rnd_fill(data, sizeof data);
		rnd_fill(start, 16);

		crypton_aes_ppc8_hinit(tp, (const block128 *) h);
		crypton_aes_generic_hinit(tg, (const block128 *) h);

		memcpy(&ap, start, 16); memcpy(&ag, start, 16);
		crypton_aes_ppc8_gf_mul4(&ap, (const block128 *) data, tp);
		crypton_aes_generic_gf_mul4(&ag, (const block128 *) data, tg);
		if (sabotage && round == 5) ((uint8_t *) &ap)[0] ^= 8;
		same("gf_mul4", (const uint8_t *) &ap, (const uint8_t *) &ag, 16);

		memcpy(&ap, start, 16); memcpy(&ag, start, 16);
		crypton_aes_ppc8_gf_mul(&ap, tp);
		crypton_aes_generic_gf_mul(&ag, tg);
		same("gf_mul", (const uint8_t *) &ap, (const uint8_t *) &ag, 16);
	}

	printf("%s: %d mismatch(es)%s\n", failures ? "FAIL" : "ok", failures,
	       sabotage ? "  (sabotage was asked for)" : "");
	return failures != 0;
}
