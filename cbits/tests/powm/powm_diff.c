/* The window the secure exponentiation walks the exponent in.
 *
 * Four bits is what the library ships with, and four is the one width that
 * divides a byte: at five or six a window falls across a byte boundary and
 * the walk has to read two.  The width is not supposed to be visible in the
 * answers, so three builds of this print the same vectors and the three
 * outputs have to match.
 *
 * Beside that, a modulus small enough to raise to a power by repeated
 * multiplication, answered both ways.  The cross-width comparison cannot see
 * a fault that every width shares; this can.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "crypton_powm.h"
#include "crypton_bignum.h"

static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;

static uint64_t rng(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

static void fill(uint8_t *p, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t) rng();
}

/* b^e mod m for numbers that fit in 32 bits, by repeated multiplication */
static uint32_t small_powm(uint32_t b, uint32_t e, uint32_t m)
{
	uint64_t acc = 1 % m;
	uint32_t i;

	for (i = 0; i < e; i++)
		acc = (acc * b) % m;
	return (uint32_t) acc;
}

static void be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t) v;
}

/* The answers for a fixed set of exponents, to be compared between builds
 * at different window widths.  Nothing here depends on the width, so a
 * difference is the window reader. */
static void dump(void)
{
	static const uint32_t sizes[] = {128, 256, 512, 1024, 2048};
	uint32_t s, k, i;

	rng_state = 0x243f6a8885a308d3ULL;
	for (s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
		uint32_t ml = sizes[s] / 8;
		uint8_t *m, *b, *e, *r;

		/* every size above is a whole number of bytes and none of them
		 * is zero, but gcc 13 cannot see that from here and warns
		 * about the m[ml - 1] below */
		if (ml == 0)
			continue;
		m = malloc(ml); b = malloc(ml);
		e = malloc(ml); r = malloc(ml);
		if (m == NULL || b == NULL || e == NULL || r == NULL) {
			printf("FAIL out of memory\n");
			free(m); free(b); free(e); free(r);
			return;
		}

		for (k = 0; k < 20; k++) {
			/* every exponent length from one byte up, so that a
			 * window falling off the top is covered as well as one
			 * falling across a byte */
			uint32_t el = 1 + (uint32_t)(rng() % ml);

			fill(m, ml); m[0] |= 0x80; m[ml - 1] |= 1;
			fill(b, ml); b[0] &= 0x7f;
			fill(e, el);
			if (crypton_powm_sec(r, b, ml, e, el, m, ml) != 0) {
				printf("declined %u %u\n", sizes[s], el);
				continue;
			}
			printf("%u %u ", sizes[s], el);
			for (i = 0; i < ml; i++)
				printf("%02x", r[i]);
			printf("\n");
		}
		free(m); free(b); free(e); free(r);
	}
}

/* R^2 mod m two ways: crypton's ladder of Montgomery squarings, and
 * s2n-bignum's bignum_montifier where it is built.  Every exponentiation and
 * every s2n ECC operation starts with this constant, so a disagreement is
 * not a slow path but a wrong answer everywhere. */
static int montifier_agrees(void)
{
#ifdef CRYPTON_MONTIFIER
	static const uint32_t sizes[] = {4, 6, 8, 16, 17, 32};
	uint32_t s, k, i, bad = 0, cases = 0;

	for (s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
		uint32_t n = sizes[s];
		limb_t *m = calloc(n, sizeof(limb_t));
		limb_t *a = calloc(n, sizeof(limb_t));
		limb_t *b = calloc(n, sizeof(limb_t));
		limb_t *t = calloc(2 * n + 8, sizeof(limb_t));

		for (k = 0; k < 50; k++) {
			for (i = 0; i < n; i++)
				m[i] = (limb_t) rng();
			/* both a modulus that fills its limbs and one that
			 * does not, since the ladder starts at the top bit */
			if (k & 1)
				m[n - 1] |= (limb_t) 1 << (LIMB_BITS - 1);
			else
				m[n - 1] >>= 1 + (k % (LIMB_BITS - 1));
			m[0] |= 1;
			if (n == 1 && m[0] == 1)
				continue;
			cases++;
			mont_r2_c(a, m, mont_n0(m[0]), n, t);
			mont_r2(b, m, mont_n0(m[0]), n, t);
			if (memcmp(a, b, n * sizeof(limb_t)) != 0) {
				printf("FAIL montifier: %u limbs disagree\n", n);
				bad++;
				break;
			}
		}
		free(m); free(a); free(b); free(t);
	}
	if (bad == 0)
		printf("ok   %u moduli: the assembly R^2 is the C's R^2\n", cases);
	return bad == 0;
#else
	printf("skip R^2: this build has no assembly montifier to compare\n");
	return 1;
#endif
}

int main(int argc, char **argv)
{
	int failures = 0, cases = 0;
	uint32_t k;

	if (argc > 1 && strcmp(argv[1], "dump") == 0) {
		dump();
		return 0;
	}

	if (!montifier_agrees())
		failures++;

	for (k = 0; k < 2000; k++) {
		uint32_t m = (uint32_t)(rng() % 60000) | 1;
		uint32_t b, e = (uint32_t)(rng() % 40);
		uint8_t mb[4], bb[4], eb[4], r[4];
		uint32_t want, got;

		if (m < 3)
			continue;
		b = (uint32_t)(rng() % m);
		be32(mb, m); be32(bb, b); be32(eb, e);
		cases++;
		if (crypton_powm_sec(r, bb, 4, eb, 4, mb, 4) != 0) {
			printf("FAIL small: it declined on %u^%u mod %u\n", b, e, m);
			failures++;
			continue;
		}
		want = small_powm(b, e, m);
		got = (uint32_t) r[0] << 24 | (uint32_t) r[1] << 16 |
		      (uint32_t) r[2] << 8 | r[3];
		if (got != want) {
			printf("FAIL small: %u^%u mod %u is %u, not %u\n",
			       b, e, m, want, got);
			failures++;
		}
	}

	if (failures == 0)
		printf("ok   %d small moduli at a window of %d bits\n",
		       cases, crypton_powm_window_bits());
	else
		printf("FAIL %d of %d small moduli\n", failures, cases);
	return failures == 0 ? 0 : 1;
}
