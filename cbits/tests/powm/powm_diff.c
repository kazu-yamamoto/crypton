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

static int failures = 0;
static int cases = 0;

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

static void show(const char *what, const uint8_t *p, uint32_t n)
{
	uint32_t i;

	printf("  %s ", what);
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

/* one trial: the two implementations must agree, and both must say they
 * succeeded */
static void trial(const uint8_t *b, uint32_t bl, const uint8_t *e, uint32_t el,
                  const uint8_t *m, uint32_t ml, const char *name)
{
	uint8_t *rs = malloc(ml), *rp = malloc(ml);
	int cs, cp;

	cases++;
	cs = crypton_powm_sec(rs, b, bl, e, el, m, ml);
	cp = crypton_powm_pub(rp, b, bl, e, el, m, ml);
	if (cs != 0) {
		printf("FAIL %s: the secure one declined (%d)\n", name, cs);
		failures++;
	} else if (cp != 0) {
		printf("FAIL %s: the public one declined (%d)\n", name, cp);
		failures++;
	} else if (memcmp(rs, rp, ml) != 0) {
		printf("FAIL %s\n", name);
		show("exponent", e, el);
		show("secure  ", rs, ml);
		show("public  ", rp, ml);
		failures++;
	}
	free(rs);
	free(rp);
}

/* the exponents the public one must refuse, because a windowed walk is the
 * better algorithm there and the caller has one */
static void declines(const uint8_t *b, uint32_t bl, const uint8_t *e,
                     uint32_t el, const uint8_t *m, uint32_t ml,
                     const char *name)
{
	uint8_t *rp = malloc(ml);
	uint32_t i;

	cases++;
	memset(rp, 0xcc, ml);
	if (crypton_powm_pub(rp, b, bl, e, el, m, ml) == 0) {
		printf("FAIL %s: the public one took a long exponent\n", name);
		failures++;
	} else
		for (i = 0; i < ml; i++)
			if (rp[i] != 0xcc) {
				printf("FAIL %s: declined but wrote\n", name);
				failures++;
				break;
			}
	free(rp);
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
	static const uint32_t sizes[] = {128, 256, 512, 1024, 1536, 2048,
	                                 3072, 4096};
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
	static const uint32_t sizes[] = {4, 6, 8, 16, 17, 24, 32, 48};
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

/* The generated multiplication and squaring against mont_mul and mont_sqr,
 * at the sizes they are generated for, on random operands and on the ones at
 * the edges of what they accept. */
#if defined(__aarch64__) && LIMB_BITS == 64 && !defined(CRYPTON_NO_MONT_FIXED) \
    && (defined(__GNUC__) || defined(__clang__))
#include "crypton_mont.h"
#define HAVE_MONT_FIXED 1
#endif

static int mont_fixed_agrees(void)
{
#ifdef HAVE_MONT_FIXED
	static const uint32_t sizes[] = {16, 24, 32, 48};
	limb_t m[48], a[48], b[48], r1[48], r2[48], t[96], n0;
	uint32_t s, k, i, bad = 0, cases = 0;

	for (s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
		uint32_t n = sizes[s];

		for (k = 0; k < 600; k++) {
			for (i = 0; i < n; i++) {
				m[i] = (limb_t) rng();
				a[i] = (limb_t) rng();
				b[i] = (limb_t) rng();
			}
			if (k % 4 == 0)
				m[n - 1] |= (limb_t) 1 << (LIMB_BITS - 1);
			if (k % 10 == 1)
				memset(m, 0xff, n * sizeof(limb_t));
			m[0] |= 1;
			if (m[n - 1] == 0)
				m[n - 1] = 1;
			a[n - 1] %= m[n - 1];
			b[n - 1] %= m[n - 1];
			switch (k % 10) {
			case 2: memset(a, 0, sizeof a); break;
			case 3: memset(a, 0, sizeof a); a[0] = 1; break;
			case 4: memcpy(a, m, n * sizeof(limb_t)); a[0] -= 1; break;
			case 5: memcpy(a, m, n * sizeof(limb_t)); a[0] -= 1;
			        memcpy(b, a, n * sizeof(limb_t)); break;
			}
			n0 = mont_n0(m[0]);
			cases++;

			/* 48 limbs has a squaring only */
			mont_mul(r1, a, b, m, n0, n, t);
			switch (n) {
			case 16: crypton_mont_mul16(r2, a, b, m, n0, t); break;
			case 24: crypton_mont_mul24(r2, a, b, m, n0, t); break;
			case 32: crypton_mont_mul32(r2, a, b, m, n0, t); break;
			default: memcpy(r2, r1, n * sizeof(limb_t)); break;
			}
			if (memcmp(r1, r2, n * sizeof(limb_t)) != 0) {
				printf("FAIL mont_mul%u: case %u disagrees\n", n, k);
				bad++;
				break;
			}

			mont_sqr(r1, a, m, n0, n, t);
			switch (n) {
			case 16: crypton_mont_sqr16(r2, a, m, n0, t); break;
			case 24: crypton_mont_sqr24(r2, a, m, n0, t); break;
			case 32: crypton_mont_sqr32(r2, a, m, n0, t); break;
			default: crypton_mont_sqr48(r2, a, m, n0, t); break;
			}
			if (memcmp(r1, r2, n * sizeof(limb_t)) != 0) {
				printf("FAIL mont_sqr%u: case %u disagrees\n", n, k);
				bad++;
				break;
			}
		}
	}
	if (bad == 0)
		printf("ok   %u operand pairs: the generated multiplication and squaring"
		       " are mont_mul's and mont_sqr's\n", cases);
	return bad == 0;
#else
	printf("skip generated code: this build has none to compare\n");
	return 1;
#endif
}

/* The normalization at the end of each IFMA multiplication, on lanes made to
 * need its second step: a run of lanes at exactly 2^52 - 1 that one carry has
 * to pass all the way through.  The exponentiations above almost never reach
 * that step -- it wants a lane within 2^12 of the top -- so it is driven here
 * directly, against carries moved one lane at a time. */
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include "crypton_cpu.h"
#include "crypton_powm_ifma.h"
#define HAVE_IFMA_NORM 1

IFMA_TARGET static void norm_by(uint32_t R, uint64_t *r, const uint64_t *x)
{
#define V(j) _mm256_loadu_si256((const __m256i *)(x + 4 * (j)))
	if (R == 5) ifma_norm5(r, V(0), V(1), V(2), V(3), V(4));
	else if (R == 8) ifma_norm8(r, V(0), V(1), V(2), V(3), V(4), V(5), V(6), V(7));
	else ifma_norm10(r, V(0), V(1), V(2), V(3), V(4), V(5), V(6), V(7), V(8), V(9));
#undef V
}
#endif

static int ifma_norm_agrees(void)
{
#ifdef HAVE_IFMA_NORM
	static const uint32_t rs[] = {5, 8, 10};
	uint64_t x[40], got[40], want[40];
	uint32_t s, k, i, cases = 0;

	if ((crypton_x86_simd_features() & CRYPTON_X86_IFMA) == 0) {
		printf("skip IFMA normalization: this processor has no AVX-512 IFMA\n");
		return 1;
	}
	for (s = 0; s < 3; s++) {
		uint32_t R = rs[s], n = 4 * R;
		for (k = 0; k < 300; k++) {
			uint64_t carry = 0;
			for (i = 0; i < n; i++)
				x[i] = rng() >> (k % 3 == 0 ? 4 : 12);
			x[n - 1] = 0;
			if (k % 3 == 1) {
				/* a run of saturated lanes, and a lane below them whose
				 * excess makes the lane under the run overflow */
				uint32_t at = (uint32_t) (rng() % (n - 6)), len = 1 + (uint32_t) (rng() % 4);
				for (i = 0; i < n; i++)
					x[i] &= ((uint64_t) 1 << 52) - 1;
				for (i = at + 1; i <= at + len; i++)
					x[i] = ((uint64_t) 1 << 52) - 1;
				x[at] = (((uint64_t) 1 << 52) - 1) + ((uint64_t) 1 << 52);
				x[n - 1] = 0;
			}
			norm_by(R, got, x);
			for (i = 0; i < n; i++) {
				uint64_t v = (x[i] & (((uint64_t) 1 << 52) - 1)) + carry;
				carry = (x[i] >> 52) + (v >> 52);
				want[i] = v & (((uint64_t) 1 << 52) - 1);
			}
			cases++;
			if (memcmp(got, want, n * sizeof(uint64_t)) != 0) {
				printf("FAIL IFMA normalization: %u lanes, case %u\n", n, k);
				return 0;
			}
		}
	}
	printf("ok   %u lane sets: the IFMA normalization moves every carry\n", cases);
	return 1;
#else
	printf("skip IFMA normalization: not x86-64\n");
	return 1;
#endif
}

/* The two-at-once exponentiation against crypton_powm_sec run twice, at the
 * sizes it takes, where the processor has what it needs.  Where it does not
 * the function has to decline, and that is checked instead. */
static int x2_agrees(void)
{
	static const uint32_t lens[] = {128, 192, 256};
	uint32_t s, k, bad = 0, ran = 0, declined = 0;

	for (s = 0; s < sizeof lens / sizeof lens[0]; s++) {
		uint32_t ml = lens[s];
		uint8_t *m1 = malloc(ml), *m2 = malloc(ml), *b1 = malloc(ml), *b2 = malloc(ml);
		uint8_t *e1 = malloc(ml), *e2 = malloc(ml);
		uint8_t *o1 = malloc(ml), *o2 = malloc(ml), *w1 = malloc(ml), *w2 = malloc(ml);

		for (k = 0; k < 40; k++) {
			fill(m1, ml); fill(m2, ml); fill(b1, ml); fill(b2, ml);
			fill(e1, ml); fill(e2, ml);
			m1[ml - 1] |= 1; m2[ml - 1] |= 1;
			if (k % 5 != 4) { m1[0] |= 0x80; m2[0] |= 0x80; }
			else { m1[0] &= 0x3f; m1[0] |= 0x20; m2[0] |= 0x01; }
			b1[0] = 0; b2[0] = 0;           /* under the modulus */
			switch (k % 8) {
			case 1: memset(b1, 0, ml); break;
			case 2: memset(b2, 0, ml); b2[ml - 1] = 1; break;
			case 3: memcpy(b1, m1, ml); b1[ml - 1] -= 1; break;
			case 5: memset(e1, 0, ml); break;
			case 6: memset(e2, 0xff, ml); break;
			case 7: memset(e1, 0, ml); e1[ml - 1] = 1; break;
			}
			if (crypton_powm_sec_x2(o1, b1, ml, e1, ml, m1, ml, o2, b2, ml, e2, ml, m2, ml) != 0) {
				declined++;
				continue;
			}
			ran++;
			crypton_powm_sec(w1, b1, ml, e1, ml, m1, ml);
			crypton_powm_sec(w2, b2, ml, e2, ml, m2, ml);
			if (memcmp(o1, w1, ml) != 0 || memcmp(o2, w2, ml) != 0) {
				printf("FAIL x2: %u-bit case %u disagrees with crypton_powm_sec\n", 8 * ml, k);
				bad++;
				break;
			}
		}
		free(m1); free(m2); free(b1); free(b2); free(e1); free(e2);
		free(o1); free(o2); free(w1); free(w2);
	}
	{
		/* sizes it does not take, and a pair that does not match */
		uint8_t m[96] = {0x80}, b[96] = {0}, e[96] = {1}, o[96];
		m[95] = 1;
		if (crypton_powm_sec_x2(o, b, 96, e, 96, m, 96, o, b, 96, e, 96, m, 96) == 0) {
			printf("FAIL x2: it took a 768-bit modulus\n");
			bad++;
		}
	}
	if (bad)
		return 0;
	if (ran == 0)
		printf("skip x2: this processor has no AVX-512 IFMA, and it declined all %u\n", declined);
	else
		printf("ok   %u pairs: two at once is crypton_powm_sec twice\n", ran);
	return 1;
}

int main(int argc, char **argv)
{
	/* in bits.  The first four are small enough that only the C runs; the
	 * rest are the sizes RSA works in -- 1024, 1536 and 2048 are the
	 * halves of a CRT exponentiation for RSA-2048, -3072 and -4096, and
	 * the ones s2n-bignum's multiplication takes where there is ADX.  This
	 * list once stopped at 512 under a comment calling it RSA sizes, so the
	 * comparison below never reached the assembly at all. */
	static const uint32_t sizes[] = {128, 256, 384, 512,
	                                 1024, 1536, 2048, 3072};
	uint32_t k, s;

	if (argc > 1 && strcmp(argv[1], "dump") == 0) {
		dump();
		return 0;
	}

	if (!montifier_agrees())
		failures++;
	if (!mont_fixed_agrees())
		failures++;
	if (!x2_agrees())
		failures++;
	if (!ifma_norm_agrees())
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

	/* RSA sizes, the exponents that turn up and the ones that do not */
	for (s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
		uint32_t ml = sizes[s] / 8;
		uint8_t *m, *b;
		uint32_t i;

		if (ml == 0)    /* never, but gcc cannot see that */
			continue;
		m = malloc(ml);
		b = malloc(ml);

		for (i = 0; i < 40; i++) {
			uint8_t e1[1], e3[3], e8[8], *el = malloc(ml);
			char nm[64];

			fill(m, ml);
			m[0] |= 0x80;           /* fills its limbs */
			m[ml - 1] |= 1;         /* odd */
			fill(b, ml);
			b[0] &= 0x7f;           /* under the modulus */

			/* 65537, the exponent of every RSA key here */
			e3[0] = 0x01; e3[1] = 0x00; e3[2] = 0x01;
			snprintf(nm, sizeof nm, "%u-bit, e=65537", sizes[s]);
			trial(b, ml, e3, 3, m, ml, nm);

			/* 3, and 1, which leaves the base where it is */
			e1[0] = 3;
			snprintf(nm, sizeof nm, "%u-bit, e=3", sizes[s]);
			trial(b, ml, e1, 1, m, ml, nm);
			e1[0] = 1;
			snprintf(nm, sizeof nm, "%u-bit, e=1", sizes[s]);
			trial(b, ml, e1, 1, m, ml, nm);

			/* an exponent whose top bit is not at a byte edge, and
			 * one with bytes of nothing above it */
			fill(e8, 8);
			e8[0] = 0x07;
			snprintf(nm, sizeof nm, "%u-bit, 59-bit exponent", sizes[s]);
			trial(b, ml, e8, 8, m, ml, nm);
			e8[0] = 0x00; e8[1] = 0x00;
			snprintf(nm, sizeof nm, "%u-bit, leading zero bytes", sizes[s]);
			trial(b, ml, e8, 8, m, ml, nm);

			/* an exponent as long as the modulus is the secure
			 * one's business, and the public one has to say so */
			fill(el, ml);
			el[0] |= 0x80;
			snprintf(nm, sizeof nm, "%u-bit, full-width exponent", sizes[s]);
			declines(b, ml, el, ml, m, ml, nm);

			/* a base of zero and a base of one */
			memset(b, 0, ml);
			snprintf(nm, sizeof nm, "%u-bit, base 0", sizes[s]);
			trial(b, ml, e3, 3, m, ml, nm);
			b[ml - 1] = 1;
			snprintf(nm, sizeof nm, "%u-bit, base 1", sizes[s]);
			trial(b, ml, e3, 3, m, ml, nm);

			/* a base one under the modulus */
			memcpy(b, m, ml);
			b[ml - 1] -= 1;
			snprintf(nm, sizeof nm, "%u-bit, base m-1", sizes[s]);
			trial(b, ml, e3, 3, m, ml, nm);

			free(el);
		}
		free(m);
		free(b);
	}

	if (failures == 0)
		printf("ok   %d cases at a window of %d bits\n",
		       cases, crypton_powm_window_bits());
	else
		printf("FAIL %d of %d cases\n", failures, cases);
	return failures == 0 ? 0 : 1;
}
