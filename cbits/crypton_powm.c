/*
 * Modular exponentiation that does the same work whatever the exponent is.
 *
 * The exponent is walked four bits at a time: four squarings and one
 * multiplication by a small power of the base, taken from a table of sixteen.
 * The table is read by touching all sixteen entries and keeping one of them
 * with a mask, so the address stream does not follow the exponent, and the
 * multiplication itself is Montgomery's, whose only conditional step -- the
 * subtraction at the end -- is also done with a mask.
 *
 * So every window costs the same four squarings, the same multiplication and
 * the same sixteen reads, and nothing here branches on, or indexes memory
 * with, anything derived from the exponent.
 *
 * What is still visible is how many bytes the caller passed: the loop runs
 * over every bit of them, so the exponent's value is hidden but its length is
 * not.  GMP's mpz_powm_sec, which this replaces on the GHCs that no longer
 * offer it, hides the same amount.
 */
#include <stdlib.h>
#include <crypton_bignum.h>
#include <crypton_powm.h>

/*
 * At RSA sizes on x86-64, the Montgomery multiplication below is the whole
 * cost, and s2n-bignum's is twice as fast because the C cannot form the two
 * carry chains ADCX and ADOX give.  The window, the table and its masked
 * scan are unchanged: only the multiply and the square are swapped, and
 * only for the sizes s2n-bignum has a Karatsuba multiplication for.
 *
 * Not on AArch64, where the C measures 5% faster than the assembly.
 * See cbits/s2n/README.md.
 */
#if defined(CRYPTON_S2N_BIGNUM) && defined(__x86_64__)
#define CRYPTON_POWM_S2N 1
#include <crypton_cpu.h>

extern void bignum_kmul_16_32(uint64_t *z, const uint64_t *x,
                              const uint64_t *y, uint64_t *t);
extern void bignum_ksqr_16_32(uint64_t *z, const uint64_t *x, uint64_t *t);
extern void bignum_kmul_32_64(uint64_t *z, const uint64_t *x,
                              const uint64_t *y, uint64_t *t);
extern void bignum_ksqr_32_64(uint64_t *z, const uint64_t *x, uint64_t *t);
extern uint64_t bignum_emontredc_8n(uint64_t k, uint64_t *z,
                                    const uint64_t *m, uint64_t w);

/* 16 limbs is 1024 bits and 32 is 2048: the halves a CRT exponentiation
 * works in for RSA-2048 and RSA-4096, and the whole thing without CRT.  The
 * reduction wants ADX, so the answer is a run-time one. */
static int powm_s2n_usable(uint32_t n)
{
	return (n == 16 || n == 32)
	    && (crypton_x86_simd_features() & CRYPTON_X86_ADX) != 0;
}

/* The scratch the widest of them asks for, in multiples of n: kmul_32_64
 * wants 96 limbs for n = 32. */
#define POWM_S2N_SCRATCH 3

/* bignum_emontredc_8n leaves the result in the top half of z with one more
 * bit as its return value, and what is there is under twice the modulus --
 * the same place mont_reduce ends up, and finished the same way. */
static void powm_s2n_finish(limb_t *r, limb_t *z, const limb_t *m,
                            limb_t carry, uint32_t n)
{
	limb_t borrow = sub_n(r, z + n, m, n);
	limb_t take = carry | (borrow ^ 1);

	select_n(r, r, z + n, take & 1, n);
}

static void powm_s2n_mul(limb_t *r, const limb_t *a, const limb_t *b,
                         const limb_t *m, limb_t n0, uint32_t n, limb_t *z,
                         limb_t *scratch)
{
	if (n == 16)
		bignum_kmul_16_32(z, a, b, scratch);
	else
		bignum_kmul_32_64(z, a, b, scratch);
	powm_s2n_finish(r, z, m, bignum_emontredc_8n(n, z, m, n0), n);
}

static void powm_s2n_sqr(limb_t *r, const limb_t *a, const limb_t *m,
                         limb_t n0, uint32_t n, limb_t *z, limb_t *scratch)
{
	if (n == 16)
		bignum_ksqr_16_32(z, a, scratch);
	else
		bignum_ksqr_32_64(z, a, scratch);
	powm_s2n_finish(r, z, m, bignum_emontredc_8n(n, z, m, n0), n);
}
#else
#define POWM_S2N_SCRATCH 0
#endif

/* One or the other, decided once per call */
static void powm_mul(limb_t *r, const limb_t *a, const limb_t *b,
                     const limb_t *m, limb_t n0, uint32_t n, limb_t *t,
                     limb_t *scratch, int s2n)
{
#ifdef CRYPTON_POWM_S2N
	if (s2n) {
		powm_s2n_mul(r, a, b, m, n0, n, t, scratch);
		return;
	}
#else
	(void)scratch;
	(void)s2n;
#endif
	mont_mul(r, a, b, m, n0, n, t);
}

static void powm_sqr(limb_t *r, const limb_t *a, const limb_t *m, limb_t n0,
                     uint32_t n, limb_t *t, limb_t *scratch, int s2n)
{
#ifdef CRYPTON_POWM_S2N
	if (s2n) {
		powm_s2n_sqr(r, a, m, n0, n, t, scratch);
		return;
	}
#else
	(void)scratch;
	(void)s2n;
#endif
	mont_sqr(r, a, m, n0, n, t);
}

/* four bits of exponent per window, so a table of sixteen and no leftover
 * bits: a byte holds exactly two windows */
#define WINDOW_BITS 4
#define TABLE_SIZE (1 << WINDOW_BITS)

int crypton_powm_sec(uint8_t *out,
                     const uint8_t *base, uint32_t baselen,
                     const uint8_t *exp, uint32_t explen,
                     const uint8_t *mod, uint32_t modlen)
{
	uint32_t n = (modlen + LIMB_BYTES - 1) / LIMB_BYTES;
	uint32_t words = (TABLE_SIZE + 7 + POWM_S2N_SCRATCH) * n;
	limb_t *space, *m, *r2, *acc, *sel, *prod, *table, *t, *scratch, n0;
	uint32_t i, j, k;
	int s2n = 0;

	if (modlen == 0 || n == 0 || (mod[modlen - 1] & 1) == 0)
		return 1;

	/* the table, five more n-limb numbers and one of 2n */
	space = calloc(words, sizeof(limb_t));
	if (space == NULL)
		return 1;
	m = space;
	r2 = m + n;
	acc = r2 + n;
	sel = acc + n;
	prod = sel + n;
	t = prod + n;
	table = t + 2 * n;
	scratch = table + TABLE_SIZE * n;

#ifdef CRYPTON_POWM_S2N
	s2n = powm_s2n_usable(n);
#endif

	if (from_be(m, n, mod, modlen) != 0)
		goto fail;
	mont_r2(r2, m, n, t);
	n0 = mont_n0(m[0]);

	/* table[k] = base^k in Montgomery form, and table[0] = 1 there */
	memset(table, 0, n * sizeof(limb_t));
	table[0] = 1;
	powm_mul(acc, table, r2, m, n0, n, t, scratch, s2n);
	memcpy(table, acc, n * sizeof(limb_t));

	if (from_be(sel, n, base, baselen) != 0)
		goto fail;
	powm_mul(table + n, sel, r2, m, n0, n, t, scratch, s2n);
	for (k = 2; k < TABLE_SIZE; k++)
		powm_mul(table + k * n, table + (k - 1) * n, table + n, m, n0, n,
			         t, scratch, s2n);

	memcpy(acc, table, n * sizeof(limb_t));

	for (i = explen * 2; i > 0; i--) {
		uint32_t nib = i - 1;
		limb_t w = (exp[explen - 1 - nib / 2] >> (4 * (nib % 2))) & 0xf;

		for (j = 0; j < WINDOW_BITS; j++) {
			powm_sqr(sel, acc, m, n0, n, t, scratch, s2n);
			memcpy(acc, sel, n * sizeof(limb_t));
		}

		/* every entry is read, and a mask keeps the one wanted */
		memset(sel, 0, n * sizeof(limb_t));
		for (k = 0; k < TABLE_SIZE; k++) {
			limb_t mask = eq_mask(k, w);
			uint32_t l;

			for (l = 0; l < n; l++)
				sel[l] |= table[k * n + l] & mask;
		}
		powm_mul(prod, acc, sel, m, n0, n, t, scratch, s2n);
		memcpy(acc, prod, n * sizeof(limb_t));
	}

	/* out of Montgomery form */
	memset(sel, 0, n * sizeof(limb_t));
	sel[0] = 1;
	powm_mul(prod, acc, sel, m, n0, n, t, scratch, s2n);
	to_be(out, modlen, prod, n);

	/* nothing here is the caller's secret, but the exponent's bits passed
	 * through the accumulators */
	memset(space, 0, words * sizeof(limb_t));
	free(space);
	return 0;

fail:
	memset(space, 0, words * sizeof(limb_t));
	free(space);
	return 1;
}
