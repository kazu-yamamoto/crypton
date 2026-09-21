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
	uint32_t words = (TABLE_SIZE + 7) * n;
	limb_t *space, *m, *r2, *acc, *sel, *prod, *table, *t, n0;
	uint32_t i, j, k;

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

	if (from_be(m, n, mod, modlen) != 0)
		goto fail;
	mont_r2(r2, m, n, t);
	n0 = mont_n0(m[0]);

	/* table[k] = base^k in Montgomery form, and table[0] = 1 there */
	memset(table, 0, n * sizeof(limb_t));
	table[0] = 1;
	mont_mul(acc, table, r2, m, n0, n, t);
	memcpy(table, acc, n * sizeof(limb_t));

	if (from_be(sel, n, base, baselen) != 0)
		goto fail;
	mont_mul(table + n, sel, r2, m, n0, n, t);
	for (k = 2; k < TABLE_SIZE; k++)
		mont_mul(table + k * n, table + (k - 1) * n, table + n, m, n0, n, t);

	memcpy(acc, table, n * sizeof(limb_t));

	for (i = explen * 2; i > 0; i--) {
		uint32_t nib = i - 1;
		limb_t w = (exp[explen - 1 - nib / 2] >> (4 * (nib % 2))) & 0xf;

		for (j = 0; j < WINDOW_BITS; j++) {
			mont_sqr(sel, acc, m, n0, n, t);
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
		mont_mul(prod, acc, sel, m, n0, n, t);
		memcpy(acc, prod, n * sizeof(limb_t));
	}

	/* out of Montgomery form */
	memset(sel, 0, n * sizeof(limb_t));
	sel[0] = 1;
	mont_mul(prod, acc, sel, m, n0, n, t);
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
