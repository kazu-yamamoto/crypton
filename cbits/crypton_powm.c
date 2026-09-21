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
 * So every window costs the same five multiplications and the same sixteen
 * reads, and nothing here branches on, or indexes memory with, anything
 * derived from the exponent.
 *
 * What is still visible is how many bytes the caller passed: the loop runs
 * over every bit of them, so the exponent's value is hidden but its length is
 * not.  GMP's mpz_powm_sec, which this replaces on the GHCs that no longer
 * offer it, hides the same amount.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <crypton_powm.h>

#if defined(__SIZEOF_INT128__)
typedef uint64_t limb_t;
typedef unsigned __int128 dlimb_t;
#define LIMB_BITS 64
#else
typedef uint32_t limb_t;
typedef uint64_t dlimb_t;
#define LIMB_BITS 32
#endif

#define LIMB_BYTES (LIMB_BITS / 8)

/* four bits of exponent per window, so a table of sixteen and no leftover
 * bits: a byte holds exactly two windows */
#define WINDOW_BITS 4
#define TABLE_SIZE (1 << WINDOW_BITS)

/* r = a - b, returning the borrow out of the top */
static limb_t sub_n(limb_t *r, const limb_t *a, const limb_t *b, uint32_t n)
{
	limb_t borrow = 0;
	uint32_t i;

	for (i = 0; i < n; i++) {
		limb_t ai = a[i], bi = b[i];
		limb_t d = ai - bi - borrow;
		/* borrow out, without branching */
		borrow = ((~ai & bi) | (~(ai ^ bi) & d)) >> (LIMB_BITS - 1);
		r[i] = d;
	}
	return borrow;
}

/* a = 2a, returning the bit shifted out of the top */
static limb_t shl1(limb_t *a, uint32_t n)
{
	limb_t carry = 0;
	uint32_t i;

	for (i = 0; i < n; i++) {
		limb_t next = a[i] >> (LIMB_BITS - 1);
		a[i] = (a[i] << 1) | carry;
		carry = next;
	}
	return carry;
}

/* r = take ? a : b */
static void select_n(limb_t *r, const limb_t *a, const limb_t *b, limb_t take,
                     uint32_t n)
{
	limb_t mask = (limb_t) 0 - take;
	uint32_t i;

	for (i = 0; i < n; i++)
		r[i] = (a[i] & mask) | (b[i] & ~mask);
}

/* all ones when a and b are equal, zero otherwise */
static limb_t eq_mask(limb_t a, limb_t b)
{
	limb_t d = a ^ b;
	limb_t nz = d | ((limb_t) 0 - d); /* top bit set unless d is zero */

	return (limb_t) 0 - ((nz >> (LIMB_BITS - 1)) ^ 1);
}

/* -m^-1 mod 2^LIMB_BITS, for odd m */
static limb_t mont_n0(limb_t m0)
{
	limb_t inv = 1;
	int i;

	/* Newton's iteration doubles the number of correct bits each time */
	for (i = 0; i < 6; i++)
		inv *= (limb_t) 2 - m0 * inv;
	return (limb_t) 0 - inv;
}

/* r = a * b * R^-1 mod m, with r, a and b of n limbs and t of n + 2 */
static void mont_mul(limb_t *r, const limb_t *a, const limb_t *b,
                     const limb_t *m, limb_t n0, uint32_t n, limb_t *t)
{
	uint32_t i, j;
	limb_t borrow, take;

	memset(t, 0, (n + 2) * sizeof(limb_t));

	for (i = 0; i < n; i++) {
		limb_t carry = 0, u;
		dlimb_t p;

		for (j = 0; j < n; j++) {
			p = (dlimb_t) a[j] * b[i] + t[j] + carry;
			t[j] = (limb_t) p;
			carry = (limb_t) (p >> LIMB_BITS);
		}
		p = (dlimb_t) t[n] + carry;
		t[n] = (limb_t) p;
		t[n + 1] = (limb_t) (p >> LIMB_BITS);

		u = t[0] * n0;
		p = (dlimb_t) u * m[0] + t[0];
		carry = (limb_t) (p >> LIMB_BITS);
		for (j = 1; j < n; j++) {
			p = (dlimb_t) u * m[j] + t[j] + carry;
			t[j - 1] = (limb_t) p;
			carry = (limb_t) (p >> LIMB_BITS);
		}
		p = (dlimb_t) t[n] + carry;
		t[n - 1] = (limb_t) p;
		t[n] = t[n + 1] + (limb_t) (p >> LIMB_BITS);
	}

	/* t is under 2m, so at most one subtraction; which one to keep is a mask */
	borrow = sub_n(r, t, m, n);
	take = t[n] | (borrow ^ 1);
	select_n(r, r, t, take & 1, n);
}

/* r2 = R^2 mod m, by doubling one 2 * n * LIMB_BITS times */
static void mont_r2(limb_t *r2, const limb_t *m, uint32_t n, limb_t *tmp)
{
	uint32_t i;

	memset(r2, 0, n * sizeof(limb_t));
	r2[0] = 1;
	for (i = 0; i < 2 * n * LIMB_BITS; i++) {
		limb_t carry = shl1(r2, n);
		limb_t borrow = sub_n(tmp, r2, m, n);
		select_n(r2, tmp, r2, (carry | (borrow ^ 1)) & 1, n);
	}
}

/* big-endian bytes into limbs, least significant limb first; anything above
 * n limbs has to be zero, which is what the contract on the base asks for */
static int from_be(limb_t *r, uint32_t n, const uint8_t *src, uint32_t len)
{
	uint32_t i;

	memset(r, 0, n * sizeof(limb_t));
	for (i = 0; i < len; i++) {
		uint8_t byte = src[len - 1 - i];

		if (i / LIMB_BYTES >= n) {
			if (byte != 0)
				return 1;
			continue;
		}
		r[i / LIMB_BYTES] |= (limb_t) byte << (8 * (i % LIMB_BYTES));
	}
	return 0;
}

static void to_be(uint8_t *dst, uint32_t len, const limb_t *a, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < len; i++) {
		uint32_t pos = len - 1 - i;
		uint32_t li = i / LIMB_BYTES;

		dst[pos] = li < n ? (uint8_t) (a[li] >> (8 * (i % LIMB_BYTES))) : 0;
	}
}

int crypton_powm_sec(uint8_t *out,
                     const uint8_t *base, uint32_t baselen,
                     const uint8_t *exp, uint32_t explen,
                     const uint8_t *mod, uint32_t modlen)
{
	uint32_t n = (modlen + LIMB_BYTES - 1) / LIMB_BYTES;
	uint32_t words = (TABLE_SIZE + 6) * n + 2;
	limb_t *space, *m, *r2, *acc, *sel, *prod, *table, *t, n0;
	uint32_t i, j, k;

	if (modlen == 0 || n == 0 || (mod[modlen - 1] & 1) == 0)
		return 1;

	/* the table, five more n-limb numbers and one of n + 2 */
	space = calloc(words, sizeof(limb_t));
	if (space == NULL)
		return 1;
	m = space;
	r2 = m + n;
	acc = r2 + n;
	sel = acc + n;
	prod = sel + n;
	t = prod + n;
	table = t + n + 2;

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
			mont_mul(sel, acc, acc, m, n0, n, t);
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
