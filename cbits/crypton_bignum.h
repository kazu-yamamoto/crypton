/*
 * Arithmetic on numbers held as arrays of limbs, least significant first.
 *
 * The modular multiplication is Montgomery's, and every choice it makes --
 * which of two numbers to keep after the final subtraction, which entry of a
 * table to take -- is made with a mask rather than a branch, so that the
 * values being worked on do not steer the work.  The exponentiation in
 * crypton_powm.c and the curve arithmetic in crypton_ecc.c are both built on
 * this.
 *
 * Everything here is static inline: each file that includes it gets its own
 * copy, which the compiler can specialise to the sizes it uses.
 */
#ifndef CRYPTON_BIGNUM_H
#define CRYPTON_BIGNUM_H

#include <stdint.h>
#include <string.h>

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
static inline limb_t sub_n(limb_t *r, const limb_t *a, const limb_t *b, uint32_t n)
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

/* r = a + b, returning the carry out of the top */
static inline limb_t add_n(limb_t *r, const limb_t *a, const limb_t *b,
                           uint32_t n)
{
	limb_t carry = 0;
	uint32_t i;

	for (i = 0; i < n; i++) {
		dlimb_t s = (dlimb_t) a[i] + b[i] + carry;

		r[i] = (limb_t) s;
		carry = (limb_t) (s >> LIMB_BITS);
	}
	return carry;
}

/* a = 2a, returning the bit shifted out of the top */
static inline limb_t shl1(limb_t *a, uint32_t n)
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
static inline void select_n(limb_t *r, const limb_t *a, const limb_t *b, limb_t take,
                     uint32_t n)
{
	limb_t mask = (limb_t) 0 - take;
	uint32_t i;

	for (i = 0; i < n; i++)
		r[i] = (a[i] & mask) | (b[i] & ~mask);
}

/* all ones when a and b are equal, zero otherwise */
static inline limb_t eq_mask(limb_t a, limb_t b)
{
	limb_t d = a ^ b;
	limb_t nz = d | ((limb_t) 0 - d); /* top bit set unless d is zero */

	return (limb_t) 0 - ((nz >> (LIMB_BITS - 1)) ^ 1);
}

/* -m^-1 mod 2^LIMB_BITS, for odd m */
static inline limb_t mont_n0(limb_t m0)
{
	limb_t inv = 1;
	int i;

	/* Newton's iteration doubles the number of correct bits each time */
	for (i = 0; i < 6; i++)
		inv *= (limb_t) 2 - m0 * inv;
	return (limb_t) 0 - inv;
}

/* t += a * b over n limbs, returning the carry.  This is where nearly all of
 * the time goes, so the limbs are taken eight at a time; what is left over at
 * the end is taken one at a time. */
#define ADDMUL_STEP(k)                                                  \
	p = (dlimb_t) a[i + (k)] * b + t[i + (k)] + carry;                  \
	t[i + (k)] = (limb_t) p;                                            \
	carry = (limb_t) (p >> LIMB_BITS);

static inline limb_t addmul_1(limb_t *t, const limb_t *a, uint32_t n, limb_t b)
{
	limb_t carry = 0;
	uint32_t i = 0;
	dlimb_t p;

	for (; i + 8 <= n; i += 8) {
		ADDMUL_STEP(0) ADDMUL_STEP(1) ADDMUL_STEP(2) ADDMUL_STEP(3)
		ADDMUL_STEP(4) ADDMUL_STEP(5) ADDMUL_STEP(6) ADDMUL_STEP(7)
	}
	for (; i + 4 <= n; i += 4) {
		ADDMUL_STEP(0) ADDMUL_STEP(1) ADDMUL_STEP(2) ADDMUL_STEP(3)
	}
	for (; i + 2 <= n; i += 2) {
		ADDMUL_STEP(0) ADDMUL_STEP(1)
	}
	for (; i < n; i++) {
		ADDMUL_STEP(0)
	}
	return carry;
}

/* r = t * R^-1 mod m, with t of 2n limbs and destroyed on the way */
static inline void mont_reduce(limb_t *r, limb_t *t, const limb_t *m, limb_t n0,
                        uint32_t n)
{
	limb_t borrow, take, carry = 0;
	uint32_t i;

	for (i = 0; i < n; i++) {
		limb_t u = t[i] * n0;
		limb_t c = addmul_1(t + i, m, n, u);
		dlimb_t s = (dlimb_t) t[n + i] + c + carry;

		t[n + i] = (limb_t) s;
		carry = (limb_t) (s >> LIMB_BITS);
	}

	/* what is left is under 2m, so at most one subtraction; which of the two
	 * to keep is a mask */
	borrow = sub_n(r, t + n, m, n);
	take = carry | (borrow ^ 1);
	select_n(r, r, t + n, take & 1, n);
}

/* r = a * b * R^-1 mod m, with t of 2n limbs */
static inline void mont_mul(limb_t *r, const limb_t *a, const limb_t *b,
                     const limb_t *m, limb_t n0, uint32_t n, limb_t *t)
{
	uint32_t i;

	memset(t, 0, 2 * n * sizeof(limb_t));
	for (i = 0; i < n; i++)
		t[n + i] = addmul_1(t + i, a, n, b[i]);
	mont_reduce(r, t, m, n0, n);
}

/* r = a * a * R^-1 mod m, with t of 2n limbs.  A square is its own mirror
 * image, so each product off the diagonal is worth two and only half of them
 * are worked out: their sum is doubled, and then the diagonal is added in. */
static inline void mont_sqr(limb_t *r, const limb_t *a, const limb_t *m, limb_t n0,
                     uint32_t n, limb_t *t)
{
	limb_t carry = 0;
	uint32_t i;

	memset(t, 0, 2 * n * sizeof(limb_t));
	for (i = 0; i + 1 < n; i++)
		t[n + i] = addmul_1(t + i + i + 1, a + i + 1, n - 1 - i, a[i]);
	shl1(t, 2 * n); /* their sum is under half of what 2n limbs hold */
	for (i = 0; i < n; i++) {
		dlimb_t p = (dlimb_t) a[i] * a[i] + t[i + i] + carry;

		t[i + i] = (limb_t) p;
		p = (dlimb_t) t[i + i + 1] + (limb_t) (p >> LIMB_BITS);
		t[i + i + 1] = (limb_t) p;
		carry = (limb_t) (p >> LIMB_BITS);
	}
	mont_reduce(r, t, m, n0, n);
}

/* r2 = R^2 mod m, by doubling one 2 * n * LIMB_BITS times */
static inline void mont_r2(limb_t *r2, const limb_t *m, uint32_t n, limb_t *tmp)
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
static inline int from_be(limb_t *r, uint32_t n, const uint8_t *src, uint32_t len)
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

static inline void to_be(uint8_t *dst, uint32_t len, const limb_t *a, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < len; i++) {
		uint32_t pos = len - 1 - i;
		uint32_t li = i / LIMB_BYTES;

		dst[pos] = li < n ? (uint8_t) (a[li] >> (8 * (i % LIMB_BYTES))) : 0;
	}
}

#endif
