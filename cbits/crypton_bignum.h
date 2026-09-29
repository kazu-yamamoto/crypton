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

/*
 * t += a * b over n limbs, returning the carry.  This is where nearly all of
 * the time goes.
 *
 * The C below takes the limbs eight at a time; what is left over at the end
 * is taken one at a time.  On AArch64 the compiler writes each limb as
 * `mul`, `umulh`, `adds`, `cset`, `adds`, `adc`: the carry out of one
 * 128-bit addition leaves the flags for a general register and is added back
 * in the next, because in C each addition is a statement of its own.  Two of
 * those instructions are that round trip.
 *
 * Three attempts to take them back measured worse than the C, and are
 * written down here so that they are not tried again -- one RSA-2048 CRT
 * private operation on an Apple M4, best of many:
 *
 *     this loop in inline assembly, a carry chain per limb       654.7 us
 *     the same with the loads hoisted out of the chain           644.5
 *     the multiply interleaved with its reduction (CIOS)         604.1
 *     the C below                                                590.1
 *     what the AArch64 block does, four limbs and two chains     514.9
 *     the same, with the ragged end of the row written out too   503.4
 *
 * The first two lose because a chain per limb serialises what the spare
 * `cset` lets overlap: `adds`, `adc`, `adds`, `adc` is four dependent steps
 * per limb, and a wide out-of-order core would rather have the extra
 * instruction than the dependency.  The third loses because shifting the
 * accumulator down a limb each round costs more than the round trip through
 * 2n limbs that it saves.  What works is neither: four limbs to an
 * iteration with the flags carrying through two long chains, one for the low
 * halves of the products and one for the high halves a place up.
 *
 * There is more still there.  OpenSSL's armv8-mont.pl runs a 16-limb
 * Montgomery multiplication at about 0.98 multiply-accumulates per cycle;
 * this file was at 0.55 and the block below brings it to 0.64, where 1.0 is
 * the ceiling -- a multiply-accumulate is two instructions and the machine
 * issues two multiplies a cycle.  That code cannot be borrowed: it is in
 * OpenSSL's tree only, under Apache-2.0, and CRYPTOGAMS, which this library
 * does vendor from, publishes no Montgomery generator at all.  BearSSL's
 * only ARM assembly is 32-bit Thumb for Cortex-M0 to M3, with fifteen-bit
 * limbs for cores that have no fast multiplier, and Botan's AArch64 inline
 * assembly is the `mul`/`umulh`/`adds`/`adc` primitive the compiler already
 * emits.
 */
#if defined(__aarch64__) && LIMB_BITS == 64 \
    && (defined(__GNUC__) || defined(__clang__))
/*
 * Four limbs to an iteration, accumulated in two chains rather than one per
 * limb: the low halves of the four products, with the carry coming in, are
 * one run of `adds` and `adcs`, and the high halves shifted up a place are
 * another.  The flags carry the whole way through each, which is what the C
 * above cannot say and what it pays for in `cset` and an extra add.
 *
 * The arrangement is the one in Go's crypto/internal/fips140/bigmod
 * (nat_arm64.s, addMulVVWx), which is BSD-3-Clause like this library --
 * cbits/LICENSE.go carries its notice.  Written out here in the assembler
 * this file's compiler speaks.
 */
static inline limb_t addmul_1(limb_t *t, const limb_t *a, uint32_t n, limb_t b)
{
	uint64_t carry = 0;
	uint64_t x0, x1, x2, x3, z0, z1, z2, z3;
	uint64_t l0, l1, l2, l3, h0, h1, h2, h3;
	uint64_t blocks = n / 4, left = n % 4;

	if (blocks) {
		__asm__ volatile(
		"1:\n\t"
		"ldp	%[x0], %[x1], [%[a]], #16\n\t"
		"ldp	%[x2], %[x3], [%[a]], #16\n\t"
		"ldp	%[z0], %[z1], [%[t]]\n\t"
		/* the low halves, one place up from the second chain, with
		 * the carry that came in */
		"adds	%[z0], %[z0], %[c]\n\t"
		"mul	%[l1], %[x1], %[b]\n\t"
		"adcs	%[z1], %[z1], %[l1]\n\t"
		"mul	%[l2], %[x2], %[b]\n\t"
		"ldp	%[z2], %[z3], [%[t], #16]\n\t"
		"adcs	%[z2], %[z2], %[l2]\n\t"
		"mul	%[l3], %[x3], %[b]\n\t"
		"adcs	%[z3], %[z3], %[l3]\n\t"
		"umulh	%[h3], %[x3], %[b]\n\t"
		"adc	%[h3], %[h3], xzr\n\t"
		/* and the high halves, which is where this block's own carry
		 * ends up */
		"mul	%[l0], %[x0], %[b]\n\t"
		"adds	%[z0], %[z0], %[l0]\n\t"
		"umulh	%[h0], %[x0], %[b]\n\t"
		"adcs	%[z1], %[z1], %[h0]\n\t"
		"umulh	%[h1], %[x1], %[b]\n\t"
		"stp	%[z0], %[z1], [%[t]], #16\n\t"
		"adcs	%[z2], %[z2], %[h1]\n\t"
		"umulh	%[h2], %[x2], %[b]\n\t"
		"adcs	%[z3], %[z3], %[h2]\n\t"
		"stp	%[z2], %[z3], [%[t]], #16\n\t"
		"adc	%[c], %[h3], xzr\n\t"
		"subs	%[k], %[k], #1\n\t"
		"b.ne	1b\n\t"
		: [a] "+r"(a), [t] "+r"(t), [c] "+r"(carry), [k] "+r"(blocks),
		  [x0] "=&r"(x0), [x1] "=&r"(x1), [x2] "=&r"(x2),
		  [x3] "=&r"(x3), [z0] "=&r"(z0), [z1] "=&r"(z1),
		  [z2] "=&r"(z2), [z3] "=&r"(z3), [l0] "=&r"(l0),
		  [l1] "=&r"(l1), [l2] "=&r"(l2), [l3] "=&r"(l3),
		  [h0] "=&r"(h0), [h1] "=&r"(h1), [h2] "=&r"(h2),
		  [h3] "=&r"(h3)
		: [b] "r"(b)
		: "cc", "memory");
	}
	/* What is left of the row: three limbs, two, or one, each the same two
	 * chains cut short.  This is not a rare case to be handed back to C --
	 * mont_sqr asks for every length from n-1 down to 1, so three rows in
	 * four end ragged.  Only 4.7% of the limbs in a 1024-bit exponentiation
	 * arrive here, but they were the dearer ones, and writing them out is
	 * worth the last two per cent in the table above.  The three lengths
	 * are spelled out rather than run as 2+1, because chaining two short
	 * blocks makes the second wait on the first: that costs two thirds of
	 * the gain.
	 */
	if (left == 3) {
		__asm__ volatile(
		"ldp	%[x0], %[x1], [%[a]]\n\t"
		"ldr	%[x2], [%[a], #16]\n\t"
		"add	%[a], %[a], #24\n\t"
		"ldp	%[z0], %[z1], [%[t]]\n\t"
		"ldr	%[z2], [%[t], #16]\n\t"
		"adds	%[z0], %[z0], %[c]\n\t"
		"mul	%[l1], %[x1], %[b]\n\t"
		"adcs	%[z1], %[z1], %[l1]\n\t"
		"mul	%[l2], %[x2], %[b]\n\t"
		"adcs	%[z2], %[z2], %[l2]\n\t"
		"umulh	%[h2], %[x2], %[b]\n\t"
		"adc	%[h2], %[h2], xzr\n\t"
		"mul	%[l0], %[x0], %[b]\n\t"
		"adds	%[z0], %[z0], %[l0]\n\t"
		"umulh	%[h0], %[x0], %[b]\n\t"
		"adcs	%[z1], %[z1], %[h0]\n\t"
		"umulh	%[h1], %[x1], %[b]\n\t"
		"stp	%[z0], %[z1], [%[t]], #16\n\t"
		"adcs	%[z2], %[z2], %[h1]\n\t"
		"str	%[z2], [%[t]], #8\n\t"
		"adc	%[c], %[h2], xzr\n\t"
		: [a] "+r"(a), [t] "+r"(t), [c] "+r"(carry),
		  [x0] "=&r"(x0), [x1] "=&r"(x1), [x2] "=&r"(x2),
		  [z0] "=&r"(z0), [z1] "=&r"(z1), [z2] "=&r"(z2),
		  [l0] "=&r"(l0), [l1] "=&r"(l1), [l2] "=&r"(l2),
		  [h0] "=&r"(h0), [h1] "=&r"(h1), [h2] "=&r"(h2)
		: [b] "r"(b)
		: "cc", "memory");
	} else if (left == 2) {
		__asm__ volatile(
		"ldp	%[x0], %[x1], [%[a]], #16\n\t"
		"ldp	%[z0], %[z1], [%[t]]\n\t"
		"adds	%[z0], %[z0], %[c]\n\t"
		"mul	%[l1], %[x1], %[b]\n\t"
		"adcs	%[z1], %[z1], %[l1]\n\t"
		"umulh	%[h1], %[x1], %[b]\n\t"
		"adc	%[h1], %[h1], xzr\n\t"
		"mul	%[l0], %[x0], %[b]\n\t"
		"adds	%[z0], %[z0], %[l0]\n\t"
		"umulh	%[h0], %[x0], %[b]\n\t"
		"adcs	%[z1], %[z1], %[h0]\n\t"
		"stp	%[z0], %[z1], [%[t]], #16\n\t"
		"adc	%[c], %[h1], xzr\n\t"
		: [a] "+r"(a), [t] "+r"(t), [c] "+r"(carry),
		  [x0] "=&r"(x0), [x1] "=&r"(x1), [z0] "=&r"(z0),
		  [z1] "=&r"(z1), [l0] "=&r"(l0), [l1] "=&r"(l1),
		  [h0] "=&r"(h0), [h1] "=&r"(h1)
		: [b] "r"(b)
		: "cc", "memory");
	} else if (left == 1) {
		__asm__ volatile(
		"ldr	%[x0], [%[a]], #8\n\t"
		"ldr	%[z0], [%[t]]\n\t"
		"mul	%[l0], %[x0], %[b]\n\t"
		"adds	%[z0], %[z0], %[c]\n\t"
		"umulh	%[h0], %[x0], %[b]\n\t"
		"adc	%[h0], %[h0], xzr\n\t"
		"adds	%[z0], %[z0], %[l0]\n\t"
		"str	%[z0], [%[t]], #8\n\t"
		"adc	%[c], %[h0], xzr\n\t"
		: [a] "+r"(a), [t] "+r"(t), [c] "+r"(carry),
		  [x0] "=&r"(x0), [z0] "=&r"(z0), [l0] "=&r"(l0),
		  [h0] "=&r"(h0)
		: [b] "r"(b)
		: "cc", "memory");
	}
	return carry;
}
#else
/* one limb of it, so that the loops below can say how many they take at a
 * time without saying the rest of it four times over */
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
#endif

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

/* r2 = R^2 mod m, by doubling
 *
 * Doubling starts at the highest power of two under the modulus rather than
 * at one, since everything below that power is where doubling would go
 * anyway: for a modulus that fills its limbs that is half the steps.
 */
static inline void mont_r2(limb_t *r2, const limb_t *m, uint32_t n, limb_t *tmp)
{
	uint32_t i, k = 0, steps;

	for (i = n; i > 0 && k == 0; i--)
		if (m[i - 1] != 0) {
			limb_t top = m[i - 1];

			k = (i - 1) * LIMB_BITS;
			while (top != 0) {
				k++;
				top >>= 1;
			}
		}
	memset(r2, 0, n * sizeof(limb_t));
	if (k == 0)
		return; /* a modulus of nothing, which the caller rules out */
	r2[(k - 1) / LIMB_BITS] = (limb_t) 1 << ((k - 1) % LIMB_BITS);
	steps = 2 * n * LIMB_BITS - (k - 1);
	for (i = 0; i < steps; i++) {
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
