/*
 * The double scalar multiplication ECDSA verification does, in variable
 * time.
 *
 * Verification asks for u1*G + u2*Q, and crypton used to work that out as
 * two separate constant-time multiplications and an addition.  Nothing here
 * is secret -- the message, the signature and the public key are all sent in
 * the clear -- so the constant-time work is paid for nothing, and the two
 * multiplications can share their doublings besides.  Measured, those two
 * were 84% of a verification.
 *
 * So this is the usual interleaved windowed form: both scalars in
 * width-5 non-adjacent form, a table of odd multiples of each point, and one
 * pass down the digits with a doubling at every step and an addition where a
 * digit is not zero.  It is s2n-bignum's Jacobian point arithmetic
 * underneath, the same assembly the constant-time paths use.
 *
 * s2n-bignum's p256_montjadd is correct except when its two arguments are
 * the same point -- that is the side condition its proof carries -- so every
 * sum is checked for the sign of that, which is a zero z where neither
 * argument had one.  There the answer is given up on and the caller falls
 * back to the constant-time pair, which has no such condition.  With random
 * inputs it does not happen; it is here because an attacker chooses the
 * public key and the signature.
 */
#include <string.h>

#include "p256/p256.h"

#ifdef CRYPTON_S2N_BIGNUM

#include "crypton_cpu.h"
#include "p256/p256_verify.h"

/* a Jacobian triple in the Montgomery domain, as the assembly keeps them */
#define JAC 12
#define AFF 8

extern void p256_montjadd(uint64_t p3[JAC], const uint64_t p1[JAC],
                          const uint64_t p2[JAC]);
extern void p256_montjadd_alt(uint64_t p3[JAC], const uint64_t p1[JAC],
                              const uint64_t p2[JAC]);
extern void p256_montjdouble(uint64_t p3[JAC], const uint64_t p1[JAC]);
extern void p256_montjdouble_alt(uint64_t p3[JAC], const uint64_t p1[JAC]);
extern void p256_montjmixadd(uint64_t p3[JAC], const uint64_t p1[JAC],
                             const uint64_t p2[AFF]);
extern void p256_montjmixadd_alt(uint64_t p3[JAC], const uint64_t p1[JAC],
                                 const uint64_t p2[AFF]);

/* the odd multiples of the base point, from cbits/p256/gen_base_table.py */
extern const uint64_t crypton_p256_wnaf_width;
extern const uint64_t crypton_p256_wnaf_table[];
extern void bignum_tomont_p256(uint64_t z[4], const uint64_t x[4]);
extern void bignum_demont_p256(uint64_t z[4], const uint64_t x[4]);
extern void bignum_neg_p256(uint64_t z[4], const uint64_t x[4]);
#if !defined(__aarch64__) && !defined(__arm64__)
extern void bignum_tomont_p256_alt(uint64_t z[4], const uint64_t x[4]);
extern void bignum_demont_p256_alt(uint64_t z[4], const uint64_t x[4]);
#endif

/* The same question as everywhere else in cbits/s2n: a microarchitecture one
 * on ARM that no feature bit answers, and exactly a feature bit on x86-64. */
static int use_alt(void)
{
#if defined(__aarch64__) || defined(__arm64__)
#ifdef __APPLE__
	return 1;
#else
	return 0;
#endif
#else
	return (crypton_x86_simd_features() & CRYPTON_X86_ADX) == 0;
#endif
}

static void padd(uint64_t r[JAC], const uint64_t a[JAC], const uint64_t b[JAC],
                 int alt)
{
	if (alt)
		p256_montjadd_alt(r, a, b);
	else
		p256_montjadd(r, a, b);
}

static void pmixadd(uint64_t r[JAC], const uint64_t a[JAC],
                    const uint64_t b[AFF], int alt)
{
	if (alt)
		p256_montjmixadd_alt(r, a, b);
	else
		p256_montjmixadd(r, a, b);
}

static void pdouble(uint64_t r[JAC], const uint64_t a[JAC], int alt)
{
	if (alt)
		p256_montjdouble_alt(r, a);
	else
		p256_montjdouble(r, a);
}

static void tomont(uint64_t z[4], const uint64_t x[4])
{
#if defined(__aarch64__) || defined(__arm64__)
	bignum_tomont_p256(z, x);
#else
	if (use_alt())
		bignum_tomont_p256_alt(z, x);
	else
		bignum_tomont_p256(z, x);
#endif
}

static void demont(uint64_t z[4], const uint64_t x[4])
{
#if defined(__aarch64__) || defined(__arm64__)
	bignum_demont_p256(z, x);
#else
	if (use_alt())
		bignum_demont_p256_alt(z, x);
	else
		bignum_demont_p256(z, x);
#endif
}

static int is_infinity(const uint64_t p[JAC])
{
	return (p[8] | p[9] | p[10] | p[11]) == 0;
}

/*
 * The base point's table is a constant, so its window is as wide as the
 * table is worth carrying: seven bits, thirty-two odd multiples, two
 * kilobytes, and one addition every eight digits.  The public key's table
 * has to be built for each verification, so five bits is the trade there --
 * eight entries, seven point operations to build, and one addition every
 * six digits.
 */
#define WG 7
#define TG (1 << (WG - 2))
#define WQ 5
#define TQ (1 << (WQ - 2))
#define NAF_MAX 258

/*
 * The width-W non-adjacent form of a scalar, one signed digit per bit
 * position: odd or zero, and never two non-zero digits within W of each
 * other.  Returns how many digits were written.
 *
 * The scalar is public, so the loop may look at it.
 */
static int wnaf(int8_t out[NAF_MAX], const uint64_t in[4], int w)
{
	uint64_t k[5];
	int len = 0;

	memcpy(k, in, 32);
	k[4] = 0;

	while (k[0] | k[1] | k[2] | k[3] | k[4]) {
		int d = 0;

		if (k[0] & 1) {
			d = (int) (k[0] & ((1u << w) - 1));
			if (d >= (1 << (w - 1)))
				d -= 1 << w;
			if (d > 0) {
				uint64_t borrow = (uint64_t) d;
				int i;

				for (i = 0; i < 5 && borrow; i++) {
					uint64_t t = k[i];

					k[i] = t - borrow;
					borrow = (k[i] > t);
				}
			} else {
				uint64_t carry = (uint64_t) (-d);
				int i;

				for (i = 0; i < 5 && carry; i++) {
					k[i] += carry;
					carry = (k[i] < carry);
				}
			}
		}
		out[len++] = (int8_t) d;

		{ /* k >>= 1 */
			int i;

			for (i = 0; i < 4; i++)
				k[i] = (k[i] >> 1) | (k[i + 1] << 63);
			k[4] >>= 1;
		}
	}
	return len;
}

/* P, 3P, 5P, ..., (2*TQ-1)P from a Jacobian P */
static int build_table(uint64_t t[TQ][JAC], const uint64_t p[JAC], int alt)
{
	uint64_t twice[JAC];
	int i;

	memcpy(t[0], p, sizeof(uint64_t) * JAC);
	pdouble(twice, p, alt);
	for (i = 1; i < TQ; i++) {
		padd(t[i], t[i - 1], twice, alt);
		/* the table is built from a point and its double, which are
		 * never the same point unless the point has order two, and
		 * P-256 has none */
		if (is_infinity(t[i]) && !is_infinity(t[i - 1])
		    && !is_infinity(twice))
			return 0;
	}
	return 1;
}

/* the table entry for a digit, negated when the digit is */
static void pick(uint64_t out[JAC], const uint64_t t[TQ][JAC], int digit)
{
	int idx = (digit > 0 ? digit : -digit) / 2;

	memcpy(out, t[idx], sizeof(uint64_t) * JAC);
	if (digit < 0)
		bignum_neg_p256(out + 4, out + 4);
}

/* the same from the base point's affine table */
static void pick_affine(uint64_t out[AFF], int digit)
{
	int idx = (digit > 0 ? digit : -digit) / 2;

	memcpy(out, crypton_p256_wnaf_table + (size_t) idx * AFF,
	       sizeof(uint64_t) * AFF);
	if (digit < 0)
		bignum_neg_p256(out + 4, out + 4);
}

int crypton_p256_verify_mul(uint64_t out[JAC], const uint64_t n1[4],
                            const uint64_t n2[4], const uint64_t qx[4],
                            const uint64_t qy[4])
{
	/* the Montgomery form of one, which is the z of an affine point */
	static const uint64_t mont_one[4] = {
		0x0000000000000001ULL, 0xffffffff00000000ULL,
		0xffffffffffffffffULL, 0x00000000fffffffeULL
	};
	uint64_t tq[TQ][JAC];
	uint64_t q[JAC], acc[JAC], addend[JAC], aff[AFF], sum[JAC];
	int8_t naf1[NAF_MAX], naf2[NAF_MAX];
	int len1, len2, len, i;
	/* asked once rather than at every point operation */
	const int alt = use_alt();

	/* the generated table has to be the width this file walks it at */
	if (crypton_p256_wnaf_width != WG)
		return 0;

	tomont(q, qx);
	tomont(q + 4, qy);
	memcpy(q + 8, mont_one, sizeof mont_one);

	if (!build_table(tq, q, alt))
		return 0;

	len1 = wnaf(naf1, n1, WG);
	len2 = wnaf(naf2, n2, WQ);
	len = len1 > len2 ? len1 : len2;

	memset(acc, 0, sizeof acc);
	for (i = len - 1; i >= 0; i--) {
		pdouble(acc, acc, alt);

		if (i < len1 && naf1[i] != 0) {
			/* the base point's entries are affine, which is a
			 * cheaper addition and no table to build */
			pick_affine(aff, naf1[i]);
			pmixadd(sum, acc, aff, alt);
			if (is_infinity(sum) && !is_infinity(acc))
				return 0;
			memcpy(acc, sum, sizeof acc);
		}
		if (i < len2 && naf2[i] != 0) {
			pick(addend, tq, naf2[i]);
			padd(sum, acc, addend, alt);
			if (is_infinity(sum) && !is_infinity(acc))
				return 0;
			memcpy(acc, sum, sizeof acc);
		}
	}

	demont(out, acc);
	demont(out + 4, acc + 4);
	demont(out + 8, acc + 8);
	return 1;
}

#endif
