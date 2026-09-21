/*
 * Arithmetic in a binary field, and the scalar multiplication a curve over
 * one needs, doing the same work whatever the scalar is.
 *
 * A carry-less multiplication is the one thing a binary field needs and
 * ordinary arithmetic does not give.  Where the processor has the instruction
 * for it this uses it -- PMULL on aarch64, which the compiler is told about,
 * and PCLMULQDQ on x86-64, which it is asked about at run time.  Where it
 * does not, each operand is split into four groups of every fourth bit, so
 * that the carries of an ordinary multiplication cannot reach the bits that
 * matter, and masked away afterwards.  None of the three has a table or a
 * branch that depends on what it is multiplying.
 *
 * Reduction folds what is above the degree back in, which the polynomial
 * being a trinomial or a pentanomial with exponents that are public makes
 * cheap.  Inversion is the exponentiation Fermat gives, whose exponent is
 * likewise public.
 *
 * The multiplication itself is Montgomery's ladder: it carries the x
 * coordinates of the multiples of two consecutive numbers, whose difference
 * is therefore the point, and spends one addition and one doubling on every
 * bit of the scalar whichever way the bit goes.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <crypton_cpu.h>
#include <crypton_f2m.h>

typedef uint64_t limb_t;
#define LIMB_BITS 64
#define LIMB_BYTES 8

#if defined(__aarch64__) && (defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_AES))
#include <arm_neon.h>
#define HAVE_CLMUL 1

static inline void clmul(limb_t a, limb_t b, limb_t *lo, limb_t *hi)
{
	uint64x2_t v = vreinterpretq_u64_p128(vmull_p64((poly64_t) a, (poly64_t) b));

	*lo = vgetq_lane_u64(v, 0);
	*hi = vgetq_lane_u64(v, 1);
}
#else
#define HAVE_CLMUL 0

/* the four groups, so that no carry of an ordinary multiplication reaches a
 * bit another partial product needs */
static void clmul32(uint32_t x, uint32_t y, limb_t *out)
{
	limb_t x0 = x & 0x11111111u, x1 = x & 0x22222222u;
	limb_t x2 = x & 0x44444444u, x3 = x & 0x88888888u;
	limb_t y0 = y & 0x11111111u, y1 = y & 0x22222222u;
	limb_t y2 = y & 0x44444444u, y3 = y & 0x88888888u;
	limb_t z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
	limb_t z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
	limb_t z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
	limb_t z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);

	*out = (z0 & 0x1111111111111111ULL) | (z1 & 0x2222222222222222ULL)
	       | (z2 & 0x4444444444444444ULL) | (z3 & 0x8888888888888888ULL);
}

static inline void clmul(limb_t a, limb_t b, limb_t *lo, limb_t *hi)
{
	limb_t ah = a >> 32, bh = b >> 32, t0, t1, t2;

	clmul32((uint32_t) a, (uint32_t) b, &t0);
	clmul32((uint32_t) ah, (uint32_t) bh, &t1);
	clmul32((uint32_t) (a ^ ah), (uint32_t) (b ^ bh), &t2);
	t2 ^= t0 ^ t1;
	*lo = t0 ^ (t2 << 32);
	*hi = t1 ^ (t2 >> 32);
}
#endif

/* t = a * b, over 2n limbs */
static void poly_mul_generic(limb_t *t, const limb_t *a, const limb_t *b,
                             uint32_t n)
{
	uint32_t i, j;

	memset(t, 0, 2 * n * sizeof(limb_t));
	for (i = 0; i < n; i++)
		for (j = 0; j < n; j++) {
			limb_t lo, hi;

			clmul(a[i], b[j], &lo, &hi);
			t[i + j] ^= lo;
			t[i + j + 1] ^= hi;
		}
}

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define HAVE_PCLMUL 1
#include <immintrin.h>

/* The same, with the instruction x86 has for it.  The attribute is what lets
 * one file hold both this and the code for a processor without it: the
 * compiler may emit the instruction here and nowhere else, and the caller
 * asks the processor before it comes this way.
 */
__attribute__((target("pclmul,sse2")))
static void poly_mul_pclmul(limb_t *t, const limb_t *a, const limb_t *b,
                            uint32_t n)
{
	uint32_t i, j;

	memset(t, 0, 2 * n * sizeof(limb_t));
	for (i = 0; i < n; i++)
		for (j = 0; j < n; j++) {
			__m128i p = _mm_clmulepi64_si128(
			    _mm_cvtsi64_si128((long long) a[i]),
			    _mm_cvtsi64_si128((long long) b[j]), 0x00);

			t[i + j] ^= (limb_t) _mm_cvtsi128_si64(p);
			t[i + j + 1] ^=
			    (limb_t) _mm_cvtsi128_si64(_mm_srli_si128(p, 8));
		}
}
#else
#define HAVE_PCLMUL 0
#endif

static void poly_mul(limb_t *t, const limb_t *a, const limb_t *b, uint32_t n)
{
#if HAVE_PCLMUL
	/* what the processor has is not what is being multiplied, so asking is
	 * not a side channel, and the answer is worked out once */
	if (crypton_x86_simd_features() & CRYPTON_X86_PCLMUL) {
		poly_mul_pclmul(t, a, b, n);
		return;
	}
#endif
	poly_mul_generic(t, a, b, n);
}

/* the bits of a 32-bit half, spread out with a zero between each pair */
static limb_t spread(limb_t x)
{
	x = (x | (x << 16)) & 0x0000ffff0000ffffULL;
	x = (x | (x << 8)) & 0x00ff00ff00ff00ffULL;
	x = (x | (x << 4)) & 0x0f0f0f0f0f0f0f0fULL;
	x = (x | (x << 2)) & 0x3333333333333333ULL;
	x = (x | (x << 1)) & 0x5555555555555555ULL;
	return x;
}

/* t = a * a, which in a binary field is the bits of a spread out */
static void poly_sqr(limb_t *t, const limb_t *a, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		t[2 * i] = spread(a[i] & 0xffffffffULL);
		t[2 * i + 1] = spread(a[i] >> 32);
	}
}

/* r = t mod fx, where fx is x^m plus the terms given, which are public
 *
 * Everything above bit m comes back in as those terms, a word at a time, and
 * then what is left above bit m within its own word is folded the same way.
 */
static void poly_reduce(limb_t *r, limb_t *t, uint32_t n, uint32_t m,
                        const uint32_t *terms, uint32_t nterms)
{
	uint32_t mw = m / LIMB_BITS, mb = m % LIMB_BITS, i, j, pass;

	for (i = 2 * n; i > mw + 1; i--) {
		limb_t w = t[i - 1];

		t[i - 1] = 0;
		for (j = 0; j < nterms; j++) {
			uint32_t pos = (i - 1) * LIMB_BITS - m + terms[j];
			uint32_t pw = pos / LIMB_BITS, pb = pos % LIMB_BITS;

			t[pw] ^= w << pb;
			if (pb != 0)
				t[pw + 1] ^= w >> (LIMB_BITS - pb);
		}
	}

	/* what is left above bit m sits in the word that holds it; folding it
	 * can put a little back, so it is done twice */
	for (pass = 0; pass < 2; pass++) {
		limb_t w;

		if (mb == 0)
			break;
		w = t[mw] >> mb;
		t[mw] &= ((limb_t) 1 << mb) - 1;
		for (j = 0; j < nterms; j++) {
			uint32_t pw = terms[j] / LIMB_BITS, pb = terms[j] % LIMB_BITS;

			t[pw] ^= w << pb;
			if (pb != 0 && pw + 1 <= mw)
				t[pw + 1] ^= w >> (LIMB_BITS - pb);
		}
	}
	memcpy(r, t, n * sizeof(limb_t));
}

/* the field: its polynomial, and scratch for a product */
typedef struct {
	uint32_t n;
	uint32_t m;
	uint32_t terms[8]; /* the polynomial without its leading term */
	uint32_t nterms;
	limb_t *t; /* 2n */
} bfield;

static void fe_mul(const bfield *f, limb_t *r, const limb_t *a, const limb_t *b)
{
	poly_mul(f->t, a, b, f->n);
	poly_reduce(r, f->t, f->n, f->m, f->terms, f->nterms);
}

static void fe_sqr(const bfield *f, limb_t *r, const limb_t *a)
{
	poly_sqr(f->t, a, f->n);
	poly_reduce(r, f->t, f->n, f->m, f->terms, f->nterms);
}

static void fe_add(const bfield *f, limb_t *r, const limb_t *a, const limb_t *b)
{
	uint32_t i;

	for (i = 0; i < f->n; i++)
		r[i] = a[i] ^ b[i];
}

static int fe_is_zero(const bfield *f, const limb_t *a)
{
	limb_t acc = 0;
	uint32_t i;

	for (i = 0; i < f->n; i++)
		acc |= a[i];
	return acc == 0;
}

/* r = 1/a, by Fermat: a to the power 2^m - 2, whose exponent is public */
static void fe_inv(const bfield *f, limb_t *r, const limb_t *a, limb_t *tmp)
{
	uint32_t i;

	memcpy(tmp, a, f->n * sizeof(limb_t));
	for (i = 1; i + 1 < f->m; i++) { /* a to the power 2^(m-1) - 1 */
		fe_sqr(f, tmp, tmp);
		fe_mul(f, tmp, tmp, a);
	}
	fe_sqr(f, r, tmp);
}

/* big-endian bytes into limbs, least significant limb first */
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
		uint32_t pos = len - 1 - i, li = i / LIMB_BYTES;

		dst[pos] = li < n ? (uint8_t) (a[li] >> (8 * (i % LIMB_BYTES))) : 0;
	}
}

/* exchange a and b when swap is one */
static void cswap(limb_t *a, limb_t *b, limb_t swap, uint32_t n)
{
	limb_t mask = (limb_t) 0 - swap;
	uint32_t i;

	for (i = 0; i < n; i++) {
		limb_t t = (a[i] ^ b[i]) & mask;

		a[i] ^= t;
		b[i] ^= t;
	}
}

int crypton_f2m_mul(uint8_t *outx, uint8_t *outy,
                    const uint8_t *px, const uint8_t *py,
                    const uint8_t *k, uint32_t klen,
                    const uint8_t *b, uint32_t flen,
                    const uint8_t *fx, uint32_t fxlen)
{
	uint32_t fn = (fxlen + LIMB_BYTES - 1) / LIMB_BYTES;
	uint32_t n, words, i;
	limb_t *space = NULL, *poly, *x, *y, *bb, *x1, *z1, *x2, *z2;
	limb_t *t1, *t2, *t3, *prod;
	bfield f;
	int ret = -1;

	if (flen == 0 || fxlen == 0 || klen == 0 || fn == 0)
		return -1;

	/* the polynomial, and the terms below its leading one */
	{
		limb_t *tmp = calloc(fn, sizeof(limb_t));
		uint32_t m = 0;

		if (tmp == NULL)
			return -1;
		if (from_be(tmp, fn, fx, fxlen) != 0) {
			free(tmp);
			return -1;
		}
		for (i = fn; i > 0 && m == 0; i--)
			if (tmp[i - 1] != 0) {
				limb_t top = tmp[i - 1];

				m = (i - 1) * LIMB_BITS;
				while (top != 0) {
					m++;
					top >>= 1;
				}
				m--; /* the degree is one under the bit count */
			}
		f.m = m;
		f.nterms = 0;
		for (i = 0; i < m; i++)
			if ((tmp[i / LIMB_BITS] >> (i % LIMB_BITS)) & 1) {
				if (f.nterms >= 8) {
					free(tmp);
					return -1; /* more terms than anything in use has */
				}
				f.terms[f.nterms++] = i;
			}
		free(tmp);
		if (m == 0 || f.nterms == 0)
			return -1;
	}

	n = (f.m + LIMB_BITS) / LIMB_BITS; /* room for the degree itself */
	f.n = n;
	words = 12 * n + 2 * n;
	space = calloc(words, sizeof(limb_t));
	if (space == NULL)
		return -1;
	poly = space;      /* unused beyond keeping the layout plain */
	x = poly + n;
	y = x + n;
	bb = y + n;
	x1 = bb + n;
	z1 = x1 + n;
	x2 = z1 + n;
	z2 = x2 + n;
	t1 = z2 + n;
	t2 = t1 + n;
	t3 = t2 + n;
	prod = t3 + n; /* 2n, and one n before it is spare */
	f.t = prod;

	if (from_be(x, n, px, flen) != 0 || from_be(y, n, py, flen) != 0
	    || from_be(bb, n, b, flen) != 0)
		goto done;
	if (fe_is_zero(&f, x))
		goto done; /* the point with no x is the caller's business */

	/* nothing, and the point next to it */
	memset(x1, 0, n * sizeof(limb_t));
	x1[0] = 1;
	memset(z1, 0, n * sizeof(limb_t));
	memcpy(x2, x, n * sizeof(limb_t));
	memset(z2, 0, n * sizeof(limb_t));
	z2[0] = 1;

	for (i = klen * 8; i > 0; i--) {
		uint32_t bit = i - 1;
		limb_t sel = (k[klen - 1 - bit / 8] >> (bit % 8)) & 1;

		/* whichever way the bit goes, one addition and one doubling: the
		 * exchange before and after is what puts them where the bit asks */
		cswap(x1, x2, sel, n);
		cswap(z1, z2, sel, n);

		/* the two added, which their difference being the point allows */
		fe_mul(&f, t1, x1, z2);
		fe_mul(&f, t2, x2, z1);
		fe_add(&f, t3, t1, t2);
		fe_sqr(&f, t3, t3); /* the new z */
		fe_mul(&f, t1, t1, t2);
		fe_mul(&f, t2, x, t3);
		fe_add(&f, t2, t2, t1); /* the new x */

		/* and one of them doubled */
		fe_sqr(&f, x1, x1);
		fe_sqr(&f, z1, z1);
		fe_mul(&f, t1, x1, z1); /* z of the double */
		fe_sqr(&f, x1, x1);
		fe_sqr(&f, z1, z1);
		fe_mul(&f, z1, z1, bb);
		fe_add(&f, x1, x1, z1); /* x of the double */
		memcpy(z1, t1, n * sizeof(limb_t));

		memcpy(x2, t2, n * sizeof(limb_t));
		memcpy(z2, t3, n * sizeof(limb_t));

		cswap(x1, x2, sel, n);
		cswap(z1, z2, sel, n);
	}

	if (fe_is_zero(&f, z1)) {
		ret = 1; /* the multiple is at infinity */
		goto done;
	}
	if (fe_is_zero(&f, z2)) {
		/* the one after it is, so this one is the negation of the point */
		to_be(outx, flen, x, n);
		fe_add(&f, t1, x, y);
		to_be(outy, flen, t1, n);
		ret = 0;
		goto done;
	}

	/* x1/z1 and x2/z2, and the y the ladder does not carry, out of one
	 * inversion: 1/(z1 z2 x) gives each of the three */
	fe_mul(&f, t1, z1, z2);
	fe_mul(&f, t1, t1, x);
	fe_inv(&f, t2, t1, t3);
	{
		limb_t *xa = x1, *xb = x2, *u = t1, *v = t3;

		fe_mul(&f, u, z2, x);
		fe_mul(&f, u, u, t2); /* 1/z1 */
		fe_mul(&f, xa, x1, u);
		fe_mul(&f, v, z1, x);
		fe_mul(&f, v, v, t2); /* 1/z2 */
		fe_mul(&f, xb, x2, v);
		fe_mul(&f, u, z1, z2);
		fe_mul(&f, u, u, t2); /* 1/x */

		fe_add(&f, v, xa, x);          /* x1 + x */
		fe_add(&f, xb, xb, x);         /* x2 + x */
		fe_mul(&f, xb, v, xb);         /* (x1 + x)(x2 + x) */
		fe_sqr(&f, t2, x);
		fe_add(&f, xb, xb, t2);
		fe_add(&f, xb, xb, y);         /* + x^2 + y */
		fe_mul(&f, xb, v, xb);
		fe_mul(&f, xb, xb, u);         /* over x */
		fe_add(&f, xb, xb, y);
		to_be(outx, flen, xa, n);
		to_be(outy, flen, xb, n);
	}
	ret = 0;

done:
	if (space != NULL) {
		memset(space, 0, words * sizeof(limb_t));
		free(space);
	}
	return ret;
}
