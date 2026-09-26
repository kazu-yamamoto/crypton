/*
 * Scalar multiplication on a curve over a prime field, doing the same work
 * whatever the scalar is.
 *
 * The scalar is walked four bits at a time: four doublings and one addition
 * of a small multiple of the point, taken from a table of sixteen that is
 * read by touching every entry and keeping one of them with a mask.  So a
 * window costs the same five operations and the same sixteen reads whatever
 * its bits are, and nothing branches on, or indexes memory with, the scalar.
 *
 * The addition and the doubling are the complete formulas of Renes, Costello
 * and Batina (eprint 2015/1060, algorithms 1 and 3), which answer for every
 * pair of points there is -- the same point twice, a point and its negation,
 * the point at infinity -- without a case to choose between.  A formula with
 * cases would need the choice to be made with a mask like everything else
 * here, and would still have to be right about which cases there are; these
 * have none.  They cost about half again what the usual Jacobian formulas do,
 * which is the price of that.
 *
 * Points are kept in homogeneous projective coordinates, where the point at
 * infinity is (0 : 1 : 0), and in Montgomery form, so that the only reduction
 * is the one the multiplication does anyway.
 */
#include <stdlib.h>
#include <crypton_bignum.h>
#include <crypton_ecc.h>
#include <crypton_powm.h>
#ifdef CRYPTON_S2N_BIGNUM
#include <crypton_ecc_s2n.h>
#endif

/* four bits of scalar per window, so a table of sixteen and no leftover
 * bits: a byte holds exactly two windows */
#define WINDOW_BITS 4
#define TABLE_SIZE (1 << WINDOW_BITS)

/* the field the curve is over, and what it takes to work in it */
typedef struct {
	uint32_t n; /* limbs in a field element */
	limb_t n0;  /* -p^-1 mod 2^LIMB_BITS */
	const limb_t *p;
	const limb_t *a;  /* the curve's a, in Montgomery form */
	const limb_t *b3; /* three times the curve's b, in Montgomery form */
	const limb_t *zero; /* n limbs of nothing, to subtract from */
	int a_is_zero;      /* a is 0 or p-3 for every curve in use, and then */
	int a_is_minus3;    /* multiplying by it is additions instead */
	limb_t *t;        /* 2n of scratch, for the multiplication */
	limb_t *s;        /* n of scratch, for the addition and subtraction */
	limb_t *s2;       /* n more, for multiplying by a, which may write over
	                   * what it is reading */
} field;

static void fe_mul(const field *f, limb_t *r, const limb_t *x, const limb_t *y)
{
	mont_mul(r, x, y, f->p, f->n0, f->n, f->t);
}

static void fe_sqr(const field *f, limb_t *r, const limb_t *x)
{
	mont_sqr(r, x, f->p, f->n0, f->n, f->t);
}

static void fe_add(const field *f, limb_t *r, const limb_t *x, const limb_t *y)
{
	limb_t carry = add_n(r, x, y, f->n);
	limb_t borrow = sub_n(f->s, r, f->p, f->n);

	select_n(r, f->s, r, (carry | (borrow ^ 1)) & 1, f->n);
}

static void fe_sub(const field *f, limb_t *r, const limb_t *x, const limb_t *y)
{
	limb_t borrow = sub_n(r, x, y, f->n);

	add_n(f->s, r, f->p, f->n);
	select_n(r, f->s, r, borrow, f->n);
}

/* r = -x */
static void fe_neg(const field *f, limb_t *r, const limb_t *x)
{
	fe_sub(f, r, f->zero, x);
}

/* r = a * x, where a is the curve's.  It is zero or minus three on every
 * curve in use, and then this is additions rather than a multiplication.
 * Which of the three it is comes from the curve, which is public. */
static void fe_mul_a(const field *f, limb_t *r, const limb_t *x)
{
	if (f->a_is_zero) {
		memset(r, 0, f->n * sizeof(limb_t));
	} else if (f->a_is_minus3) {
		/* r and x are the same buffer in places, so this goes through one
		 * of its own */
		fe_add(f, f->s2, x, x);
		fe_add(f, f->s2, f->s2, x);
		fe_neg(f, r, f->s2);
	} else {
		fe_mul(f, r, f->a, x);
	}
}

/* Renes-Costello-Batina algorithm 1: r = x + y, for any two points */
static void point_add(const field *f, limb_t *r, const limb_t *x,
                      const limb_t *y, limb_t *w)
{
	uint32_t n = f->n;
	const limb_t *x1 = x, *y1 = x + n, *z1 = x + 2 * n;
	const limb_t *x2 = y, *y2 = y + n, *z2 = y + 2 * n;
	limb_t *t0 = w, *t1 = w + n, *t2 = w + 2 * n, *t3 = w + 3 * n;
	limb_t *t4 = w + 4 * n, *t5 = w + 5 * n;
	limb_t *x3 = w + 6 * n, *y3 = w + 7 * n, *z3 = w + 8 * n;

	fe_mul(f, t0, x1, x2);
	fe_mul(f, t1, y1, y2);
	fe_mul(f, t2, z1, z2);
	fe_add(f, t3, x1, y1);
	fe_add(f, t4, x2, y2);
	fe_mul(f, t3, t3, t4);
	fe_add(f, t4, t0, t1);
	fe_sub(f, t3, t3, t4);
	fe_add(f, t4, x1, z1);
	fe_add(f, t5, x2, z2);
	fe_mul(f, t4, t4, t5);
	fe_add(f, t5, t0, t2);
	fe_sub(f, t4, t4, t5);
	fe_add(f, t5, y1, z1);
	fe_add(f, x3, y2, z2);
	fe_mul(f, t5, t5, x3);
	fe_add(f, x3, t1, t2);
	fe_sub(f, t5, t5, x3);
	fe_mul_a(f, z3, t4);
	fe_mul(f, x3, f->b3, t2);
	fe_add(f, z3, x3, z3);
	fe_sub(f, x3, t1, z3);
	fe_add(f, z3, t1, z3);
	fe_mul(f, y3, x3, z3);
	fe_add(f, t1, t0, t0);
	fe_add(f, t1, t1, t0);
	fe_mul_a(f, t2, t2);
	fe_mul(f, t4, f->b3, t4);
	fe_add(f, t1, t1, t2);
	fe_sub(f, t2, t0, t2);
	fe_mul_a(f, t2, t2);
	fe_add(f, t4, t4, t2);
	fe_mul(f, t0, t1, t4);
	fe_add(f, y3, y3, t0);
	fe_mul(f, t0, t5, t4);
	fe_mul(f, x3, t3, x3);
	fe_sub(f, x3, x3, t0);
	fe_mul(f, t0, t3, t1);
	fe_mul(f, t1, t5, z3);
	fe_add(f, z3, t1, t0);

	memcpy(r, x3, n * sizeof(limb_t));
	memcpy(r + n, y3, n * sizeof(limb_t));
	memcpy(r + 2 * n, z3, n * sizeof(limb_t));
}

/* Renes-Costello-Batina algorithm 3: r = x + x, for any point */
static void point_double(const field *f, limb_t *r, const limb_t *x, limb_t *w)
{
	uint32_t n = f->n;
	const limb_t *px = x, *py = x + n, *pz = x + 2 * n;
	limb_t *t0 = w, *t1 = w + n, *t2 = w + 2 * n, *t3 = w + 3 * n;
	limb_t *x3 = w + 6 * n, *y3 = w + 7 * n, *z3 = w + 8 * n;

	fe_sqr(f, t0, px);
	fe_sqr(f, t1, py);
	fe_sqr(f, t2, pz);
	fe_mul(f, t3, px, py);
	fe_add(f, t3, t3, t3);
	fe_mul(f, z3, px, pz);
	fe_add(f, z3, z3, z3);
	fe_mul_a(f, x3, z3);
	fe_mul(f, y3, f->b3, t2);
	fe_add(f, y3, x3, y3);
	fe_sub(f, x3, t1, y3);
	fe_add(f, y3, t1, y3);
	fe_mul(f, y3, x3, y3);
	fe_mul(f, x3, t3, x3);
	fe_mul(f, z3, f->b3, z3);
	fe_mul_a(f, t2, t2);
	fe_sub(f, t3, t0, t2);
	fe_mul_a(f, t3, t3);
	fe_add(f, t3, t3, z3);
	fe_add(f, z3, t0, t0);
	fe_add(f, t0, z3, t0);
	fe_add(f, t0, t0, t2);
	fe_mul(f, t0, t0, t3);
	fe_add(f, y3, y3, t0);
	fe_mul(f, t2, py, pz);
	fe_add(f, t2, t2, t2);
	fe_mul(f, t0, t2, t3);
	fe_sub(f, x3, x3, t0);
	fe_mul(f, z3, t2, t1);
	fe_add(f, z3, z3, z3);
	fe_add(f, z3, z3, z3);

	memcpy(r, x3, n * sizeof(limb_t));
	memcpy(r + n, y3, n * sizeof(limb_t));
	memcpy(r + 2 * n, z3, n * sizeof(limb_t));
}

/* Everything a curve needs, in one allocation: the field, the buffers the
 * formulas work in, and a table of sixteen points.  The caller frees it with
 * ctx_free. */
typedef struct {
	field f;
	limb_t *space;
	uint32_t words;
	uint32_t n;
	limb_t *r2;   /* R^2 mod p, which is what takes a number to Montgomery form */
	limb_t *one;  /* 1, in Montgomery form */
	limb_t *acc;  /* a point */
	limb_t *sel;  /* a point */
	limb_t *tmp;  /* a point */
	limb_t *work; /* 9n, for the formulas */
	limb_t *table; /* sixteen points */
	uint8_t *bytes; /* 2 * plen, for the inversion */
	uint32_t plen;
} curve_ctx;

static void ctx_free(curve_ctx *c)
{
	if (c->space != NULL) {
		memset(c->space, 0, c->words * sizeof(limb_t));
		free(c->space);
	}
	if (c->bytes != NULL) {
		memset(c->bytes, 0, 2 * c->plen);
		free(c->bytes);
	}
	c->space = NULL;
	c->bytes = NULL;
}

/* r = x, taken into Montgomery form */
static void to_mont(const curve_ctx *c, limb_t *r, const limb_t *x)
{
	mont_mul(r, x, c->r2, c->f.p, c->f.n0, c->n, c->f.t);
}

/* r = x, taken back out of it */
static void from_mont(const curve_ctx *c, limb_t *r, const limb_t *x)
{
	mont_mul(r, x, c->one, c->f.p, c->f.n0, c->n, c->f.t);
}

static int ctx_init(curve_ctx *c, const uint8_t *a, const uint8_t *b,
                    const uint8_t *p, uint32_t plen)
{
	uint32_t n = (plen + LIMB_BYTES - 1) / LIMB_BYTES;
	limb_t *mp, *ma, *mb3, *zero, *scratch, *mont_t;
	uint32_t i;

	memset(c, 0, sizeof(*c));
	if (plen == 0 || n == 0 || (p[plen - 1] & 1) == 0)
		return -1;

	/* six single numbers, three points, four of scratch, nine for the
	 * formulas, and a table of sixteen points */
	c->n = n;
	c->plen = plen;
	c->words = (6 + 9 + 4 + 9 + 3 * TABLE_SIZE) * n;
	c->space = calloc(c->words, sizeof(limb_t));
	c->bytes = calloc(2, plen);
	if (c->space == NULL || c->bytes == NULL) {
		ctx_free(c);
		return -1;
	}
	mp = c->space;
	ma = mp + n;
	mb3 = ma + n;
	c->r2 = mb3 + n;
	c->one = c->r2 + n;
	zero = c->one + n;
	c->acc = zero + n;
	c->sel = c->acc + 3 * n;
	c->tmp = c->sel + 3 * n;
	scratch = c->tmp + 3 * n;
	mont_t = scratch + 2 * n;
	c->work = mont_t + 2 * n;
	c->table = c->work + 9 * n;

	if (from_be(mp, n, p, plen) != 0) {
		ctx_free(c);
		return -1;
	}
	mont_r2(c->r2, mp, n, mont_t);

	c->f.n = n;
	c->f.n0 = mont_n0(mp[0]);
	c->f.p = mp;
	c->f.a = ma;
	c->f.b3 = mb3;
	c->f.zero = zero;
	c->f.t = mont_t;
	c->f.s = scratch;
	c->f.s2 = scratch + n;
	c->f.a_is_zero = 0;
	c->f.a_is_minus3 = 0;

	memset(c->one, 0, n * sizeof(limb_t));
	c->one[0] = 1;
	to_mont(c, c->tmp, c->one);
	memcpy(c->one, c->tmp, n * sizeof(limb_t));

	/* the curve's a, and which of the three shapes it has */
	if (from_be(c->tmp, n, a, plen) != 0) {
		ctx_free(c);
		return -1;
	}
	{
		limb_t nonzero = 0, differs = 0;

		for (i = 0; i < n; i++)
			nonzero |= c->tmp[i];
		memset(c->sel, 0, n * sizeof(limb_t));
		c->sel[0] = 3;
		sub_n(c->sel, mp, c->sel, n); /* p - 3 */
		for (i = 0; i < n; i++)
			differs |= c->tmp[i] ^ c->sel[i];
		c->f.a_is_zero = nonzero == 0;
		c->f.a_is_minus3 = differs == 0;
	}
	to_mont(c, ma, c->tmp);

	/* three times the curve's b, which is what the formulas want */
	if (from_be(c->tmp, n, b, plen) != 0) {
		ctx_free(c);
		return -1;
	}
	to_mont(c, mb3, c->tmp);
	fe_add(&c->f, c->tmp, mb3, mb3);
	fe_add(&c->f, mb3, c->tmp, mb3);
	return 0;
}

/* a point, in Montgomery form, from its coordinates */
static int point_from_be(const curve_ctx *c, limb_t *r, const uint8_t *px,
                         const uint8_t *py)
{
	uint32_t n = c->n;

	if (from_be(c->tmp, n, px, c->plen) != 0)
		return -1;
	to_mont(c, r, c->tmp);
	if (from_be(c->tmp, n, py, c->plen) != 0)
		return -1;
	to_mont(c, r + n, c->tmp);
	memcpy(r + 2 * n, c->one, n * sizeof(limb_t));
	return 0;
}

/* x = X/Z and y = Y/Z, with the inverse from Fermat, which is the
 * exponentiation that hides its exponent.  Returns 1 for the point at
 * infinity, which has no coordinates. */
static int point_to_be(curve_ctx *c, uint8_t *outx, uint8_t *outy,
                       const limb_t *pt, const uint8_t *p)
{
	uint32_t n = c->n, plen = c->plen, i;
	limb_t empty = 0;
	uint8_t *zbytes = c->bytes, *pm2 = c->bytes + plen;

	for (i = 0; i < n; i++)
		empty |= pt[2 * n + i];
	if (empty == 0)
		return 1;

	from_mont(c, c->tmp, pt + 2 * n);
	to_be(zbytes, plen, c->tmp, n);
	memset(c->sel, 0, n * sizeof(limb_t));
	c->sel[0] = 2;
	sub_n(c->sel, c->f.p, c->sel, n); /* p - 2 */
	to_be(pm2, plen, c->sel, n);
	if (crypton_powm_sec(zbytes, zbytes, plen, pm2, plen, p, plen) != 0)
		return -1;
	if (from_be(c->tmp, n, zbytes, plen) != 0)
		return -1;
	to_mont(c, c->sel, c->tmp); /* 1/Z, in Montgomery form */

	fe_mul(&c->f, c->tmp, pt, c->sel);
	from_mont(c, c->tmp + n, c->tmp);
	to_be(outx, plen, c->tmp + n, n);

	fe_mul(&c->f, c->tmp, pt + n, c->sel);
	from_mont(c, c->tmp + n, c->tmp);
	to_be(outy, plen, c->tmp + n, n);
	return 0;
}

/* every one of the sixteen entries is read, and a mask keeps the one wanted */
static void table_select(const curve_ctx *c, limb_t *r, const limb_t *table,
                         limb_t w)
{
	uint32_t n = c->n, j, l;

	memset(r, 0, 3 * n * sizeof(limb_t));
	for (j = 0; j < TABLE_SIZE; j++) {
		limb_t mask = eq_mask(j, w);

		for (l = 0; l < 3 * n; l++)
			r[l] |= table[3 * j * n + l] & mask;
	}
}

int crypton_ecc_mul(uint8_t *outx, uint8_t *outy,
                    const uint8_t *px, const uint8_t *py,
                    const uint8_t *k, uint32_t klen,
                    const uint8_t *a, const uint8_t *b,
                    const uint8_t *p, uint32_t plen)
{
	curve_ctx c;
	uint32_t n, i, j;
	int ret = -1;

#ifdef CRYPTON_S2N_BIGNUM
	/* Two of the curves that reach here have hand-written assembly, six
	 * to ten times faster than what follows; see cbits/s2n/README.md.
	 * Anything else, including those two named with a different a or b,
	 * goes on down. */
	{
		int s2n_ret;

		if (crypton_s2n_ecc_mul(&s2n_ret, outx, outy, px, py, k, klen,
		                        a, b, p, plen))
			return s2n_ret;
	}
#endif

	if (klen == 0 || ctx_init(&c, a, b, p, plen) != 0)
		return -1;
	n = c.n;

	/* the table: nothing, the point, and its multiples up to fifteen */
	memset(c.table, 0, 3 * n * sizeof(limb_t));
	memcpy(c.table + n, c.one, n * sizeof(limb_t)); /* (0 : 1 : 0) */
	if (point_from_be(&c, c.table + 3 * n, px, py) != 0)
		goto done;
	for (i = 2; i < TABLE_SIZE; i++)
		point_add(&c.f, c.table + 3 * i * n, c.table + 3 * (i - 1) * n,
		          c.table + 3 * n, c.work);

	/* four bits at a time, from the top */
	memcpy(c.acc, c.table, 3 * n * sizeof(limb_t));
	for (i = klen * 2; i > 0; i--) {
		uint32_t nib = i - 1;
		limb_t w = (k[klen - 1 - nib / 2] >> (4 * (nib % 2))) & 0xf;

		for (j = 0; j < WINDOW_BITS; j++)
			point_double(&c.f, c.acc, c.acc, c.work);
		table_select(&c, c.sel, c.table, w);
		point_add(&c.f, c.acc, c.acc, c.sel, c.work);
	}
	ret = point_to_be(&c, outx, outy, c.acc, p);

done:
	ctx_free(&c);
	return ret;
}

uint32_t crypton_ecc_table_size(uint32_t plen, uint32_t klen)
{
	uint32_t n = (plen + LIMB_BYTES - 1) / LIMB_BYTES;

	if (plen == 0 || klen == 0 || n == 0)
		return 0;
	return klen * 2 * TABLE_SIZE * 3 * n * (uint32_t) sizeof(limb_t);
}

int crypton_ecc_table_build(uint8_t *tab,
                            const uint8_t *gx, const uint8_t *gy,
                            uint32_t klen,
                            const uint8_t *a, const uint8_t *b,
                            const uint8_t *p, uint32_t plen)
{
	curve_ctx c;
	limb_t *t = (limb_t *) (void *) tab;
	uint32_t n, i, j, windows;
	int ret = -1;

	if (klen == 0 || ctx_init(&c, a, b, p, plen) != 0)
		return -1;
	n = c.n;
	windows = klen * 2;

	/* acc walks the powers: at window i it holds 16^i times the point */
	if (point_from_be(&c, c.acc, gx, gy) != 0)
		goto done;
	for (i = 0; i < windows; i++) {
		limb_t *slot = t + (size_t) i * TABLE_SIZE * 3 * n;

		memset(slot, 0, 3 * n * sizeof(limb_t));
		memcpy(slot + n, c.one, n * sizeof(limb_t)); /* (0 : 1 : 0) */
		memcpy(slot + 3 * n, c.acc, 3 * n * sizeof(limb_t));
		for (j = 2; j < TABLE_SIZE; j++)
			point_add(&c.f, slot + 3 * j * n, slot + 3 * (j - 1) * n,
			          c.acc, c.work);
		for (j = 0; j < WINDOW_BITS; j++)
			point_double(&c.f, c.acc, c.acc, c.work);
	}
	ret = 0;

done:
	ctx_free(&c);
	return ret;
}

int crypton_ecc_table_mul(uint8_t *outx, uint8_t *outy, const uint8_t *tab,
                          const uint8_t *k, uint32_t klen,
                          const uint8_t *a, const uint8_t *b,
                          const uint8_t *p, uint32_t plen)
{
	curve_ctx c;
	const limb_t *t = (const limb_t *) (const void *) tab;
	uint32_t n, i;
	int ret;

	if (klen == 0 || ctx_init(&c, a, b, p, plen) != 0)
		return -1;
	n = c.n;

	/* nothing to start with, and one addition for every four bits: the
	 * multiples the doubling would work out are all in the table */
	memset(c.acc, 0, 3 * n * sizeof(limb_t));
	memcpy(c.acc + n, c.one, n * sizeof(limb_t));
	for (i = 0; i < klen * 2; i++) {
		limb_t w = (k[klen - 1 - i / 2] >> (4 * (i % 2))) & 0xf;

		table_select(&c, c.sel, t + (size_t) i * TABLE_SIZE * 3 * n, w);
		point_add(&c.f, c.acc, c.acc, c.sel, c.work);
	}
	ret = point_to_be(&c, outx, outy, c.acc, p);

	ctx_free(&c);
	return ret;
}
