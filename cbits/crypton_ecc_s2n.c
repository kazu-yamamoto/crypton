#include <string.h>

#include "crypton_ecc_s2n.h"
#include "crypton_ecc_s2n_curves.h"
#include "crypton_cpu.h"

/* P-384, Montgomery domain, six words a coordinate */
extern void p384_montjscalarmul(uint64_t *res, const uint64_t *s, const uint64_t *p);
extern void p384_montjscalarmul_alt(uint64_t *res, const uint64_t *s, const uint64_t *p);
extern void bignum_tomont_p384(uint64_t *z, const uint64_t *x);
extern void bignum_tomont_p384_alt(uint64_t *z, const uint64_t *x);
extern void bignum_deamont_p384(uint64_t *z, const uint64_t *x);
extern void bignum_deamont_p384_alt(uint64_t *z, const uint64_t *x);
extern void bignum_montmul_p384(uint64_t *z, const uint64_t *x, const uint64_t *y);
extern void bignum_montmul_p384_alt(uint64_t *z, const uint64_t *x, const uint64_t *y);
extern void bignum_montsqr_p384(uint64_t *z, const uint64_t *x);
extern void bignum_montsqr_p384_alt(uint64_t *z, const uint64_t *x);
extern void bignum_montinv_p384(uint64_t *z, const uint64_t *x);

/* P-521, ordinary values, nine words a coordinate */
extern void p521_jscalarmul(uint64_t *res, const uint64_t *s, const uint64_t *p);
extern void p521_jscalarmul_alt(uint64_t *res, const uint64_t *s, const uint64_t *p);
extern void bignum_mul_p521(uint64_t *z, const uint64_t *x, const uint64_t *y);
extern void bignum_mul_p521_alt(uint64_t *z, const uint64_t *x, const uint64_t *y);
extern void bignum_sqr_p521(uint64_t *z, const uint64_t *x);
extern void bignum_sqr_p521_alt(uint64_t *z, const uint64_t *x);
extern void bignum_inv_p521(uint64_t *z, const uint64_t *x);

/* One flavour or the other, all the way through: on x86-64 the plain form
 * wants MULX, ADCX and ADOX and _alt is the fallback, so mixing them would
 * fault on a machine without those. */
struct p384_asm {
	void (*tomont)(uint64_t *, const uint64_t *);
	void (*deamont)(uint64_t *, const uint64_t *);
	void (*montmul)(uint64_t *, const uint64_t *, const uint64_t *);
	void (*montsqr)(uint64_t *, const uint64_t *);
	void (*jscalarmul)(uint64_t *, const uint64_t *, const uint64_t *);
};
struct p521_asm {
	void (*mul)(uint64_t *, const uint64_t *, const uint64_t *);
	void (*sqr)(uint64_t *, const uint64_t *);
	void (*jscalarmul)(uint64_t *, const uint64_t *, const uint64_t *);
};

static const struct p384_asm p384_std = {
	bignum_tomont_p384, bignum_deamont_p384, bignum_montmul_p384,
	bignum_montsqr_p384, p384_montjscalarmul
};
static const struct p384_asm p384_alt = {
	bignum_tomont_p384_alt, bignum_deamont_p384_alt,
	bignum_montmul_p384_alt, bignum_montsqr_p384_alt,
	p384_montjscalarmul_alt
};
static const struct p521_asm p521_std = {
	bignum_mul_p521, bignum_sqr_p521, p521_jscalarmul
};
static const struct p521_asm p521_alt = {
	bignum_mul_p521_alt, bignum_sqr_p521_alt, p521_jscalarmul_alt
};

/* The same question as for P-256, answered the same way; see
 * cbits/p256/p256_s2n.c. */
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

#define MAXWORDS 9

static void be_to_le64(uint64_t *w, const uint8_t *b, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < MAXWORDS; i++)
		w[i] = 0;
	for (i = 0; i < len; i++) {
		uint32_t pos = len - 1 - i;
		w[pos / 8] |= (uint64_t)b[i] << (8 * (pos % 8));
	}
}

static void le64_to_be(uint8_t *b, uint32_t len, const uint64_t *w)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		b[len - 1 - i] = (uint8_t)(w[i / 8] >> (8 * (i % 8)));
}

static int is_zero(const uint64_t *w, int words)
{
	uint64_t acc = 0;
	int i;

	for (i = 0; i < words; i++)
		acc |= w[i];
	return acc == 0;
}

static int mul_p384(uint8_t *outx, uint8_t *outy, const uint8_t *px,
                    const uint8_t *py, const uint8_t *k, uint32_t klen)
{
	const struct p384_asm *f = use_alt() ? &p384_alt : &p384_std;
	uint64_t pt[18], res[18], sc[MAXWORDS], t[MAXWORDS];
	uint64_t zi[6], zi2[6], zi3[6], num[6];
	static const uint64_t one[6] = {1, 0, 0, 0, 0, 0};

	be_to_le64(t, px, P384_PLEN);
	f->tomont(pt, t);
	be_to_le64(t, py, P384_PLEN);
	f->tomont(pt + 6, t);
	f->tomont(pt + 12, one);
	be_to_le64(sc, k, klen);

	f->jscalarmul(res, sc, pt);
	if (is_zero(res + 12, 6))
		return 1;

	/* affine again: x = X/Z^2, y = Y/Z^3, with the inverse taken in the
	 * Montgomery domain so that it lands where the rest of these are */
	bignum_montinv_p384(zi, res + 12);
	f->montsqr(zi2, zi);
	f->montmul(zi3, zi2, zi);
	f->montmul(num, res, zi2);
	f->deamont(t, num);
	le64_to_be(outx, P384_PLEN, t);
	f->montmul(num, res + 6, zi3);
	f->deamont(t, num);
	le64_to_be(outy, P384_PLEN, t);
	return 0;
}

static int mul_p521(uint8_t *outx, uint8_t *outy, const uint8_t *px,
                    const uint8_t *py, const uint8_t *k, uint32_t klen)
{
	const struct p521_asm *f = use_alt() ? &p521_alt : &p521_std;
	uint64_t pt[27], res[27], sc[MAXWORDS], t[MAXWORDS];
	uint64_t zi[9], zi2[9], zi3[9];
	static const uint64_t one[9] = {1, 0, 0, 0, 0, 0, 0, 0, 0};

	be_to_le64(pt, px, P521_PLEN);
	be_to_le64(pt + 9, py, P521_PLEN);
	memcpy(pt + 18, one, sizeof(one));
	be_to_le64(sc, k, klen);

	f->jscalarmul(res, sc, pt);
	if (is_zero(res + 18, 9))
		return 1;

	bignum_inv_p521(zi, res + 18);
	f->sqr(zi2, zi);
	f->mul(zi3, zi2, zi);
	f->mul(t, res, zi2);
	le64_to_be(outx, P521_PLEN, t);
	f->mul(t, res + 9, zi3);
	le64_to_be(outy, P521_PLEN, t);
	return 0;
}

int crypton_s2n_ecc_mul(int *ret, uint8_t *outx, uint8_t *outy,
                        const uint8_t *px, const uint8_t *py,
                        const uint8_t *k, uint32_t klen,
                        const uint8_t *a, const uint8_t *b,
                        const uint8_t *p, uint32_t plen)
{
	int is384;

	if (plen == P384_PLEN && memcmp(p, P384_P, plen) == 0
	    && memcmp(a, P384_A, plen) == 0 && memcmp(b, P384_B, plen) == 0)
		is384 = 1;
	else if (plen == P521_PLEN && memcmp(p, P521_P, plen) == 0
	         && memcmp(a, P521_A, plen) == 0
	         && memcmp(b, P521_B, plen) == 0)
		is384 = 0;
	else
		return 0; /* some other curve; the C answers it */

	/* A scalar longer than the prime is not something the word arrays
	 * here hold, and it is not what any caller of these two curves
	 * sends, so leave it to the C rather than grow a second path. */
	if (klen == 0 || klen > plen)
		return 0;

	/* The C does not require the coordinates to be reduced -- it takes
	 * whatever fits in its limbs and lets the conversion to Montgomery
	 * form reduce it.  Rather than carry a reduction here to match, hand
	 * that case back: nothing sends one, and this way the two cannot
	 * disagree about it.  (A differential test against the C found this;
	 * the first version of this check returned -1 and was wrong.) */
	if (memcmp(px, p, plen) >= 0 || memcmp(py, p, plen) >= 0)
		return 0;

	*ret = is384 ? mul_p384(outx, outy, px, py, k, klen)
	             : mul_p521(outx, outy, px, py, k, klen);
	return 1;
}
