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

/* Four bits of exponent per window, so a table of sixteen and no leftover
 * bits: a byte holds exactly two windows.
 *
 * Five was written and measured, and is not here.  A wider window saves
 * multiplications -- 205 of them against 256 at 1024 bits, with the same
 * 1024 squarings -- and pays for it in the masked scan of a table twice as
 * long, and which way that comes out depends on the machine and on which
 * multiplication is running: 3.5% better on an Apple M4, about 1% worse on
 * an older x86-64, and 7% worse anywhere s2n-bignum's multiplication is
 * used, since that makes the scan the expensive half.  Six measured level
 * with five on the M4 and seven worse.  What would make a wider window pay
 * everywhere is a cheaper scan, not a wider window. */
#define WINDOW_BITS 4
#define TABLE_SIZE (1 << WINDOW_BITS)

/* The masked scan of the table: every entry is read and a mask keeps the one
 * wanted, so that the address stream does not follow the exponent.  At
 * RSA-2048's CRT size that is two kilobytes read per window, and the window
 * loop runs 256 times per exponentiation, which is why it is worth a vector
 * register: removing the scan altogether measures 11% of an exponentiation
 * where s2n-bignum's multiplication runs, and the AVX2 form below gets
 * essentially all of it. */
static void scan_table(limb_t *sel, const limb_t *table, uint32_t n, limb_t w)
{
	uint32_t k, l;

	memset(sel, 0, n * sizeof(limb_t));
	for (k = 0; k < TABLE_SIZE; k++) {
		limb_t mask = eq_mask(k, w);

		for (l = 0; l < n; l++)
			sel[l] |= table[k * n + l] & mask;
	}
}

#if defined(__x86_64__) && defined(WITH_TARGET_ATTRIBUTES) && LIMB_BITS == 64
#define CRYPTON_POWM_SCAN_AVX2 1
#include <crypton_cpu.h>
#include <immintrin.h>

/* The same scan four limbs at a time.  The sixteen masks are worked out
 * once; after that each register of the answer is one pass over the table's
 * column, reading every entry exactly as the scalar form does. */
__attribute__((target("avx2")))
static void scan_table_avx2(limb_t *sel, const limb_t *table, uint32_t n,
                            limb_t w)
{
	__m256i masks[TABLE_SIZE];
	uint32_t k, l;

	for (k = 0; k < TABLE_SIZE; k++)
		masks[k] = _mm256_cmpeq_epi64(
			_mm256_set1_epi64x((long long) k),
			_mm256_set1_epi64x((long long) w));

	for (l = 0; l + 4 <= n; l += 4) {
		__m256i acc = _mm256_setzero_si256();

		for (k = 0; k < TABLE_SIZE; k++) {
			__m256i v = _mm256_loadu_si256(
				(const __m256i *) (table + k * n + l));

			acc = _mm256_or_si256(acc,
			                      _mm256_and_si256(v, masks[k]));
		}
		_mm256_storeu_si256((__m256i *) (sel + l), acc);
	}

	/* a modulus whose limbs do not come in fours ends here */
	for (; l < n; l++) {
		limb_t v = 0;

		for (k = 0; k < TABLE_SIZE; k++)
			v |= table[k * n + l] & eq_mask(k, w);
		sel[l] = v;
	}
}
#endif

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
#ifdef CRYPTON_POWM_SCAN_AVX2
	int avx2 = (crypton_x86_simd_features() & CRYPTON_X86_AVX2) != 0;
#endif

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

		/* squaring into the other buffer and swapping the two saves a
		 * copy of the modulus' width every time; which of the three
		 * buffers a pointer names is nobody's secret */
		for (j = 0; j < WINDOW_BITS; j++) {
			limb_t *swap;

			powm_sqr(sel, acc, m, n0, n, t, scratch, s2n);
			swap = acc;
			acc = sel;
			sel = swap;
		}

#ifdef CRYPTON_POWM_SCAN_AVX2
		if (avx2)
			scan_table_avx2(sel, table, n, w);
		else
#endif
			scan_table(sel, table, n, w);
		powm_mul(prod, acc, sel, m, n0, n, t, scratch, s2n);
		{
			limb_t *swap = acc;

			acc = prod;
			prod = swap;
		}
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
