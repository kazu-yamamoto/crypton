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
#include <crypton_bzero.h>

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

/* Four bits of exponent per window, so a table of sixteen.
 *
 * Five was written and measured and is not here.  A wider window saves
 * multiplications -- 205 of them against 256 at 1024 bits, with the same
 * 1024 squarings -- and pays for it in the masked scan of a table twice as
 * long.  When that was first measured the scan was the scalar one, and five
 * came out 3.5% better on an Apple M4, about 1% worse on an older x86-64 and
 * 7% worse where s2n-bignum's multiplication runs, since that makes the scan
 * the expensive half.  The conclusion written here was that what would make
 * a wider window pay is a cheaper scan.
 *
 * The cheaper scan arrived twenty-one minutes later, in the AVX2 form above,
 * and nobody measured the window again.  Measured since, on the machine the
 * x86-64 table is measured on and with both builds raced in one run: five is
 * 0.6% worse than four, beside 0.5% between two builds that differ in
 * nothing.  So the cheaper scan did not turn it round -- the window stays at
 * four, and now for a reason that was checked after the scan rather than
 * before it.
 *
 * The width is POWM_WINDOW_BITS so that it can be measured rather than
 * argued about.  It had to be renamed to be settable at all: WINDOW_BITS was
 * defined here, in cbits/crypton_ecc.c and in cbits/crypton_bignum.h, all
 * three to four, and a redefinition to the same value is silent -- so
 * -DWINDOW_BITS=5 was overridden by the header and three builds meant to
 * differ did not.  cbits/tests/powm builds the walk at four, five and six
 * and requires the same answers of all three. */
#ifndef POWM_WINDOW_BITS
#define POWM_WINDOW_BITS 4
#endif
#define WINDOW_BITS POWM_WINDOW_BITS
#define TABLE_SIZE (1 << WINDOW_BITS)

/* Window number k counting from the bottom, where the bottom window holds
 * the exponent's least significant WINDOW_BITS bits.  The exponent is
 * big-endian bytes, and a window may straddle a byte boundary once the width
 * stops dividing eight, so this reads the two bytes it can fall across.
 *
 * Which window is being read is the loop counter, not the exponent, so the
 * shifts and the index here are public.
 */
static limb_t exp_window(const uint8_t *exp, uint32_t explen, uint32_t k)
{
	uint32_t lo = k * WINDOW_BITS;          /* bit offset from the bottom */
	uint32_t byte = lo / 8, off = lo % 8;
	uint32_t v;

	if (byte >= explen)
		return 0;
	v = exp[explen - 1 - byte];
	if (off + WINDOW_BITS > 8 && byte + 1 < explen)
		v |= (uint32_t) exp[explen - 2 - byte] << 8;
	return (v >> off) & (TABLE_SIZE - 1);
}

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

/* Modular exponentiation for an exponent that is not a secret.
 *
 * RSA verification raises a signature to the public exponent, which is in
 * the public key and is usually 65537.  crypton_powm_sec below hides the
 * exponent and pays for it twice: a table of sixteen powers built before the
 * walk begins, and every entry of that table read at every window.  For a
 * seventeen-bit exponent the table alone costs more than the exponentiation.
 *
 * So this one reads the exponent's bits and branches on them, squaring at
 * every step and multiplying where a bit is set.  It is for public exponents
 * only, and nothing in this library may call it with a secret.
 *
 * It declines -- returning 1 without touching out -- in two cases, so a
 * caller must have something to fall back to.
 *
 * The first is a long exponent.  Walking it a bit at a time costs about one
 * and a half multiplications per bit where a windowed walk costs a quarter
 * less, and the table that buys the difference pays for itself after some
 * sixty-odd bits.  Past that the caller's own exponentiation is the better
 * algorithm and this one would have to grow a table to compete, which is
 * the thing it exists not to have.  RSA public exponents are seventeen
 * bits; the bound is set well above them and well below where a Diffie-
 * Hellman or DSA exponent starts.
 *
 * The second is a machine where s2n-bignum's Montgomery multiplication does
 * not run.  There the multiplication here is the C one, which is not faster
 * than what the caller already has, so there is nothing to take over.  That
 * was written as an expectation and has since been measured: on an Apple
 * M4, verification through here and through GMP come out level, the
 * difference no larger than between two rows neither of them touches.
 * Define CRYPTON_POWM_PUB_ALWAYS to make it accept anyway: the differential
 * test builds that way, so that this arithmetic is exercised on the
 * machines the assembly never reaches.
 */
#define POWM_PUB_MAX_EXP_BYTES 8

static int powm_pub_wanted(uint32_t n)
{
#if defined(CRYPTON_POWM_PUB_ALWAYS)
	return n > 0;
#elif defined(CRYPTON_POWM_S2N)
	return powm_s2n_usable(n);
#else
	(void) n;
	return 0;
#endif
}

int crypton_powm_window_bits(void)
{
	return WINDOW_BITS;
}

int crypton_powm_pub(uint8_t *out,
                     const uint8_t *base, uint32_t baselen,
                     const uint8_t *exp, uint32_t explen,
                     const uint8_t *mod, uint32_t modlen)
{
	uint32_t n = (modlen + LIMB_BYTES - 1) / LIMB_BYTES;
	uint32_t words = (6 + 2 + POWM_S2N_SCRATCH) * n;
	limb_t *space, *m, *r2, *acc, *tmp, *bm, *one, *t, *scratch, n0;
	uint32_t top, i;
	int s2n = 0;

	if (modlen == 0 || n == 0 || (mod[modlen - 1] & 1) == 0)
		return 1;
	if (explen > POWM_PUB_MAX_EXP_BYTES)
		return 1;
	if (!powm_pub_wanted(n))
		return 1;
#ifdef CRYPTON_POWM_S2N
	s2n = powm_s2n_usable(n);
#endif

	/* the exponent's top set bit, counted from the bottom.  An exponent of
	 * zero is left to the caller, whose answer for it is already right. */
	top = explen * 8;
	while (top > 0 &&
	       ((exp[explen - 1 - (top - 1) / 8] >> ((top - 1) % 8)) & 1) == 0)
		top--;
	if (top == 0)
		return 1;

	space = calloc(words, sizeof(limb_t));
	if (space == NULL)
		return 1;
	m = space;
	r2 = m + n;
	acc = r2 + n;
	tmp = acc + n;
	bm = tmp + n;
	one = bm + n;
	t = one + n;
	scratch = t + 2 * n;

	if (from_be(m, n, mod, modlen) != 0)
		goto fail;
	n0 = mont_n0(m[0]);
	mont_r2(r2, m, n0, n, t);

	/* the base into Montgomery form.  The accumulator starts there rather
	 * than at one, because the exponent's top bit is a one by
	 * construction and the first squaring would be of one. */
	if (from_be(tmp, n, base, baselen) != 0)
		goto fail;
	powm_mul(bm, tmp, r2, m, n0, n, t, scratch, s2n);
	memcpy(acc, bm, n * sizeof(limb_t));

	for (i = top - 1; i > 0; i--) {
		limb_t *swap;

		powm_sqr(tmp, acc, m, n0, n, t, scratch, s2n);
		swap = acc; acc = tmp; tmp = swap;
		if ((exp[explen - 1 - (i - 1) / 8] >> ((i - 1) % 8)) & 1) {
			powm_mul(tmp, acc, bm, m, n0, n, t, scratch, s2n);
			swap = acc; acc = tmp; tmp = swap;
		}
	}

	/* out of Montgomery form */
	one[0] = 1;
	powm_mul(tmp, acc, one, m, n0, n, t, scratch, s2n);
	to_be(out, modlen, tmp, n);

	free(space);
	return 0;

fail:
	free(space);
	return 1;
}

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
	n0 = mont_n0(m[0]);
	mont_r2(r2, m, n0, n, t);

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

	for (i = (explen * 8 + WINDOW_BITS - 1) / WINDOW_BITS; i > 0; i--) {
		limb_t w = exp_window(exp, explen, i - 1);

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
	 * through the accumulators.  crypton_bzero rather than memset, since
	 * this memory is freed on the next line and a store to memory about to
	 * die is one an optimizer may drop. */
	crypton_bzero(space, words * sizeof(limb_t));
	free(space);
	return 0;

fail:
	crypton_bzero(space, words * sizeof(limb_t));
	free(space);
	return 1;
}
