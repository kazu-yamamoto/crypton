/* The generated product-scanning Montgomery routines against crypton's
 * mont_mul/mont_sqr: the same answers first, then the time. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "crypton_bignum.h"
#include "fips_gen.h"

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
	return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static uint64_t rs = 0x243f6a8885a308d3ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

#define CHECK_AND_TIME(N)                                                      \
	{                                                                          \
		uint32_t n = N, i, k;                                                  \
		limb_t a[N], b[N], m[N], t[2 * N], r1[N], r2[N], n0;                   \
		int trial, rep, M = 50000;                                             \
		double best[4] = {1e18, 1e18, 1e18, 1e18};                             \
		for (trial = 0; trial < 2000; trial++) {                               \
			for (i = 0; i < n; i++) { m[i] = rnd(); a[i] = rnd(); b[i] = rnd(); } \
			m[0] |= 1;                                                         \
			if (trial % 3 == 0) m[n - 1] |= 1ull << 63;                        \
			if (trial % 5 == 0) for (i = 0; i < n; i++) m[i] |= (i ? ~0ull : ~1ull) | 1; \
			/* operands under m */                                             \
			a[n - 1] %= m[n - 1]; b[n - 1] %= m[n - 1];                        \
			if (trial % 7 == 0) { memcpy(a, m, sizeof a); a[0] -= 1; }        \
			n0 = mont_n0(m[0]);                                                \
			mont_mul(r1, a, b, m, n0, n, t);                                   \
			fips_mul##N(r2, a, b, m, n0);                                      \
			if (memcmp(r1, r2, sizeof r1)) { printf("mul%d DISAGREE at %d\n", N, trial); exit(1); } \
			mont_sqr(r1, a, m, n0, n, t);                                      \
			fips_sqr##N(r2, a, m, n0);                                         \
			if (memcmp(r1, r2, sizeof r1)) { printf("sqr%d DISAGREE at %d\n", N, trial); exit(1); } \
		}                                                                      \
		for (rep = 0; rep < 15; rep++) {                                       \
			double t0 = now();                                                 \
			for (k = 0; k < M; k++) { mont_mul(r1, a, b, m, n0, n, t); a[0] ^= r1[0] & 1; } \
			double t1 = now();                                                 \
			for (k = 0; k < M; k++) { fips_mul##N(r2, a, b, m, n0); a[0] ^= r2[0] & 1; } \
			double t2 = now();                                                 \
			for (k = 0; k < M; k++) { mont_sqr(r1, a, m, n0, n, t); a[0] ^= r1[0] & 1; } \
			double t3 = now();                                                 \
			for (k = 0; k < M; k++) { fips_sqr##N(r2, a, m, n0); a[0] ^= r2[0] & 1; } \
			double t4 = now();                                                 \
			double v[4] = {t1 - t0, t2 - t1, t3 - t2, t4 - t3};                \
			for (i = 0; i < 4; i++) if (v[i] / M < best[i]) best[i] = v[i] / M; \
		}                                                                      \
		printf("n=%2d agree; mul: crypton %6.1f ns  fips %6.1f ns (%.2fx) | sqr: crypton %6.1f ns  fips %6.1f ns (%.2fx)\n", \
		       N, best[0], best[1], best[0] / best[1], best[2], best[3], best[2] / best[3]); \
	}

int main(void)
{
	CHECK_AND_TIME(16)
	CHECK_AND_TIME(24)
	CHECK_AND_TIME(32)
	return 0;
}
