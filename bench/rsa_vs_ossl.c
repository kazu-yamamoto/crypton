/* crypton's exponentiation and Montgomery multiplication against OpenSSL's,
 * same inputs, thread CPU time, alternated, best of R. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include "crypton_bignum.h"

int crypton_powm_sec(uint8_t *out, const uint8_t *base, uint32_t baselen,
                     const uint8_t *exp, uint32_t explen,
                     const uint8_t *mod, uint32_t modlen);
int bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                const BN_ULONG *np, const BN_ULONG *n0, int num);

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
	return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

volatile uint64_t sink;

int main(int argc, char **argv)
{
	int bits = argc > 1 ? atoi(argv[1]) : 1024;
	int R = argc > 2 ? atoi(argv[2]) : 15;
	int bytes = bits / 8, n = bits / 64;
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *m = BN_new(), *b = BN_new(), *e = BN_new(), *r = BN_new();
	BN_MONT_CTX *mont = BN_MONT_CTX_new();
	uint8_t mb[512], bb[512], eb[512], out[512], ob[512];
	int i, rep;

	BN_generate_prime_ex(m, bits, 0, NULL, NULL, NULL);
	BN_rand_range(b, m);
	BN_rand(e, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
	BN_set_flags(e, BN_FLG_CONSTTIME);
	BN_MONT_CTX_set(mont, m, ctx);
	BN_bn2binpad(m, mb, bytes);
	BN_bn2binpad(b, bb, bytes);
	BN_bn2binpad(e, eb, bytes);

	/* agree first */
	crypton_powm_sec(out, bb, bytes, eb, bytes, mb, bytes);
	BN_mod_exp_mont_consttime(r, b, e, m, ctx, mont);
	BN_bn2binpad(r, ob, bytes);
	if (memcmp(out, ob, bytes)) { printf("DISAGREE\n"); return 1; }

	double best_c = 1e18, best_o = 1e18, best_cm = 1e18, best_om = 1e18,
	       best_cs = 1e18, best_os = 1e18;
	int K = 20, M = 20000;
	limb_t a[64], bl[64], ml[64], t[128], rr[64], n0;
	BN_ULONG oa[64], ob2[64], om[64], orr[64], on0[2];
	for (i = 0; i < n; i++) {
		a[i] = ((uint64_t)rand() << 33) ^ rand();
		bl[i] = ((uint64_t)rand() << 33) ^ rand();
	}
	from_be(ml, n, mb, bytes);
	a[n - 1] &= ml[n - 1] >> 1; bl[n - 1] &= ml[n - 1] >> 1;
	n0 = mont_n0(ml[0]);
	memcpy(oa, a, n * 8); memcpy(ob2, bl, n * 8); memcpy(om, ml, n * 8);
	on0[0] = n0; on0[1] = 0;

	for (rep = 0; rep < R; rep++) {
		double t0 = now();
		for (i = 0; i < K; i++)
			crypton_powm_sec(out, bb, bytes, eb, bytes, mb, bytes);
		double t1 = now();
		for (i = 0; i < K; i++)
			BN_mod_exp_mont_consttime(r, b, e, m, ctx, mont);
		double t2 = now();
		for (i = 0; i < M; i++) { mont_mul(rr, a, bl, ml, n0, n, t); a[0] ^= rr[0] & 1; }
		double t3 = now();
		for (i = 0; i < M; i++) { bn_mul_mont(orr, oa, ob2, om, on0, n); oa[0] ^= orr[0] & 1; }
		double t4 = now();
		for (i = 0; i < M; i++) { mont_sqr(rr, a, ml, n0, n, t); a[0] ^= rr[0] & 1; }
		double t5 = now();
		for (i = 0; i < M; i++) { bn_mul_mont(orr, oa, oa, om, on0, n); oa[0] ^= orr[0] & 1; }
		double t6 = now();
		if ((t6 - t5) * 1e3 / M < best_os) best_os = (t6 - t5) * 1e3 / M;
		if ((t1 - t0) / K < best_c) best_c = (t1 - t0) / K;
		if ((t2 - t1) / K < best_o) best_o = (t2 - t1) / K;
		if ((t3 - t2) * 1e3 / M < best_cm) best_cm = (t3 - t2) * 1e3 / M;
		if ((t4 - t3) * 1e3 / M < best_om) best_om = (t4 - t3) * 1e3 / M;
		if ((t5 - t4) * 1e3 / M < best_cs) best_cs = (t5 - t4) * 1e3 / M;
	}
	sink = rr[0] + orr[0];
	printf("%d-bit modulus, %d-bit exponent\n", bits, bits);
	printf("  exponentiation  crypton %8.2f us   OpenSSL %8.2f us   ratio %.2f\n",
	       best_c, best_o, best_c / best_o);
	printf("  montmul         crypton %8.1f ns   OpenSSL %8.1f ns   ratio %.2f\n",
	       best_cm, best_om, best_cm / best_om);
	printf("  montsqr         crypton %8.1f ns   OpenSSL %8.1f ns   ratio %.2f\n",
	       best_cs, best_os, best_cs / best_os);
	return 0;
}
