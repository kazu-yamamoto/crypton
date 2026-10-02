/* ML-KEM-768 through mlkem-native: keygen, encapsulate, decapsulate.
 * Deterministic API, so no RNG is needed. */
/* clock_gettime and struct timespec are POSIX, and -std=c99 hides them on
 * glibc.  Apple's headers declare them anyway, so this only shows up on
 * Linux -- it did, on the first run of this harness in CI. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <mlkem_native.h>

#define CAT_(a, b) a ## b
#define CAT(a, b) CAT_(a, b)
#define NS(sym) CAT(NSP, _ ## sym)

#define LVL MLK_CONFIG_PARAMETER_SET
#define PK MLKEM_PUBLICKEYBYTES(LVL)
#define SK MLKEM_SECRETKEYBYTES(LVL)
#define CT MLKEM_CIPHERTEXTBYTES(LVL)

static uint8_t pk[PK], sk[SK], ct[CT], ss[MLKEM_BYTES], ss2[MLKEM_BYTES];
static uint8_t kcoins[2 * MLKEM_SYMBYTES], ecoins[MLKEM_SYMBYTES];
static volatile uint64_t sink;

/* The randomised API is compiled in and wants this symbol.  Nothing here
 * calls it -- the benchmark uses the deterministic entry points -- so it
 * refuses rather than pretending to be a source of randomness. */
void randombytes(uint8_t *out, size_t outlen);
void randombytes(uint8_t *out, size_t outlen)
{
	(void) out; (void) outlen;
	abort();
}

/* CLOCK_MONOTONIC, not CLOCK_THREAD_CPUTIME_ID: the Haskell side can only
 * reach a monotonic wall clock, and a comparison between the two is only
 * worth printing if both are measured the same way. */
static double best(void (*f)(void), int reps, int batches)
{
	struct timespec t0, t1;
	double us = 1e18;
	int i, b;

	f();
	for (b = 0; b < batches; b++) {
		double this;

		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (i = 0; i < reps; i++)
			f();
		clock_gettime(CLOCK_MONOTONIC, &t1);
		this = ((t1.tv_sec - t0.tv_sec) * 1e6
		        + (t1.tv_nsec - t0.tv_nsec) / 1e3) / reps;
		if (this < us)
			us = this;
	}
	return us;
}

static void do_keypair(void)
{
	kcoins[0]++;
	if (NS(keypair_derand)(pk, sk, kcoins) != 0) abort();
	sink += pk[0];
}

static void do_enc(void)
{
	ecoins[0]++;
	if (NS(enc_derand)(ct, ss, pk, ecoins) != 0) abort();
	sink += ct[0];
}

static void do_dec(void)
{
	if (NS(dec)(ss2, ct, sk) != 0) abort();
	sink += ss2[0];
}

static void report(const char *name, double us)
{
	printf("%-7s %8.2f us  (%.0f/s)\n", name, us, 1e6 / us);
}

int main(int argc, char **argv)
{
	int reps = argc > 1 ? atoi(argv[1]) : 2000, i;

	for (i = 0; i < (int) sizeof(kcoins); i++) kcoins[i] = (uint8_t) (i * 7 + 1);
	for (i = 0; i < (int) sizeof(ecoins); i++) ecoins[i] = (uint8_t) (i * 5 + 2);

	if (NS(keypair_derand)(pk, sk, kcoins) != 0) abort();
	if (NS(enc_derand)(ct, ss, pk, ecoins) != 0) abort();
	if (NS(dec)(ss2, ct, sk) != 0) abort();
	if (memcmp(ss, ss2, MLKEM_BYTES) != 0) { puts("shared secrets differ"); return 1; }

	report("keygen", best(do_keypair, reps, 20));
	report("encap", best(do_enc, reps, 20));
	report("decap", best(do_dec, reps, 20));
	return 0;
}
