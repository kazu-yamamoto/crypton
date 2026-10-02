/* ML-DSA through mldsa-native: keygen, sign, verify.
 *
 * The comparison is against `openssl speed -signature-algorithms`, which
 * reports a mean over a time window, so this reports a mean too.  That
 * matters more here than it would for a KEM: ML-DSA signing uses rejection
 * sampling, so its cost varies from one (key, message, rnd) to the next, and
 * a best-of would systematically report the luckiest draw.  Each batch is a
 * mean over many operations with the randomness varied each iteration, so
 * the rejection distribution is averaged inside a batch; the minimum is then
 * taken across batches, which removes interference from the machine without
 * touching the distribution being measured.
 *
 * CLOCK_MONOTONIC, to match `openssl speed -elapsed`.
 */
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
#include <mldsa_native.h>

/* mldsa_native.h undefines MLD_API_NAMESPACE_PREFIX once it is done with it,
 * so the symbol names are assembled here from -DNSP=... instead. */
#define CAT_(a, b) a ## b
#define CAT(a, b) CAT_(a, b)
#define NS(sym) CAT(NSP, _ ## sym)

#define LVL MLD_CONFIG_PARAMETER_SET
#define PK MLDSA_PUBLICKEYBYTES(LVL)
#define SK MLDSA_SECRETKEYBYTES(LVL)
#define SIG MLDSA_BYTES(LVL)

/* 32 bytes, because openssl's SIG_sign_loop signs a SHA256-sized buffer,
 * and an empty context, which is what EVP_PKEY_sign uses by default. */
#define MLEN 32
static const uint8_t pre[2] = {0, 0};

static uint8_t pk[PK], sk[SK], sig[SIG];
static uint8_t seed[MLDSA_SEEDBYTES], rnd[MLDSA_RNDBYTES], m[MLEN];
static volatile uint64_t sink;

void randombytes(uint8_t *out, size_t outlen);
void randombytes(uint8_t *out, size_t outlen)
{
	(void) out; (void) outlen;
	abort();
}

static double now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void do_keypair(void)
{
	seed[0]++;
	if (NS(keypair_internal)(pk, sk, seed) != 0) abort();
	sink += pk[0];
}

static void do_sign(void)
{
	/* a different message and a different rnd each time, so the batch
	 * averages over the rejection sampling rather than repeating one draw */
	m[0]++;
	rnd[0]++;
	if (NS(signature_internal)(sig, m, MLEN, pre, sizeof pre,
	                                          rnd, sk, 0) != 0) abort();
	sink += sig[0];
}

static void do_verify(void)
{
	if (NS(verify_internal)(sig, m, MLEN, pre, sizeof pre,
	                                       pk, 0) != 0) abort();
	sink += sig[0];
}

static double mean(void (*f)(void), int reps, int batches)
{
	double us = 1e18;
	int i, b;

	for (i = 0; i < 16; i++) f();
	for (b = 0; b < batches; b++) {
		double t0 = now_us(), t1, this;

		for (i = 0; i < reps; i++)
			f();
		t1 = now_us();
		this = (t1 - t0) / reps;
		if (this < us)
			us = this;
	}
	return us;
}

int main(int argc, char **argv)
{
	int reps = argc > 1 ? atoi(argv[1]) : 300, i;

	for (i = 0; i < (int) sizeof seed; i++) seed[i] = (uint8_t) (i * 7 + 1);
	for (i = 0; i < (int) sizeof rnd; i++) rnd[i] = (uint8_t) (i * 5 + 2);
	for (i = 0; i < MLEN; i++) m[i] = (uint8_t) (i * 3 + 4);

	if (NS(keypair_internal)(pk, sk, seed) != 0) abort();
	if (NS(signature_internal)(sig, m, MLEN, pre, sizeof pre,
	                                          rnd, sk, 0) != 0) abort();
	if (NS(verify_internal)(sig, m, MLEN, pre, sizeof pre,
	                                       pk, 0) != 0) {
		puts("the signature it just made did not verify");
		return 1;
	}

	printf("keygen  %8.2f us\n", mean(do_keypair, reps, 12));
	/* sign leaves sig/m/rnd on a fresh signature, which verify then uses */
	printf("sign    %8.2f us\n", mean(do_sign, reps, 12));
	printf("verify  %8.2f us\n", mean(do_verify, reps, 12));
	return 0;
}
