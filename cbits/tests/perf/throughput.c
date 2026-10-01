/* Throughput of the primitives that have an accelerated implementation, one
 * per process so that a caller can ask for them one at a time.
 *
 * Prints MB/s over 16 KiB.  The state is set up once and the same buffer run
 * through it, which is the shape `openssl speed` measures and the shape the
 * README's tables are in.
 *
 * This is here to be compared with itself -- see run.sh -- and not to be
 * quoted.  A number from a CI runner is a number from whichever machine the
 * job landed on.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "crypton_aes.h"
#include "crypton_sha1.h"
#include "crypton_sha256.h"
#include "crypton_sha512.h"
#include "crypton_sha3.h"
#include "crypton_chacha.h"
#include "crypton_poly1305.h"

#define LEN 16384
#define REPS 12

static uint8_t inb[LEN], outb[LEN + 64];
static uint64_t sink;

static double now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void bench_gcm(int keybits, int iters)
{
	aes_key key;
	aes_gcm gcm;
	uint8_t kb[32], iv[12], tag[16];
	int i;
	for (i = 0; i < 32; i++) kb[i] = (uint8_t)(i * 7);
	for (i = 0; i < 12; i++) iv[i] = (uint8_t)(i + 3);
	crypton_aes_initkey(&key, kb, keybits / 8);
	crypton_aes_gcm_init(&gcm, &key, iv, 12);
	for (i = 0; i < iters; i++) {
		crypton_aes_gcm_encrypt(outb, &gcm, &key, inb, LEN);
		sink += outb[i & 1023];
	}
	crypton_aes_gcm_finish(tag, &gcm, &key);
	sink += tag[0];
}

static void bench_chachapoly(int iters)
{
	crypton_chacha_context ctx;
	poly1305_ctx pctx;
	poly1305_key pkey;
	poly1305_mac mac;
	uint8_t kb[32], iv[12];
	int i;
	for (i = 0; i < 32; i++) kb[i] = (uint8_t)(i * 5);
	for (i = 0; i < 12; i++) iv[i] = (uint8_t)(i + 1);
	memcpy(&pkey, kb, sizeof(pkey));
	for (i = 0; i < iters; i++) {
		crypton_chacha_init(&ctx, 20, 32, kb, 12, iv);
		crypton_chacha_combine(outb, &ctx, inb, LEN);
		crypton_poly1305_init(&pctx, &pkey);
		crypton_poly1305_update(&pctx, outb, LEN);
		crypton_poly1305_finalize(mac, &pctx);
		sink += mac[0] + outb[i & 1023];
	}
}

static void bench_sha1(int iters)
{
	struct sha1_ctx c;
	uint8_t out[20];
	int i;
	for (i = 0; i < iters; i++) {
		crypton_sha1_init(&c);
		crypton_sha1_update(&c, inb, LEN);
		crypton_sha1_finalize(&c, out);
		sink += out[0];
	}
}

static void bench_sha256(int iters)
{
	struct sha256_ctx c;
	uint8_t out[32];
	int i;
	for (i = 0; i < iters; i++) {
		crypton_sha256_init(&c);
		crypton_sha256_update(&c, inb, LEN);
		crypton_sha256_finalize(&c, out);
		sink += out[0];
	}
}

static void bench_sha512(int iters)
{
	struct sha512_ctx c;
	uint8_t out[64];
	int i;
	for (i = 0; i < iters; i++) {
		crypton_sha512_init(&c);
		crypton_sha512_update(&c, inb, LEN);
		crypton_sha512_finalize(&c, out);
		sink += out[0];
	}
}

static void bench_sha3(int iters)
{
	/* sha3_ctx ends in a flexible array the caller provides room for. */
	uint8_t raw[SHA3_CTX_BUF_MAX_SIZE];
	struct sha3_ctx *c = (struct sha3_ctx *)raw;
	uint8_t out[32];
	int i;
	for (i = 0; i < iters; i++) {
		crypton_sha3_init(c, 256);
		crypton_sha3_update(c, inb, LEN);
		crypton_sha3_finalize(c, 256, out);
		sink += out[0];
	}
}

int main(int argc, char **argv)
{
	const char *algo = argc > 1 ? argv[1] : "sha256";
	int iters = 2000, r, i;
	double best = 1e30;

	for (i = 0; i < LEN; i++) inb[i] = (uint8_t)(i * 17 + 3);

	for (r = 0; r < REPS; r++) {
		double t0 = now_us(), t1;
		if      (!strcmp(algo, "aes128gcm"))  bench_gcm(128, iters);
		else if (!strcmp(algo, "aes256gcm"))  bench_gcm(256, iters);
		else if (!strcmp(algo, "chachapoly")) bench_chachapoly(iters);
		else if (!strcmp(algo, "sha1"))       bench_sha1(iters);
		else if (!strcmp(algo, "sha256"))     bench_sha256(iters);
		else if (!strcmp(algo, "sha512"))     bench_sha512(iters);
		else if (!strcmp(algo, "sha3-256"))   bench_sha3(iters);
		else { fprintf(stderr, "unknown algo %s\n", algo); return 2; }
		t1 = now_us();
		if (r > 1 && t1 - t0 < best) best = t1 - t0;
	}
	if (sink == 0) return 3;
	printf("%.1f\n", (double)LEN * iters / best);   /* bytes/us == MB/s */
	return 0;
}
