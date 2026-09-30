/* What this C answers, so that a big-endian machine can be asked the same.
 *
 * Every primitive here reads its input a word at a time, or writes its output
 * that way, or both -- which is the step that goes wrong when the byte order
 * changes.  Each one is fed the same deterministic bytes at several lengths,
 * including lengths either side of its block, since the tail is where the
 * length is packed in and where the byte order shows.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "crypton_md4.h"
#include "crypton_md5.h"
#include "crypton_sha1.h"
#include "crypton_sha256.h"
#include "crypton_sha512.h"
#include "crypton_sha3.h"
#include "crypton_ripemd.h"
#include "crypton_skein256.h"
#include "crypton_skein512.h"
#include "crypton_tiger.h"
#include "crypton_whirlpool.h"
/* The stream ciphers are not here: crypton_chacha.h and crypton_salsa.h both
 * typedef the name "block", so no translation unit can hold them both.  They
 * want a driver of their own, and a header that does not claim that name. */

/* The skein headers spell the prefix "cryponite", which nothing defines. */
void crypton_skein256_init(struct skein256_ctx *ctx, uint32_t hashlen);
void crypton_skein256_update(struct skein256_ctx *ctx, const uint8_t *data, uint32_t len);
void crypton_skein256_finalize(struct skein256_ctx *ctx, uint32_t hashlen, uint8_t *out);
void crypton_skein512_init(struct skein512_ctx *ctx, uint32_t hashlen);
void crypton_skein512_update(struct skein512_ctx *ctx, const uint8_t *data, uint32_t len);
void crypton_skein512_finalize(struct skein512_ctx *ctx, uint32_t hashlen, uint8_t *out);

static int generating;
static FILE *vf;
static int failures, checked;

/* one answer: named, and either written out or compared with what was */
static void answer(const char *name, const uint8_t *out, size_t n) {
    char got[512], want[512], label[128];
    size_t i;
    for (i = 0; i < n && i * 2 + 2 < sizeof got; i++)
        sprintf(got + i * 2, "%02x", out[i]);
    got[n * 2] = 0;
    if (generating) {
        fprintf(vf, "%s %s\n", name, got);
        return;
    }
    if (fscanf(vf, "%127s %511s", label, want) != 2) {
        printf("FAIL %s: vectors.txt ended early\n", name);
        failures++;
        return;
    }
    checked++;
    if (strcmp(label, name) != 0) {
        printf("FAIL out of step: expected %s, vectors.txt has %s\n", name, label);
        failures++;
    } else if (strcmp(got, want) != 0) {
        printf("FAIL %s\n  little-endian %s\n  this machine  %s\n", name, want, got);
        failures++;
    }
}

/* the input: deterministic, and at lengths either side of every block size */
static const size_t lengths[] = {0, 1, 3, 55, 56, 63, 64, 65, 111, 112,
                                 127, 128, 129, 135, 136, 255, 256, 1000};
static uint8_t buf[1024];
static void fill(void) {
    size_t i;
    for (i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)(i * 7 + (i >> 5) * 31);
}

#define HASH(nm, ctxt, initcall, updcall, fincall, outlen)                  \
    do {                                                                    \
        size_t li;                                                          \
        for (li = 0; li < sizeof lengths / sizeof *lengths; li++) {         \
            ctxt ctx;                                                       \
            uint8_t out[outlen];                                            \
            char nmbuf[128];                                                \
            initcall;                                                       \
            updcall;                                                        \
            fincall;                                                        \
            sprintf(nmbuf, "%s/%zu", nm, lengths[li]);                      \
            answer(nmbuf, out, outlen);                                     \
        }                                                                   \
    } while (0)

int main(int argc, char **argv) {
    generating = (argc > 1 && strcmp(argv[1], "generate") == 0);
    vf = fopen(argc > 2 ? argv[2] : "cbits/tests/endian/vectors.txt",
               generating ? "w" : "r");
    if (!vf) { printf("cannot open vectors.txt\n"); return 2; }
    fill();

    HASH("md4", struct md4_ctx, crypton_md4_init(&ctx),
         crypton_md4_update(&ctx, buf, (uint32_t)lengths[li]),
         crypton_md4_finalize(&ctx, out), 16);
    HASH("md5", struct md5_ctx, crypton_md5_init(&ctx),
         crypton_md5_update(&ctx, buf, (uint32_t)lengths[li]),
         crypton_md5_finalize(&ctx, out), 16);
    HASH("sha1", struct sha1_ctx, crypton_sha1_init(&ctx),
         crypton_sha1_update(&ctx, buf, (uint32_t)lengths[li]),
         crypton_sha1_finalize(&ctx, out), 20);
    HASH("sha256", struct sha256_ctx, crypton_sha256_init(&ctx),
         crypton_sha256_update(&ctx, buf, (uint32_t)lengths[li]),
         crypton_sha256_finalize(&ctx, out), 32);
    HASH("sha512", struct sha512_ctx, crypton_sha512_init(&ctx),
         crypton_sha512_update(&ctx, buf, (uint32_t)lengths[li]),
         crypton_sha512_finalize(&ctx, out), 64);
    /* sha3's context ends in a flexible buffer whose width comes from the
     * hash length, so it is not a plain automatic variable like the rest. */
    {
        size_t li;
        for (li = 0; li < sizeof lengths / sizeof *lengths; li++) {
            uint8_t space[SHA3_CTX_BUF_MAX_SIZE];
            struct sha3_ctx *ctx = (struct sha3_ctx *)space;
            uint8_t out[32];
            char nmbuf[128];
            crypton_sha3_init(ctx, 256);
            crypton_sha3_update(ctx, buf, (uint32_t)lengths[li]);
            crypton_sha3_finalize(ctx, 256, out);
            sprintf(nmbuf, "sha3-256/%zu", lengths[li]);
            answer(nmbuf, out, sizeof out);
        }
    }
    HASH("ripemd160", struct ripemd160_ctx, crypton_ripemd160_init(&ctx),
         crypton_ripemd160_update(&ctx, buf, (uint32_t)lengths[li]),
         crypton_ripemd160_finalize(&ctx, out), 20);
    HASH("skein256", struct skein256_ctx, crypton_skein256_init(&ctx, 256),
         crypton_skein256_update(&ctx, buf, (uint32_t)lengths[li]),
         crypton_skein256_finalize(&ctx, 256, out), 32);
    HASH("skein512", struct skein512_ctx, crypton_skein512_init(&ctx, 512),
         crypton_skein512_update(&ctx, buf, (uint32_t)lengths[li]),
         crypton_skein512_finalize(&ctx, 512, out), 64);
    HASH("tiger", struct tiger_ctx, crypton_tiger_init(&ctx),
         crypton_tiger_update(&ctx, buf, (uint32_t)lengths[li]),
         crypton_tiger_finalize(&ctx, out), 24);
    HASH("whirlpool", struct whirlpool_ctx, crypton_whirlpool_init(&ctx),
         crypton_whirlpool_update(&ctx, buf, (uint32_t)lengths[li]),
         crypton_whirlpool_finalize(&ctx, out), 64);

    if (!generating && failures == 0)
        printf("ok   %d answers match the little-endian ones\n", checked);
    else if (!generating)
        printf("FAIL %d of %d answers differ\n", failures, checked);
    fclose(vf);
    return failures != 0;
}
