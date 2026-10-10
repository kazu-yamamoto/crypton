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
#include "crypton_chacha.h"
#include "crypton_salsa.h"
#include "crypton_poly1305.h"
#include "crypton_aes.h"
#include "aes/gf.h"
#include "aes/block128.h"

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
        snprintf(got + i * 2, 3, "%02x", out[i]);
    got[n * 2] = 0;
    /* an answer of no bytes still has to be a token, or the reader below
       takes the next line's name for this line's answer and everything
       after it is compared against the wrong thing */
    if (n == 0) strcpy(got, "-");
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
            snprintf(nmbuf, sizeof nmbuf, "%s/%zu", nm, lengths[li]);                      \
            answer(nmbuf, out, outlen);                                     \
        }                                                                   \
    } while (0)

/*
 * AES, which reaches further into the byte order than the hashes above do.
 *
 * The portable implementation keeps its schedule as 64-bit words and reads
 * its input through br_dec32le; the GHASH beside it reads H and the
 * accumulator as big-endian words; the counter modes carry a counter that is
 * incremented big-endian and stored little-endian in one case and the other
 * way round in another; and XTS doubles its tweak in GF(2^128) through
 * cpu_to_le64.  Every one of those is a place where a big-endian machine can
 * differ, and none of them was asked about here until now.
 *
 * The entries called are the public ones, so this is whichever
 * implementation the build installed -- which, for the build this harness
 * makes, is the portable one.  That is the one a big-endian machine runs:
 * crypton has no AES instructions for s390x, and the POWER8 ones are
 * little-endian only.
 */
static void aes_answers(void) {
    static const uint8_t keylens[] = {16, 24, 32};
    /* multiples of the block, for the modes that take whole blocks */
    static const uint32_t blocks[] = {1, 2, 4, 7};
    /* and byte counts, including a partial block, for the ones that do not */
    static const uint32_t bytes[] = {0, 1, 15, 16, 17, 64, 100};
    uint8_t key[32], key2[32], iv[16], out[128], tmp[128];
    char nm[128];
    size_t ki, li;
    uint32_t i;

    for (i = 0; i < 32; i++) { key[i] = (uint8_t)(i * 3 + 1);
                               key2[i] = (uint8_t)(i * 5 + 2); }
    for (i = 0; i < 16; i++) iv[i] = (uint8_t)(i * 11 + 7);

    for (ki = 0; ki < sizeof keylens / sizeof *keylens; ki++) {
        uint8_t kl = keylens[ki];
        aes_key k, k2;
        aes_gcm_key gk;

        crypton_aes_initkey(&k, key, kl);
        crypton_aes_initkey(&k2, key2, kl);
        crypton_aes_gcm_key_init(&gk, &k);

        for (li = 0; li < sizeof blocks / sizeof *blocks; li++) {
            uint32_t nb = blocks[li];
            aes_block ivb;

            crypton_aes_encrypt_ecb((aes_block *)out, &k, (aes_block *)buf, nb);
            snprintf(nm, sizeof nm, "aes%u-ecb/%u", kl * 8, nb);
            answer(nm, out, nb * 16);

            crypton_aes_decrypt_ecb((aes_block *)out, &k, (aes_block *)buf, nb);
            snprintf(nm, sizeof nm, "aes%u-ecbd/%u", kl * 8, nb);
            answer(nm, out, nb * 16);

            memcpy(&ivb, iv, 16);
            crypton_aes_encrypt_cbc((aes_block *)out, &k, &ivb, (aes_block *)buf, nb);
            snprintf(nm, sizeof nm, "aes%u-cbc/%u", kl * 8, nb);
            answer(nm, out, nb * 16);

            memcpy(&ivb, iv, 16);
            crypton_aes_decrypt_cbc((aes_block *)out, &k, &ivb, (aes_block *)buf, nb);
            snprintf(nm, sizeof nm, "aes%u-cbcd/%u", kl * 8, nb);
            answer(nm, out, nb * 16);

            memcpy(&ivb, iv, 16);
            crypton_aes_encrypt_xts((aes_block *)out, &k, &k2, &ivb, 0,
                                    (aes_block *)buf, nb);
            snprintf(nm, sizeof nm, "aes%u-xts/%u", kl * 8, nb);
            answer(nm, out, nb * 16);

            memcpy(&ivb, iv, 16);
            crypton_aes_decrypt_xts((aes_block *)out, &k, &k2, &ivb, 0,
                                    (aes_block *)buf, nb);
            snprintf(nm, sizeof nm, "aes%u-xtsd/%u", kl * 8, nb);
            answer(nm, out, nb * 16);

            /* a starting point too, since that is extra tweak doubling */
            memcpy(&ivb, iv, 16);
            crypton_aes_encrypt_xts((aes_block *)out, &k, &k2, &ivb, 3,
                                    (aes_block *)buf, nb);
            snprintf(nm, sizeof nm, "aes%u-xts-sp3/%u", kl * 8, nb);
            answer(nm, out, nb * 16);
        }

        for (li = 0; li < sizeof bytes / sizeof *bytes; li++) {
            uint32_t n = bytes[li];
            aes_block ivb;

            memcpy(&ivb, iv, 16);
            crypton_aes_encrypt_ctr(out, &k, &ivb, buf, n);
            snprintf(nm, sizeof nm, "aes%u-ctr/%u", kl * 8, n);
            answer(nm, out, n);

            /* the tag goes after the ciphertext, so this answers for both */
            crypton_aes_gcm_full_encrypt(out, &gk, &k, iv, 12, buf, 13,
                                         buf, n, 16);
            snprintf(nm, sizeof nm, "aes%u-gcm/%u", kl * 8, n);
            answer(nm, out, n + 16);
        }
    }

    /* GHASH and POLYVAL on their own, which the modes above reach only
     * through whatever length they were given */
    {
        table_4bit ht;
        block128 acc;
        aes_polyval pv;

        crypton_aes_generic_hinit(ht, (const block128 *)buf);
        memcpy(&acc, buf + 16, 16);
        crypton_aes_generic_gf_mul(&acc, ht);
        answer("ghash-mul", (const uint8_t *)&acc, 16);

        crypton_aes_generic_hinit(ht, (const block128 *)buf);
        memcpy(&acc, buf + 16, 16);
        crypton_aes_generic_gf_mul4(&acc, (const block128 *)(buf + 32), ht);
        answer("ghash-mul4", (const uint8_t *)&acc, 16);

        memcpy(tmp, buf, 16);
        crypton_aes_polyval_init(&pv, (const aes_block *)tmp);
        crypton_aes_polyval_update(&pv, buf + 16, 64);
        crypton_aes_polyval_finalize(&pv, (aes_block *)out);
        answer("polyval", out, 16);
    }
}

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
            snprintf(nmbuf, sizeof nmbuf, "sha3-256/%zu", lengths[li]);
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

    /* The stream ciphers and the one-time authenticator.  Each reads its key
     * and its input a word at a time and writes its output the same way, so
     * the byte order shows in the answer rather than in a length field. */
    {
        size_t li;
        for (li = 0; li < sizeof lengths / sizeof *lengths; li++) {
            crypton_chacha_context cctx;
            crypton_salsa_context sctx;
            poly1305_ctx pctx;
            poly1305_key pkey;
            poly1305_mac mac;
            uint8_t key[32], iv[8], outbuf[1024];
            char nmbuf[128];
            size_t i;

            for (i = 0; i < sizeof key; i++) key[i] = (uint8_t)(i * 11 + 3);
            for (i = 0; i < sizeof iv; i++) iv[i] = (uint8_t)(i * 5 + 1);

            crypton_chacha_init(&cctx, 20, sizeof key, key, sizeof iv, iv);
            crypton_chacha_combine(outbuf, &cctx, buf, (uint32_t)lengths[li]);
            snprintf(nmbuf, sizeof nmbuf, "chacha20/%zu", lengths[li]);
            answer(nmbuf, outbuf, lengths[li] < 64 ? lengths[li] : 64);

            crypton_salsa_init(&sctx, 20, sizeof key, key, sizeof iv, iv);
            crypton_salsa_combine(outbuf, &sctx, buf, (uint32_t)lengths[li]);
            snprintf(nmbuf, sizeof nmbuf, "salsa20/%zu", lengths[li]);
            answer(nmbuf, outbuf, lengths[li] < 64 ? lengths[li] : 64);

            for (i = 0; i < sizeof pkey; i++) pkey[i] = (uint8_t)(i * 13 + 7);
            crypton_poly1305_init(&pctx, &pkey);
            crypton_poly1305_update(&pctx, buf, (uint32_t)lengths[li]);
            crypton_poly1305_finalize(mac, &pctx);
            snprintf(nmbuf, sizeof nmbuf, "poly1305/%zu", lengths[li]);
            answer(nmbuf, mac, sizeof mac);
        }
    }

    aes_answers();

    if (!generating && failures == 0)
        printf("ok   %d answers match the little-endian ones\n", checked);
    else if (!generating)
        printf("FAIL %d of %d answers differ\n", failures, checked);
    fclose(vf);
    return failures != 0;
}
