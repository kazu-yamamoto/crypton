/* What is left on the stack after a secret has been through it.
 *
 * The stack below a returning function is not erased -- it is simply no
 * longer addressed -- so whatever the function kept there stays until
 * something else writes over it.  For a hash context or a key schedule that
 * means a copy of the key can outlive every object the caller thinks holds
 * it, and a later crash dump, core file or swapped page carries it away.
 *
 * So: paint the stack with a filler, run the primitive on a secret made of
 * an unmistakable pattern, copy the painted region somewhere else before
 * anything can disturb it, and look for the pattern in the copy.  A hit is a
 * place where the secret outlived the call.
 *
 * The region examined is below this file's own frame, so the driver's own
 * copy of the secret is not what is being found.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Each probed function needs a frame of its own: inlined into probe, its
 * locals would sit in a live frame rather than an abandoned one, and finding
 * them there would mean nothing.  That cost the first attempt at this file. */
#if defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

/* 32 bytes that nothing else would produce */
static const uint8_t SECRET[32] = {
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15,
    0xf3, 0x9c, 0xc0, 0x60, 0x5c, 0xed, 0xc8, 0x34,
    0x1a, 0x2e, 0x8f, 0x5b, 0xd7, 0x06, 0x41, 0x92,
    0xc3, 0x58, 0xe6, 0x70, 0xb1, 0x24, 0xaf, 0x8d,
};

#define REGION  (512 * 1024)
#define FILLER  0x5a

/* Write the filler over the stack the primitive is about to use.  Recursion
 * rather than one large frame, so that the compiler cannot decide the whole
 * thing is dead and skip it. */
static void paint(int depth) {
    volatile uint8_t pad[8192];
    size_t i;
    for (i = 0; i < sizeof pad; i++) pad[i] = FILLER;
    if (depth > 0) paint(depth - 1);
}

/* How many times the pattern appears in the copy.  A run of the filler is
 * what is expected; anything else is what was left behind. */
static int count_hits(const uint8_t *hay, size_t n, const uint8_t *needle,
                      size_t m) {
    size_t i;
    int hits = 0;
    if (n < m) return 0;
    for (i = 0; i + m <= n; i++)
        if (hay[i] == needle[0] && memcmp(hay + i, needle, m) == 0) hits++;
    return hits;
}

static uint8_t *snapshot;
static int failures, checked;

/* The context a primitive is handed, on the heap where crypton's own callers
 * put it.  After the call it is looked at directly: whatever is still in it
 * is what the caller is left holding. */
static void *ctx_mem;
static size_t ctx_len;

/* known.txt lists the places that keep the secret and are understood.  A
 * probe that reports only those passes; anything else is new and fails. */
static int is_known(const char *name, const char *what) {
    char line[256], want[128];
    FILE *f = fopen("cbits/tests/scrub/known.txt", "r");
    int found = 0;
    if (!f) return 0;
    snprintf(want, sizeof want, "%s %s", name, what);
    while (fgets(line, sizeof line, f)) {
        char a[64], b[64];
        if (line[0] == '#' || sscanf(line, "%63s %63s", a, b) != 2) continue;
        if (strcmp(a, name) == 0 && strcmp(b, what) == 0) { found = 1; break; }
    }
    fclose(f);
    return found;
}

/* Run one primitive and report what it left.  The callback is handed the
 * secret and is expected to use it and return. */
static void probe(const char *name, void (*run)(const uint8_t *, size_t),
                  size_t look_for) {
    volatile uint8_t here;
    const uint8_t *low;
    int hits;

    paint(24);                     /* about 200 KB of filler */
    run(SECRET, sizeof SECRET);

    /* Everything below this frame is what the call used.  Copied with a
     * loop rather than memcpy: a call pushes a frame exactly where the one
     * being examined was, and would erase the top of the evidence before it
     * could be read.  That is how the first version of this reported that
     * nothing was ever left behind, including by the canary. */
    low = (const uint8_t *)&here - REGION;
    {
        /* volatile, or the compiler recognises the loop and emits memcpy --
         * which is the call this loop exists to avoid.  That cost the first
         * two attempts at this file. */
        const volatile uint8_t *v = low;
        size_t k;
        for (k = 0; k < REGION; k++) snapshot[k] = v[k];
    }

    hits = count_hits(snapshot, REGION, SECRET, look_for);
    checked++;
    if (strcmp(name, "canary") == 0) {
        if (hits == 0) {
            printf("FAIL canary: the driver that keeps the secret on purpose\n"
                   "     was not found, so nothing below this line counts\n");
            failures++;
        } else {
            printf("ok   canary: found %d, so the search works\n", hits);
        }
        return;
    }
    /* two separate questions: what the primitive left in its own scratch,
       and what it left in the context its caller still holds */
    if (hits == 0) {
        printf("ok   %-9s scratch: no verbatim copy below the frame\n", name);
    } else if (is_known(name, "scratch")) {
        printf("note %-9s scratch: %d verbatim copy(ies), known\n", name, hits);
    } else {
        printf("LEFT %-9s scratch: %d verbatim copy(ies) below the frame,\n"
               "     and cbits/tests/scrub/known.txt does not list it\n",
               name, hits);
        failures++;
    }
    if (ctx_len) {
        int chits = count_hits((const uint8_t *)ctx_mem, ctx_len, SECRET,
                               look_for);
        /* No hit is not the same as no secret.  A primitive that stores the
           key transformed -- Poly1305 clamps it into r and pad -- keeps key
           material the search cannot see.  All this can say is whether the
           bytes survive as they were handed over. */
        if (chits == 0) {
            printf("ok   %-9s context: no verbatim copy of the secret\n",
                   name);
        } else if (is_known(name, "context")) {
            printf("note %-9s context: %d verbatim copy(ies), known\n",
                   name, chits);
        } else {
            printf("LEFT %-9s context: %d verbatim copy(ies) of the secret,\n"
                   "     and cbits/tests/scrub/known.txt does not list it\n",
                   name, chits);
            failures++;
        }
        ctx_len = 0;
    }
}

/* ---- the primitives ---------------------------------------------------- */

#include "crypton_sha256.h"
#include "crypton_sha512.h"
#include "crypton_chacha.h"
#include "crypton_poly1305.h"
#include "crypton_powm.h"

NOINLINE static void run_sha256(const uint8_t *s, size_t n) {
    struct sha256_ctx *ctx = ctx_mem;
    uint8_t out[32];
    ctx_len = sizeof *ctx;
    crypton_sha256_init(ctx);
    crypton_sha256_update(ctx, s, (uint32_t)n);
    crypton_sha256_finalize(ctx, out);
    if (out[0] == 0xff && out[31] == 0xff) printf("unreachable\n");
}

NOINLINE static void run_sha512(const uint8_t *s, size_t n) {
    struct sha512_ctx *ctx = ctx_mem;
    uint8_t out[64];
    ctx_len = sizeof *ctx;
    crypton_sha512_init(ctx);
    crypton_sha512_update(ctx, s, (uint32_t)n);
    crypton_sha512_finalize(ctx, out);
    if (out[0] == 0xff && out[63] == 0xff) printf("unreachable\n");
}

NOINLINE static void run_chacha(const uint8_t *s, size_t n) {
    crypton_chacha_context *ctx = ctx_mem;
    uint8_t iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t out[64];
    ctx_len = sizeof *ctx;
    crypton_chacha_init(ctx, 20, (uint32_t)n, s, sizeof iv, iv);
    crypton_chacha_combine(out, ctx, out, sizeof out);
    if (out[0] == 0xff && out[63] == 0xff) printf("unreachable\n");
}

NOINLINE static void run_poly1305(const uint8_t *s, size_t n) {
    poly1305_ctx *ctx = ctx_mem;
    poly1305_mac mac;
    uint8_t msg[64];
    /* the key is handed over where it already lies, so that nothing of it is
       put on this frame by the driver rather than by the library */
    (void)n;
    memset(msg, 0x11, sizeof msg);
    ctx_len = sizeof *ctx;
    crypton_poly1305_init(ctx, (poly1305_key *)(void *)(uintptr_t)s);
    crypton_poly1305_update(ctx, msg, sizeof msg);
    crypton_poly1305_finalize(mac, ctx);
    if (mac[0] == 0xff && mac[15] == 0xff) printf("unreachable\n");
}

/* The RSA private-key exponentiation.  Its scratch is on the heap, but the
 * windows it selects and the accumulators pass through the stack. */
static uint8_t *powm_out, *powm_base, *powm_mod, *powm_exp;
NOINLINE static void run_powm(const uint8_t *s, size_t n) {
    /* Everything is on the heap: the exponent because it is the secret and
       must not be put on this frame by the driver, the rest to keep the
       frame small enough that what is found below it came from the library. */
    enum { LEN = 128 };
    uint8_t *out = powm_out, *base = powm_base, *mod = powm_mod;
    (void)s; (void)n;
    if (crypton_powm_sec(out, base, LEN, powm_exp, LEN, mod, LEN) != 0)
        printf("powm_sec refused\n");
    if (out[0] == 0xff && out[LEN - 1] == 0xff) printf("unreachable\n");
}

/* The calibration.  This one keeps the secret on the stack on purpose, so it
 * has to be found; if it is not, the painting or the snapshot is looking
 * somewhere the calls do not use and every "ok" below means nothing. */
NOINLINE static void run_canary(const uint8_t *s, size_t n) {
    volatile uint8_t copy[128];
    size_t i;
    for (i = 0; i < n && i < sizeof copy; i++) copy[i] = s[i];
    if (copy[0] == 0xff && copy[31] == 0xff) printf("unreachable\n");
}

int main(void) {
    size_t i;
    snapshot = malloc(REGION);
    ctx_mem = malloc(4096);
    powm_out = malloc(128); powm_base = malloc(128);
    powm_mod = malloc(128); powm_exp = malloc(128);
    if (!snapshot || !ctx_mem || !powm_out || !powm_base || !powm_mod || !powm_exp) return 2;
    for (i = 0; i < 128; i++) {
        powm_base[i] = (uint8_t)(i * 3 + 1);
        powm_mod[i] = (uint8_t)(i * 5 + 7);
        powm_exp[i] = SECRET[i % sizeof SECRET];
    }
    powm_mod[0] |= 0x80;
    powm_mod[127] |= 1;
    powm_base[0] &= 0x7f;

    probe("canary", run_canary, 32);
    probe("sha256", run_sha256, 32);
    probe("sha512", run_sha512, 32);
    probe("chacha20", run_chacha, 32);
    probe("poly1305", run_poly1305, 16);
    probe("powm_sec", run_powm, 32);

    free(snapshot);
    if (failures)
        printf("\n%d place(s) keep the secret and are not in known.txt\n",
               failures);
    else
        printf("\nnothing keeps the secret that known.txt does not name\n");
    return failures != 0;
}
