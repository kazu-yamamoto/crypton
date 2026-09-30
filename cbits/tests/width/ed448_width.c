/* Ed448 and X448 asked of the 32-bit field arithmetic and of the 64-bit one.
   Only the f_impl.c under p448/arch_32 or p448/arch_ref64, and the two arch
   include directories, differ between the builds; everything above them is
   the same source. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "decaf/ed448.h"
#include "decaf/point_448.h"

static uint64_t s0 = 0x243f6a8885a308d3ULL, s1 = 0x13198a2e03707344ULL;
static uint64_t rnd(void) {
    uint64_t x = s0, y = s1;
    s0 = y; x ^= x << 23;
    s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
    return s1 + y;
}
static void fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(rnd() >> 24);
}
static void show(const char *t, const uint8_t *b, size_t n) {
    printf("%s ", t);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    uint8_t priv[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES];
    uint8_t pub[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES];
    uint8_t sig[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES];
    uint8_t msg[256], ctx[8];
    uint8_t xs[CRYPTON_DECAF_X448_PRIVATE_BYTES];
    uint8_t xb[CRYPTON_DECAF_X448_PUBLIC_BYTES];
    uint8_t xo[CRYPTON_DECAF_X448_PUBLIC_BYTES];

    /* the scalars and points worth naming */
    static const uint8_t edge[3] = {0x00, 0x01, 0xff};
    for (unsigned e = 0; e < 3; e++) {
        memset(priv, edge[e], sizeof priv);
        crypton_decaf_ed448_derive_public_key(pub, priv);
        show("epub", pub, sizeof pub);
        crypton_decaf_ed448_sign(sig, priv, pub, (const uint8_t *)"", 0, 0, NULL, 0);
        show("esig", sig, sizeof sig);
        printf("everify=%d\n",
            crypton_decaf_ed448_verify(sig, pub, (const uint8_t *)"", 0, 0, NULL, 0));

        memset(xs, edge[e], sizeof xs);
        crypton_decaf_x448_derive_public_key(xo, xs);
        show("xpub", xo, sizeof xo);
        memset(xb, edge[e], sizeof xb);
        printf("x448=%d\n", crypton_decaf_x448(xo, xb, xs));
        show("xsh", xo, sizeof xo);
    }

    for (int it = 0; it < 512; it++) {
        size_t mlen = (size_t)(rnd() % sizeof msg);
        uint8_t clen = (uint8_t)(rnd() % sizeof ctx);
        fill(priv, sizeof priv);
        fill(msg, sizeof msg);
        fill(ctx, sizeof ctx);

        crypton_decaf_ed448_derive_public_key(pub, priv);
        show("pub", pub, sizeof pub);
        crypton_decaf_ed448_sign(sig, priv, pub, msg, mlen, 0, ctx, clen);
        show("sig", sig, sizeof sig);
        printf("ok=%d bad=%d\n",
            crypton_decaf_ed448_verify(sig, pub, msg, mlen, 0, ctx, clen),
            crypton_decaf_ed448_verify(sig, pub, msg, mlen, 1, ctx, clen));
        /* a signature with one bit moved has to fail on both builds alike */
        sig[(size_t)(rnd() % sizeof sig)] ^= 1;
        printf("tampered=%d\n",
            crypton_decaf_ed448_verify(sig, pub, msg, mlen, 0, ctx, clen));

        fill(xs, sizeof xs);
        crypton_decaf_x448_derive_public_key(xb, xs);
        show("xp", xb, sizeof xb);
        uint8_t xs2[CRYPTON_DECAF_X448_PRIVATE_BYTES], xb2[CRYPTON_DECAF_X448_PUBLIC_BYTES];
        uint8_t sh1[CRYPTON_DECAF_X448_PUBLIC_BYTES], sh2[CRYPTON_DECAF_X448_PUBLIC_BYTES];
        fill(xs2, sizeof xs2);
        crypton_decaf_x448_derive_public_key(xb2, xs2);
        int r1 = crypton_decaf_x448(sh1, xb2, xs);
        int r2 = crypton_decaf_x448(sh2, xb, xs2);
        printf("r=%d,%d agree=%d\n", r1, r2, memcmp(sh1, sh2, sizeof sh1) == 0);
        show("sh", sh1, sizeof sh1);
    }
    return 0;
}
