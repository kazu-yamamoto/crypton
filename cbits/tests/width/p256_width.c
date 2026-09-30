/* Exercise the public P-256 API and print everything it answers, so that the
   32-bit build and the 64-bit build can be compared byte for byte.  Every
   value crosses the boundary as big-endian bytes, which is the one form the
   two representations agree on by construction. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "p256/p256.h"

/* The header declares crypton_p256_point_mul and crypton_p256_modinv, and
   nothing defines them.  What exists is this family, which has no header at
   all -- the Haskell side declares it through the FFI. */
void crypton_p256e_point_mul(const crypton_p256_int *n,
    const crypton_p256_int *in_x, const crypton_p256_int *in_y,
    crypton_p256_int *out_x, crypton_p256_int *out_y);
void crypton_p256e_point_add(
    const crypton_p256_int *in_x1, const crypton_p256_int *in_y1,
    const crypton_p256_int *in_x2, const crypton_p256_int *in_y2,
    crypton_p256_int *out_x, crypton_p256_int *out_y);
void crypton_p256e_point_negate(
    const crypton_p256_int *in_x, const crypton_p256_int *in_y,
    crypton_p256_int *out_x, crypton_p256_int *out_y);
void crypton_p256e_modadd(const crypton_p256_int *MOD,
    const crypton_p256_int *a, const crypton_p256_int *b, crypton_p256_int *c);
void crypton_p256e_modsub(const crypton_p256_int *MOD,
    const crypton_p256_int *a, const crypton_p256_int *b, crypton_p256_int *c);
void crypton_p256e_scalar_invert(const crypton_p256_int *a, crypton_p256_int *b);

static uint64_t s0 = 0x243f6a8885a308d3ULL, s1 = 0x13198a2e03707344ULL;
static uint64_t rnd(void) {           /* xoroshiro-ish, deterministic */
    uint64_t x = s0, y = s1;
    s0 = y;
    x ^= x << 23;
    s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
    return s1 + y;
}
static void rnd_bytes(uint8_t *p, int n) {
    for (int i = 0; i < n; i++) p[i] = (uint8_t)(rnd() >> 24);
}
static void show(const char *tag, const crypton_p256_int *v) {
    uint8_t b[P256_NBYTES];
    crypton_p256_to_bin(v, b);
    printf("%s ", tag);
    for (int i = 0; i < P256_NBYTES; i++) printf("%02x", b[i]);
    printf("\n");
}
static void from_hex(const char *h, crypton_p256_int *out) {
    uint8_t b[P256_NBYTES];
    for (int i = 0; i < P256_NBYTES; i++) {
        unsigned v; sscanf(h + 2 * i, "%2x", &v); b[i] = (uint8_t)v;
    }
    crypton_p256_from_bin(b, out);
}

int main(void) {
    crypton_p256_int n, x, y, x2, y2, r, a, b, n2tmp;
    uint8_t buf[P256_NBYTES];

    show("order", &crypton_SECP256r1_n);
    show("prime", &crypton_SECP256r1_p);
    show("bparam", &crypton_SECP256r1_b);

    /* the scalars worth naming: zero, one, the order and its neighbours, and
       the all-bits-set shapes the comb recoding has to single out */
    static const char *corners[] = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", /* n */
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", /* n-1 */
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552", /* n+1 */
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "0000000000000000000000000000000000000000000000000000000000000000",
    };
    for (unsigned i = 0; i < sizeof corners / sizeof *corners; i++) {
        from_hex(corners[i], &n);
        crypton_p256_base_point_mul(&n, &x, &y);
        printf("corner%u valid=%d\n", i, crypton_p256_is_valid_point(&x, &y));
        show("  cx", &x); show("  cy", &y);
    }

    for (int it = 0; it < 1024; it++) {
        rnd_bytes(buf, P256_NBYTES);
        crypton_p256_from_bin(buf, &n);
        crypton_p256_mod(&crypton_SECP256r1_n, &n, &n);
        show("n", &n);

        crypton_p256_base_point_mul(&n, &x, &y);
        printf("valid=%d zero=%d odd=%d even=%d\n",
               crypton_p256_is_valid_point(&x, &y),
               crypton_p256_is_zero(&x), crypton_p256_is_odd(&y),
               crypton_p256_is_even(&y));
        show("x", &x); show("y", &y);

        /* n2 * (that point), then n1*G + n2*P through the vartime pair */
        rnd_bytes(buf, P256_NBYTES);
        crypton_p256_from_bin(buf, &a);
        crypton_p256_mod(&crypton_SECP256r1_n, &a, &a);
        crypton_p256e_point_mul(&a, &x, &y, &x2, &y2);
        show("px", &x2); show("py", &y2);
        printf("pvalid=%d\n", crypton_p256_is_valid_point(&x2, &y2));

        rnd_bytes(buf, P256_NBYTES);
        crypton_p256_from_bin(buf, &b);
        crypton_p256_mod(&crypton_SECP256r1_n, &b, &b);
        crypton_p256_points_mul_vartime(&a, &b, &x, &y, &x2, &y2);
        show("vx", &x2); show("vy", &y2);

        /* the integer side: every arithmetic entry point the header offers */
        crypton_p256_modmul(&crypton_SECP256r1_n, &a, 0, &b, &r); show("mul", &r);
        crypton_p256_modmul(&crypton_SECP256r1_p, &a, 1, &b, &r); show("mulc", &r);
        crypton_p256e_scalar_invert(&a, &r); show("inv", &r);
        crypton_p256e_modadd(&crypton_SECP256r1_n, &a, &b, &r); show("madd", &r);
        crypton_p256e_modsub(&crypton_SECP256r1_n, &a, &b, &r); show("msub", &r);
        crypton_p256e_point_add(&x, &y, &x2, &y2, &r, &n2tmp); show("ax", &r); show("ay", &n2tmp);
        crypton_p256e_point_negate(&x, &y, &r, &n2tmp); show("gx", &r); show("gy", &n2tmp);
        crypton_p256_modinv_vartime(&crypton_SECP256r1_n, &a, &r); show("invv", &r);
        printf("cmp=%d add=%d sub=%d addd=%d\n",
               crypton_p256_cmp(&a, &b),
               crypton_p256_add(&a, &b, &r),
               crypton_p256_sub(&a, &b, &r),
               crypton_p256_add_d(&a, 0x9e3779b9u, &r));
        show("sum", &r);
        /* the shifts are defined as n % P256_BITSPERDIGIT, which is 32 on one
           build and 64 on the other, so keep the ask inside both */
        for (int s = 0; s < 3; s++) {
            int k = (int)(rnd() % 32);
            printf("shl%d=%d\n", k, (int)(crypton_p256_shl(&a, k, &r) & 0xff));
            show("shl", &r);
            crypton_p256_shr(&a, k, &r); show("shr", &r);
        }
        for (int bit = 0; bit < 256; bit += 37)
            printf("bit%d=%d ", bit, crypton_p256_get_bit(&a, bit));
        printf("\n");
    }
    return 0;
}
