/* The two P-256 scalar multiplications and the scalar inversion, all of
 * which take the private key as the scalar. */
#include "tests/ct/ct.h"
#include <string.h>
#include "p256/p256.h"

void crypton_p256e_point_mul(const crypton_p256_int *n,
    const crypton_p256_int *ix, const crypton_p256_int *iy,
    crypton_p256_int *ox, crypton_p256_int *oy);
void crypton_p256e_scalar_invert(const crypton_p256_int *a,
                                 crypton_p256_int *b);

int main(void) {
    crypton_p256_int n, px, py, ox, oy, inv, one;
    int i;

    /* a public point to be multiplied: the generator's 0x9e3779b9 multiple */
    crypton_p256_init(&one);
    P256_DIGIT(&one, 0) = 0x9e3779b9u;
    crypton_p256_base_point_mul(&one, &px, &py);

    for (i = 0; i < P256_NDIGITS; i++)
        P256_DIGIT(&n, i) = (crypton_p256_digit)ct_rnd();
    crypton_p256_mod(&crypton_SECP256r1_n, &n, &n);

    CT_SECRET(&n, sizeof n);

    crypton_p256_base_point_mul(&n, &ox, &oy);
    CT_PUBLIC(&ox, sizeof ox);
    CT_PUBLIC(&oy, sizeof oy);
    ct_sink(&ox, sizeof ox);

    crypton_p256e_point_mul(&n, &px, &py, &ox, &oy);
    CT_PUBLIC(&ox, sizeof ox);
    CT_PUBLIC(&oy, sizeof oy);
    ct_sink(&oy, sizeof oy);

    crypton_p256e_scalar_invert(&n, &inv);
    CT_PUBLIC(&inv, sizeof inv);
    ct_sink(&inv, sizeof inv);
    return 0;
}
