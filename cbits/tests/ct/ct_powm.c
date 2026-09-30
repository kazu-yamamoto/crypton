/* The windowed modular exponentiation, which is what an RSA private key
 * operation runs.  The exponent is the secret it is built to hide. */
#include "tests/ct/ct.h"
#include <string.h>
#include "crypton_powm.h"

int main(void) {
    enum { LEN = 256 };                 /* a 2048-bit modulus */
    uint8_t out[LEN], base[LEN], mod[LEN], exp[LEN];

    ct_fill(base, sizeof base);
    ct_fill(mod, sizeof mod);
    ct_fill(exp, sizeof exp);
    mod[0] |= 0x80;                     /* full width */
    mod[LEN - 1] |= 1;                  /* and odd, which is what it wants */
    base[0] &= 0x7f;                    /* below the modulus */

    /* The exponent is the private key.  The base is the ciphertext, which an
     * attacker chooses and already knows, so it stays public. */
    CT_SECRET(exp, sizeof exp);

    if (crypton_powm_sec(out, base, LEN, exp, LEN, mod, LEN) != 0) {
        printf("powm_sec refused\n");
        return 1;
    }
    CT_PUBLIC(out, sizeof out);
    ct_sink(out, sizeof out);
    return 0;
}
