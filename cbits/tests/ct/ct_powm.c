/* The windowed modular exponentiation, which is what an RSA private key
 * operation runs.  The exponent is the secret it is built to hide. */
#include "tests/ct/ct.h"
#include <string.h>
#include "crypton_powm.h"

/* A 2048-bit modulus unless the build says otherwise: run.sh builds it at
 * the other sizes the vendored multiplication takes as well, since those
 * are different code. */
#ifndef CT_POWM_BYTES
#define CT_POWM_BYTES 256
#endif

#ifdef CT_POWM_COUNT_S2N
/* run.sh links this build with -Wl,--wrap=bignum_emontredc_8n, so every
 * reduction the s2n-bignum path does comes through here and is counted.
 * The build then says which implementation it ran, rather than leaving it
 * to be inferred: under valgrind the processor's answers are valgrind's,
 * and a build that quietly took the C would pass here while checking what
 * the plain powm build already has. */
#include <stdint.h>
uint64_t __real_bignum_emontredc_8n(uint64_t k, uint64_t *z,
                                    const uint64_t *m, uint64_t w);
static unsigned long s2n_reductions;
uint64_t __wrap_bignum_emontredc_8n(uint64_t k, uint64_t *z,
                                    const uint64_t *m, uint64_t w)
{
    s2n_reductions++;
    return __real_bignum_emontredc_8n(k, z, m, w);
}
#endif

int main(void) {
    enum { LEN = CT_POWM_BYTES };
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
#ifdef CT_POWM_COUNT_S2N
    printf("dispatch powm_s2n=%lu\n", s2n_reductions);
#endif
    return 0;
}
