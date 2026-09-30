/* X448 and Ed448.  The scalar and the private key are the secrets. */
#include "tests/ct/ct.h"
#include <string.h>
#include "decaf/ed448.h"
#include "decaf/point_448.h"

int main(void) {
    uint8_t priv[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES];
    uint8_t pub[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES];
    uint8_t sig[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES];
    uint8_t xs[CRYPTON_DECAF_X448_PRIVATE_BYTES];
    uint8_t xb[CRYPTON_DECAF_X448_PUBLIC_BYTES];
    uint8_t xo[CRYPTON_DECAF_X448_PUBLIC_BYTES];
    uint8_t msg[64];

    ct_fill(priv, sizeof priv);
    ct_fill(msg, sizeof msg);
    ct_fill(xs, sizeof xs);
    ct_fill(xb, sizeof xb);
    CT_SECRET(priv, sizeof priv);
    CT_SECRET(xs, sizeof xs);

    crypton_decaf_ed448_derive_public_key(pub, priv);
    CT_PUBLIC(pub, sizeof pub);
    crypton_decaf_ed448_sign(sig, priv, pub, msg, sizeof msg, 0, NULL, 0);
    CT_PUBLIC(sig, sizeof sig);
    ct_sink(sig, sizeof sig);

    crypton_decaf_x448_derive_public_key(xo, xs);
    CT_PUBLIC(xo, sizeof xo);
    ct_sink(xo, sizeof xo);
    (void)crypton_decaf_x448(xo, xb, xs);
    CT_PUBLIC(xo, sizeof xo);
    ct_sink(xo, sizeof xo);
    return 0;
}
