/* X25519.  The scalar is the private key; the base point is the peer's
 * public key and is not secret. */
#include "tests/ct/ct.h"
#include <string.h>

void crypton_curve25519_donna(uint8_t *mypublic, const uint8_t *secret,
                              const uint8_t *basepoint);

int main(void) {
    uint8_t sec[32], base[32], out[32];
    static const uint8_t g[32] = {9};

    ct_fill(sec, sizeof sec);
    ct_fill(base, sizeof base);
    CT_SECRET(sec, sizeof sec);

    crypton_curve25519_donna(out, sec, g);       /* the public key */
    CT_PUBLIC(out, sizeof out);
    ct_sink(out, sizeof out);

    crypton_curve25519_donna(out, sec, base);    /* the shared secret */
    CT_PUBLIC(out, sizeof out);
    ct_sink(out, sizeof out);
    return 0;
}
