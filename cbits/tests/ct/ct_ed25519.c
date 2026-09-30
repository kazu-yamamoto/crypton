/* Ed25519 signing.  The private key is the secret; the message is not. */
#include "tests/ct/ct.h"
#include <string.h>
#include "ed25519/ed25519.h"

int main(void) {
    ed25519_secret_key sk;
    ed25519_public_key pk;
    ed25519_signature sig;
    uint8_t msg[64];

    ct_fill(sk, sizeof sk);
    ct_fill(msg, sizeof msg);
    CT_SECRET(sk, sizeof sk);

    crypton_ed25519_publickey(sk, pk);
    CT_PUBLIC(pk, sizeof pk);

    crypton_ed25519_sign(msg, sizeof msg, sk, pk, sig);
    CT_PUBLIC(sig, sizeof sig);
    ct_sink(sig, sizeof sig);
    return 0;
}
