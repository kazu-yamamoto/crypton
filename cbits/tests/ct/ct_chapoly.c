/* ChaCha20 and Poly1305.  The key is the secret, and so is the plaintext. */
#include "tests/ct/ct.h"
#include <string.h>
#include "crypton_chacha.h"
#include "crypton_poly1305.h"

int main(void) {
    crypton_chacha_context ctx;
    poly1305_ctx pctx;
    poly1305_key pkey;
    poly1305_mac mac;
    uint8_t key[32], iv[12], pt[256], ct[256];

    ct_fill(key, sizeof key);
    ct_fill(iv, sizeof iv);
    ct_fill(pt, sizeof pt);
    ct_fill(pkey, sizeof pkey);
    CT_SECRET(key, sizeof key);
    CT_SECRET(pt, sizeof pt);
    CT_SECRET(pkey, sizeof pkey);

    crypton_chacha_init(&ctx, 20, sizeof key, key, sizeof iv, iv);
    crypton_chacha_combine(ct, &ctx, pt, sizeof pt);
    CT_PUBLIC(ct, sizeof ct);          /* the ciphertext goes on the wire */
    ct_sink(ct, sizeof ct);

    crypton_poly1305_init(&pctx, &pkey);
    crypton_poly1305_update(&pctx, ct, sizeof ct);
    crypton_poly1305_finalize(mac, &pctx);
    CT_PUBLIC(mac, sizeof mac);
    ct_sink(mac, sizeof mac);
    return 0;
}
