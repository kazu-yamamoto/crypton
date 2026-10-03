/* ML-KEM-768, which is the parameter set TLS uses.  The seed and the
 * decapsulation key are secret; the encapsulation key and the ciphertext are
 * published, and the shared secret is the answer the caller asked for.
 *
 * mlkem-native's AArch64 and x86-64 assembly carries a HOL-Light proof of
 * secret-independent timing, so a report from the backend build means the
 * proof does not cover what crypton built, or that crypton reached it
 * wrongly.  The portable C has no such proof, which is the reason to ask it
 * the question at all. */
#include "tests/ct/ct.h"

int crypton_mlkem768_keypair_derand(uint8_t *pk, uint8_t *sk,
                                    const uint8_t *coins);
int crypton_mlkem768_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                const uint8_t *coins);
int crypton_mlkem768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int main(void) {
    uint8_t pk[1184], sk[2400], ct[1088], ss[32], ss2[32];
    uint8_t kcoins[64], ecoins[32];

    ct_fill(kcoins, sizeof kcoins);
    ct_fill(ecoins, sizeof ecoins);

    CT_SECRET(kcoins, sizeof kcoins);
    if (crypton_mlkem768_keypair_derand(pk, sk, kcoins) != 0) return 1;
    CT_PUBLIC(pk, sizeof pk);
    ct_sink(pk, sizeof pk);

    /* The message encapsulation draws is as secret as the key it derives. */
    CT_SECRET(ecoins, sizeof ecoins);
    if (crypton_mlkem768_enc_derand(ct, ss, pk, ecoins) != 0) return 1;
    CT_PUBLIC(ct, sizeof ct);
    CT_PUBLIC(ss, sizeof ss);
    ct_sink(ct, sizeof ct);
    ct_sink(ss, sizeof ss);

    /* sk is still undefined here: decapsulation is the half that runs on the
     * long-lived secret, and the half an attacker can drive by sending
     * ciphertexts of their choosing. */
    if (crypton_mlkem768_dec(ss2, ct, sk) != 0) return 1;
    CT_PUBLIC(ss2, sizeof ss2);
    ct_sink(ss2, sizeof ss2);
    return 0;
}
