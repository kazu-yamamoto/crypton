/* AES, and AES-GCM.  The key is the secret, and so is the plaintext.
 *
 * Whether this reports depends on which implementation the machine selected.
 * AES-NI and the ARMv8 instructions do not look anything up; the generic C
 * is table-driven and is variable-time by construction, which is a property
 * of that code rather than a defect in it.  See cbits/tests/ct/README. */
#include "tests/ct/ct.h"
#include <stdio.h>
#include <string.h>
#include "crypton_aes.h"
#include "crypton_cpu.h"

/* crypton_aes.c fills this; run.sh reads the line below to tell the three
 * builds of this driver apart.  They are all silent now, so which one took
 * which implementation cannot be read off a leak any more. */
uint8_t *crypton_aes_cpu_init(void);

int main(void) {
    aes_key k;
    aes_gcm_key gk;
    uint8_t key[32], pt[256], ct[256 + 16], iv[12];

    printf("dispatch aes=%d pclmul=%d\n",
           crypton_aes_cpu_init()[CPU_AESNI] != 0,
           crypton_aes_cpu_init()[CPU_PCLMUL] != 0);

    ct_fill(key, sizeof key);
    ct_fill(pt, sizeof pt);
    ct_fill(iv, sizeof iv);
    CT_SECRET(key, sizeof key);
    CT_SECRET(pt, sizeof pt);

    crypton_aes_initkey(&k, key, sizeof key);
    crypton_aes_encrypt_ecb((aes_block *)ct, &k, (aes_block *)pt,
                            sizeof pt / 16);
    CT_PUBLIC(ct, sizeof pt);
    ct_sink(ct, sizeof pt);

    crypton_aes_gcm_key_init(&gk, &k);
    /* the output takes the ciphertext and then the tag */
    crypton_aes_gcm_full_encrypt(ct, &gk, &k, iv, sizeof iv, NULL, 0,
                                 pt, sizeof pt, 16);
    CT_PUBLIC(ct, sizeof ct);
    ct_sink(ct, sizeof ct);
    return 0;
}
