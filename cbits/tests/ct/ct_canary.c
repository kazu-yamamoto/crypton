/* The calibration.  This one is deliberately not constant time: it branches
 * on a secret byte and indexes a table with another.  If it reports nothing,
 * the marking is not reaching the code and every other driver's silence in
 * this run means nothing either -- which is the whole reason it is here. */
#include "tests/ct/ct.h"

static const uint8_t table[256] = {1};

int main(void) {
    uint8_t secret[32], out[2];

    ct_fill(secret, sizeof secret);
    CT_SECRET(secret, sizeof secret);

    out[0] = secret[0] & 1 ? 0x5a : 0xa5;   /* a branch on the secret */
    out[1] = table[secret[1]];              /* an address from the secret */

    CT_PUBLIC(out, sizeof out);
    ct_sink(out, sizeof out);
    return 0;
}
