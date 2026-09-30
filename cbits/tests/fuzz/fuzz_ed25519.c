/* Ed25519 signature verification: the public key and the signature are both
 * whatever the sender chose, and both are decoded before anything is
 * checked. */
#include "tests/fuzz/fuzz.h"
#include "ed25519/ed25519.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	ed25519_public_key pk;
	ed25519_signature sig;
	const uint8_t *p = data;
	size_t left = size;

	if (!fz_take(&p, &left, pk, sizeof pk))
		return 0;
	if (!fz_take(&p, &left, sig, sizeof sig))
		return 0;

	/* whatever is left is the message */
	(void)crypton_ed25519_sign_open(p, left, pk, sig);
	return 0;
}
