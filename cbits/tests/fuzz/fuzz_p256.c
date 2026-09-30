/* A P-256 point as it arrives: two field elements, checked for being on the
 * curve, and then multiplied if they are. */
#include "tests/fuzz/fuzz.h"
#include "p256/p256.h"

void crypton_p256e_point_mul(const crypton_p256_int *n,
    const crypton_p256_int *ix, const crypton_p256_int *iy,
    crypton_p256_int *ox, crypton_p256_int *oy);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t xb[P256_NBYTES], yb[P256_NBYTES], nb[P256_NBYTES];
	crypton_p256_int x, y, n, ox, oy;
	const uint8_t *p = data;
	size_t left = size;

	if (!fz_take(&p, &left, xb, sizeof xb))
		return 0;
	if (!fz_take(&p, &left, yb, sizeof yb))
		return 0;
	if (!fz_take(&p, &left, nb, sizeof nb))
		return 0;

	crypton_p256_from_bin(xb, &x);
	crypton_p256_from_bin(yb, &y);
	crypton_p256_from_bin(nb, &n);

	if (crypton_p256_is_valid_point(&x, &y)) {
		crypton_p256_mod(&crypton_SECP256r1_n, &n, &n);
		crypton_p256e_point_mul(&n, &x, &y, &ox, &oy);
	}
	return 0;
}
