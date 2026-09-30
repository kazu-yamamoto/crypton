/* Decoding a point and verifying an Ed448 signature, both from bytes that
 * came from somewhere else.  point_decode validates; the EdDSA decode is the
 * first thing a verifier does with a public key. */
#include "tests/fuzz/fuzz.h"
#include "decaf/point_448.h"
#include "decaf/ed448.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t ser[CRYPTON_DECAF_448_SER_BYTES];
	uint8_t pub[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES];
	uint8_t sig[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES];
	crypton_decaf_448_point_t pt;
	const uint8_t *p = data;
	size_t left = size;
	uint8_t selector;

	if (!fz_take(&p, &left, &selector, 1))
		return 0;

	if (selector & 1) {
		if (!fz_take(&p, &left, ser, sizeof ser))
			return 0;
		(void)crypton_decaf_448_point_decode(pt, ser, selector & 2 ? 1 : 0);
		return 0;
	}

	if (!fz_take(&p, &left, pub, sizeof pub))
		return 0;
	if (selector & 2) {
		(void)crypton_decaf_448_point_decode_like_eddsa_and_mul_by_ratio(pt, pub);
		return 0;
	}
	if (!fz_take(&p, &left, sig, sizeof sig))
		return 0;
	/* a context of at most 255 bytes, as the API takes a uint8_t length */
	(void)crypton_decaf_ed448_verify(sig, pub, p, left, selector & 4 ? 1 : 0,
	                                 NULL, 0);
	return 0;
}
