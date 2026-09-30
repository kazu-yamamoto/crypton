/* AES-GCM decryption, where the lengths and the tag are the sender's to
 * choose.  The key is not attacker-controlled and is fixed here; what varies
 * is everything that arrives with the message. */
#include "tests/fuzz/fuzz.h"
#include <stdlib.h>
#include "crypton_aes.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint8_t key[16] = {
		0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15,
		0xf3, 0x9c, 0xc0, 0x60, 0x5c, 0xed, 0xc8, 0x34,
	};
	aes_key k;
	aes_gcm_key gk;
	uint8_t ivlen, aadlen, taglen;
	const uint8_t *p = data;
	size_t left = size;
	uint8_t *out;

	if (!fz_take(&p, &left, &ivlen, 1))
		return 0;
	if (!fz_take(&p, &left, &aadlen, 1))
		return 0;
	if (!fz_take(&p, &left, &taglen, 1))
		return 0;

	/* the three lengths are the sender's, so they are taken as they come,
	 * short of asking for more bytes than arrived */
	if (left < (size_t)ivlen + aadlen)
		return 0;
	taglen = (uint8_t)(taglen % 17);      /* 0..16, as the API allows */

	{
		const uint8_t *iv = p;
		const uint8_t *aad = p + ivlen;
		const uint8_t *ct = p + ivlen + aadlen;
		size_t rest = left - ivlen - aadlen;
		const uint8_t *tag;
		size_t ctlen;

		/* the tag arrives with the message, so it comes off the end */
		if (rest < taglen)
			return 0;
		ctlen = rest - taglen;
		tag = ct + ctlen;

		out = (uint8_t *)malloc(ctlen + 1);
		if (!out)
			return 0;
		crypton_aes_initkey(&k, (uint8_t *)key, sizeof key);
		crypton_aes_gcm_key_init(&gk, &k);
		(void)crypton_aes_gcm_full_decrypt(out, &gk, &k, (uint8_t *)iv, ivlen,
		                                   (uint8_t *)aad, aadlen,
		                                   (uint8_t *)ct, (uint32_t)ctlen,
		                                   tag, taglen);
		free(out);
	}
	return 0;
}
