/*
 * AES using the ARMv8-A Cryptographic Extensions.
 *
 * The generic code in aes/generic.c is S-box table driven, which on AArch64
 * was the only thing available: crypton_aes.c only ever swapped in the AES-NI
 * implementation, and that is gated on x86.  This provides the AArch64
 * equivalent.
 *
 * The key schedule is laid out exactly as x86ni.c lays it out, because
 * crypton_aes.c leaves some operations -- XTS decryption, OCB, CCM, AES-192 --
 * pointing at the generic implementation even once the accelerated table is
 * installed, and those read the forward schedule.  So: the forward round keys
 * k[0..nbr] first, exactly as crypton_aes_generic_init writes them, then
 * InvMixColumns(k[nbr-1]) down to InvMixColumns(k[1]) for decryption.  The two
 * ends of the decryption schedule, k[nbr] and k[0], are read back out of the
 * forward half rather than stored twice, which is what makes AES-256 fit in
 * the 16*14*2 bytes of aes_key.data.
 */

#include <stdint.h>
#include <string.h>
#include <arm_neon.h>
#if defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif
#include "crypton_aes.h"
#include "aes/generic.h"

/* forward round keys: nbr + 1 of them, written by the generic key expansion */
#define FWD(key)  ((const uint8_t *) (key)->data)
/* InvMixColumns(k[nbr-1]) .. InvMixColumns(k[1]): nbr - 1 of them */
#define INV(key)  (((const uint8_t *) (key)->data) + 16 * ((key)->nbr + 1))

void crypton_aes_armv8_init(aes_key *key, uint8_t *origkey, uint8_t size)
{
	int i;
	uint8_t *inv;

	crypton_aes_generic_init(key, origkey, size);

	/* the generic expansion leaves key->nbr set for this size */
	inv = ((uint8_t *) key->data) + 16 * (key->nbr + 1);
	for (i = 1; i < key->nbr; i++) {
		uint8x16_t rk = vld1q_u8(((const uint8_t *) key->data) + 16 * (key->nbr - i));
		vst1q_u8(inv + 16 * (i - 1), vaesimcq_u8(rk));
	}
}

static inline uint8x16_t aes_encrypt_block_armv8(uint8x16_t s, const aes_key *key)
{
	const uint8_t *rk = FWD(key);
	int i;

	for (i = 0; i < key->nbr - 1; i++)
		s = vaesmcq_u8(vaeseq_u8(s, vld1q_u8(rk + 16 * i)));
	s = vaeseq_u8(s, vld1q_u8(rk + 16 * (key->nbr - 1)));
	return veorq_u8(s, vld1q_u8(rk + 16 * key->nbr));
}

static inline uint8x16_t aes_decrypt_block_armv8(uint8x16_t s, const aes_key *key)
{
	const uint8_t *fwd = FWD(key);
	const uint8_t *inv = INV(key);
	int i;

	/* the decryption schedule is k[nbr], imc(k[nbr-1]) .. imc(k[1]), k[0];
	 * the two ends come from the forward half, the middle from inv[] */
	s = vaesimcq_u8(vaesdq_u8(s, vld1q_u8(fwd + 16 * key->nbr)));
	for (i = 0; i < key->nbr - 2; i++)
		s = vaesimcq_u8(vaesdq_u8(s, vld1q_u8(inv + 16 * i)));
	s = vaesdq_u8(s, vld1q_u8(inv + 16 * (key->nbr - 2)));
	return veorq_u8(s, vld1q_u8(fwd));
}

void crypton_aes_armv8_encrypt_block(aes_block *output, aes_key *key, aes_block *input)
{
	vst1q_u8((uint8_t *) output,
	         aes_encrypt_block_armv8(vld1q_u8((const uint8_t *) input), key));
}

void crypton_aes_armv8_decrypt_block(aes_block *output, aes_key *key, aes_block *input)
{
	vst1q_u8((uint8_t *) output,
	         aes_decrypt_block_armv8(vld1q_u8((const uint8_t *) input), key));
}

void crypton_aes_armv8_encrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	for (; nb_blocks-- > 0; input++, output++)
		crypton_aes_armv8_encrypt_block(output, key, input);
}

void crypton_aes_armv8_decrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	for (; nb_blocks-- > 0; input++, output++)
		crypton_aes_armv8_decrypt_block(output, key, input);
}

void crypton_aes_armv8_encrypt_cbc(aes_block *output, aes_key *key, aes_block *_iv, aes_block *input, uint32_t nb_blocks)
{
	uint8x16_t iv = vld1q_u8((const uint8_t *) _iv);

	for (; nb_blocks-- > 0; input++, output++) {
		iv = aes_encrypt_block_armv8(veorq_u8(iv, vld1q_u8((const uint8_t *) input)), key);
		vst1q_u8((uint8_t *) output, iv);
	}
}

void crypton_aes_armv8_decrypt_cbc(aes_block *output, aes_key *key, aes_block *_iv, aes_block *input, uint32_t nb_blocks)
{
	uint8x16_t iv = vld1q_u8((const uint8_t *) _iv);

	for (; nb_blocks-- > 0; input++, output++) {
		uint8x16_t in = vld1q_u8((const uint8_t *) input);
		vst1q_u8((uint8_t *) output, veorq_u8(aes_decrypt_block_armv8(in, key), iv));
		iv = in;
	}
}

/*
 * Whether the extensions are actually present.
 *
 * They are mandatory on Apple silicon, and on other AArch64 systems the
 * kernel reports them through the auxiliary vector.  A system without them
 * keeps the generic implementation.
 */
int crypton_aes_armv8_available(void)
{
#if defined(__APPLE__)
	return 1;
#elif defined(__linux__)
	return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#else
	return 0;
#endif
}
