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
#include "crypton_bitfn.h"

/*
 * The AES and PMULL instructions are extensions, so a translation unit
 * compiled for baseline ARMv8-A may not use them.  Mark the functions that do,
 * the way cbits/aes/x86ni.h marks their x86 counterparts, rather than raising
 * -march for every file in the library: the flag use_target_attributes picks
 * between the two, and with it set -- which is the default -- nothing else
 * enables the extensions, so without these the file does not compile at all on
 * a toolchain whose baseline lacks them.  Apple's does not lack them, which is
 * why only Linux noticed.
 *
 * "+crypto" rather than "crypto": GCC rejects the latter.
 */
#ifdef WITH_TARGET_ATTRIBUTES
#define TARGET_ARMV8_CRYPTO __attribute__((target("+crypto")))
#else
#define TARGET_ARMV8_CRYPTO
#endif

/* forward round keys: nbr + 1 of them, written by the generic key expansion */
#define FWD(key)  ((const uint8_t *) (key)->data)
/* InvMixColumns(k[nbr-1]) .. InvMixColumns(k[1]): nbr - 1 of them */
#define INV(key)  (((const uint8_t *) (key)->data) + 16 * ((key)->nbr + 1))

TARGET_ARMV8_CRYPTO
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

TARGET_ARMV8_CRYPTO
static inline uint8x16_t aes_encrypt_block_armv8(uint8x16_t s, const aes_key *key)
{
	const uint8_t *rk = FWD(key);
	int i;

	for (i = 0; i < key->nbr - 1; i++)
		s = vaesmcq_u8(vaeseq_u8(s, vld1q_u8(rk + 16 * i)));
	s = vaeseq_u8(s, vld1q_u8(rk + 16 * (key->nbr - 1)));
	return veorq_u8(s, vld1q_u8(rk + 16 * key->nbr));
}

TARGET_ARMV8_CRYPTO
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

TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_encrypt_block(aes_block *output, aes_key *key, aes_block *input)
{
	vst1q_u8((uint8_t *) output,
	         aes_encrypt_block_armv8(vld1q_u8((const uint8_t *) input), key));
}

TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_decrypt_block(aes_block *output, aes_key *key, aes_block *input)
{
	vst1q_u8((uint8_t *) output,
	         aes_decrypt_block_armv8(vld1q_u8((const uint8_t *) input), key));
}

TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_encrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	for (; nb_blocks-- > 0; input++, output++)
		crypton_aes_armv8_encrypt_block(output, key, input);
}

TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_decrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	for (; nb_blocks-- > 0; input++, output++)
		crypton_aes_armv8_decrypt_block(output, key, input);
}

TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_encrypt_cbc(aes_block *output, aes_key *key, aes_block *_iv, aes_block *input, uint32_t nb_blocks)
{
	uint8x16_t iv = vld1q_u8((const uint8_t *) _iv);

	for (; nb_blocks-- > 0; input++, output++) {
		iv = aes_encrypt_block_armv8(veorq_u8(iv, vld1q_u8((const uint8_t *) input)), key);
		vst1q_u8((uint8_t *) output, iv);
	}
}

TARGET_ARMV8_CRYPTO
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

/*
 * GHASH using PMULL, the AArch64 counterpart to PCLMULQDQ.
 *
 * This is a transliteration of gfmul_pclmuldq in x86ni.c rather than a fresh
 * formulation: that code is already pinned by the GCM known-answer tests, and
 * every operation it uses has a direct NEON equivalent, so translating it is
 * easier to check than reasoning about a new reduction from scratch.
 *
 *   _mm_shuffle_epi8 with a reversing mask  ->  vrev64q_u8 then vextq_u8
 *   _mm_clmulepi64_si128                    ->  vmull_p64 / vmull_high_p64
 *   _mm_slli_si128 / _mm_srli_si128         ->  vextq_u8 against zero
 *   _mm_slli_epi32 / _mm_srli_epi32         ->  vshlq_n_u32 / vshrq_n_u32
 */

/* reverse all 16 bytes */
TARGET_ARMV8_CRYPTO
static inline uint8x16_t bswap128(uint8x16_t v)
{
	return vextq_u8(vrev64q_u8(v), vrev64q_u8(v), 8);
}

/* shift the whole register left by n bytes, as _mm_slli_si128 does */
#define SHIFT_LEFT_BYTES(v, n)  vextq_u8(vdupq_n_u8(0), (v), 16 - (n))
/* and right, as _mm_srli_si128 does */
#define SHIFT_RIGHT_BYTES(v, n) vextq_u8((v), vdupq_n_u8(0), (n))

#define SHL32(v, n) vreinterpretq_u8_u32(vshlq_n_u32(vreinterpretq_u32_u8(v), (n)))
#define SHR32(v, n) vreinterpretq_u8_u32(vshrq_n_u32(vreinterpretq_u32_u8(v), (n)))

TARGET_ARMV8_CRYPTO
static inline uint8x16_t clmul_ll(uint8x16_t a, uint8x16_t b)
{
	return vreinterpretq_u8_p128(vmull_p64(
	    (poly64_t) vgetq_lane_u64(vreinterpretq_u64_u8(a), 0),
	    (poly64_t) vgetq_lane_u64(vreinterpretq_u64_u8(b), 0)));
}

TARGET_ARMV8_CRYPTO
static inline uint8x16_t clmul_lh(uint8x16_t a, uint8x16_t b)
{
	return vreinterpretq_u8_p128(vmull_p64(
	    (poly64_t) vgetq_lane_u64(vreinterpretq_u64_u8(a), 0),
	    (poly64_t) vgetq_lane_u64(vreinterpretq_u64_u8(b), 1)));
}

TARGET_ARMV8_CRYPTO
static inline uint8x16_t clmul_hl(uint8x16_t a, uint8x16_t b)
{
	return vreinterpretq_u8_p128(vmull_p64(
	    (poly64_t) vgetq_lane_u64(vreinterpretq_u64_u8(a), 1),
	    (poly64_t) vgetq_lane_u64(vreinterpretq_u64_u8(b), 0)));
}

TARGET_ARMV8_CRYPTO
static inline uint8x16_t clmul_hh(uint8x16_t a, uint8x16_t b)
{
	return vreinterpretq_u8_p128(vmull_high_p64(
	    vreinterpretq_p64_u8(a), vreinterpretq_p64_u8(b)));
}

/*
 * The 256-bit carry-less product of a (normal byte order) and b (already
 * reversed, as it sits in the table), before the reflection fixup and the
 * reduction.  Split out from the reduction because both of those are linear
 * over XOR: several products can be added together and fixed up just once,
 * which is what gf_mul4 below does.
 */
TARGET_ARMV8_CRYPTO
static inline void clmul_pmull(uint8x16_t a, uint8x16_t b,
                               uint8x16_t *lo, uint8x16_t *hi)
{
	uint8x16_t t3, t4, t5, t6;

	a = bswap128(a);

	t3 = clmul_ll(a, b);
	t4 = clmul_lh(a, b);
	t5 = clmul_hl(a, b);
	t6 = clmul_hh(a, b);

	t4 = veorq_u8(t4, t5);
	t5 = SHIFT_LEFT_BYTES(t4, 8);
	t4 = SHIFT_RIGHT_BYTES(t4, 8);

	*lo = veorq_u8(t3, t5);
	*hi = veorq_u8(t6, t4);
}

/* Shift the 256-bit product left by one to undo GCM's bit reflection, then
 * reduce modulo the GCM polynomial.  This is the expensive half. */
TARGET_ARMV8_CRYPTO
static inline uint8x16_t gfred_pmull(uint8x16_t t3, uint8x16_t t6)
{
	uint8x16_t t2, t4, t5, t7, t8, t9;

	t7 = SHR32(t3, 31);
	t8 = SHR32(t6, 31);
	t3 = SHL32(t3, 1);
	t6 = SHL32(t6, 1);

	t9 = SHIFT_RIGHT_BYTES(t7, 12);
	t8 = SHIFT_LEFT_BYTES(t8, 4);
	t7 = SHIFT_LEFT_BYTES(t7, 4);
	t3 = vorrq_u8(t3, t7);
	t6 = vorrq_u8(t6, t8);
	t6 = vorrq_u8(t6, t9);

	t7 = SHL32(t3, 31);
	t8 = SHL32(t3, 30);
	t9 = SHL32(t3, 25);

	t7 = veorq_u8(t7, t8);
	t7 = veorq_u8(t7, t9);
	t8 = SHIFT_RIGHT_BYTES(t7, 4);
	t7 = SHIFT_LEFT_BYTES(t7, 12);
	t3 = veorq_u8(t3, t7);

	t2 = SHR32(t3, 1);
	t4 = SHR32(t3, 2);
	t5 = SHR32(t3, 7);
	t2 = veorq_u8(t2, t4);
	t2 = veorq_u8(t2, t5);
	t2 = veorq_u8(t2, t8);
	t3 = veorq_u8(t3, t2);
	t6 = veorq_u8(t6, t3);

	return bswap128(t6);
}

TARGET_ARMV8_CRYPTO
static uint8x16_t gfmul_pmull(uint8x16_t a, const uint8_t *htable)
{
	uint8x16_t lo, hi;

	clmul_pmull(a, vld1q_u8(htable), &lo, &hi);
	return gfred_pmull(lo, hi);
}

/*
 * With PMULL there is no 4-bit table to fill: H goes in at index 0, byte
 * reversed, so that gfmul_pmull does not have to swap it every time.  This
 * mirrors crypton_aesni_hinit_pclmul.
 *
 * Indices 1..3 get H^2, H^3 and H^4, which is what lets gf_mul4 fold four
 * blocks into one reduction.  The table has sixteen slots, so they are free.
 */
TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_hinit_pmull(block128 *htable, const block128 *h)
{
	uint8x16_t p;
	int i;

	htable[0].q[0] = bitfn_swap64(h->q[1]);
	htable[0].q[1] = bitfn_swap64(h->q[0]);

	p = vld1q_u8((const uint8_t *) h);
	for (i = 1; i < 4; i++) {
		p = gfmul_pmull(p, (const uint8_t *) &htable[0]);
		vst1q_u8((uint8_t *) &htable[i], bswap128(p));
	}
}

TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_gf_mul_pmull(block128 *a, const block128 *htable)
{
	vst1q_u8((uint8_t *) a,
	         gfmul_pmull(vld1q_u8((const uint8_t *) a), (const uint8_t *) htable));
}

/*
 * Four GHASH steps -- ((((a^b0)H ^ b1)H ^ b2)H ^ b3)H -- with a single
 * reduction.  Expanded that is (a^b0)H^4 ^ b1*H^3 ^ b2*H^2 ^ b3*H, so the
 * four products can be summed first and reduced once, which is where the
 * time goes.  Aggregated reduction, from the Intel GCM paper.
 */
TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_gf_mul4_pmull(block128 *a, const block128 *blocks,
                                     const block128 *htable)
{
	uint8x16_t lo, hi, l, h;
	int i;

	clmul_pmull(veorq_u8(vld1q_u8((const uint8_t *) a),
	                     vld1q_u8((const uint8_t *) &blocks[0])),
	            vld1q_u8((const uint8_t *) &htable[3]), &lo, &hi);

	for (i = 1; i < 4; i++) {
		clmul_pmull(vld1q_u8((const uint8_t *) &blocks[i]),
		            vld1q_u8((const uint8_t *) &htable[3 - i]), &l, &h);
		lo = veorq_u8(lo, l);
		hi = veorq_u8(hi, h);
	}

	vst1q_u8((uint8_t *) a, gfred_pmull(lo, hi));
}

int crypton_aes_armv8_pmull_available(void)
{
#if defined(__APPLE__)
	return 1;
#elif defined(__linux__)
	return (getauxval(AT_HWCAP) & HWCAP_PMULL) != 0;
#else
	return 0;
#endif
}
