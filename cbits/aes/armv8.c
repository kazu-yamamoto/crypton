/*
 * AES using the ARMv8-A Cryptographic Extensions.
 *
 * The generic code in aes/generic.c is S-box table driven, which on AArch64
 * was the only thing available: crypton_aes.c only ever swapped in the AES-NI
 * implementation, and that is gated on x86.  This provides the AArch64
 * equivalent.
 *
 * The key schedule is laid out exactly as x86ni.c lays it out, because
 * crypton_aes.c leaves some operations -- OCB and CCM -- pointing at the
 * generic implementation even once the accelerated table is installed, and
 * those read the forward schedule.  So: the forward round keys k[0..nbr]
 * first, in the order crypton_aes_generic_init writes them, then
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

/*
 * The key schedule of FIPS 197 5.2, with the S-box the schedule needs coming
 * from the instructions rather than a table in memory.
 *
 * AArch64 has no counterpart to x86's AESKEYGENASSIST, but AESE is
 * AddRoundKey, SubBytes and ShiftRows together, so against a zero key it is
 * SubBytes and ShiftRows.  Give it a word in all four columns and ShiftRows
 * only moves identical bytes between them, which leaves every column holding
 * SubWord of that word.  RotWord is then a byte rotation, and on a register
 * whose four words are equal a rotation of the whole register by one byte
 * rotates each word.
 *
 * The words stay in vector registers throughout: a word moved to a general
 * register and back costs more than the instruction it is moved for.
 *
 * The exposure this removes is a small one -- sixteen lookups at addresses
 * derived from the key, once per key, against the per-block indexing the
 * instructions exist to remove -- but a key schedule is the one thing an
 * attacker most wants and it costs little to keep it out of the cache.
 */
TARGET_ARMV8_CRYPTO
static uint32x4_t sub_word(uint32x4_t w)
{
	return vreinterpretq_u32_u8(
	    vaeseq_u8(vreinterpretq_u8_u32(w), vdupq_n_u8(0)));
}

TARGET_ARMV8_CRYPTO
static uint32x4_t sub_rot_word(uint32x4_t w)
{
	const uint8x16_t s = vreinterpretq_u8_u32(sub_word(w));

	return vreinterpretq_u32_u8(vextq_u8(s, s, 1));
}

TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_init(aes_key *key, uint8_t *origkey, uint8_t size)
{
	/* 2^0 .. 2^9 in GF(2^8), which is as far as any key size reaches */
	static const uint32_t rcon[10] = {
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
	};
	uint32_t *w = (uint32_t *) key->data;
	uint8_t *inv;
	int nk, nw, i;

	switch (size) {
	case 16: key->nbr = 10; break;
	case 24: key->nbr = 12; break;
	case 32: key->nbr = 14; break;
	default: return;
	}
	nk = size / 4;                  /* words of key */
	nw = 4 * (key->nbr + 1);        /* words of schedule */

	memcpy(w, origkey, size);
	for (i = nk; i < nw; i++) {
		uint32x4_t t = vld1q_dup_u32(w + i - 1);

		if (i % nk == 0)
			t = veorq_u32(sub_rot_word(t),
			              vdupq_n_u32(rcon[i / nk - 1]));
		else if (nk > 6 && i % nk == 4)
			t = sub_word(t);
		vst1q_lane_u32(w + i, veorq_u32(t, vld1q_dup_u32(w + i - nk)), 0);
	}

	/* and the inverted round keys the decryption modes read */
	inv = ((uint8_t *) key->data) + 16 * (key->nbr + 1);
	for (i = 1; i < key->nbr; i++) {
		uint8x16_t rk =
		    vld1q_u8(((const uint8_t *) key->data) + 16 * (key->nbr - i));
		vst1q_u8(inv + 16 * (i - 1), vaesimcq_u8(rk));
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
 * Indices 1..7 get H^2 .. H^8, which is what lets a group of blocks fold
 * into one reduction: gf_mul4 uses the first four, the GCM loop all eight.
 * The table has sixteen slots, so they are free.
 */
TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_hinit_pmull(block128 *htable, const block128 *h)
{
	uint8x16_t p;
	int i;

	htable[0].q[0] = bitfn_swap64(h->q[1]);
	htable[0].q[1] = bitfn_swap64(h->q[0]);

	p = vld1q_u8((const uint8_t *) h);
	for (i = 1; i < 8; i++) {
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

/*
 * The XTS tweak advances by doubling in GF(2^128), which
 * crypton_aes_generic_gf_mulx does through memory.  Here it stays in a
 * register: shift both halves left by one, carry the low half's top bit into
 * the high half, and fold the bit that leaves the top back in as 0x87.  The
 * block is little-endian, so lane 0 is the low half.
 */
TARGET_ARMV8_CRYPTO
static inline uint8x16_t gfmulx_neon(uint8x16_t v)
{
	const uint64x2_t x = vreinterpretq_u64_u8(v);
	const uint64x2_t zero = vdupq_n_u64(0);
	const uint64x2_t carry = vshrq_n_u64(x, 63);
	/* the low half's carry becomes the high half's bit 0 */
	const uint64x2_t into_hi = vextq_u64(zero, carry, 1);
	/* and the high half's becomes all ones, or nothing, in the low half */
	const uint64x2_t out = vsubq_u64(zero, vextq_u64(carry, zero, 1));
	const uint64x2_t poly = vsetq_lane_u64(0x87, zero, 0);

	return vreinterpretq_u8_u64(veorq_u64(
	    vorrq_u64(vshlq_n_u64(x, 1), into_hi), vandq_u64(out, poly)));
}

/*
 * The modes, generated once per key size.  See armv8_impl.c for why the
 * round count has to be a compile-time constant.
 */
#define SIZED(m) m##128
#define NBR 10
#include <aes/armv8_impl.c>
#undef SIZED
#undef NBR

#define SIZED(m) m##192
#define NBR 12
#include <aes/armv8_impl.c>
#undef SIZED
#undef NBR

#define SIZED(m) m##256
#define NBR 14
#include <aes/armv8_impl.c>
#undef SIZED
#undef NBR

/*
 * The fused entry point, over the three key sizes.  Each was generated with
 * its round count fixed, which is what lets the eight chains stay in
 * registers; the choice between them is made once per message here.
 */
TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_gcm_fused(uint8_t *out, const block128 *ht,
                                 aes_key *key, const uint8_t *nonce,
                                 const uint8_t *aad, uint32_t aadlen,
                                 const uint8_t *in, uint32_t inlen,
                                 uint32_t taglen, aes_key *hpkey,
                                 uint32_t sampleoff, uint8_t *mask)
{
	switch (key->strength) {
	case 0:
		crypton_aes_armv8_gcm_fused128(out, ht, key, nonce, aad, aadlen,
		                               in, inlen, taglen, hpkey,
		                               sampleoff, mask);
		break;
	case 1:
		crypton_aes_armv8_gcm_fused192(out, ht, key, nonce, aad, aadlen,
		                               in, inlen, taglen, hpkey,
		                               sampleoff, mask);
		break;
	default:
		crypton_aes_armv8_gcm_fused256(out, ht, key, nonce, aad, aadlen,
		                               in, inlen, taglen, hpkey,
		                               sampleoff, mask);
		break;
	}
}

TARGET_ARMV8_CRYPTO
int crypton_aes_armv8_gcm_fused_dec(uint8_t *out, const block128 *ht,
                                    aes_key *key, const uint8_t *nonce,
                                    const uint8_t *aad, uint32_t aadlen,
                                    const uint8_t *in, uint32_t inlen,
                                    const uint8_t *tag, uint32_t taglen)
{
	switch (key->strength) {
	case 0:
		return crypton_aes_armv8_gcm_fused_dec128(out, ht, key, nonce,
		                                          aad, aadlen, in, inlen,
		                                          tag, taglen);
	case 1:
		return crypton_aes_armv8_gcm_fused_dec192(out, ht, key, nonce,
		                                          aad, aadlen, in, inlen,
		                                          tag, taglen);
	default:
		return crypton_aes_armv8_gcm_fused_dec256(out, ht, key, nonce,
		                                          aad, aadlen, in, inlen,
		                                          tag, taglen);
	}
}
