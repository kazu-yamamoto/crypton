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
#include "crypton_aes.h"
#include "crypton_bitfn.h"
#include "crypton_cpu.h"

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
#include "crypton_armv8_target.h"

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
CRYPTON_TARGET_ARMV8_CRYPTO
static uint32x4_t sub_word(uint32x4_t w)
{
	return vreinterpretq_u32_u8(
	    vaeseq_u8(vreinterpretq_u8_u32(w), vdupq_n_u8(0)));
}

CRYPTON_TARGET_ARMV8_CRYPTO
static uint32x4_t sub_rot_word(uint32x4_t w)
{
	const uint8x16_t s = vreinterpretq_u8_u32(sub_word(w));

	return vreinterpretq_u32_u8(vextq_u8(s, s, 1));
}

CRYPTON_TARGET_ARMV8_CRYPTO
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
 * Whether the extensions are actually present.  crypton_cpu.c asks the
 * system once, in the one place that knows how each system answers; a
 * processor without them keeps the generic implementation.
 */
int crypton_aes_armv8_available(void)
{
	return (crypton_arm_features() & CRYPTON_ARM_AES) != 0;
}

/*
 * GHASH using PMULL, the AArch64 counterpart to PCLMULQDQ.
 *
 * Not the transliteration of gfmul_pclmuldq in x86ni.c this used to be.  The
 * x86 formulation keeps H in the order GCM writes it and pays, at the end of
 * every batch, a reduction that first has to undo GCM's bit reflection: some
 * twenty-five shifts and XORs, and a batch of eight costs it once.
 *
 * Instead H is twisted once, at key setup, so that the reflection is already
 * undone and a reversed-polynomial multiply lands in the right place.  Two
 * things follow.  The reduction becomes two PMULL against 0xC2000..0 and six
 * EOR, a third of what it was.  And because nothing has to be byte-reversed
 * back and forth, Karatsuba pays: three PMULL a block rather than four, with
 * the middle terms accumulated in a third register and tidied up once per
 * batch.
 *
 * crypton tried Karatsuba in the old representation and measured it 1.6 per
 * cent slower -- the saved PMULL did not cover the extra EOR when the
 * reduction stayed as expensive as it was.  It is the pair that pays.
 * Measured over 16 KiB messages, this against the old code:
 *
 *                      Apple M4        Neoverse N2
 *     AES-128-GCM        1.30             1.25
 *     AES-192-GCM        1.22             1.25
 *     AES-256-GCM        1.19             1.24
 *
 * The scheme is ARM's, from the 'big' AES-GCM kernel of
 * https://github.com/ARM-software/AArch64cryptolib, which is BSD-3-Clause,
 * (c) 2018-2019 ARM Limited.  Their kernels under AArch64cryptolib_opt_bigger
 * are faster again and are NOT under that licence, whatever the repository's
 * LICENSE.md says; nothing here comes from those files.
 *
 * The table holds the twisted powers H^1 .. H^8 at htable[0 .. 7] and the
 * Karatsuba half of each -- its high 64 bits XOR its low -- in the first
 * eight bytes of htable[8 .. 15].  The running tag is kept the way GCM
 * writes it at every boundary, and swapped into the internal form on the way
 * in and out, which is two instructions.
 */

#define GHASH_MODC ((poly64_t) 0xC200000000000000ul)

/* the internal accumulator form, and back again: its own inverse */
CRYPTON_TARGET_ARMV8_CRYPTO
static inline uint8x16_t ghash_swap(uint8x16_t t)
{
	t = vrev64q_u8(t);
	return vextq_u8(t, t, 8);
}

/* the high and low halves XORed together, which is what Karatsuba wants */
CRYPTON_TARGET_ARMV8_CRYPTO
static inline poly64_t ghash_karat(poly64x2_t v)
{
	return (poly64_t) veor_u64(vget_high_u64(vreinterpretq_u64_p64(v)),
	                           vget_low_u64(vreinterpretq_u64_p64(v)));
}

/* the twisted power H^(i+1) */
#define GHASH_POW(ht, i)                                                      \
	vreinterpretq_p64_u8(vld1q_u8((const uint8_t *) &(ht)[i]))
/* and its Karatsuba half */
#define GHASH_KARAT(ht, i)                                                    \
	((poly64_t) vgetq_lane_u64(                                           \
	    vreinterpretq_u64_u8(vld1q_u8((const uint8_t *) &(ht)[8 + (i)])), 0))

/*
 * One block's three partial products, XORed into the accumulators.  b is
 * already in the internal form; hp and hk are the power it is to meet.
 */
#define GHASH_MUL(b, hp, hk, H, M, L)                                         \
	do {                                                                  \
		poly64x2_t b__ = (b);                                         \
		poly64x2_t hp__ = (hp);                                       \
		(H) = veorq_u64((H), vreinterpretq_u64_p128(                  \
		    vmull_high_p64(b__, hp__)));                              \
		(L) = veorq_u64((L), vreinterpretq_u64_p128(vmull_p64(        \
		    (poly64_t) vgetq_lane_u64(vreinterpretq_u64_p64(b__), 0), \
		    (poly64_t) vgetq_lane_u64(vreinterpretq_u64_p64(hp__), 0)))); \
		(M) = veorq_u64((M), vreinterpretq_u64_p128(                  \
		    vmull_p64(ghash_karat(b__), (hk))));                      \
	} while (0)

/*
 * Finish the Karatsuba -- the middle accumulator still holds only the
 * (ah^al)(bh^bl) terms and wants the other two taken out of it -- and reduce
 * the 256 bits modulo the GCM polynomial.  The result is in internal form.
 */
CRYPTON_TARGET_ARMV8_CRYPTO
static inline uint64x2_t ghash_reduce(uint64x2_t H, uint64x2_t M, uint64x2_t L)
{
	uint64x2_t t;

	M = veorq_u64(M, H);
	M = veorq_u64(M, L);

	t = vreinterpretq_u64_p128(vmull_p64(
	    (poly64_t) vgetq_lane_u64(H, 0), GHASH_MODC));
	H = vreinterpretq_u64_u8(vextq_u8(vreinterpretq_u8_u64(H),
	                                  vreinterpretq_u8_u64(H), 8));
	M = veorq_u64(M, t);
	M = veorq_u64(M, H);

	t = vreinterpretq_u64_p128(vmull_p64(
	    (poly64_t) vgetq_lane_u64(M, 0), GHASH_MODC));
	M = vreinterpretq_u64_u8(vextq_u8(vreinterpretq_u8_u64(M),
	                                  vreinterpretq_u8_u64(M), 8));
	L = veorq_u64(L, t);
	return veorq_u64(L, M);
}

/* a single block against H^1, accumulator in internal form */
CRYPTON_TARGET_ARMV8_CRYPTO
static inline uint64x2_t ghash_one(uint64x2_t acc, uint8x16_t blk,
                                   const block128 *ht)
{
	uint64x2_t H = vdupq_n_u64(0), M = H, L = H;
	poly64x2_t b;

	acc = vreinterpretq_u64_u8(vextq_u8(vreinterpretq_u8_u64(acc),
	                                    vreinterpretq_u8_u64(acc), 8));
	b = vreinterpretq_p64_u64(veorq_u64(
	    vreinterpretq_u64_u8(vrev64q_u8(blk)), acc));
	GHASH_MUL(b, GHASH_POW(ht, 0), GHASH_KARAT(ht, 0), H, M, L);
	return ghash_reduce(H, M, L);
}

/*
 * Twist H and raise it to the powers a batch needs.
 *
 * The twist is a shift left by one with 0xC2000..01 folded back in when a
 * bit falls off the top -- the same correction the old reduction applied to
 * every product, done once here instead.  Each further power is one multiply
 * in the twisted domain; the result comes out of ghash_reduce with its
 * halves swapped, which a batch undoes on the way in, so a stored power has
 * to be swapped back.
 */
CRYPTON_TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_hinit_pmull(block128 *htable, const block128 *h)
{
	uint8x16_t hk = vrev64q_u8(vld1q_u8((const uint8_t *) h));
	uint64x2_t shl = vshlq_n_u64(vreinterpretq_u64_u8(hk), 1);
	uint64x2_t shr = vreinterpretq_u64_s64(
	    vshrq_n_s64(vreinterpretq_s64_u8(hk), 63));
	uint8x16_t mask = vextq_u8(vreinterpretq_u8_u64(shr),
	                           vreinterpretq_u8_u64(shr), 12);
	uint64x2_t tc = vdupq_n_u64(0);
	poly64x2_t base, p;
	int i;

	tc = vsetq_lane_u64(0xC200000000000001ul, tc, 0);
	tc = vsetq_lane_u64(1, tc, 1);
	tc = vandq_u64(vreinterpretq_u64_u8(mask), tc);
	base = vreinterpretq_p64_u64(veorq_u64(tc, shl));

	p = base;
	for (i = 0; i < 8; i++) {
		uint64x2_t H = vdupq_n_u64(0), M = H, L = H, r;

		vst1q_u8((uint8_t *) &htable[i],
		         vreinterpretq_u8_p64(p));
		vst1q_u8((uint8_t *) &htable[8 + i],
		         vreinterpretq_u8_u64(
		             vdupq_n_u64((uint64_t) ghash_karat(p))));

		GHASH_MUL(p, base, ghash_karat(base), H, M, L);
		r = ghash_reduce(H, M, L);
		p = vreinterpretq_p64_u8(vextq_u8(vreinterpretq_u8_u64(r),
		                                  vreinterpretq_u8_u64(r), 8));
	}
}

CRYPTON_TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_gf_mul_pmull(block128 *a, const block128 *htable)
{
	uint64x2_t acc = vreinterpretq_u64_u8(
	    ghash_swap(vld1q_u8((const uint8_t *) a)));

	acc = ghash_one(acc, vdupq_n_u8(0), htable);
	vst1q_u8((uint8_t *) a, ghash_swap(vreinterpretq_u8_u64(acc)));
}

/*
 * Four GHASH steps -- ((((a^b0)H ^ b1)H ^ b2)H ^ b3)H -- with a single
 * reduction.  Expanded that is (a^b0)H^4 ^ b1*H^3 ^ b2*H^2 ^ b3*H, so the
 * four products can be summed first and reduced once, which is where the
 * time goes.  Aggregated reduction, from the Intel GCM paper.
 */
CRYPTON_TARGET_ARMV8_CRYPTO
void crypton_aes_armv8_gf_mul4_pmull(block128 *a, const block128 *blocks,
                                     const block128 *htable)
{
	uint64x2_t acc = vreinterpretq_u64_u8(
	    ghash_swap(vld1q_u8((const uint8_t *) a)));
	uint64x2_t H = vdupq_n_u64(0), M = H, L = H;
	poly64x2_t b;
	int i;

	acc = vreinterpretq_u64_u8(vextq_u8(vreinterpretq_u8_u64(acc),
	                                    vreinterpretq_u8_u64(acc), 8));
	b = vreinterpretq_p64_u64(veorq_u64(
	    vreinterpretq_u64_u8(vrev64q_u8(
	        vld1q_u8((const uint8_t *) &blocks[0]))), acc));
	GHASH_MUL(b, GHASH_POW(htable, 3), GHASH_KARAT(htable, 3), H, M, L);

	for (i = 1; i < 4; i++) {
		b = vreinterpretq_p64_u8(vrev64q_u8(
		    vld1q_u8((const uint8_t *) &blocks[i])));
		GHASH_MUL(b, GHASH_POW(htable, 3 - i),
		          GHASH_KARAT(htable, 3 - i), H, M, L);
	}

	acc = ghash_reduce(H, M, L);
	vst1q_u8((uint8_t *) a, ghash_swap(vreinterpretq_u8_u64(acc)));
}


int crypton_aes_armv8_pmull_available(void)
{
	return (crypton_arm_features() & CRYPTON_ARM_PMULL) != 0;
}

/*
 * The XTS tweak advances by doubling in GF(2^128), which
 * crypton_aes_generic_gf_mulx does through memory.  Here it stays in a
 * register: shift both halves left by one, carry the low half's top bit into
 * the high half, and fold the bit that leaves the top back in as 0x87.  The
 * block is little-endian, so lane 0 is the low half.
 */
CRYPTON_TARGET_ARMV8_CRYPTO
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
CRYPTON_TARGET_ARMV8_CRYPTO
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

CRYPTON_TARGET_ARMV8_CRYPTO
int crypton_aes_armv8_gcm_fused_dec(uint8_t *out, const block128 *ht,
                                    aes_key *key, const uint8_t *nonce,
                                    const uint8_t *aad, uint32_t aadlen,
                                    const uint8_t *in, uint32_t inlen,
                                    const uint8_t *tag, uint32_t taglen,
                                    uint8_t *outtag)
{
	switch (key->strength) {
	case 0:
		return crypton_aes_armv8_gcm_fused_dec128(out, ht, key, nonce,
		                                          aad, aadlen, in, inlen,
		                                          tag, taglen, outtag);
	case 1:
		return crypton_aes_armv8_gcm_fused_dec192(out, ht, key, nonce,
		                                          aad, aadlen, in, inlen,
		                                          tag, taglen, outtag);
	default:
		return crypton_aes_armv8_gcm_fused_dec256(out, ht, key, nonce,
		                                          aad, aadlen, in, inlen,
		                                          tag, taglen, outtag);
	}
}
