/*
 * Copyright 2013 The Android Open Source Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Google Inc. nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Google Inc. ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL Google Inc. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// This is an implementation of the P256 finite field. It's written to be
// portable and still constant-time.
//
// WARNING: Implementing these functions in a constant-time manner is far from
//          obvious. Be careful when touching this code.
//
// See http://www.imperialviolet.org/2010/12/04/ecc.html ([1]) for background.

#include <stdint.h>
#include <stdio.h>

#include <string.h>
#include <stdlib.h>

#include "p256/p256.h"

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
typedef __uint128_t u128;

/* Our field elements are represented as five 64-bit limbs.
 *
 * The value of an felem (field element) is:
 *   x[0] + (x[1] * 2**51) + (x[2] * 2**103) + ... + (x[4] * 2**206)
 *
 * That is, each limb is alternately 51 or 52-bits wide in little-endian
 * order.
 *
 * This means that an felem hits 2**257, rather than 2**256 as we would like.
 *
 * Finally, the values stored in an felem are in Montgomery form. So the value
 * |y| is stored as (y*R) mod p, where p is the P-256 prime and R is 2**257.
 */
typedef u64 limb;
#define NLIMBS 5
typedef limb felem[NLIMBS];

/* On AArch64, the three functions that do the field arithmetic are asked to
 * be inlined rather than left for the compiler to decide.
 *
 * felem_mul and felem_square end in felem_reduce_degree, a carry chain the
 * whole width of the number, and that chain is what their latency is: one
 * product feeding the next costs 18.1 ns on an Apple M4, while four
 * independent ones cost 11.4 ns each.  The curve arithmetic has independent
 * products to offer -- the two squarings that open a point doubling, the
 * multiplication and the squaring that close it -- but only if the compiler
 * can see one reduction while the other is still going.  Left alone it emits
 * felem_reduce_degree once and calls it, and a call is a fence: the two
 * chains cannot overlap.  Plain `inline` does not change its mind.
 *
 * Asking costs code: this file's object goes from 30 to 116 kilobytes.  That
 * is worth it where there are registers to hold two chains at once and not
 * where there are not, which is the architecture talking rather than the
 * compiler.  Measured on a variable-point scalar multiplication:
 *
 *   Apple M4, Apple clang 21      1.23x
 *   Neoverse, clang 18            1.12x
 *   Neoverse, gcc 13              1.05x
 *   EPYC 7763, clang 18           0.95x
 *   Xeon 8370C, gcc 13            0.82x
 *
 * so x86-64 keeps the compiler's own judgement.
 */
#if defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
#define FELEM_INLINE static inline __attribute__((always_inline))
#else
#define FELEM_INLINE static
#endif

static const limb kBottom51Bits = 0x7ffffffffffff;
static const limb kBottom52Bits = 0xfffffffffffff;

/* kOne is the number 1 as an felem. It's 2**257 mod p split up into 51 and
 * 52-bit words. */
static const felem kOne = {
    2, 0xfc00000000000, 0x7ffffffffffff, 0xfff7fffffffff, 0x7ffff
};
static const felem kZero = {0};

/* the curve's b, in Montgomery form, for the complete addition formula */
static const felem kB = {
    0x1bec453897bbf, 0x33e210c243627, 0x484bb5ab3c017, 0x41a32d11055fb,
    0x2e18030ec243a
};
static const felem kP = {
    0x7ffffffffffff, 0x1fffffffffff, 0, 0x4000000000, 0x3fffffffc0000
};
static const felem k2P = {
    0x7fffffffffffe, 0x3fffffffffff, 0, 0x8000000000, 0x7fffffff80000
};
/* kPrecomputed holds the multiples of the base point G that the comb in
 * scalar_base_mult reads.  Two tables of sixteen affine points, one after the
 * other.
 *
 * The comb takes five bits of the signed all-bits-set representation at a
 * time, from positions 52 apart, and the two tables are offset from each
 * other by 26:
 *
 *   first table    i, 52+i, 104+i, 156+i, 208+i
 *   second table   26+i, 78+i, 130+i, 182+i, 234+i
 *
 * for i from 25 down to 0, which covers all 260 bits between them.
 *
 * Every digit of that representation is +-1, so a block of five teeth takes
 * one of thirty-two values -- and they come in pairs that differ only by
 * sign.  So sixteen entries are enough: the top tooth is taken positive, bit
 * j of the index says that tooth j agrees with it, and where the top tooth is
 * negative the caller negates y, which costs a subtraction.  Entry zero is a
 * point like any other here, unlike the unsigned table this replaces, where
 * it stood for the infinity.
 *
 *   Index  |  Index (binary) | Value
 *       0  |           0000  | 2**208G - 2**156G - 2**104G - 2**52G - G
 *       1  |           0001  | 2**208G - 2**156G - 2**104G - 2**52G + G
 *     ...  |            ...  | ...
 *      15  |           1111  | 2**208G + 2**156G + 2**104G + 2**52G + G
 *
 * This is ~2KB of data. */
static const limb kPrecomputed[NLIMBS * 2 * 16 * 2] = {
    0x17d166e01bd76, 0xd59ea12530768, 0x3d8c40217b04, 0x17bef9a4c9338, 0x7ecef3946ccf,
    0x1bb3639cdd45, 0xd7a338c14f5f7, 0x1d44d614250ff, 0xff813fc37580a, 0x16fc126e089f2,
    0x596ebe0b9487d, 0x6794652096fcb, 0x70ca729479eb8, 0x286b775769b0c, 0x365b421ada4b,
    0xfd4f7db081dc, 0x7a1064395526a, 0x4bdf0a89c2d26, 0xac80afd3f5e7a, 0x551466941e3f,
    0x27f44abf15dea, 0x641245c721691, 0x66eaa738302bb, 0x12c08cf44e3db, 0x207ff2c77aa29,
    0x42337261a56fa, 0x93f5442fee6dd, 0x253ccbdeda1ea, 0xbb019d239c3a2, 0x14f564e046543,
    0x19e66e694e7c9, 0x28bfdb62b9438, 0x5fd268170b101, 0x81f5d2fd7a276, 0x481bfa2871fd,
    0x71505f1b1c908, 0x2c741aac5e803, 0x55001687f5a40, 0xe8cb1db73f5b4, 0x236a913685d59,
    0x181c6361dc9, 0xd341d469ec73b, 0x5c0b21ff0159a, 0xa3e263a8ae02a, 0x96fbbe0e6601,
    0x32b9c888138de, 0x895b615971422, 0x3d9623d32b307, 0xd16a8f42e9505, 0x3a1944eacccd1,
    0x61e2d87f8d2bc, 0x1eae233791d5f, 0x67ad41964d0d6, 0x6f3066502d527, 0x13c23333b20b,
    0x50ca4072c4394, 0xc0d087a117391, 0x5d67a89ad2fd8, 0xf8d8c79d1424c, 0x176f356ba05e5,
    0x5a9d222a5d603, 0xd5f5321b86cc6, 0x175dc308523c9, 0x4e9bb0a11ab7, 0x35f0d7602ef2a,
    0x1bee93bab7afc, 0x464492b2d3a81, 0x420a2a9572fd7, 0x9429ec53edb83, 0x396a72e88da3f,
    0xef8a067576f7, 0xcf7c758f24aa7, 0x33553a986a5dd, 0x8df4138a812c6, 0x3b46808adb40f,
    0x39047b9c59f49, 0x728b5e8a37c51, 0x7fb7156d41405, 0x182753d7e3372, 0x3780d8cbc79d8,
    0x6af7074e318b9, 0xc50b946a6a49e, 0x6c2e6f494499b, 0xd457756bc8b2a, 0x20d580d1e02c7,
    0x672c9075eca28, 0x2e6cbcbf6f69b, 0xb159bacf3a63, 0xa9b448864e218, 0x3d31127e348da,
    0x7d4feaf9ba24, 0x3bd8791bb30ee, 0x7d13566f669f9, 0x750907ae43eb2, 0x19b501815f4a7,
    0x285bdb67c14af, 0xd529305a272b0, 0x4fa4682bb4328, 0xecbfa5072e13, 0x260ced527dbd6,
    0x22b864d17e2d6, 0x522de5c3bc90a, 0x7268e14f04f46, 0xb16b5f7c30243, 0x20d2897043203,
    0x57582ca37f0b0, 0xc9033b5213f35, 0x15c9edc5d8c3c, 0x966640653b9cc, 0x24539ebc1e770,
    0x152868860a414, 0x69f3140e5b3ae, 0x464ae0a979c81, 0xed2e180aa6ea7, 0x192f58eee8a5b,
    0x284e9f18cbb94, 0x9be7c8736ffa7, 0xd0645eef8dc8, 0xc888d568342b3, 0x1a0457c447c77,
    0x46a3242f1f708, 0xf0d377facff3b, 0x662ecd6e5da70, 0x84c75a436cd10, 0x2c3e2d2e766a7,
    0x6aefb0cd8bc3a, 0xf46b7ff2e5f40, 0x6f7e3bb188698, 0xc30b505db2b69, 0x2f287ab902ee,
    0x4a42f39462e0b, 0xf346d3c53c248, 0x583dd2f9bab2, 0x9ecf2836699a3, 0x1ebbc6ad3471e,
    0x31cf1b599efe9, 0xa3cbeb4ce45d9, 0x418c8a976e3f3, 0x581becef9befb, 0x12ea3bb24c576,
    0x59f406c45cd82, 0xd375b8996d246, 0x30544ebb0c867, 0x4f74220d0000f, 0x195588ab859cb,
    0x6720921607ca6, 0x6eba95153dc00, 0x439899e75b887, 0xf984c62adc7dd, 0x40d829fadb76,
    0x7baa04fd5f981, 0x5b1f99b6ef91, 0x29377748f7c41, 0xa96cc64bbffbc, 0x1a8ab2ec0e968,
    0x54daaf1e949bc, 0x81f61acb2893d, 0x4ed0f2aef056c, 0x41cd03269ce0e, 0x2a924333a9100,
    0x4bd600512324a, 0x5015bb978401a, 0x370dc4e4c9eb0, 0xb94920618b9ff, 0x386c9f301016b,
    0x151b802e73a15, 0xc2f01e076ffe7, 0x3f6c4272644fe, 0x4c65a96d2810e, 0x3abd30e3d0bdd,
    0x507b582802a4c, 0xdd3a9d6440284, 0xaa79901e9e59, 0x28f954b3df137, 0xdfda79ce1298,
    0x418aa5e56d569, 0x6cda605cd2a84, 0x38a3c8c72727e, 0x5c577b1659af2, 0x29ebd4cc67d3e,
    0x5fe67cbb69948, 0xcbb87ceb0460f, 0x2fb2c44c7e9b9, 0xd94fcdb26c47f, 0x185464b74c699,
    0x439cb4f543d28, 0xd46bc2b92ce79, 0x7add9a636f66a, 0xdf31c41270332, 0x2696553f66dbf,
    0x2783576782589, 0x968618b71297b, 0x44e45e45be560, 0x26efc23b82d1d, 0x1015ba1501f7c,
    0x488bd29858305, 0xf74fe2c48c2bf, 0x4e0542975a40a, 0x6c35069031288, 0x86495d91e4d6,
    0x4901896d5e61b, 0x73cc7582e2dff, 0x5720d009880e3, 0x1cf8b3eeb3330, 0x39d782d92776a,
    0x64cfb1b2b7536, 0x2c925510c2142, 0x15d3fdca3fa2f, 0x7c71f8ad652d2, 0x2c8639f12eb8e,
    0x32be1915c3b16, 0x401ba942b1327, 0x73a61e3dd1e67, 0x57855aa9e04e, 0x6692e349a453,
    0x1708b23f8a1a6, 0x994bfdde94868, 0x51ceeeda593ec, 0x4cdc508073c99, 0x155d6d8b5f390,
    0x3f62bd2bb7dc1, 0x1e9f2950a19ef, 0x3879b3fdeef4a, 0x769c9aebe06f6, 0x2fdbb0a2e42c2,
    0x4b669ca5182c8, 0x9f7d2af918087, 0x47a04688c10e0, 0x6fc09c1c63852, 0x103c53a1b2bb3,
    0x3f6293b845e4a, 0x7eddacd3d44ea, 0x3427d6919a9d0, 0xf18b5ac4b772, 0xc48971f25ff7,
    0x30b22ab28a9ee, 0x684778d576841, 0x219063e835137, 0xabfbe8b9b4cbe, 0xa5ee7bb20c8f,
    0x739e1c031098, 0x4f194a1f5e7e7, 0x7c3800ab2834d, 0x665b9b090387b, 0x3bfcc848c5569,
    0x4d7a0fa6ecdd0, 0x5a3be381deaf4, 0x60c235b9afa21, 0x2b6af4dca92ba, 0x3d4ef541da8da,
    0x15368f12c5e0, 0x1089d55881802, 0x4e950a255aa08, 0xea013ebd20bf4, 0x9bf696b8d0d0,
    0x74755b59e06a4, 0xca3ec0966d7d7, 0x23f8c820bf534, 0x7a9c3d0d130fb, 0x22243e7f72df8,
    0x177eb94dece80, 0x18e56144e85e5, 0x746051389a65, 0xaaa6ded4b788c, 0x2e7e3c710e646,
    0x10535c987ba48, 0xce1ab4a74c92c, 0x355c567052319, 0x3dff053e8baa7, 0x30145933a20bb,
    0x3f829e6bd6bba, 0x5f8c66072ace7, 0x6d4eed643467f, 0xcc0b57a9729d8, 0x63d4c7dcdff6,
    0x6e2f1ed3c2a71, 0xbfed27df0cb8c, 0x57b9be8c8fece, 0xe8296dacbba0e, 0x19ec43845e7cd,
    0x499487bfb2cfd, 0x15507fb8a4c3f, 0x4eb4c133c44c6, 0x46f4d7d05d5e9, 0x1403ec072267b,
    0x42f3db0918e6f, 0x4a12f29990cd, 0x21c078f7b096c, 0x5d7cb674f5b94, 0x4b6ab2b6b85,
    0x64dcbb337dda8, 0xae2a09ce386d8, 0x47d4c764502e5, 0x37ab82e784a4c, 0x279485eef7e12,
    0x6e3a35d64f447, 0xb5f72cb08d802, 0x130922ccaf665, 0xfcb727b232952, 0x3aaa4745db15f,
    0x555f7a3941881, 0x9c78701503430, 0x6109825b920d4, 0x237def01f0a49, 0x2fa436baf03a9,
    0x52f3c5d10d5d8, 0x1249c36d73132, 0x73b2269c79aa7, 0x6425b9fe81796, 0x379a76cb42ac8,
    0x61c0bf3594366, 0xda97bf0917530, 0x60340c80e3c62, 0x6e3d5ac5d53a3, 0x3272121adefa2,
    0x55f37132a6fa0, 0x20c61072d5855, 0x514a0e230d7ba, 0xbad776d17830, 0x1c421a5a5b50f
};


/* Field element operations: */

/* NON_ZERO_TO_ALL_ONES returns:
 *   0xffffffffffffffff for 0 < x <= 2**63
 *   0 for x == 0 or x > 2**63.
 *
 * x must be a u64 or an equivalent type such as limb. */
#define NON_ZERO_TO_ALL_ONES(x) ((((u64)(x) - 1) >> 63) - 1)

/* felem_reduce_carry adds a multiple of p in order to cancel |carry|,
 * which is a term at 2**257.
 *
 * On entry: carry < 2**6, inout[0,2,...] < 2**51, inout[1,3,...] < 2**52.
 * On exit: inout[0,2,..] < 2**52, inout[1,3,...] < 2**53. */
static void felem_reduce_carry(felem inout, limb carry) {
  const u64 carry_mask = NON_ZERO_TO_ALL_ONES(carry);

  inout[0] += carry << 1;
  inout[1] += 0x10000000000000 & carry_mask;
  /* carry < 2**6 thus (carry << 46) < 2**52 and we added 2**52 in the
   * previous line therefore this doesn't underflow. */
  inout[1] -= carry << 46;
  inout[2] += (0x8000000000000 - 1) & carry_mask;
  inout[3] += (0x10000000000000 - 1) & carry_mask;
  inout[3] -= carry << 39;
  /* This may underflow if carry is non-zero but, if so, we'll fix it in the
   * next line. */
  inout[4] -= 1 & carry_mask;
  inout[4] += carry << 19;
}

/* felem_sum sets out = in+in2.
 *
 * On entry, in[i]+in2[i] must not overflow a 64-bit word.
 * On exit: out[0,2,...] < 2**52, out[1,3,...] < 2**53 */
static void felem_sum(felem out, const felem in, const felem in2) {
  limb carry = 0;
  unsigned i;

  for (i = 0;; i++) {
    out[i] = in[i] + in2[i];
    out[i] += carry;
    carry = out[i] >> 51;
    out[i] &= kBottom51Bits;

    i++;
    if (i == NLIMBS)
      break;

    out[i] = in[i] + in2[i];
    out[i] += carry;
    carry = out[i] >> 52;
    out[i] &= kBottom52Bits;
  }

  felem_reduce_carry(out, carry);
}

#define two53m3 (((limb)1) << 53) - (((limb)1) << 3)
#define two54m52p48m2 (((limb)1) << 54) - (((limb)1) << 52) + (((limb)1) << 48) - (((limb)1) << 2)
#define two53m2p0 (((limb)1) << 53) - (((limb)1) << 2) + (((limb)1) << 0)
#define two54m52p41m2 (((limb)1) << 54) - (((limb)1) << 52) + (((limb)1) << 41) - (((limb)1) << 2)
#define two53m21m2p0 (((limb)1) << 53) - (((limb)1) << 21) - (((limb)1) << 2) + (((limb)1) << 0)

/* zero53 is 0 mod p. */
static const felem zero53 = { two53m3, two54m52p48m2, two53m2p0, two54m52p41m2, two53m21m2p0 };

/* felem_diff sets out = in-in2.
 *
 * On entry: in[0,2,...] < 2**52, in[1,3,...] < 2**53 and
 *           in2[0,2,...] < 2**52, in2[1,3,...] < 2**53.
 * On exit: out[0,2,...] < 2**52, out[1,3,...] < 2**53. */
static void felem_diff(felem out, const felem in, const felem in2) {
  limb carry = 0;
  unsigned i;

   for (i = 0;; i++) {
    out[i] = in[i] - in2[i];
    out[i] += zero53[i];
    out[i] += carry;
    carry = out[i] >> 51;
    out[i] &= kBottom51Bits;

    i++;
    if (i == NLIMBS)
      break;

    out[i] = in[i] - in2[i];
    out[i] += zero53[i];
    out[i] += carry;
    carry = out[i] >> 52;
    out[i] &= kBottom52Bits;
  }

  felem_reduce_carry(out, carry);
}

/* felem_reduce_degree sets out = tmp/R mod p where tmp contains 64-bit words
 * with the same 51,52,... bit positions as an felem.
 *
 * The values in felems are in Montgomery form: x*R mod p where R = 2**257.
 * Since we just multiplied two Montgomery values together, the result is
 * x*y*R*R mod p. We wish to divide by R in order for the result also to be
 * in Montgomery form.
 *
 * On entry: tmp[i] < 2**128
 * On exit: out[0,2,...] < 2**52, out[1,3,...] < 2**53 */
FELEM_INLINE void felem_reduce_degree(felem out, u128 tmp[9]) {
   /* The following table may be helpful when reading this code:
    *
    * Limb number:   0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10
    * Width (bits):  51| 52| 51| 52| 51| 52| 51| 52| 51| 52| 51
    * Start bit:     0 | 51|103|154|206|257|309|360|412|463|515
    *   (odd phase): 0 | 52|103|155|206|258|309|361|412|464|515 */
  limb tmp2[10], carry, x, xShiftedMask;
  unsigned i;

  /* tmp contains 128-bit words with the same 51,52,51-bit positions as an
   * felem. So the top of an element of tmp might overlap with another
   * element two positions down. The following loop eliminates this
   * overlap. */
  tmp2[0] = (limb)(tmp[0] & kBottom51Bits);

  /* In the following we use "(limb) tmp[x]" and "(limb) (tmp[x]>>64)" to try
   * and hint to the compiler that it can do a single-word shift by selecting
   * the right register rather than doing a double-word shift and truncating
   * afterwards. */
  tmp2[1] = ((limb) tmp[0]) >> 51;
  tmp2[1] |= (((limb)(tmp[0] >> 64)) << 13) & kBottom52Bits;
  tmp2[1] += ((limb) tmp[1]) & kBottom52Bits;
  carry = tmp2[1] >> 52;
  tmp2[1] &= kBottom52Bits;

  for (i = 2; i < 9; i++) {
    tmp2[i] = ((limb)(tmp[i - 2] >> 64)) >> 39;
    tmp2[i] += ((limb)(tmp[i - 1])) >> 52;
    tmp2[i] += (((limb)(tmp[i - 1] >> 64)) << 12) & kBottom51Bits;
    tmp2[i] += ((limb) tmp[i]) & kBottom51Bits;
    tmp2[i] += carry;
    carry = tmp2[i] >> 51;
    tmp2[i] &= kBottom51Bits;

    i++;
    if (i == 9)
      break;
    tmp2[i] = ((limb)(tmp[i - 2] >> 64)) >> 39;
    tmp2[i] += ((limb)(tmp[i - 1])) >> 51;
    tmp2[i] += (((limb)(tmp[i - 1] >> 64)) << 13) & kBottom52Bits;
    tmp2[i] += ((limb) tmp[i]) & kBottom52Bits;
    tmp2[i] += carry;
    carry = tmp2[i] >> 52;
    tmp2[i] &= kBottom52Bits;
  }

  tmp2[9] = ((limb)(tmp[7] >> 64)) >> 39;
  tmp2[9] += ((limb)(tmp[8])) >> 51;
  tmp2[9] += (((limb)(tmp[8] >> 64)) << 13);
  tmp2[9] += carry;

  /* Montgomery elimination of terms.
   *
   * Since R is 2**257, we can divide by R with a bitwise shift if we can
   * ensure that the right-most 257 bits are all zero. We can make that true by
   * adding multiplies of p without affecting the value.
   *
   * So we eliminate limbs from right to left. Since the bottom 51 bits of p
   * are all ones, then by adding tmp2[0]*p to tmp2 we'll make tmp2[0] == 0.
   * We can do that for 8 further limbs and then right shift to eliminate the
   * extra factor of R. */
  for (i = 0;; i += 2) {
    tmp2[i + 1] += tmp2[i] >> 51;
    x = tmp2[i] & kBottom51Bits;
    xShiftedMask = NON_ZERO_TO_ALL_ONES(x >> 1);
    tmp2[i] = 0;

    /* The bounds calculations for this loop are tricky. Each iteration of
     * the loop eliminates two words by adding values to words to their
     * right.
     *
     * The following table contains the amounts added to each word (as an
     * offset from the value of i at the top of the loop). The amounts are
     * accounted for from the first and second half of the loop separately
     * and are written as, for example, 51 to mean a value <2**51.
     *
     * Word:                   1   2   3   4   5   6
     * Added in top half:     52  44  52  37  50
     *                                    51
     *                                    51
     * Added in bottom half:      51  45  51  38  50
     *                                        52
     *                                        52
     *
     * The value that is currently offset 5 will be offset 3 for the next
     * iteration and then offset 1 for the iteration after that. Therefore
     * the total value added will be the values added at 5, 3 and 1.
     *
     * The following table accumulates these values. The sums at the bottom
     * are written as, for example, 53+45, to mean a value < 2**53+2**45.
     *
     * Word:                   1   2   3   4   5   6   7   8   9
     *                        52  44  52  37  50  50  50  50  50
     *                            51  45  51  38  37  38  37
     *                                52  51  52  51  52  51
     *                                    51  52  51  52  51
     *                                    44  52  51  52
     *                                    51  45  44
     *                                        52
     *                        ------------------------------------
     *                                53+ 53+ 54+ 52+ 53+ 52+
     *                                45  44+ 50+ 51+ 52+ 50+
     *                                    37  45+ 50+ 50+ 37
     *                                        38  44+ 38
     *                                            37
     *
     * So the greatest amount is added to tmp2[5]. If tmp2[5] has an initial
     * value of <2**52, then the maximum value will be < 2**54 + 2**52 + 2**50 +
     * 2**45 + 2**38, which is < 2**64, as required. */
    tmp2[i + 1] += (x << 45) & kBottom52Bits;
    tmp2[i + 2] += x >> 7;

    tmp2[i + 3] += (x << 38) & kBottom52Bits;
    tmp2[i + 4] += x >> 14;

    /* On tmp2[i + 4], when x < 2**1, the subtraction with (x << 18) will not
     * underflow because it is balanced with the (x << 50) term.  On the next
     * word tmp2[i + 5], terms with (x >> 1) and (x >> 33) are both zero and
     * there is no underflow either.
     *
     * When x >= 2**1, we add 2**51 to tmp2[i + 4] to avoid an underflow.
     * Removing 1 from tmp2[i + 5] is safe because (x >> 1) - (x >> 33) is
     * strictly positive.
     */
    tmp2[i + 4] += 0x8000000000000 & xShiftedMask;
    tmp2[i + 5] -= 1 & xShiftedMask;

    tmp2[i + 4] -= (x << 18) & kBottom51Bits;
    tmp2[i + 4] += (x << 50) & kBottom51Bits;
    tmp2[i + 5] += (x >> 1) - (x >> 33);

    if (i+1 == NLIMBS)
      break;
    tmp2[i + 2] += tmp2[i + 1] >> 52;
    x = tmp2[i + 1] & kBottom52Bits;
    xShiftedMask = NON_ZERO_TO_ALL_ONES(x >> 2);
    tmp2[i + 1] = 0;

    tmp2[i + 2] += (x << 44) & kBottom51Bits;
    tmp2[i + 3] += x >> 7;

    tmp2[i + 4] += (x << 37) & kBottom51Bits;
    tmp2[i + 5] += x >> 14;

    /* On tmp2[i + 5], when x < 2**2, the subtraction with (x << 18) will not
     * underflow because it is balanced with the (x << 50) term.  On the next
     * word tmp2[i + 6], terms with (x >> 2) and (x >> 34) are both zero and
     * there is no underflow either.
     *
     * When x >= 2**2, we add 2**52 to tmp2[i + 5] to avoid an underflow.
     * Removing 1 from tmp2[i + 6] is safe because (x >> 2) - (x >> 34) is
     * stricly positive.
     */
    tmp2[i + 5] += 0x10000000000000 & xShiftedMask;
    tmp2[i + 6] -= 1 & xShiftedMask;

    tmp2[i + 5] -= (x << 18) & kBottom52Bits;
    tmp2[i + 5] += (x << 50) & kBottom52Bits;
    tmp2[i + 6] += (x >> 2) - (x >> 34);
  }

  /* We merge the right shift with a carry chain. The words above 2**257 have
   * widths of 52,51,... which we need to correct when copying them down.  */
  carry = 0;
  for (i = 0; i < 4; i++) {
    out[i] = tmp2[i + 5];
    out[i] += carry;
    carry = out[i] >> 51;
    out[i] &= kBottom51Bits;

    i++;
    out[i] = tmp2[i + 5] << 1;
    out[i] += carry;
    carry = out[i] >> 52;
    out[i] &= kBottom52Bits;
  }

  out[4] = tmp2[9];
  out[4] += carry;
  carry = out[4] >> 51;
  out[4] &= kBottom51Bits;

  felem_reduce_carry(out, carry);
}

/* felem_square sets out=in*in.
 *
 * On entry: in[0,2,...] < 2**52, in[1,3,...] < 2**53.
 * On exit: out[0,2,...] < 2**52, out[1,3,...] < 2**53. */
FELEM_INLINE void felem_square(felem out, const felem in) {
  u128 tmp[9], x1x1, x3x3;

  x1x1 = ((u128) in[1]) * in[1];
  x3x3 = ((u128) in[3]) * in[3];

  tmp[0] = ((u128) in[0]) * (in[0] << 0);
  tmp[1] = ((u128) in[0]) * (in[1] << 1) + ((x1x1 & 1) << 51);
  tmp[2] = ((u128) in[0]) * (in[2] << 1) + (x1x1 >> 1);
  tmp[3] = ((u128) in[0]) * (in[3] << 1) +
           ((u128) in[1]) * (in[2] << 1);
  tmp[4] = ((u128) in[0]) * (in[4] << 1) +
           ((u128) in[1]) * (in[3] << 0) +
           ((u128) in[2]) * (in[2] << 0);
  tmp[5] = ((u128) in[1]) * (in[4] << 1) +
           ((u128) in[2]) * (in[3] << 1) + ((x3x3 & 1) << 51);
  tmp[6] = ((u128) in[2]) * (in[4] << 1) + (x3x3 >> 1);
  tmp[7] = ((u128) in[3]) * (in[4] << 1);
  tmp[8] = ((u128) in[4]) * (in[4] << 0);

  felem_reduce_degree(out, tmp);
}

/* felem_mul sets out=in*in2.
 *
 * On entry: in[0,2,...] < 2**52, in[1,3,...] < 2**53 and
 *           in2[0,2,...] < 2**52, in2[1,3,...] < 2**53.
 * On exit: out[0,2,...] < 2**52, out[1,3,...] < 2**53. */
FELEM_INLINE void felem_mul(felem out, const felem in, const felem in2) {
  u128 tmp[9], x1y1, x1y3, x3y1, x3y3;

  x1y1 = ((u128) in[1]) * in2[1];
  x1y3 = ((u128) in[1]) * in2[3];
  x3y1 = ((u128) in[3]) * in2[1];
  x3y3 = ((u128) in[3]) * in2[3];

  tmp[0] = ((u128) in[0]) * in2[0];
  tmp[1] = ((u128) in[0]) * in2[1] +
           ((u128) in[1]) * in2[0] + ((x1y1 & 1) << 51);
  tmp[2] = ((u128) in[0]) * in2[2] + (x1y1 >> 1) +
           ((u128) in[2]) * in2[0];
  tmp[3] = ((u128) in[0]) * in2[3] +
           ((u128) in[1]) * in2[2] +
           ((u128) in[2]) * in2[1] + ((x1y3 & 1) << 51) +
           ((u128) in[3]) * in2[0] + ((x3y1 & 1) << 51);
  tmp[4] = ((u128) in[0]) * in2[4] + (x1y3 >> 1) +
           ((u128) in[2]) * in2[2] + (x3y1 >> 1) +
           ((u128) in[4]) * in2[0];
  tmp[5] = ((u128) in[1]) * in2[4] +
           ((u128) in[2]) * in2[3] +
           ((u128) in[3]) * in2[2] +
           ((u128) in[4]) * in2[1] + ((x3y3 & 1) << 51);
  tmp[6] = ((u128) in[2]) * in2[4] + (x3y3 >> 1) +
           ((u128) in[4]) * in2[2];
  tmp[7] = ((u128) in[3]) * in2[4] +
           ((u128) in[4]) * in2[3];
  tmp[8] = ((u128) in[4]) * in2[4];

  felem_reduce_degree(out, tmp);
}

static void felem_assign(felem out, const felem in) {
  memcpy(out, in, sizeof(felem));
}

/* felem_scalar_3 sets out=3*out.
 *
 * On entry: out[0,2,...] < 2**52, out[1,3,...] < 2**53.
 * On exit: out[0,2,...] < 2**52, out[1,3,...] < 2**53. */
static void felem_scalar_3(felem out) {
  limb carry = 0;
  unsigned i;

  for (i = 0;; i++) {
    out[i] *= 3;
    out[i] += carry;
    carry = out[i] >> 51;
    out[i] &= kBottom51Bits;

    i++;
    if (i == NLIMBS)
      break;

    out[i] *= 3;
    out[i] += carry;
    carry = out[i] >> 52;
    out[i] &= kBottom52Bits;
  }

  felem_reduce_carry(out, carry);
}

/* felem_scalar_4 sets out=4*out.
 *
 * On entry: out[0,2,...] < 2**52, out[1,3,...] < 2**53.
 * On exit: out[0,2,...] < 2**52, out[1,3,...] < 2**53. */
static void felem_scalar_4(felem out) {
  limb carry = 0, next_carry;
  unsigned i;

  for (i = 0;; i++) {
    next_carry = out[i] >> 49;
    out[i] <<= 2;
    out[i] &= kBottom51Bits;
    out[i] += carry;
    carry = next_carry + (out[i] >> 51);
    out[i] &= kBottom51Bits;

    i++;
    if (i == NLIMBS)
      break;

    next_carry = out[i] >> 50;
    out[i] <<= 2;
    out[i] &= kBottom52Bits;
    out[i] += carry;
    carry = next_carry + (out[i] >> 52);
    out[i] &= kBottom52Bits;
  }

  felem_reduce_carry(out, carry);
}

/* felem_scalar_8 sets out=8*out.
 *
 * On entry: out[0,2,...] < 2**52, out[1,3,...] < 2**53.
 * On exit: out[0,2,...] < 2**52, out[1,3,...] < 2**53. */
static void felem_scalar_8(felem out) {
  limb carry = 0, next_carry;
  unsigned i;

  for (i = 0;; i++) {
    next_carry = out[i] >> 48;
    out[i] <<= 3;
    out[i] &= kBottom51Bits;
    out[i] += carry;
    carry = next_carry + (out[i] >> 51);
    out[i] &= kBottom51Bits;

    i++;
    if (i == NLIMBS)
      break;

    next_carry = out[i] >> 49;
    out[i] <<= 3;
    out[i] &= kBottom52Bits;
    out[i] += carry;
    carry = next_carry + (out[i] >> 52);
    out[i] &= kBottom52Bits;
  }

  felem_reduce_carry(out, carry);
}

/* felem_is_zero_vartime returns 1 iff |in| == 0. It takes a variable amount of
 * time depending on the value of |in|. */
static char felem_is_zero_vartime(const felem in) {
  limb carry;
  int i;
  limb tmp[NLIMBS];

  felem_assign(tmp, in);

  /* First, reduce tmp to a minimal form. */
  do {
    carry = 0;
    for (i = 0;; i++) {
      tmp[i] += carry;
      carry = tmp[i] >> 51;
      tmp[i] &= kBottom51Bits;

      i++;
      if (i == NLIMBS)
        break;

      tmp[i] += carry;
      carry = tmp[i] >> 52;
      tmp[i] &= kBottom52Bits;
    }

    felem_reduce_carry(tmp, carry);
  } while (carry);

  /* tmp < 2**257, so the only possible zero values are 0, p and 2p. */
  return memcmp(tmp, kZero, sizeof(tmp)) == 0 ||
         memcmp(tmp, kP, sizeof(tmp)) == 0 ||
         memcmp(tmp, k2P, sizeof(tmp)) == 0;
}


/* Montgomery operations: */

#define kRDigits {2, 0xfffffffe00000000, 0xffffffffffffffff, 0x1fffffffd} // 2^257 mod p256.p

#define kRInvDigits {0x180000000, 0xffffffff, 0xfffffffe80000001, 0x7fffffff00000001}  // 1 / 2^257 mod p256.p

static const crypton_p256_int kR = { kRDigits };
static const crypton_p256_int kRInv = { kRInvDigits };

/* to_montgomery sets out = R*in. */
static void to_montgomery(felem out, const crypton_p256_int* in) {
  crypton_p256_int in_shifted;
  int i;

  crypton_p256_init(&in_shifted);
  crypton_p256_modmul(&crypton_SECP256r1_p, in, 0, &kR, &in_shifted);

  for (i = 0; i < NLIMBS; i++) {
    if ((i & 1) == 0) {
      out[i] = P256_DIGIT(&in_shifted, 0) & kBottom51Bits;
      crypton_p256_shr(&in_shifted, 51, &in_shifted);
    } else {
      out[i] = P256_DIGIT(&in_shifted, 0) & kBottom52Bits;
      crypton_p256_shr(&in_shifted, 52, &in_shifted);
    }
  }

  crypton_p256_clear(&in_shifted);
}

/* from_montgomery sets out=in/R. */
static void from_montgomery(crypton_p256_int* out, const felem in) {
  crypton_p256_int result, tmp;
  int i, top;

  crypton_p256_init(&result);
  crypton_p256_init(&tmp);

  crypton_p256_add_d(&tmp, in[NLIMBS - 1], &result);
  for (i = NLIMBS - 2; i >= 0; i--) {
    if ((i & 1) == 0) {
      top = crypton_p256_shl(&result, 51, &tmp);
    } else {
      top = crypton_p256_shl(&result, 52, &tmp);
    }
    top += crypton_p256_add_d(&tmp, in[i], &result);
  }

  crypton_p256_modmul(&crypton_SECP256r1_p, &kRInv, top, &result, out);

  crypton_p256_clear(&result);
  crypton_p256_clear(&tmp);
}
