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
typedef int32_t s32;
typedef uint64_t u64;

/* Our field elements are represented as nine 32-bit limbs.
 *
 * The value of an felem (field element) is:
 *   x[0] + (x[1] * 2**29) + (x[2] * 2**57) + ... + (x[8] * 2**228)
 *
 * That is, each limb is alternately 29 or 28-bits wide in little-endian
 * order.
 *
 * This means that an felem hits 2**257, rather than 2**256 as we would like. A
 * 28, 29, ... pattern would cause us to hit 2**256, but that causes problems
 * when multiplying as terms end up one bit short of a limb which would require
 * much bit-shifting to correct.
 *
 * Finally, the values stored in an felem are in Montgomery form. So the value
 * |y| is stored as (y*R) mod p, where p is the P-256 prime and R is 2**257.
 */
typedef u32 limb;
#define NLIMBS 9
typedef limb felem[NLIMBS];

static const limb kBottom28Bits = 0xfffffff;
static const limb kBottom29Bits = 0x1fffffff;

/* kOne is the number 1 as an felem. It's 2**257 mod p split up into 29 and
 * 28-bit words. */
static const felem kOne = {
    2, 0, 0, 0xffff800,
    0x1fffffff, 0xfffffff, 0x1fbfffff, 0x1ffffff,
    0
};
static const felem kZero = {0};
static const felem kP = {
    0x1fffffff, 0xfffffff, 0x1fffffff, 0x3ff,
    0, 0, 0x200000, 0xf000000,
    0xfffffff
};
static const felem k2P = {
    0x1ffffffe, 0xfffffff, 0x1fffffff, 0x7ff,
    0, 0, 0x400000, 0xe000000,
    0x1fffffff
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
    0xe01bd76, 0xa0be8b3, 0x8494c1d, 0x609ab3d, 0x1188042f, 0x499c03d, 0x1df7cd26, 0x51b33c5, 0x1fb3bce,
    0x39cdd45, 0xdc0dd9b, 0xe3053d7, 0x1ffaf46, 0x9ac284a, 0xac051d4, 0x1c09fe1b, 0x8227cbf, 0x5bf049b,
    0xb9487d, 0x2ecb75f, 0x194825bf, 0xd70cf28, 0x14e528f3, 0x4d8670c, 0x35bbabb, 0x6b692ca, 0xd96d08,
    0x1db081dc, 0xa87ea7b, 0x190e5549, 0xa4cf420, 0x1e151385, 0xaf3d4bd, 0x4057e9f, 0x5078feb, 0x154519a,
    0xbf15dea, 0x453fa25, 0x1171c85a, 0x576c824, 0x154e7060, 0x71ede6e, 0x160467a2, 0xdea8a44, 0x81ffcb1,
    0x61a56fa, 0x76119b9, 0x110bfb9b, 0x3d527ea, 0x1997bdb4, 0xe1d1253, 0x180ce91c, 0x11950ee, 0x53d5938,
    0x694e7c9, 0xe0cf337, 0x16d8ae50, 0x202517f, 0x4d02e16, 0xd13b5fd, 0xfae97eb, 0xa1c7f60, 0x1206fe8,
    0x11b1c908, 0xf8a82f, 0x6ab17a0, 0x48058e8, 0x2d0feb, 0xfada550, 0x658edb9, 0xa17567a, 0x8daa44d,
    0x6361dc9, 0xec00c0e, 0x151a7b1c, 0xb35a683, 0x1643fe02, 0x70155c0, 0x1f131d45, 0x3998068, 0x25beef8,
    0x88138de, 0x8995ce4, 0x18565c50, 0x60f12b6, 0xc47a656, 0x4a82bd9, 0xb547a17, 0xb333474, 0xe86513a,
    0x7f8d2bc, 0x7f0f16c, 0x8cde475, 0x1ac3d5c, 0x1a832c9a, 0x6a93e7a, 0x19833281, 0xcec82db, 0x4f08cc,
    0x72c4394, 0x4686520, 0x1e845ce, 0xfb181a1, 0xf5135a5, 0xa1265d6, 0x6c63ce8, 0xe81797e, 0x5dbcd5a,
    0x2a5d603, 0x1ad4e91, 0xc86e1b3, 0x793abea, 0x1b8610a4, 0x8d5b975, 0x74dd850, 0xbbca81, 0xd7c35d8,
    0x1bab7afc, 0x4df749, 0x4acb4ea, 0xfae8c89, 0x14552ae5, 0x6dc1c20, 0x14f629f, 0x2368fe5, 0xe5a9cba,
    0x67576f7, 0x9c77c50, 0x1d63c92a, 0xbbb9ef8, 0xa7530d4, 0x963335, 0xfa09c54, 0xb6d03e3, 0xed1a022,
    0x19c59f49, 0x45c823d, 0x17a28df1, 0x80ae516, 0xe2ada82, 0x19b97fb, 0x13a9ebf, 0xf1e7606, 0xde03632,
    0x14e318b9, 0x7b57b83, 0x51a9a92, 0x3378a17, 0x1cde9289, 0x45956c2, 0x2bbab5e, 0x780b1f5, 0x8356034,
    0x75eca28, 0x6f39648, 0xf2fdbda, 0x4c65cd9, 0xb3759e7, 0x710c0b1, 0xda24432, 0x8d236aa, 0xf4c449f,
    0xaf9ba24, 0xb83ea7f, 0x1e46ecc3, 0x3f277b0, 0x6acdecd, 0x1f597d1, 0x8483d72, 0x57d29dd, 0x66d4060,
    0x167c14af, 0xc142ded, 0xc1689ca, 0x651aa52, 0x8d05768, 0x9709cfa, 0x165fd283, 0x9f6f583, 0x9833b54,
    0xd17e2d6, 0x2915c32, 0x1970ef24, 0xe8ca45b, 0x11c29e09, 0x8121f26, 0xb5afbe1, 0x10c80ec, 0x834a25c,
    0xa37f0b0, 0xd6bac16, 0xed484fc, 0x8799206, 0x13db8bb1, 0xdce615c, 0x13320329, 0x79dc25, 0x914e7af,
    0x860a414, 0xb8a9434, 0x50396ce, 0x902d3e6, 0x15c152f3, 0x3753c64, 0x970c055, 0xba296fb, 0x64bd63b,
    0x118cbb94, 0x9d4274f, 0x121cdbfe, 0xb9137cf, 0xc8bddf1, 0xa1598d0, 0x446ab41, 0x11f1df2, 0x68115f1,
    0x2f1f708, 0xee35192, 0x1dfeb3fc, 0x4e1e1a6, 0x1d9adcbb, 0x6688662, 0x63ad21b, 0x9d9a9e1, 0xb0f8b4b,
    0xcd8bc3a, 0x3577d8, 0x1ffcb97d, 0xd31e8d6, 0x1c776310, 0x95b4ef7, 0x185a82ed, 0xe40bbb0, 0xbca1ea,
    0x19462e0b, 0x2252179, 0x14f14f09, 0x565e68d, 0x7ba5f37, 0x4cd1858, 0x167941b3, 0x4d1c7a7, 0x7aef1ab,
    0x1599efe9, 0x658e78d, 0x1ad33917, 0x7e74797, 0x19152edc, 0xdf7dc18, 0xdf677c, 0x9315d96, 0x4ba8eec,
    0xc45cd82, 0x1acfa03, 0xe265b49, 0xcfa6eb, 0x89d7619, 0x7b05, 0x1ba11068, 0xe1672d3, 0x655622a,
    0x1607ca6, 0x339049, 0x5454f70, 0x10edd75, 0x1133ceb7, 0xe3eec39, 0xc263156, 0xeb6ddbe, 0x10360a7,
    0xfd5f981, 0x47dd502, 0x1e66dbbe, 0x8820b63, 0xeee91ef, 0xffde293, 0xb66325d, 0x3a5a2a, 0x6a2acbb,
    0x11e949bc, 0xf6a6d57, 0x6b2ca24, 0xad903ec, 0x1e55de0, 0xe7074ed, 0xe681934, 0xea44010, 0xaa490cc,
    0x512324a, 0x6a5eb00, 0xee5e100, 0xd60a02b, 0x1b89c993, 0x5cffb70, 0xa49030c, 0x405aee, 0xe1b27cc,
    0x2e73a15, 0x9ca8dc0, 0x781dbff, 0x9fd85e0, 0x1884e4c8, 0x40873f6, 0x32d4b69, 0xf42f753, 0xeaf4c38,
    0x2802a4c, 0x1283dac, 0x759100a, 0xcb3ba75, 0xf3203d3, 0xf89b8aa, 0x7caa59e, 0x384a60a, 0x37f69e7,
    0x1e56d569, 0x120c552, 0x181734aa, 0x4fcd9b4, 0x7918e4e, 0xcd7938a, 0x2bbd8b2, 0x19f4f97, 0xa7af533,
    0xbb69948, 0x3eff33e, 0x1f3ac118, 0x3739770, 0x58898fd, 0x623fafb, 0xa7e6d93, 0xd31a676, 0x615192d,
    0xf543d28, 0xe61ce5a, 0x10ae4b39, 0xcd5a8d7, 0x1b34c6de, 0x81997ad, 0x198e2093, 0xd9b6ff7, 0x9a5954f,
    0x16782589, 0xed3c1ab, 0x62dc4a5, 0xac12d0c, 0x8bc8b7c, 0x168ec4e, 0x177e11dc, 0x407df09, 0x4056e85,
    0x9858305, 0xfe445e9, 0x18b1230a, 0x815ee9f, 0xa852eb4, 0x89444e0, 0x1a83481, 0x479359b, 0x2192576,
    0x16d5e61b, 0xfe480c4, 0x1d60b8b7, 0x1c6e798, 0x1a01310, 0x9998572, 0x7c59f75, 0x49dda87, 0xe75e0b6,
    0x1b2b7536, 0xb267d8, 0x15443085, 0x45e5924, 0x7fb947f, 0x296915d, 0x38fc56b, 0x4bae39f, 0xb218e7c,
    0x115c3b16, 0x9d95f0c, 0xa50ac4c, 0xcce8037, 0xc3c7ba3, 0xf02773a, 0xbc2ad54, 0x26914c1, 0x19a4b8d,
    0x3f8a1a6, 0xa0b8459, 0x1f77a521, 0x7d93297, 0x1dddb4b2, 0x9e4cd1c, 0x6e28403, 0xd7ce413, 0x5575b62,
    0x12bb7dc1, 0xbdfb15e, 0xa542867, 0xe943d3e, 0x1367fbdd, 0x37b387, 0x14e4d75f, 0xb90b09d, 0xbf6ec28,
    0xa5182c8, 0x1e5b34e, 0xabe4602, 0x1c13efa, 0x8d1182, 0x1c2947a, 0x1e04e0e3, 0x6caecdb, 0x40f14e8,
    0x1b845e4a, 0xa9fb149, 0xb34f513, 0x3a0fdbb, 0xfad2335, 0x5bb9342, 0x18c5ad62, 0xc97fdc3, 0x31225c7,
    0xb28a9ee, 0x585915, 0x1e355da1, 0x26ed08e, 0xc7d06a, 0xa65f219, 0x1fdf45cd, 0xc8323ea, 0x297b9ee,
    0x1c031098, 0x9c39cf0, 0x1287d79f, 0x69a9e32, 0x10015650, 0x1c3dfc3, 0x12dcd848, 0x3155a59, 0xeff3212,
    0x1a6ecdd0, 0xd26bd07, 0x18e077ab, 0x442b477, 0x46b735f, 0x495d60c, 0x1b57a6e5, 0x76a368a, 0xf53bd50,
    0xf12c5e0, 0x80a9b4, 0x15562060, 0x4102113, 0xa144ab5, 0x5fa4e9, 0x1009f5e9, 0xe34343a, 0x26fda5a,
    0x159e06a4, 0x5fa3aad, 0x10259b5f, 0xa69947d, 0x1190417e, 0x987da3f, 0x14e1e868, 0xdcb7e1e, 0x8890f9f,
    0x14dece80, 0x94bbf5c, 0x18513a17, 0x4ca31ca, 0xc0a2713, 0xbc46074, 0x1536f6a5, 0x43991aa, 0xb9f8f1c,
    0x987ba48, 0xb0829ae, 0xd29d324, 0x6339c35, 0x18ace0a4, 0x5d53b55, 0xff829f4, 0xe882ecf, 0xc05164c,
    0x6bd6bba, 0x9dfc14f, 0x1981cab3, 0xcfebf18, 0x1ddac868, 0x94ec6d4, 0x5abd4b, 0x737fdb3, 0x18f531f,
    0xd3c2a71, 0x337178f, 0x9f7c32e, 0xd9d7fda, 0x137d191f, 0xdd0757b, 0x14b6d65, 0x179f37a, 0x67b10e1,
    0x1bfb2cfd, 0xfe4ca43, 0x1fee2930, 0x98c2aa0, 0x9826788, 0xeaf4ceb, 0x17a6be82, 0xc899ed1, 0x500fb01,
    0x10918e6f, 0x36179ed, 0xbca6643, 0x2d80942, 0xf1ef61, 0xadca21c, 0xbe5b3a7, 0xadae157, 0x12daac,
    0x1337dda8, 0x6326e5d, 0x2738e1b, 0x5cb5c54, 0x98ec8a0, 0x252647d, 0x1d5c173c, 0xbdf848d, 0x9e5217b,
    0x1d64f447, 0xb71d1a, 0xb2c2360, 0xccb6bee, 0x1245995e, 0x94a9130, 0x5b93d91, 0x76c57ff, 0xeaa91d1,
    0x3941881, 0xc2aafbd, 0x1c0540d0, 0x1a938f0, 0x1304b724, 0x8524e10, 0x1bef780f, 0xbc0ea48, 0xbe90dae,
    0x1d10d5d8, 0xca979e2, 0x10db5cc4, 0x54e2493, 0x44d38f3, 0xbcb73b, 0x12dcff4, 0xd0ab219, 0xde69db2,
    0x13594366, 0xc30e05f, 0xfc245d4, 0x8c5b52f, 0x81901c7, 0xa9d1e03, 0x11ead62e, 0xb7be89b, 0xc9c8486,
    0x132a6fa0, 0x56af9b8, 0x41cb561, 0xf74418c, 0x141c461a, 0xbc18514, 0x1d6bbb68, 0x96d43c2, 0x7108696
};


/* Field element operations: */

/* NON_ZERO_TO_ALL_ONES returns:
 *   0xffffffff for 0 < x <= 2**31
 *   0 for x == 0 or x > 2**31.
 *
 * x must be a u32 or an equivalent type such as limb. */
#define NON_ZERO_TO_ALL_ONES(x) ((((u32)(x) - 1) >> 31) - 1)

/* felem_reduce_carry adds a multiple of p in order to cancel |carry|,
 * which is a term at 2**257.
 *
 * On entry: carry < 2**3, inout[0,2,...] < 2**29, inout[1,3,...] < 2**28.
 * On exit: inout[0,2,..] < 2**30, inout[1,3,...] < 2**29. */
static void felem_reduce_carry(felem inout, limb carry) {
  const u32 carry_mask = NON_ZERO_TO_ALL_ONES(carry);

  inout[0] += carry << 1;
  inout[3] += 0x10000000 & carry_mask;
  /* carry < 2**3 thus (carry << 11) < 2**14 and we added 2**28 in the
   * previous line therefore this doesn't underflow. */
  inout[3] -= carry << 11;
  inout[4] += (0x20000000 - 1) & carry_mask;
  inout[5] += (0x10000000 - 1) & carry_mask;
  inout[6] += (0x20000000 - 1) & carry_mask;
  inout[6] -= carry << 22;
  /* This may underflow if carry is non-zero but, if so, we'll fix it in the
   * next line. */
  inout[7] -= 1 & carry_mask;
  inout[7] += carry << 25;
}

/* felem_sum sets out = in+in2.
 *
 * On entry, in[i]+in2[i] must not overflow a 32-bit word.
 * On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29 */
static void felem_sum(felem out, const felem in, const felem in2) {
  limb carry = 0;
  unsigned i;

  for (i = 0;; i++) {
    out[i] = in[i] + in2[i];
    out[i] += carry;
    carry = out[i] >> 29;
    out[i] &= kBottom29Bits;

    i++;
    if (i == NLIMBS)
      break;

    out[i] = in[i] + in2[i];
    out[i] += carry;
    carry = out[i] >> 28;
    out[i] &= kBottom28Bits;
  }

  felem_reduce_carry(out, carry);
}

#define two31m3 (((limb)1) << 31) - (((limb)1) << 3)
#define two30m2 (((limb)1) << 30) - (((limb)1) << 2)
#define two30p13m2 (((limb)1) << 30) + (((limb)1) << 13) - (((limb)1) << 2)
#define two31m2 (((limb)1) << 31) - (((limb)1) << 2)
#define two31p24m2 (((limb)1) << 31) + (((limb)1) << 24) - (((limb)1) << 2)
#define two30m27m2 (((limb)1) << 30) - (((limb)1) << 27) - (((limb)1) << 2)

/* zero31 is 0 mod p. */
static const felem zero31 = { two31m3, two30m2, two31m2, two30p13m2, two31m2, two30m2, two31p24m2, two30m27m2, two31m2 };

/* felem_diff sets out = in-in2.
 *
 * On entry: in[0,2,...] < 2**30, in[1,3,...] < 2**29 and
 *           in2[0,2,...] < 2**30, in2[1,3,...] < 2**29.
 * On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29. */
static void felem_diff(felem out, const felem in, const felem in2) {
  limb carry = 0;
  unsigned i;

   for (i = 0;; i++) {
    out[i] = in[i] - in2[i];
    out[i] += zero31[i];
    out[i] += carry;
    carry = out[i] >> 29;
    out[i] &= kBottom29Bits;

    i++;
    if (i == NLIMBS)
      break;

    out[i] = in[i] - in2[i];
    out[i] += zero31[i];
    out[i] += carry;
    carry = out[i] >> 28;
    out[i] &= kBottom28Bits;
  }

  felem_reduce_carry(out, carry);
}

/* felem_reduce_degree sets out = tmp/R mod p where tmp contains 64-bit words
 * with the same 29,28,... bit positions as an felem.
 *
 * The values in felems are in Montgomery form: x*R mod p where R = 2**257.
 * Since we just multiplied two Montgomery values together, the result is
 * x*y*R*R mod p. We wish to divide by R in order for the result also to be
 * in Montgomery form.
 *
 * On entry: tmp[i] < 2**64
 * On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29 */
static void felem_reduce_degree(felem out, u64 tmp[17]) {
   /* The following table may be helpful when reading this code:
    *
    * Limb number:   0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10...
    * Width (bits):  29| 28| 29| 28| 29| 28| 29| 28| 29| 28| 29
    * Start bit:     0 | 29| 57| 86|114|143|171|200|228|257|285
    *   (odd phase): 0 | 28| 57| 85|114|142|171|199|228|256|285 */
  limb tmp2[18], carry, x, xMask;
  unsigned i;

  /* tmp contains 64-bit words with the same 29,28,29-bit positions as an
   * felem. So the top of an element of tmp might overlap with another
   * element two positions down. The following loop eliminates this
   * overlap. */
  tmp2[0] = (limb)(tmp[0] & kBottom29Bits);

  /* In the following we use "(limb) tmp[x]" and "(limb) (tmp[x]>>32)" to try
   * and hint to the compiler that it can do a single-word shift by selecting
   * the right register rather than doing a double-word shift and truncating
   * afterwards. */
  tmp2[1] = ((limb) tmp[0]) >> 29;
  tmp2[1] |= (((limb)(tmp[0] >> 32)) << 3) & kBottom28Bits;
  tmp2[1] += ((limb) tmp[1]) & kBottom28Bits;
  carry = tmp2[1] >> 28;
  tmp2[1] &= kBottom28Bits;

  for (i = 2; i < 17; i++) {
    tmp2[i] = ((limb)(tmp[i - 2] >> 32)) >> 25;
    tmp2[i] += ((limb)(tmp[i - 1])) >> 28;
    tmp2[i] += (((limb)(tmp[i - 1] >> 32)) << 4) & kBottom29Bits;
    tmp2[i] += ((limb) tmp[i]) & kBottom29Bits;
    tmp2[i] += carry;
    carry = tmp2[i] >> 29;
    tmp2[i] &= kBottom29Bits;

    i++;
    if (i == 17)
      break;
    tmp2[i] = ((limb)(tmp[i - 2] >> 32)) >> 25;
    tmp2[i] += ((limb)(tmp[i - 1])) >> 29;
    tmp2[i] += (((limb)(tmp[i - 1] >> 32)) << 3) & kBottom28Bits;
    tmp2[i] += ((limb) tmp[i]) & kBottom28Bits;
    tmp2[i] += carry;
    carry = tmp2[i] >> 28;
    tmp2[i] &= kBottom28Bits;
  }

  tmp2[17] = ((limb)(tmp[15] >> 32)) >> 25;
  tmp2[17] += ((limb)(tmp[16])) >> 29;
  tmp2[17] += (((limb)(tmp[16] >> 32)) << 3);
  tmp2[17] += carry;

  /* Montgomery elimination of terms.
   *
   * Since R is 2**257, we can divide by R with a bitwise shift if we can
   * ensure that the right-most 257 bits are all zero. We can make that true by
   * adding multiplies of p without affecting the value.
   *
   * So we eliminate limbs from right to left. Since the bottom 29 bits of p
   * are all ones, then by adding tmp2[0]*p to tmp2 we'll make tmp2[0] == 0.
   * We can do that for 8 further limbs and then right shift to eliminate the
   * extra factor of R. */
  for (i = 0;; i += 2) {
    tmp2[i + 1] += tmp2[i] >> 29;
    x = tmp2[i] & kBottom29Bits;
    xMask = NON_ZERO_TO_ALL_ONES(x);
    tmp2[i] = 0;

    /* The bounds calculations for this loop are tricky. Each iteration of
     * the loop eliminates two words by adding values to words to their
     * right.
     *
     * The following table contains the amounts added to each word (as an
     * offset from the value of i at the top of the loop). The amounts are
     * accounted for from the first and second half of the loop separately
     * and are written as, for example, 28 to mean a value <2**28.
     *
     * Word:                   3   4   5   6   7   8   9   10
     * Added in top half:     28  11      29  21  29  28
     *                                        28  29
     *                                            29
     * Added in bottom half:      29  10      28  21  28   28
     *                                            29
     *
     * The value that is currently offset 7 will be offset 5 for the next
     * iteration and then offset 3 for the iteration after that. Therefore
     * the total value added will be the values added at 7, 5 and 3.
     *
     * The following table accumulates these values. The sums at the bottom
     * are written as, for example, 29+28, to mean a value < 2**29+2**28.
     *
     * Word:                   3   4   5   6   7   8   9  10  11  12  13
     *                        28  11  10  29  21  29  28  28  28  28  28
     *                            29  28  11  28  29  28  29  28  29  28
     *                                    29  28  21  21  29  21  29  21
     *                                        10  29  28  21  28  21  28
     *                                        28  29  28  29  28  29  28
     *                                            11  10  29  10  29  10
     *                                            29  28  11  28  11
     *                                                    29      29
     *                        --------------------------------------------
     *                                                30+ 31+ 30+ 31+ 30+
     *                                                28+ 29+ 28+ 29+ 21+
     *                                                21+ 28+ 21+ 28+ 10
     *                                                10  21+ 10  21+
     *                                                    11      11
     *
     * So the greatest amount is added to tmp2[10] and tmp2[12]. If
     * tmp2[10/12] has an initial value of <2**29, then the maximum value
     * will be < 2**31 + 2**30 + 2**28 + 2**21 + 2**11, which is < 2**32,
     * as required. */
    tmp2[i + 3] += (x << 10) & kBottom28Bits;
    tmp2[i + 4] += (x >> 18);

    tmp2[i + 6] += (x << 21) & kBottom29Bits;
    tmp2[i + 7] += x >> 8;

    /* At position 200, which is the starting bit position for word 7, we
     * have a factor of 0xf000000 = 2**28 - 2**24. */
    tmp2[i + 7] += 0x10000000 & xMask;
    /* Word 7 is 28 bits wide, so the 2**28 term exactly hits word 8. */
    tmp2[i + 8] += (x - 1) & xMask;
    tmp2[i + 7] -= (x << 24) & kBottom28Bits;
    tmp2[i + 8] -= x >> 4;

    tmp2[i + 8] += 0x20000000 & xMask;
    tmp2[i + 8] -= x;
    tmp2[i + 8] += (x << 28) & kBottom29Bits;
    tmp2[i + 9] += ((x >> 1) - 1) & xMask;

    if (i+1 == NLIMBS)
      break;
    tmp2[i + 2] += tmp2[i + 1] >> 28;
    x = tmp2[i + 1] & kBottom28Bits;
    xMask = NON_ZERO_TO_ALL_ONES(x);
    tmp2[i + 1] = 0;

    tmp2[i + 4] += (x << 11) & kBottom29Bits;
    tmp2[i + 5] += (x >> 18);

    tmp2[i + 7] += (x << 21) & kBottom28Bits;
    tmp2[i + 8] += x >> 7;

    /* At position 199, which is the starting bit of the 8th word when
     * dealing with a context starting on an odd word, we have a factor of
     * 0x1e000000 = 2**29 - 2**25. Since we have not updated i, the 8th
     * word from i+1 is i+8. */
    tmp2[i + 8] += 0x20000000 & xMask;
    tmp2[i + 9] += (x - 1) & xMask;
    tmp2[i + 8] -= (x << 25) & kBottom29Bits;
    tmp2[i + 9] -= x >> 4;

    tmp2[i + 9] += 0x10000000 & xMask;
    tmp2[i + 9] -= x;
    tmp2[i + 10] += (x - 1) & xMask;
  }

  /* We merge the right shift with a carry chain. The words above 2**257 have
   * widths of 28,29,... which we need to correct when copying them down.  */
  carry = 0;
  for (i = 0; i < 8; i++) {
    /* The maximum value of tmp2[i + 9] occurs on the first iteration and
     * is < 2**30+2**29+2**28. Adding 2**29 (from tmp2[i + 10]) is
     * therefore safe. */
    out[i] = tmp2[i + 9];
    out[i] += carry;
    out[i] += (tmp2[i + 10] << 28) & kBottom29Bits;
    carry = out[i] >> 29;
    out[i] &= kBottom29Bits;

    i++;
    out[i] = tmp2[i + 9] >> 1;
    out[i] += carry;
    carry = out[i] >> 28;
    out[i] &= kBottom28Bits;
  }

  out[8] = tmp2[17];
  out[8] += carry;
  carry = out[8] >> 29;
  out[8] &= kBottom29Bits;

  felem_reduce_carry(out, carry);
}

/* felem_square sets out=in*in.
 *
 * On entry: in[0,2,...] < 2**30, in[1,3,...] < 2**29.
 * On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29. */
static void felem_square(felem out, const felem in) {
  u64 tmp[17];

  tmp[0] = ((u64) in[0]) * in[0];
  tmp[1] = ((u64) in[0]) * (in[1] << 1);
  tmp[2] = ((u64) in[0]) * (in[2] << 1) +
           ((u64) in[1]) * (in[1] << 1);
  tmp[3] = ((u64) in[0]) * (in[3] << 1) +
           ((u64) in[1]) * (in[2] << 1);
  tmp[4] = ((u64) in[0]) * (in[4] << 1) +
           ((u64) in[1]) * (in[3] << 2) + ((u64) in[2]) * in[2];
  tmp[5] = ((u64) in[0]) * (in[5] << 1) + ((u64) in[1]) *
           (in[4] << 1) + ((u64) in[2]) * (in[3] << 1);
  tmp[6] = ((u64) in[0]) * (in[6] << 1) + ((u64) in[1]) *
           (in[5] << 2) + ((u64) in[2]) * (in[4] << 1) +
           ((u64) in[3]) * (in[3] << 1);
  tmp[7] = ((u64) in[0]) * (in[7] << 1) + ((u64) in[1]) *
           (in[6] << 1) + ((u64) in[2]) * (in[5] << 1) +
           ((u64) in[3]) * (in[4] << 1);
  /* tmp[8] has the greatest value of 2**61 + 2**60 + 2**61 + 2**60 + 2**60,
   * which is < 2**64 as required. */
  tmp[8] = ((u64) in[0]) * (in[8] << 1) + ((u64) in[1]) *
           (in[7] << 2) + ((u64) in[2]) * (in[6] << 1) +
           ((u64) in[3]) * (in[5] << 2) + ((u64) in[4]) * in[4];
  tmp[9] = ((u64) in[1]) * (in[8] << 1) + ((u64) in[2]) *
           (in[7] << 1) + ((u64) in[3]) * (in[6] << 1) +
           ((u64) in[4]) * (in[5] << 1);
  tmp[10] = ((u64) in[2]) * (in[8] << 1) + ((u64) in[3]) *
            (in[7] << 2) + ((u64) in[4]) * (in[6] << 1) +
            ((u64) in[5]) * (in[5] << 1);
  tmp[11] = ((u64) in[3]) * (in[8] << 1) + ((u64) in[4]) *
            (in[7] << 1) + ((u64) in[5]) * (in[6] << 1);
  tmp[12] = ((u64) in[4]) * (in[8] << 1) +
            ((u64) in[5]) * (in[7] << 2) + ((u64) in[6]) * in[6];
  tmp[13] = ((u64) in[5]) * (in[8] << 1) +
            ((u64) in[6]) * (in[7] << 1);
  tmp[14] = ((u64) in[6]) * (in[8] << 1) +
            ((u64) in[7]) * (in[7] << 1);
  tmp[15] = ((u64) in[7]) * (in[8] << 1);
  tmp[16] = ((u64) in[8]) * in[8];

  felem_reduce_degree(out, tmp);
}

/* felem_mul sets out=in*in2.
 *
 * On entry: in[0,2,...] < 2**30, in[1,3,...] < 2**29 and
 *           in2[0,2,...] < 2**30, in2[1,3,...] < 2**29.
 * On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29. */
static void felem_mul(felem out, const felem in, const felem in2) {
  u64 tmp[17];

  tmp[0] = ((u64) in[0]) * in2[0];
  tmp[1] = ((u64) in[0]) * (in2[1] << 0) +
           ((u64) in[1]) * (in2[0] << 0);
  tmp[2] = ((u64) in[0]) * (in2[2] << 0) + ((u64) in[1]) *
           (in2[1] << 1) + ((u64) in[2]) * (in2[0] << 0);
  tmp[3] = ((u64) in[0]) * (in2[3] << 0) + ((u64) in[1]) *
           (in2[2] << 0) + ((u64) in[2]) * (in2[1] << 0) +
           ((u64) in[3]) * (in2[0] << 0);
  tmp[4] = ((u64) in[0]) * (in2[4] << 0) + ((u64) in[1]) *
           (in2[3] << 1) + ((u64) in[2]) * (in2[2] << 0) +
           ((u64) in[3]) * (in2[1] << 1) +
           ((u64) in[4]) * (in2[0] << 0);
  tmp[5] = ((u64) in[0]) * (in2[5] << 0) + ((u64) in[1]) *
           (in2[4] << 0) + ((u64) in[2]) * (in2[3] << 0) +
           ((u64) in[3]) * (in2[2] << 0) + ((u64) in[4]) *
           (in2[1] << 0) + ((u64) in[5]) * (in2[0] << 0);
  tmp[6] = ((u64) in[0]) * (in2[6] << 0) + ((u64) in[1]) *
           (in2[5] << 1) + ((u64) in[2]) * (in2[4] << 0) +
           ((u64) in[3]) * (in2[3] << 1) + ((u64) in[4]) *
           (in2[2] << 0) + ((u64) in[5]) * (in2[1] << 1) +
           ((u64) in[6]) * (in2[0] << 0);
  tmp[7] = ((u64) in[0]) * (in2[7] << 0) + ((u64) in[1]) *
           (in2[6] << 0) + ((u64) in[2]) * (in2[5] << 0) +
           ((u64) in[3]) * (in2[4] << 0) + ((u64) in[4]) *
           (in2[3] << 0) + ((u64) in[5]) * (in2[2] << 0) +
           ((u64) in[6]) * (in2[1] << 0) +
           ((u64) in[7]) * (in2[0] << 0);
  /* tmp[8] has the greatest value but doesn't overflow. See logic in
   * felem_square. */
  tmp[8] = ((u64) in[0]) * (in2[8] << 0) + ((u64) in[1]) *
           (in2[7] << 1) + ((u64) in[2]) * (in2[6] << 0) +
           ((u64) in[3]) * (in2[5] << 1) + ((u64) in[4]) *
           (in2[4] << 0) + ((u64) in[5]) * (in2[3] << 1) +
           ((u64) in[6]) * (in2[2] << 0) + ((u64) in[7]) *
           (in2[1] << 1) + ((u64) in[8]) * (in2[0] << 0);
  tmp[9] = ((u64) in[1]) * (in2[8] << 0) + ((u64) in[2]) *
           (in2[7] << 0) + ((u64) in[3]) * (in2[6] << 0) +
           ((u64) in[4]) * (in2[5] << 0) + ((u64) in[5]) *
           (in2[4] << 0) + ((u64) in[6]) * (in2[3] << 0) +
           ((u64) in[7]) * (in2[2] << 0) +
           ((u64) in[8]) * (in2[1] << 0);
  tmp[10] = ((u64) in[2]) * (in2[8] << 0) + ((u64) in[3]) *
            (in2[7] << 1) + ((u64) in[4]) * (in2[6] << 0) +
            ((u64) in[5]) * (in2[5] << 1) + ((u64) in[6]) *
            (in2[4] << 0) + ((u64) in[7]) * (in2[3] << 1) +
            ((u64) in[8]) * (in2[2] << 0);
  tmp[11] = ((u64) in[3]) * (in2[8] << 0) + ((u64) in[4]) *
            (in2[7] << 0) + ((u64) in[5]) * (in2[6] << 0) +
            ((u64) in[6]) * (in2[5] << 0) + ((u64) in[7]) *
            (in2[4] << 0) + ((u64) in[8]) * (in2[3] << 0);
  tmp[12] = ((u64) in[4]) * (in2[8] << 0) + ((u64) in[5]) *
            (in2[7] << 1) + ((u64) in[6]) * (in2[6] << 0) +
            ((u64) in[7]) * (in2[5] << 1) +
            ((u64) in[8]) * (in2[4] << 0);
  tmp[13] = ((u64) in[5]) * (in2[8] << 0) + ((u64) in[6]) *
            (in2[7] << 0) + ((u64) in[7]) * (in2[6] << 0) +
            ((u64) in[8]) * (in2[5] << 0);
  tmp[14] = ((u64) in[6]) * (in2[8] << 0) + ((u64) in[7]) *
            (in2[7] << 1) + ((u64) in[8]) * (in2[6] << 0);
  tmp[15] = ((u64) in[7]) * (in2[8] << 0) +
            ((u64) in[8]) * (in2[7] << 0);
  tmp[16] = ((u64) in[8]) * (in2[8] << 0);

  felem_reduce_degree(out, tmp);
}

static void felem_assign(felem out, const felem in) {
  memcpy(out, in, sizeof(felem));
}

/* felem_scalar_3 sets out=3*out.
 *
 * On entry: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
 * On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29. */
static void felem_scalar_3(felem out) {
  limb carry = 0;
  unsigned i;

  for (i = 0;; i++) {
    out[i] *= 3;
    out[i] += carry;
    carry = out[i] >> 29;
    out[i] &= kBottom29Bits;

    i++;
    if (i == NLIMBS)
      break;

    out[i] *= 3;
    out[i] += carry;
    carry = out[i] >> 28;
    out[i] &= kBottom28Bits;
  }

  felem_reduce_carry(out, carry);
}

/* felem_scalar_4 sets out=4*out.
 *
 * On entry: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
 * On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29. */
static void felem_scalar_4(felem out) {
  limb carry = 0, next_carry;
  unsigned i;

  for (i = 0;; i++) {
    next_carry = out[i] >> 27;
    out[i] <<= 2;
    out[i] &= kBottom29Bits;
    out[i] += carry;
    carry = next_carry + (out[i] >> 29);
    out[i] &= kBottom29Bits;

    i++;
    if (i == NLIMBS)
      break;

    next_carry = out[i] >> 26;
    out[i] <<= 2;
    out[i] &= kBottom28Bits;
    out[i] += carry;
    carry = next_carry + (out[i] >> 28);
    out[i] &= kBottom28Bits;
  }

  felem_reduce_carry(out, carry);
}

/* felem_scalar_8 sets out=8*out.
 *
 * On entry: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
 * On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29. */
static void felem_scalar_8(felem out) {
  limb carry = 0, next_carry;
  unsigned i;

  for (i = 0;; i++) {
    next_carry = out[i] >> 26;
    out[i] <<= 3;
    out[i] &= kBottom29Bits;
    out[i] += carry;
    carry = next_carry + (out[i] >> 29);
    out[i] &= kBottom29Bits;

    i++;
    if (i == NLIMBS)
      break;

    next_carry = out[i] >> 25;
    out[i] <<= 3;
    out[i] &= kBottom28Bits;
    out[i] += carry;
    carry = next_carry + (out[i] >> 28);
    out[i] &= kBottom28Bits;
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
      carry = tmp[i] >> 29;
      tmp[i] &= kBottom29Bits;

      i++;
      if (i == NLIMBS)
        break;

      tmp[i] += carry;
      carry = tmp[i] >> 28;
      tmp[i] &= kBottom28Bits;
    }

    felem_reduce_carry(tmp, carry);
  } while (carry);

  /* tmp < 2**257, so the only possible zero values are 0, p and 2p. */
  return memcmp(tmp, kZero, sizeof(tmp)) == 0 ||
         memcmp(tmp, kP, sizeof(tmp)) == 0 ||
         memcmp(tmp, k2P, sizeof(tmp)) == 0;
}


/* Montgomery operations: */

#define kRDigits {2, 0, 0, 0xfffffffe, 0xffffffff, 0xffffffff, 0xfffffffd, 1} // 2^257 mod p256.p

#define kRInvDigits {0x80000000, 1, 0xffffffff, 0, 0x80000001, 0xfffffffe, 1, 0x7fffffff}  // 1 / 2^257 mod p256.p

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
      out[i] = P256_DIGIT(&in_shifted, 0) & kBottom29Bits;
      crypton_p256_shr(&in_shifted, 29, &in_shifted);
    } else {
      out[i] = P256_DIGIT(&in_shifted, 0) & kBottom28Bits;
      crypton_p256_shr(&in_shifted, 28, &in_shifted);
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
      top = crypton_p256_shl(&result, 29, &tmp);
    } else {
      top = crypton_p256_shl(&result, 28, &tmp);
    }
    top |= crypton_p256_add_d(&tmp, in[i], &result);
  }

  crypton_p256_modmul(&crypton_SECP256r1_p, &kRInv, top, &result, out);

  crypton_p256_clear(&result);
  crypton_p256_clear(&tmp);
}
