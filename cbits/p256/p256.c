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

// This is an implementation of the P256 elliptic curve group. It's written to
// be portable and still constant-time.
//
// WARNING: Implementing these functions in a constant-time manner is far from
//          obvious. Be careful when touching this code.
//
// See http://www.imperialviolet.org/2010/12/04/ecc.html ([1]) for background.

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "p256/p256.h"

const crypton_p256_int crypton_SECP256r1_n =  // curve order
  {{P256_LITERAL(0xfc632551, 0xf3b9cac2), P256_LITERAL(0xa7179e84, 0xbce6faad),
    P256_LITERAL(-1, -1), P256_LITERAL(0, -1)}};

const crypton_p256_int crypton_SECP256r1_p =  // curve field size
  {{P256_LITERAL(-1, -1), P256_LITERAL(-1, 0),
    P256_LITERAL(0, 0), P256_LITERAL(1, -1) }};

const crypton_p256_int crypton_SECP256r1_b =  // curve b
  {{P256_LITERAL(0x27d2604b, 0x3bce3c3e), P256_LITERAL(0xcc53b0f6, 0x651d06b0),
    P256_LITERAL(0x769886bc, 0xb3ebbd55), P256_LITERAL(0xaa3a93e7, 0x5ac635d8)}};

void crypton_p256_init(crypton_p256_int* a) {
  memset(a, 0, sizeof(*a));
}

void crypton_p256_clear(crypton_p256_int* a) { crypton_p256_init(a); }

int crypton_p256_get_bit(const crypton_p256_int* scalar, int bit) {
  return (P256_DIGIT(scalar, bit / P256_BITSPERDIGIT)
              >> (bit & (P256_BITSPERDIGIT - 1))) & 1;
}

int crypton_p256_is_zero(const crypton_p256_int* a) {
  crypton_p256_digit result = 0;
  int i = 0;
  for (i = 0; i < P256_NDIGITS; ++i) result |= P256_DIGIT(a, i);
  return result == 0;
}

// top, c[] += a[] * b
// Returns new top
static crypton_p256_digit mulAdd(const crypton_p256_int* a,
                         crypton_p256_digit b,
                         crypton_p256_digit top,
                         crypton_p256_digit* c) {
  int i;
  crypton_p256_ddigit carry = 0;

  for (i = 0; i < P256_NDIGITS; ++i) {
    carry += *c;
    carry += (crypton_p256_ddigit)P256_DIGIT(a, i) * b;
    *c++ = (crypton_p256_digit)carry;
    carry >>= P256_BITSPERDIGIT;
  }
  return top + (crypton_p256_digit)carry;
}

// top, c[] -= top_a, a[]
static crypton_p256_digit subTop(crypton_p256_digit top_a,
                         const crypton_p256_digit* a,
                         crypton_p256_digit top_c,
                         crypton_p256_digit* c) {
  int i;
  crypton_p256_sddigit borrow = 0;

  for (i = 0; i < P256_NDIGITS; ++i) {
    borrow += *c;
    borrow -= *a++;
    *c++ = (crypton_p256_digit)borrow;
    borrow >>= P256_BITSPERDIGIT;
  }
  borrow += top_c;
  borrow -= top_a;
  top_c = (crypton_p256_digit)borrow;
  assert((borrow >> P256_BITSPERDIGIT) == 0);
  return top_c;
}

// top, c[] -= MOD[] & mask (0 or -1)
// returns new top.
static crypton_p256_digit subM(const crypton_p256_int* MOD,
                       crypton_p256_digit top,
                       crypton_p256_digit* c,
                       crypton_p256_digit mask) {
  int i;
  crypton_p256_sddigit borrow = 0;
  for (i = 0; i < P256_NDIGITS; ++i) {
    borrow += *c;
    borrow -= P256_DIGIT(MOD, i) & mask;
    *c++ = (crypton_p256_digit)borrow;
    borrow >>= P256_BITSPERDIGIT;
  }
  return top + (crypton_p256_digit)borrow;
}

// top, c[] += MOD[] & mask (0 or -1)
// returns new top.
static crypton_p256_digit addM(const crypton_p256_int* MOD,
                       crypton_p256_digit top,
                       crypton_p256_digit* c,
                       crypton_p256_digit mask) {
  int i;
  crypton_p256_ddigit carry = 0;
  for (i = 0; i < P256_NDIGITS; ++i) {
    carry += *c;
    carry += P256_DIGIT(MOD, i) & mask;
    *c++ = (crypton_p256_digit)carry;
    carry >>= P256_BITSPERDIGIT;
  }
  return top + (crypton_p256_digit)carry;
}

// c = a * b mod MOD. c can be a and/or b.
void crypton_p256_modmul(const crypton_p256_int* MOD,
                 const crypton_p256_int* a,
                 const crypton_p256_digit top_b,
                 const crypton_p256_int* b,
                 crypton_p256_int* c) {
  crypton_p256_digit tmp[P256_NDIGITS * 2 + 1] = { 0 };
  crypton_p256_digit top = 0;
  int i;

  // Multiply/add into tmp.
  for (i = 0; i < P256_NDIGITS; ++i) {
    if (i) tmp[i + P256_NDIGITS - 1] = top;
    top = mulAdd(a, P256_DIGIT(b, i), 0, tmp + i);
  }

  // Multiply/add top digit
  tmp[i + P256_NDIGITS - 1] = top;
  top = mulAdd(a, top_b, 0, tmp + i);

  // Reduce tmp, digit by digit.
  for (; i >= 0; --i) {
    crypton_p256_digit reducer[P256_NDIGITS] = { 0 };
    crypton_p256_digit top_reducer;

    // top can be any value at this point.
    // Guestimate reducer as top * MOD, since msw of MOD is -1.
    top_reducer = mulAdd(MOD, top, 0, reducer);
#if P256_BITSPERDIGIT > 32
    // Correction when msw of MOD has only high 32 bits set
    top_reducer += mulAdd(MOD, top >> 32, 0, reducer);
#endif

    // Subtract reducer from top | tmp.
    top = subTop(top_reducer, reducer, top, tmp + i);

    // top is now either 0 or 1. Make it 0, fixed-timing.
    assert(top <= 1);

    top = subM(MOD, top, tmp + i, ~(top - 1));

    assert(top == 0);

    // We have now reduced the top digit off tmp. Fetch new top digit.
    top = tmp[i + P256_NDIGITS - 1];
  }

  // tmp might still be larger than MOD, yet same bit length.
  // Make sure it is less, fixed-timing.
  addM(MOD, 0, tmp, subM(MOD, 0, tmp, -1));

  memcpy(c, tmp, P256_NBYTES);
}
int crypton_p256_is_odd(const crypton_p256_int* a) { return P256_DIGIT(a, 0) & 1; }
int crypton_p256_is_even(const crypton_p256_int* a) { return !(P256_DIGIT(a, 0) & 1); }

crypton_p256_digit crypton_p256_shl(const crypton_p256_int* a, int n, crypton_p256_int* b) {
  int i;
  crypton_p256_digit top = P256_DIGIT(a, P256_NDIGITS - 1);

  n %= P256_BITSPERDIGIT;
  for (i = P256_NDIGITS - 1; i > 0; --i) {
    crypton_p256_digit accu = (P256_DIGIT(a, i) << n);
    accu |= (P256_DIGIT(a, i - 1) >> (P256_BITSPERDIGIT - n));
    P256_DIGIT(b, i) = accu;
  }
  P256_DIGIT(b, i) = (P256_DIGIT(a, i) << n);

  top = (crypton_p256_digit)((((crypton_p256_ddigit)top) << n) >> P256_BITSPERDIGIT);

  return top;
}

void crypton_p256_shr(const crypton_p256_int* a, int n, crypton_p256_int* b) {
  int i;

  n %= P256_BITSPERDIGIT;
  for (i = 0; i < P256_NDIGITS - 1; ++i) {
    crypton_p256_digit accu = (P256_DIGIT(a, i) >> n);
    accu |= (P256_DIGIT(a, i + 1) << (P256_BITSPERDIGIT - n));
    P256_DIGIT(b, i) = accu;
  }
  P256_DIGIT(b, i) = (P256_DIGIT(a, i) >> n);
}

static void crypton_p256_shr1(const crypton_p256_int* a, int highbit, crypton_p256_int* b) {
  int i;

  for (i = 0; i < P256_NDIGITS - 1; ++i) {
    crypton_p256_digit accu = (P256_DIGIT(a, i) >> 1);
    accu |= (P256_DIGIT(a, i + 1) << (P256_BITSPERDIGIT - 1));
    P256_DIGIT(b, i) = accu;
  }
  P256_DIGIT(b, i) = (P256_DIGIT(a, i) >> 1) |
      (((crypton_p256_sdigit) highbit) << (P256_BITSPERDIGIT - 1));
}

// Return -1, 0, 1 for a < b, a == b or a > b respectively.
int crypton_p256_cmp(const crypton_p256_int* a, const crypton_p256_int* b) {
  int i;
  crypton_p256_sddigit borrow = 0;
  crypton_p256_digit notzero = 0;

  for (i = 0; i < P256_NDIGITS; ++i) {
    borrow += (crypton_p256_sddigit)P256_DIGIT(a, i) - P256_DIGIT(b, i);
    // Track whether any result digit is ever not zero.
    // Relies on !!(non-zero) evaluating to 1, e.g., !!(-1) evaluating to 1.
    notzero |= !!((crypton_p256_digit)borrow);
    borrow >>= P256_BITSPERDIGIT;
  }
  return (int)borrow | notzero;
}

// c = a - b. Returns borrow: 0 or -1.
int crypton_p256_sub(const crypton_p256_int* a, const crypton_p256_int* b, crypton_p256_int* c) {
  int i;
  crypton_p256_sddigit borrow = 0;

  for (i = 0; i < P256_NDIGITS; ++i) {
    borrow += (crypton_p256_sddigit)P256_DIGIT(a, i) - P256_DIGIT(b, i);
    if (c) P256_DIGIT(c, i) = (crypton_p256_digit)borrow;
    borrow >>= P256_BITSPERDIGIT;
  }
  return (int)borrow;
}

// c = a + b. Returns carry: 0 or 1.
int crypton_p256_add(const crypton_p256_int* a, const crypton_p256_int* b, crypton_p256_int* c) {
  int i;
  crypton_p256_ddigit carry = 0;

  for (i = 0; i < P256_NDIGITS; ++i) {
    carry += (crypton_p256_ddigit)P256_DIGIT(a, i) + P256_DIGIT(b, i);
    if (c) P256_DIGIT(c, i) = (crypton_p256_digit)carry;
    carry >>= P256_BITSPERDIGIT;
  }
  return (int)carry;
}

// b = a + d. Returns carry, 0 or 1.
int crypton_p256_add_d(const crypton_p256_int* a, crypton_p256_digit d, crypton_p256_int* b) {
  int i;
  crypton_p256_ddigit carry = d;

  for (i = 0; i < P256_NDIGITS; ++i) {
    carry += (crypton_p256_ddigit)P256_DIGIT(a, i);
    if (b) P256_DIGIT(b, i) = (crypton_p256_digit)carry;
    carry >>= P256_BITSPERDIGIT;
  }
  return (int)carry;
}

// b = 1/a mod MOD, binary euclid.
void crypton_p256_modinv_vartime(const crypton_p256_int* MOD,
                         const crypton_p256_int* a,
                         crypton_p256_int* b) {
  crypton_p256_int R = P256_ZERO;
  crypton_p256_int S = P256_ONE;
  crypton_p256_int U = *MOD;
  crypton_p256_int V = *a;

  for (;;) {
    if (crypton_p256_is_even(&U)) {
      crypton_p256_shr1(&U, 0, &U);
      if (crypton_p256_is_even(&R)) {
        crypton_p256_shr1(&R, 0, &R);
      } else {
        // R = (R+MOD)/2
        crypton_p256_shr1(&R, crypton_p256_add(&R, MOD, &R), &R);
      }
    } else if (crypton_p256_is_even(&V)) {
      crypton_p256_shr1(&V, 0, &V);
      if (crypton_p256_is_even(&S)) {
        crypton_p256_shr1(&S, 0, &S);
      } else {
        // S = (S+MOD)/2
        crypton_p256_shr1(&S, crypton_p256_add(&S, MOD, &S) , &S);
      }
    } else {  // U,V both odd.
      if (!crypton_p256_sub(&V, &U, NULL)) {
        crypton_p256_sub(&V, &U, &V);
        if (crypton_p256_sub(&S, &R, &S)) crypton_p256_add(&S, MOD, &S);
        if (crypton_p256_is_zero(&V)) break;  // done.
      } else {
        crypton_p256_sub(&U, &V, &U);
        if (crypton_p256_sub(&R, &S, &R)) crypton_p256_add(&R, MOD, &R);
      }
    }
  }

  crypton_p256_mod(MOD, &R, b);
}

void crypton_p256_mod(const crypton_p256_int* MOD,
              const crypton_p256_int* in,
              crypton_p256_int* out) {
  if (out != in) *out = *in;
  addM(MOD, 0, P256_DIGITS(out), subM(MOD, 0, P256_DIGITS(out), -1));
}

// Verify y^2 == x^3 - 3x + b mod p
// and 0 < x < p and 0 < y < p
int crypton_p256_is_valid_point(const crypton_p256_int* x, const crypton_p256_int* y) {
  crypton_p256_int y2, x3;

  if (crypton_p256_cmp(&crypton_SECP256r1_p, x) <= 0 ||
      crypton_p256_cmp(&crypton_SECP256r1_p, y) <= 0 ||
      crypton_p256_is_zero(x) ||
      crypton_p256_is_zero(y)) return 0;

  crypton_p256_modmul(&crypton_SECP256r1_p, y, 0, y, &y2);  // y^2

  crypton_p256_modmul(&crypton_SECP256r1_p, x, 0, x, &x3);  // x^2
  crypton_p256_modmul(&crypton_SECP256r1_p, x, 0, &x3, &x3);  // x^3
  if (crypton_p256_sub(&x3, x, &x3)) crypton_p256_add(&x3, &crypton_SECP256r1_p, &x3);  // x^3 - x
  if (crypton_p256_sub(&x3, x, &x3)) crypton_p256_add(&x3, &crypton_SECP256r1_p, &x3);  // x^3 - 2x
  if (crypton_p256_sub(&x3, x, &x3)) crypton_p256_add(&x3, &crypton_SECP256r1_p, &x3);  // x^3 - 3x
  if (crypton_p256_add(&x3, &crypton_SECP256r1_b, &x3))  // x^3 - 3x + b
    crypton_p256_sub(&x3, &crypton_SECP256r1_p, &x3);

  return crypton_p256_cmp(&y2, &x3) == 0;
}

void crypton_p256_from_bin(const uint8_t src[P256_NBYTES], crypton_p256_int* dst) {
  int i, n;
  const uint8_t* p = &src[0];

  for (i = P256_NDIGITS - 1; i >= 0; --i) {
    crypton_p256_digit dig = 0;
    n = P256_BITSPERDIGIT;
    while (n > 0) {
      n -= 8;
      dig |= ((crypton_p256_digit) *(p++)) << n;
    }
    P256_DIGIT(dst, i) = dig;
  }
}

void crypton_p256_to_bin(const crypton_p256_int* src, uint8_t dst[P256_NBYTES])
{
	int i, n;
	uint8_t* p = &dst[0];

	for (i = P256_NDIGITS -1; i >= 0; --i) {
		const crypton_p256_digit dig = P256_DIGIT(src, i);
		n = P256_BITSPERDIGIT;
		while (n > 0) {
			n -= 8;
			*(p++) = dig >> n;
		}
	}
}

/*
  "p256e" functions are not part of the original source
*/

#define MSB_COMPLEMENT(x) (((x) >> (P256_BITSPERDIGIT - 1)) - 1)

// c = a + b mod MOD
void crypton_p256e_modadd(const crypton_p256_int* MOD, const crypton_p256_int* a, const crypton_p256_int* b, crypton_p256_int* c) {
  assert(c);  /* avoid repeated checks inside inlined crypton_p256_add */
  crypton_p256_digit top = crypton_p256_add(a, b, c);
  top = subM(MOD, top, P256_DIGITS(c), -1);
  top = subM(MOD, top, P256_DIGITS(c), MSB_COMPLEMENT(top));
  addM(MOD, 0, P256_DIGITS(c), top);
}

// c = a - b mod MOD
void crypton_p256e_modsub(const crypton_p256_int* MOD, const crypton_p256_int* a, const crypton_p256_int* b, crypton_p256_int* c) {
  assert(c); /* avoid repeated checks inside inlined crypton_p256_sub */
  crypton_p256_digit top = crypton_p256_sub(a, b, c);
  top = addM(MOD, top, P256_DIGITS(c), ~MSB_COMPLEMENT(top));
  top = subM(MOD, top, P256_DIGITS(c), MSB_COMPLEMENT(top));
  addM(MOD, 0, P256_DIGITS(c), top);
}

#define NTH_DOUBLE_THEN_ADD(i, a, nth, b, out)   \
    crypton_p256e_montmul(a, a, out);         \
    for (i = 1; i < nth; i++)                    \
        crypton_p256e_montmul(out, out, out); \
    crypton_p256e_montmul(out, b, out);

const crypton_p256_int crypton_SECP256r1_r2 = // r^2 mod n
  {{P256_LITERAL(0xBE79EEA2, 0x83244C95), P256_LITERAL(0x49BD6FA6, 0x4699799C),
    P256_LITERAL(0x2B6BEC59, 0x2845B239), P256_LITERAL(0xF3D95620, 0x66E12D94)}};

const crypton_p256_int crypton_SECP256r1_one = {{1}};

// Montgomery multiplication, i.e. c = ab/r mod n with r = 2^256.
// Implementation is adapted from 'sc_montmul' in libdecaf.
static void crypton_p256e_montmul(const crypton_p256_int* a, const crypton_p256_int* b, crypton_p256_int* c) {
  int i, j, borrow;
  crypton_p256_digit accum[P256_NDIGITS+1] = {0};
  crypton_p256_digit hi_carry = 0;

  for (i=0; i<P256_NDIGITS; i++) {
    crypton_p256_digit mand = P256_DIGIT(a, i);
    const crypton_p256_digit *mier = P256_DIGITS(b);

    crypton_p256_ddigit chain = 0;
    for (j=0; j<P256_NDIGITS; j++) {
      chain += ((crypton_p256_ddigit)mand)*mier[j] + accum[j];
      accum[j] = chain;
      chain >>= P256_BITSPERDIGIT;
    }
    accum[j] = chain;

    mand = accum[0] * P256_MONTGOMERY_FACTOR;
    chain = 0;
    mier = P256_DIGITS(&crypton_SECP256r1_n);
    for (j=0; j<P256_NDIGITS; j++) {
      chain += (crypton_p256_ddigit)mand*mier[j] + accum[j];
      if (j) accum[j-1] = chain;
      chain >>= P256_BITSPERDIGIT;
    }
    chain += accum[j];
    chain += hi_carry;
    accum[j-1] = chain;
    hi_carry = chain >> P256_BITSPERDIGIT;
  }

  memcpy(P256_DIGITS(c), accum, sizeof(*c));
  borrow = crypton_p256_sub(c, &crypton_SECP256r1_n, c);
  addM(&crypton_SECP256r1_n, 0, P256_DIGITS(c), borrow + hi_carry);
}

// b = 1/a mod n, using Fermat's little theorem.
void crypton_p256e_scalar_invert(const crypton_p256_int* a, crypton_p256_int* b) {
  crypton_p256_int _1, _10, _11, _101, _111, _1010, _1111;
  crypton_p256_int _10101, _101010, _101111, x6, x8, x16, x32;
  int i;

  // Montgomerize
  crypton_p256e_montmul(a, &crypton_SECP256r1_r2, &_1);

  // P-256 (secp256r1) Scalar Inversion
  // <https://briansmith.org/ecc-inversion-addition-chains-01>
  crypton_p256e_montmul(&_1     , &_1     , &_10);
  crypton_p256e_montmul(&_10    , &_1     , &_11);
  crypton_p256e_montmul(&_10    , &_11    , &_101);
  crypton_p256e_montmul(&_10    , &_101   , &_111);
  crypton_p256e_montmul(&_101   , &_101   , &_1010);
  crypton_p256e_montmul(&_101   , &_1010  , &_1111);
  NTH_DOUBLE_THEN_ADD(i, &_1010,  1   , &_1     , &_10101);
  crypton_p256e_montmul(&_10101 , &_10101 , &_101010);
  crypton_p256e_montmul(&_101   , &_101010, &_101111);
  crypton_p256e_montmul(&_10101 , &_101010, &x6);
  NTH_DOUBLE_THEN_ADD(i, &x6   ,  2   , &_11    , &x8);
  NTH_DOUBLE_THEN_ADD(i, &x8   ,  8   , &x8     , &x16);
  NTH_DOUBLE_THEN_ADD(i, &x16  , 16   , &x16    , &x32);

  NTH_DOUBLE_THEN_ADD(i, &x32  , 32+32, &x32    , b);
  NTH_DOUBLE_THEN_ADD(i, b     ,    32, &x32    , b);
  NTH_DOUBLE_THEN_ADD(i, b     ,     6, &_101111, b);
  NTH_DOUBLE_THEN_ADD(i, b     , 2 + 3, &_111   , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 2 + 2, &_11    , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 1 + 4, &_1111  , b);
  NTH_DOUBLE_THEN_ADD(i, b     ,     5, &_10101 , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 1 + 3, &_101   , b);
  NTH_DOUBLE_THEN_ADD(i, b     ,     3, &_101   , b);
  NTH_DOUBLE_THEN_ADD(i, b     ,     3, &_101   , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 2 + 3, &_111   , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 3 + 6, &_101111, b);
  NTH_DOUBLE_THEN_ADD(i, b     , 2 + 4, &_1111  , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 1 + 1, &_1     , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 4 + 1, &_1     , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 2 + 4, &_1111  , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 2 + 3, &_111   , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 1 + 3, &_111   , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 2 + 3, &_111   , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 2 + 3, &_101   , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 1 + 2, &_11    , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 4 + 6, &_101111, b);
  NTH_DOUBLE_THEN_ADD(i, b     ,     2, &_11    , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 3 + 2, &_11    , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 3 + 2, &_11    , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 2 + 1, &_1     , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 2 + 5, &_10101 , b);
  NTH_DOUBLE_THEN_ADD(i, b     , 2 + 4, &_1111  , b);

  // Demontgomerize
  crypton_p256e_montmul(b, &crypton_SECP256r1_one, b);
}
