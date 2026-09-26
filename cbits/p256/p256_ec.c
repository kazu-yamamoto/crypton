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

#include "p256/p256_gf.h"


/* Field element operations: */

/* felem_inv calculates |out| = |in|^{-1}
 *
 * Based on Fermat's Little Theorem:
 *   a^p = a (mod p)
 *   a^{p-1} = 1 (mod p)
 *   a^{p-2} = a^{-1} (mod p)
 *
 * The exponent is built left to right from the shape of p - 2, which for
 * this prime is
 *
 *   ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffd
 *   \__32 ones__/ \_31 zeros, one 1_/ \______ 96 zeros ______/ \_94 ones, 0, 1_/
 *
 * A run of k zeros is k squarings; a run of k ones is k squarings and one
 * multiplication by a^(2^k - 1), which is why the powers below are kept.  The
 * whole chain is 255 squarings, which is the least an exponent of 256 bits
 * can be done in, and 13 multiplications.
 *
 * The chain this replaces built the low 94 ones in a second accumulator and
 * multiplied the two at the end, which cost 32 squarings more than the 255. */
static void felem_inv(felem out, const felem in) {
  felem ftmp, x2, x4, x8, x16, x32;
  unsigned i;

  /* x{k} holds in^(2^k - 1), a run of k ones. */
  felem_square(ftmp, in);
  felem_mul(x2, ftmp, in); /* 2^2 - 1 */

  felem_square(ftmp, x2);
  felem_square(ftmp, ftmp);
  felem_mul(x4, ftmp, x2); /* 2^4 - 1 */

  felem_assign(ftmp, x4);
  for (i = 0; i < 4; i++) {
    felem_square(ftmp, ftmp);
  }
  felem_mul(x8, ftmp, x4); /* 2^8 - 1 */

  felem_assign(ftmp, x8);
  for (i = 0; i < 8; i++) {
    felem_square(ftmp, ftmp);
  }
  felem_mul(x16, ftmp, x8); /* 2^16 - 1 */

  felem_assign(ftmp, x16);
  for (i = 0; i < 16; i++) {
    felem_square(ftmp, ftmp);
  }
  felem_mul(x32, ftmp, x16); /* 2^32 - 1 */

  /* The top 32 ones. */
  felem_assign(ftmp, x32);

  /* 31 zeros and a one: the 00000001 word. */
  for (i = 0; i < 32; i++) {
    felem_square(ftmp, ftmp);
  }
  felem_mul(ftmp, ftmp, in);

  /* 96 zeros. */
  for (i = 0; i < 96; i++) {
    felem_square(ftmp, ftmp);
  }

  /* 94 ones, as 32 + 32 + 16 + 8 + 4 + 2. */
  for (i = 0; i < 32; i++) {
    felem_square(ftmp, ftmp);
  }
  felem_mul(ftmp, ftmp, x32);
  for (i = 0; i < 32; i++) {
    felem_square(ftmp, ftmp);
  }
  felem_mul(ftmp, ftmp, x32);
  for (i = 0; i < 16; i++) {
    felem_square(ftmp, ftmp);
  }
  felem_mul(ftmp, ftmp, x16);
  for (i = 0; i < 8; i++) {
    felem_square(ftmp, ftmp);
  }
  felem_mul(ftmp, ftmp, x8);
  for (i = 0; i < 4; i++) {
    felem_square(ftmp, ftmp);
  }
  felem_mul(ftmp, ftmp, x4);
  felem_square(ftmp, ftmp);
  felem_square(ftmp, ftmp);
  felem_mul(ftmp, ftmp, x2);

  /* A zero and a one: the d of fffffffd. */
  felem_square(ftmp, ftmp);
  felem_square(ftmp, ftmp);
  felem_mul(out, ftmp, in);
}

/* Group operations:
 *
 * Elements of the elliptic curve group are represented in Jacobian
 * coordinates: (x, y, z). An affine point (x', y') is x'=x/z**2, y'=y/z**3 in
 * Jacobian form. */

/* point_double sets {x_out,y_out,z_out} = 2*{x,y,z}.
 *
 * See http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l */
static void point_double(felem x_out, felem y_out, felem z_out, const felem x,
                         const felem y, const felem z) {
  felem delta, gamma, alpha, beta, tmp, tmp2;

  felem_square(delta, z);
  felem_square(gamma, y);
  felem_mul(beta, x, gamma);

  felem_sum(tmp, x, delta);
  felem_diff(tmp2, x, delta);
  felem_mul(alpha, tmp, tmp2);
  felem_scalar_3(alpha);

  felem_sum(tmp, y, z);
  felem_square(tmp, tmp);
  felem_diff(tmp, tmp, gamma);
  felem_diff(z_out, tmp, delta);

  felem_scalar_4(beta);
  felem_square(x_out, alpha);
  felem_diff(x_out, x_out, beta);
  felem_diff(x_out, x_out, beta);

  felem_diff(tmp, beta, x_out);
  felem_mul(tmp, alpha, tmp);
  felem_square(tmp2, gamma);
  felem_scalar_8(tmp2);
  felem_diff(y_out, tmp, tmp2);
}

/* point_add_mixed sets {x_out,y_out,z_out} = {x1,y1,z1} + {x2,y2,1}.
 * (i.e. the second point is affine.)
 *
 * See http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
 *
 * Note that this function does not handle P+P, infinity+P nor P+infinity
 * correctly. */
static void point_add_mixed(felem x_out, felem y_out, felem z_out,
                            const felem x1, const felem y1, const felem z1,
                            const felem x2, const felem y2) {
  felem z1z1, z1z1z1, s2, u2, h, i, j, r, rr, v, tmp;

  felem_square(z1z1, z1);
  felem_sum(tmp, z1, z1);

  felem_mul(u2, x2, z1z1);
  felem_mul(z1z1z1, z1, z1z1);
  felem_mul(s2, y2, z1z1z1);
  felem_diff(h, u2, x1);
  felem_sum(i, h, h);
  felem_square(i, i);
  felem_mul(j, h, i);
  felem_diff(r, s2, y1);
  felem_sum(r, r, r);
  felem_mul(v, x1, i);

  felem_mul(z_out, tmp, h);
  felem_square(rr, r);
  felem_diff(x_out, rr, j);
  felem_diff(x_out, x_out, v);
  felem_diff(x_out, x_out, v);

  felem_diff(tmp, v, x_out);
  felem_mul(y_out, tmp, r);
  felem_mul(tmp, y1, j);
  felem_diff(y_out, y_out, tmp);
  felem_diff(y_out, y_out, tmp);
}

/* point_add sets {x_out,y_out,z_out} = {x1,y1,z1} + {x2,y2,z2}.
 *
 * See http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
 *
 * Note that this function does not handle P+P, infinity+P nor P+infinity
 * correctly. */
static void point_add(felem x_out, felem y_out, felem z_out, const felem x1,
                      const felem y1, const felem z1, const felem x2,
                      const felem y2, const felem z2) {
  felem z1z1, z1z1z1, z2z2, z2z2z2, s1, s2, u1, u2, h, i, j, r, rr, v, tmp;

  felem_square(z1z1, z1);
  felem_square(z2z2, z2);
  felem_mul(u1, x1, z2z2);

  felem_sum(tmp, z1, z2);
  felem_square(tmp, tmp);
  felem_diff(tmp, tmp, z1z1);
  felem_diff(tmp, tmp, z2z2);

  felem_mul(z2z2z2, z2, z2z2);
  felem_mul(s1, y1, z2z2z2);

  felem_mul(u2, x2, z1z1);
  felem_mul(z1z1z1, z1, z1z1);
  felem_mul(s2, y2, z1z1z1);
  felem_diff(h, u2, u1);
  felem_sum(i, h, h);
  felem_square(i, i);
  felem_mul(j, h, i);
  felem_diff(r, s2, s1);
  felem_sum(r, r, r);
  felem_mul(v, u1, i);

  felem_mul(z_out, tmp, h);
  felem_square(rr, r);
  felem_diff(x_out, rr, j);
  felem_diff(x_out, x_out, v);
  felem_diff(x_out, x_out, v);

  felem_diff(tmp, v, x_out);
  felem_mul(y_out, tmp, r);
  felem_mul(tmp, s1, j);
  felem_diff(y_out, y_out, tmp);
  felem_diff(y_out, y_out, tmp);
}

/* point_add_or_double_vartime sets {x_out,y_out,z_out} = {x1,y1,z1} +
 *                                                        {x2,y2,z2}.
 *
 * See http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
 *
 * This function handles the case where {x1,y1,z1}={x2,y2,z2}. */
static void point_add_or_double_vartime(
    felem x_out, felem y_out, felem z_out, const felem x1, const felem y1,
    const felem z1, const felem x2, const felem y2, const felem z2) {
  felem z1z1, z1z1z1, z2z2, z2z2z2, s1, s2, u1, u2, h, i, j, r, rr, v, tmp;
  char x_equal, y_equal;

  felem_square(z1z1, z1);
  felem_square(z2z2, z2);
  felem_mul(u1, x1, z2z2);

  felem_sum(tmp, z1, z2);
  felem_square(tmp, tmp);
  felem_diff(tmp, tmp, z1z1);
  felem_diff(tmp, tmp, z2z2);

  felem_mul(z2z2z2, z2, z2z2);
  felem_mul(s1, y1, z2z2z2);

  felem_mul(u2, x2, z1z1);
  felem_mul(z1z1z1, z1, z1z1);
  felem_mul(s2, y2, z1z1z1);
  felem_diff(h, u2, u1);
  x_equal = felem_is_zero_vartime(h);
  felem_sum(i, h, h);
  felem_square(i, i);
  felem_mul(j, h, i);
  felem_diff(r, s2, s1);
  y_equal = felem_is_zero_vartime(r);
  if (x_equal && y_equal) {
    point_double(x_out, y_out, z_out, x1, y1, z1);
    return;
  }
  felem_sum(r, r, r);
  felem_mul(v, u1, i);

  felem_mul(z_out, tmp, h);
  felem_square(rr, r);
  felem_diff(x_out, rr, j);
  felem_diff(x_out, x_out, v);
  felem_diff(x_out, x_out, v);

  felem_diff(tmp, v, x_out);
  felem_mul(y_out, tmp, r);
  felem_mul(tmp, s1, j);
  felem_diff(y_out, y_out, tmp);
  felem_diff(y_out, y_out, tmp);
}

/* copy_conditional sets out=in if mask = -1 in constant time.
 *
 * On entry: mask is either 0 or -1. */
static void copy_conditional(felem out, const felem in, limb mask) {
  int i;

  for (i = 0; i < NLIMBS; i++) {
    const limb tmp = mask & (in[i] ^ out[i]);
    out[i] ^= tmp;
  }
}

/* select_affine_point sets {out_x,out_y} to the index'th entry of table.
 * On entry: index < 16, table[0] must be zero. */
static void select_affine_point(felem out_x, felem out_y, const limb* table,
                                limb index) {
  limb i, j;

  memset(out_x, 0, sizeof(felem));
  memset(out_y, 0, sizeof(felem));

  for (i = 1; i < 16; i++) {
    limb mask = i ^ index;
    mask |= mask >> 2;
    mask |= mask >> 1;
    mask &= 1;
    mask--;
    for (j = 0; j < NLIMBS; j++, table++) {
      out_x[j] |= *table & mask;
    }
    for (j = 0; j < NLIMBS; j++, table++) {
      out_y[j] |= *table & mask;
    }
  }
}

/* scalar_base_mult sets {nx,ny,nz} = scalar*G where scalar is a little-endian
 * number. Note that the value of scalar must be less than the order of the
 * group. */
static void scalar_base_mult(felem nx, felem ny, felem nz,
                             const crypton_p256_int* scalar) {
  int i, j;
  limb n_is_infinity_mask = -1, p_is_noninfinite_mask, mask;
  u32 table_offset;

  felem px, py;
  felem tx, ty, tz;

  memset(nx, 0, sizeof(felem));
  memset(ny, 0, sizeof(felem));
  memset(nz, 0, sizeof(felem));

  /* The loop adds bits at positions 0, 64, 128 and 192, followed by
   * positions 32,96,160 and 224 and does this 32 times. */
  for (i = 0; i < 32; i++) {
    if (i) {
      point_double(nx, ny, nz, nx, ny, nz);
    }
    table_offset = 0;
    for (j = 0; j <= 32; j += 32) {
      char bit0 = crypton_p256_get_bit(scalar, 31 - i + j);
      char bit1 = crypton_p256_get_bit(scalar, 95 - i + j);
      char bit2 = crypton_p256_get_bit(scalar, 159 - i + j);
      char bit3 = crypton_p256_get_bit(scalar, 223 - i + j);
      limb index = bit0 | (bit1 << 1) | (bit2 << 2) | (bit3 << 3);

      select_affine_point(px, py, kPrecomputed + table_offset, index);
      table_offset += 30 * NLIMBS;

      /* Since scalar is less than the order of the group, we know that
       * {nx,ny,nz} != {px,py,1}, unless both are zero, which we handle
       * below. */
      point_add_mixed(tx, ty, tz, nx, ny, nz, px, py);
      /* The result of point_add_mixed is incorrect if {nx,ny,nz} is zero
       * (a.k.a.  the point at infinity). We handle that situation by
       * copying the point from the table. */
      copy_conditional(nx, px, n_is_infinity_mask);
      copy_conditional(ny, py, n_is_infinity_mask);
      copy_conditional(nz, kOne, n_is_infinity_mask);

      /* Equally, the result is also wrong if the point from the table is
       * zero, which happens when the index is zero. We handle that by
       * only copying from {tx,ty,tz} to {nx,ny,nz} if index != 0. */
      p_is_noninfinite_mask = NON_ZERO_TO_ALL_ONES(index);
      mask = p_is_noninfinite_mask & ~n_is_infinity_mask;
      copy_conditional(nx, tx, mask);
      copy_conditional(ny, ty, mask);
      copy_conditional(nz, tz, mask);
      /* If p was not zero, then n is now non-zero. */
      n_is_infinity_mask &= ~p_is_noninfinite_mask;
    }
  }
}

/* point_to_affine converts a Jacobian point to an affine point. If the input
 * is the point at infinity then it returns (0, 0) in constant time. */
static void point_to_affine(felem x_out, felem y_out, const felem nx,
                            const felem ny, const felem nz) {
  felem z_inv, z_inv_sq;
  felem_inv(z_inv, nz);
  felem_square(z_inv_sq, z_inv);
  felem_mul(x_out, nx, z_inv_sq);
  felem_mul(z_inv, z_inv, z_inv_sq);
  felem_mul(y_out, ny, z_inv);
}

/* point_add_mixed_pm sets {xp,yp,zp} = {x1,y1,z1} + {x2,y2} and
 * {xm,ym,zm} = {x1,y1,z1} - {x2,y2}, where {x2,y2} is affine.
 *
 * Negating the second point changes the sign of s2 and so of r, and nothing
 * else: z1z1, tmp, u2, z1z1z1, h, i, j, v, the output z and the product y1*j
 * are common to the two.  What the second point costs over the first is one
 * squaring (r*r) and one multiplication (by r), rather than another eleven.
 *
 * The same restrictions as point_add_mixed: this does not handle P+P,
 * infinity+P nor P+infinity. */
static void point_add_mixed_pm(felem xp, felem yp, felem zp,
                               felem xm, felem ym, felem zm,
                               const felem x1, const felem y1, const felem z1,
                               const felem x2, const felem y2) {
  felem z1z1, z1z1z1, s2, u2, h, i, j, r, rr, v, y1j, tmp;

  felem_square(z1z1, z1);
  felem_sum(tmp, z1, z1);

  felem_mul(u2, x2, z1z1);
  felem_mul(z1z1z1, z1, z1z1);
  felem_mul(s2, y2, z1z1z1);
  felem_diff(h, u2, x1);
  felem_sum(i, h, h);
  felem_square(i, i);
  felem_mul(j, h, i);
  felem_mul(v, x1, i);
  felem_mul(y1j, y1, j);

  /* The two points share their z. */
  felem_mul(zp, tmp, h);
  felem_assign(zm, zp);

  /* X + P */
  felem_diff(r, s2, y1);
  felem_sum(r, r, r);
  felem_square(rr, r);
  felem_diff(xp, rr, j);
  felem_diff(xp, xp, v);
  felem_diff(xp, xp, v);
  felem_diff(tmp, v, xp);
  felem_mul(yp, tmp, r);
  felem_diff(yp, yp, y1j);
  felem_diff(yp, yp, y1j);

  /* X - P.  Negating the point negates s2, so r becomes -q where
   * q = 2*(s2 + y1).  The square is the same either way, and the sign is
   * carried into y by taking (xm - v) where the other took (v - xp):
   *   xm = q^2 - j - 2v
   *   ym = (v - xm)*(-q) - 2*y1*j = (xm - v)*q - 2*y1*j
   * so no field negation is needed. */
  felem_sum(r, s2, y1);
  felem_sum(r, r, r);
  felem_square(rr, r);
  felem_diff(xm, rr, j);
  felem_diff(xm, xm, v);
  felem_diff(xm, xm, v);
  felem_diff(tmp, xm, v);
  felem_mul(ym, tmp, r);
  felem_diff(ym, ym, y1j);
  felem_diff(ym, ym, y1j);
}

/* select_jacobian_odd sets {out_x,out_y,out_z} to the index'th of the 16
 * entries of table, for index < 16.  There is no implicit infinity at index
 * zero, as the unsigned window this replaces had: every entry is a real
 * point, which is what lets the signed representation below do without the
 * infinity masks. */
static void select_jacobian_odd(felem out_x, felem out_y, felem out_z,
                                const limb* table, limb index) {
  limb i, j;

  memset(out_x, 0, sizeof(felem));
  memset(out_y, 0, sizeof(felem));
  memset(out_z, 0, sizeof(felem));

  for (i = 0; i < 16; i++) {
    limb mask = i ^ index;
    mask |= mask >> 2;
    mask |= mask >> 1;
    mask &= 1;
    mask--;
    for (j = 0; j < NLIMBS; j++, table++) {
      out_x[j] |= *table & mask;
    }
    for (j = 0; j < NLIMBS; j++, table++) {
      out_y[j] |= *table & mask;
    }
    for (j = 0; j < NLIMBS; j++, table++) {
      out_z[j] |= *table & mask;
    }
  }
}

/* The scalar, recoded: 52 signed odd digits, each in {+-1,+-3,...,+-31}, so
 * that scalar = sum d_i * 32^i.  A digit is one byte: the low four bits are
 * the table index (|d|-1)/2, and bit four is set when d is negative.  One
 * byte rather than a byte and a word because this is the private key in
 * another form and has to be wiped afterwards. */
#define SABS_DIGITS 52
#define SABS_INDEX(b) ((limb)((b) & 15))
#define SABS_NEGMASK(b) ((limb)0 - (limb)((b) >> 4))
typedef struct {
  u8 digit[SABS_DIGITS];
} sabs_scalar;

/* words_are_zero returns 1 when |v| is zero and 0 otherwise, without a
 * branch. */
static u32 words_are_zero(u32 v) {
  v |= v >> 16;
  v |= v >> 8;
  v |= v >> 4;
  v |= v >> 2;
  v |= v >> 1;
  return (v & 1) ^ 1;
}

/* sabs_recode writes the signed representation of |scalar| into |out|.
 *
 * The recoding is the regular one of Joye and Tunstall: take the low six bits,
 * subtract 32, and carry the difference upwards.  It needs an odd input, which
 * is arranged by adding the group order to an even scalar -- that changes the
 * scalar but not the point it selects, the order being the order.  A zero
 * scalar is replaced by one and the caller is told, since zero times a point
 * is the infinity this code deliberately cannot represent.
 *
 * *dbl_mask is set to all ones when the last addition of the main loop would
 * be an addition of a point to itself, which the formulas there cannot do.
 * That happens exactly when the recoded scalar k' is congruent to twice its
 * lowest digit: the accumulator entering that step is (k' - d0)*P and what it
 * adds is d0*P, so they coincide when k' - d0 = d0.  With k' below 2^257 and
 * |2*d0| at most 62, k' - 2*d0 is then either zero or the order itself, which
 * is what is tested for below.  No earlier step can do this: entering step i
 * the accumulator is 32*m*P with |32*m| below the order, and the digit is at
 * most 31 in absolute value, so the two can only coincide as integers, which
 * they cannot -- m is odd and so is never zero.
 *
 * Constant time in the scalar: every branch below is on a loop counter. */
static limb sabs_recode(sabs_scalar* out, limb* dbl_mask,
                        const crypton_p256_int* scalar) {
  u32 k[9], n[9], ksaved[9];
  u32 nonzero;
  limb is_zero_mask;
  int i, b;

  for (i = 0; i < 9; i++) {
    k[i] = 0;
    n[i] = 0;
  }
  /* A word at a time.  Bit at a time would be 512 calls into another
   * translation unit, which the compiler cannot inline away. */
  for (b = 0; b < 256; b += 32) {
    k[b >> 5] = (u32)(P256_DIGIT(scalar, b / P256_BITSPERDIGIT)
                      >> (b % P256_BITSPERDIGIT));
    n[b >> 5] = (u32)(P256_DIGIT(&crypton_SECP256r1_n, b / P256_BITSPERDIGIT)
                      >> (b % P256_BITSPERDIGIT));
  }

  /* Replace a zero scalar by one, and report it. */
  nonzero = 0;
  for (i = 0; i < 9; i++) {
    nonzero |= k[i];
  }
  {
    u32 z = words_are_zero(nonzero);
    k[0] |= z;
    is_zero_mask = (limb)0 - (limb)z;
  }

  /* An even scalar becomes odd by adding the order.  The sum is below 2^257,
   * which is why nine words and fifty-two digits are enough. */
  {
    u32 addmask = (u32)0 - (u32)((k[0] & 1) ^ 1);
    u64 carry = 0;
    for (i = 0; i < 9; i++) {
      u64 t = (u64)k[i] + (u64)(n[i] & addmask) + carry;
      k[i] = (u32)t;
      carry = t >> 32;
    }
  }

  for (i = 0; i < 9; i++) {
    ksaved[i] = k[i];
  }

  for (i = 0; i < SABS_DIGITS - 1; i++) {
    u32 r6 = k[0] & 63;            /* odd, so never 32 */
    u32 hi = (r6 >> 5) & 1;        /* 1 when the digit is positive */
    u32 wabs = ((r6 - 32) & (0u - hi)) | ((32 - r6) & (hi - 1));
    u32 mlo = 32u - r6;            /* two's complement of the digit's negation */
    u32 ext = 0u - hi;             /* its sign extension */
    u64 carry = 0;
    int w;

    out->digit[i] = (u8)(((wabs - 1) >> 1) | ((hi ^ 1) << 4));

    if (i == 0) {
      /* k' - 2*d0, against zero and against the order. */
      u32 two_w = (u32)(2u * r6) - 64u;   /* 2*d0, two's complement */
      u32 two_w_ext = 0u - (hi ^ 1);      /* its sign extension */
      u32 zero_acc = 0, order_acc = 0;
      u64 borrow = 0;
      int w2;
      for (w2 = 0; w2 < 9; w2++) {
        u32 sub = (w2 == 0) ? two_w : two_w_ext;
        u64 d = (u64)ksaved[w2] - ((u64)sub + borrow);
        u32 dw = (u32)d;
        borrow = (d >> 32) & 1;
        zero_acc |= dw;
        order_acc |= dw ^ n[w2];
      }
      zero_acc |= (u32)borrow;      /* a negative difference is neither */
      order_acc |= (u32)borrow;
      *dbl_mask = (limb)0 - (limb)(words_are_zero(zero_acc)
                                   | words_are_zero(order_acc));
    }

    /* k -= digit, i.e. k += -digit, sign extended over the nine words. */
    for (w = 0; w < 9; w++) {
      u64 t = (u64)k[w] + (u64)(w == 0 ? mlo : ext) + carry;
      k[w] = (u32)t;
      carry = t >> 32;
    }
    /* k >>= 5 */
    for (w = 0; w < 8; w++) {
      k[w] = (k[w] >> 5) | (k[w + 1] << 27);
    }
    k[8] >>= 5;
  }

  /* What is left is odd, positive and at most five: the scalar is below
   * 2^257 and fifty-one digits have taken 255 bits off it, each leaving a
   * remainder below one. */
  out->digit[SABS_DIGITS - 1] = (u8)((k[0] - 1) >> 1);

  return is_zero_mask;
}

/* scalar_mult sets {nx,ny,nz} = scalar*{x,y}.
 *
 * A five-bit signed window.  The scalar is recoded into 52 digits, every one
 * of them odd and none of them zero, so the table holds only the odd
 * multiples P, 3P, ..., 31P and a negative digit is served by negating y,
 * which is free.  Against the four-bit unsigned window this replaces, the
 * main loop trades 252 doublings and 64 additions for 255 and 51, and --
 * because no digit is zero and no partial sum is the infinity -- it drops the
 * masks that stood in for infinity on every iteration.
 *
 * The table is built so that each pair of neighbouring odd multiples comes
 * out of one doubling and one shared addition:
 *
 *   2P = 2*P                3P  = 2P + P
 *   6P = 2*(3P)             5P  = 6P - P,  7P  = 6P + P
 *   10P = 2*(5P)            9P  = 10P - P, 11P = 10P + P
 *   ...
 *   30P = 2*(15P)           29P = 30P - P, 31P = 30P + P
 *
 * which is eight doublings, one mixed addition and seven shared pairs. */
static void scalar_mult(felem nx, felem ny, felem nz, const felem x,
                        const felem y, const crypton_p256_int* scalar) {
  /* odd[k] is (2k+1)*P, for k in 0..15. */
  felem odd[16][3];
  felem dx, dy, dz, px, py, pz, negy, ddx, ddy, ddz;
  sabs_scalar rec;
  limb is_zero_mask, dbl_mask;
  int i, k;

  is_zero_mask = sabs_recode(&rec, &dbl_mask, scalar);

  felem_assign(odd[0][0], x);
  felem_assign(odd[0][1], y);
  memcpy(odd[0][2], kOne, sizeof(felem));

  /* 3P = 2P + P */
  point_double(dx, dy, dz, x, y, kOne);
  point_add_mixed(odd[1][0], odd[1][1], odd[1][2], dx, dy, dz, x, y);

  /* (4k+2)P from (2k+1)P, then (4k+1)P and (4k+3)P from it. */
  for (k = 1; k < 8; k++) {
    point_double(dx, dy, dz, odd[k][0], odd[k][1], odd[k][2]);
    point_add_mixed_pm(odd[2 * k + 1][0], odd[2 * k + 1][1], odd[2 * k + 1][2],
                       odd[2 * k][0], odd[2 * k][1], odd[2 * k][2],
                       dx, dy, dz, x, y);
  }

  /* The top digit initialises the accumulator; it is always positive. */
  select_jacobian_odd(nx, ny, nz, odd[0][0],
                      SABS_INDEX(rec.digit[SABS_DIGITS - 1]));

  for (i = SABS_DIGITS - 2; i >= 0; i--) {
    point_double(nx, ny, nz, nx, ny, nz);
    point_double(nx, ny, nz, nx, ny, nz);
    point_double(nx, ny, nz, nx, ny, nz);
    point_double(nx, ny, nz, nx, ny, nz);
    point_double(nx, ny, nz, nx, ny, nz);

    select_jacobian_odd(px, py, pz, odd[0][0], SABS_INDEX(rec.digit[i]));
    felem_diff(negy, kZero, py);
    copy_conditional(py, negy, SABS_NEGMASK(rec.digit[i]));

    /* point_add finishes with z before it touches x, and with each of x
     * and y before the next, so the accumulator can be its own output. */
    point_add(nx, ny, nz, nx, ny, nz, px, py, pz);

    /* On the last step alone the accumulator can be the very point being
     * added, and these formulas answer the infinity where the truth is twice
     * that point.  Doubling it is the answer there; the recoder said whether
     * this is that case.  One doubling on one of fifty-one iterations. */
    if (i == 0) {
      point_double(ddx, ddy, ddz, px, py, pz);
      copy_conditional(nx, ddx, dbl_mask);
      copy_conditional(ny, ddy, dbl_mask);
      copy_conditional(nz, ddz, dbl_mask);
    }
  }

  /* Zero was replaced by one on the way in; put the infinity back.  All
   * three coordinates, not just z: crypton_p256_points_mul_vartime reads the
   * comment above it as saying the whole point is zero. */
  for (i = 0; i < NLIMBS; i++) {
    nx[i] &= ~is_zero_mask;
    ny[i] &= ~is_zero_mask;
    nz[i] &= ~is_zero_mask;
  }

  /* The recoded scalar is the private key in another representation, so it
   * does not stay on the stack.  Written through a volatile pointer, since a
   * plain memset here is dead and may be dropped. */
  {
    volatile unsigned char* p = (volatile unsigned char*)&rec;
    unsigned b;
    for (b = 0; b < sizeof(rec); b++) {
      p[b] = 0;
    }
  }
}

/* crypton_p256_base_point_mul sets {out_x,out_y} = nG, where n is < the
 * order of the group. */
void crypton_p256_base_point_mul(const crypton_p256_int* n, crypton_p256_int* out_x, crypton_p256_int* out_y) {
  felem x, y, z;

  scalar_base_mult(x, y, z, n);

  {
    felem x_affine, y_affine;

    point_to_affine(x_affine, y_affine, x, y, z);
    from_montgomery(out_x, x_affine);
    from_montgomery(out_y, y_affine);
  }
}

/* crypton_p256_points_mul_vartime sets {out_x,out_y} = n1*G + n2*{in_x,in_y}, where
 * n1 and n2 are < the order of the group.
 *
 * As indicated by the name, this function operates in variable time. This
 * is safe because it's used for signature validation which doesn't deal
 * with secrets. */
void crypton_p256_points_mul_vartime(
    const crypton_p256_int* n1, const crypton_p256_int* n2, const crypton_p256_int* in_x,
    const crypton_p256_int* in_y, crypton_p256_int* out_x, crypton_p256_int* out_y) {
  felem x1, y1, z1, x2, y2, z2, px, py;

  /* If both scalars are zero, then the result is the point at infinity. */
  if (crypton_p256_is_zero(n1) != 0 && crypton_p256_is_zero(n2) != 0) {
    crypton_p256_clear(out_x);
    crypton_p256_clear(out_y);
    return;
  }

  to_montgomery(px, in_x);
  to_montgomery(py, in_y);
  scalar_base_mult(x1, y1, z1, n1);
  scalar_mult(x2, y2, z2, px, py, n2);

  if (crypton_p256_is_zero(n2) != 0) {
    /* If n2 == 0, then {x2,y2,z2} is zero and the result is just
         * {x1,y1,z1}. */
  } else if (crypton_p256_is_zero(n1) != 0) {
    /* If n1 == 0, then {x1,y1,z1} is zero and the result is just
         * {x2,y2,z2}. */
    memcpy(x1, x2, sizeof(x2));
    memcpy(y1, y2, sizeof(y2));
    memcpy(z1, z2, sizeof(z2));
  } else {
    /* This function handles the case where {x1,y1,z1} == {x2,y2,z2}. */
    point_add_or_double_vartime(x1, y1, z1, x1, y1, z1, x2, y2, z2);
  }

  point_to_affine(px, py, x1, y1, z1);
  from_montgomery(out_x, px);
  from_montgomery(out_y, py);
}

/* this function is not part of the original source
   add 2 points together. so far untested.
   probably vartime, as it use point_add_or_double_vartime
 */
void crypton_p256e_point_add(
    const crypton_p256_int *in_x1, const crypton_p256_int *in_y1,
    const crypton_p256_int *in_x2, const crypton_p256_int *in_y2,
    crypton_p256_int *out_x, crypton_p256_int *out_y)
{
    felem x, y, z, px1, py1, px2, py2;

    to_montgomery(px1, in_x1);
    to_montgomery(py1, in_y1);
    to_montgomery(px2, in_x2);
    to_montgomery(py2, in_y2);

    point_add_or_double_vartime(x, y, z, px1, py1, kOne, px2, py2, kOne);

    point_to_affine(px1, py1, x, y, z);
    from_montgomery(out_x, px1);
    from_montgomery(out_y, py1);
}

/* this function is not part of the original source
   negate a point, i.e. (out_x, out_y) = (in_x, -in_y)
 */
void crypton_p256e_point_negate(
    const crypton_p256_int *in_x, const crypton_p256_int *in_y,
    crypton_p256_int *out_x, crypton_p256_int *out_y)
{
    memcpy(out_x, in_x, P256_NBYTES);
    crypton_p256_sub(&crypton_SECP256r1_p, in_y, out_y);
}

/* this function is not part of the original source
   crypton_p256e_point_mul sets {out_x,out_y} = n*{in_x,in_y}, where
   n is < the order of the group.
 */
void crypton_p256e_point_mul(const crypton_p256_int* n,
    const crypton_p256_int* in_x, const crypton_p256_int* in_y,
    crypton_p256_int* out_x, crypton_p256_int* out_y) {
  felem x, y, z, px, py;

  to_montgomery(px, in_x);
  to_montgomery(py, in_y);
  scalar_mult(x, y, z, px, py, n);
  point_to_affine(px, py, x, y, z);
  from_montgomery(out_x, px);
  from_montgomery(out_y, py);
}
