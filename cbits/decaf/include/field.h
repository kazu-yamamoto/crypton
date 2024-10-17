/**
 * @file field.h
 * @brief Generic gf header.
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 */

#ifndef __GF_H__
#define __GF_H__

#include "constant_time.h"
#include "f_field.h"
#include <string.h>
    
/** Square x, n times. */
static CRYPTON_DECAF_INLINE void crypton_gf_sqrn (
    crypton_gf_s *__restrict__ y,
    const gf x,
    int n
) {
    gf tmp;
    assert(n>0);
    if (n&1) {
        crypton_gf_sqr(y,x);
        n--;
    } else {
        crypton_gf_sqr(tmp,x);
        crypton_gf_sqr(y,tmp);
        n-=2;
    }
    for (; n; n-=2) {
        crypton_gf_sqr(tmp,y);
        crypton_gf_sqr(y,tmp);
    }
}

#define crypton_gf_add_nr crypton_gf_add_RAW

/** Subtract mod p.  Bias by 2 and don't reduce  */
static inline void crypton_gf_sub_nr ( gf c, const gf a, const gf b ) {
    crypton_gf_sub_RAW(c,a,b);
    crypton_gf_bias(c, 2);
    if (GF_HEADROOM < 3) crypton_gf_weak_reduce(c);
}

/** Subtract mod p. Bias by amt but don't reduce.  */
static inline void crypton_gf_subx_nr ( gf c, const gf a, const gf b, int amt ) {
    crypton_gf_sub_RAW(c,a,b);
    crypton_gf_bias(c, amt);
    if (GF_HEADROOM < amt+1) crypton_gf_weak_reduce(c);
}

/** Mul by signed int.  Not constant-time WRT the sign of that int. */
static inline void crypton_gf_mulw(gf c, const gf a, int32_t w) {
    if (w>0) {
        crypton_gf_mulw_unsigned(c, a, w);
    } else {
        crypton_gf_mulw_unsigned(c, a, -w);
        crypton_gf_sub(c,ZERO,c);
    }
}

/** Constant time, x = is_z ? z : y */
static inline void crypton_gf_cond_sel(gf x, const gf y, const gf z, mask_t is_z) {
    constant_time_select(x,y,z,sizeof(gf),is_z,0);
}

/** Constant time, if (neg) x=-x; */
static inline void crypton_gf_cond_neg(gf x, mask_t neg) {
    gf y;
    crypton_gf_sub(y,ZERO,x);
    crypton_gf_cond_sel(x,x,y,neg);
}

/** Constant time, if (swap) (x,y) = (y,x); */
static inline void
crypton_gf_cond_swap(gf x, crypton_gf_s *__restrict__ y, mask_t swap) {
    constant_time_cond_swap(x,y,sizeof(crypton_gf_s),swap);
}

static CRYPTON_DECAF_INLINE void crypton_gf_mul_qnr(crypton_gf_s *__restrict__ out, const gf x) {
#if P_MOD_8 == 5
    /* r = QNR * r0^2 */
    crypton_gf_mul(out,x,SQRT_MINUS_ONE);
#elif P_MOD_8 == 3 || P_MOD_8 == 7
    crypton_gf_sub(out,ZERO,x);
#else
    #error "Only supporting p=3,5,7 mod 8"
#endif
}

static CRYPTON_DECAF_INLINE void crypton_gf_div_qnr(crypton_gf_s *__restrict__ out, const gf x) {
#if P_MOD_8 == 5
    /* r = QNR * r0^2 */
    crypton_gf_mul(out,x,SQRT_MINUS_ONE);
    crypton_gf_sub(out,ZERO,out);
#elif P_MOD_8 == 3 || P_MOD_8 == 7
    crypton_gf_sub(out,ZERO,x);
#else
    #error "Only supporting p=3,5,7 mod 8"
#endif
}

#if P_MOD_8 == 5
#define crypton_gf_mul_i crypton_gf_mul_qnr
#define crypton_gf_div_i crypton_gf_div_qnr
#endif


#endif // __GF_H__
