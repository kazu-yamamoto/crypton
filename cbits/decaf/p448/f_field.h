/**
 * @file p448/f_field.h
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Field-specific code for 2^448 - 2^224 - 1.
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */

#ifndef __P448_F_FIELD_H__
#define __P448_F_FIELD_H__ 1

#include "constant_time.h"
#include <string.h>
#include <assert.h>

#include "word.h"

#define __CRYPTON_DECAF_448_GF_DEFINED__ 1
#define NLIMBS (64/sizeof(word_t))
#define X_SER_BYTES 56
#define SER_BYTES 56
typedef struct crypton_gf_448_s {
    word_t limb[NLIMBS];
} __attribute__((aligned(32))) crypton_gf_448_s, crypton_gf_448_t[1];

#define GF_LIT_LIMB_BITS  56
#define GF_BITS           448
#define ZERO              crypton_gf_448_ZERO
#define ONE               crypton_gf_448_ONE
#define MODULUS           crypton_gf_448_MODULUS
#define gf                crypton_gf_448_t
#define crypton_gf_s              crypton_gf_448_s
#define crypton_gf_eq             crypton_gf_448_eq
#define crypton_gf_hibit          crypton_gf_448_hibit
#define crypton_gf_copy           crypton_gf_448_copy
#define crypton_gf_add            crypton_gf_448_add
#define crypton_gf_sub            crypton_gf_448_sub
#define crypton_gf_add_RAW        crypton_gf_448_add_RAW
#define crypton_gf_sub_RAW        crypton_gf_448_sub_RAW
#define crypton_gf_bias           crypton_gf_448_bias
#define crypton_gf_weak_reduce    crypton_gf_448_weak_reduce
#define crypton_gf_strong_reduce  crypton_gf_448_strong_reduce
#define crypton_gf_mul            crypton_gf_448_mul
#define crypton_gf_sqr            crypton_gf_448_sqr
#define crypton_gf_mulw_unsigned  crypton_gf_448_mulw_unsigned
#define crypton_gf_isr            crypton_gf_448_isr
#define crypton_gf_serialize      crypton_gf_448_serialize
#define crypton_gf_deserialize    crypton_gf_448_deserialize

/* RFC 7748 support */
#define X_PUBLIC_BYTES  X_SER_BYTES
#define X_PRIVATE_BYTES X_PUBLIC_BYTES
#define X_PRIVATE_BITS  448

#define SQRT_MINUS_ONE    P448_SQRT_MINUS_ONE /* might not be defined */

#define INLINE_UNUSED __inline__ __attribute__((unused,always_inline))

#ifdef __cplusplus
extern "C" {
#endif

/* Defined below in f_impl.h */
static INLINE_UNUSED void crypton_gf_copy (gf out, const gf a) { *out = *a; }
static INLINE_UNUSED void crypton_gf_add_RAW (gf out, const gf a, const gf b);
static INLINE_UNUSED void crypton_gf_sub_RAW (gf out, const gf a, const gf b);
static INLINE_UNUSED void crypton_gf_bias (gf inout, int amount);
static INLINE_UNUSED void crypton_gf_weak_reduce (gf inout);

void crypton_gf_strong_reduce (gf inout);   
void crypton_gf_add (gf out, const gf a, const gf b);
void crypton_gf_sub (gf out, const gf a, const gf b);
void crypton_gf_mul (crypton_gf_s *__restrict__ out, const gf a, const gf b);
void crypton_gf_mulw_unsigned (crypton_gf_s *__restrict__ out, const gf a, uint32_t b);
void crypton_gf_sqr (crypton_gf_s *__restrict__ out, const gf a);
mask_t crypton_gf_isr(gf a, const gf x); /** a^2 x = 1, QNR, or 0 if x=0.  Return true if successful */
mask_t crypton_gf_eq (const gf x, const gf y);
mask_t crypton_gf_hibit (const gf x);

void crypton_gf_serialize (uint8_t *serial, const gf x,int with_highbit);
mask_t crypton_gf_deserialize (gf x, const uint8_t serial[SER_BYTES],int with_highbit);


#ifdef __cplusplus
} /* extern "C" */
#endif

#include "f_impl.h" /* Bring in the inline implementations */

#define P_MOD_8 7
#if P_MOD_8 == 5
    extern const gf SQRT_MINUS_ONE;
#endif

#ifndef LIMBPERM
  #define LIMBPERM(i) (i)
#endif
#define LIMB_MASK(i) (((1ull)<<LIMB_PLACE_VALUE(i))-1)

static const gf ZERO = {{{0}}}, ONE = {{{ [LIMBPERM(0)] = 1 }}};

#endif /* __P448_F_FIELD_H__ */
