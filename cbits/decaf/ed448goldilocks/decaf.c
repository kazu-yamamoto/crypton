/**
 * @file ed448goldilocks/decaf.c
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Decaf high-level functions.
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */
#define _XOPEN_SOURCE 600 /* for posix_memalign */
#include "word.h"
#include "field.h"

#include <decaf.h>
#include <decaf/ed448.h>

/* Template stuff */
#define API_NS(_id) crypton_decaf_448_##_id
#define SCALAR_BITS CRYPTON_DECAF_448_SCALAR_BITS
#define SCALAR_SER_BYTES CRYPTON_DECAF_448_SCALAR_BYTES
#define SCALAR_LIMBS CRYPTON_DECAF_448_SCALAR_LIMBS
#define scalar_t API_NS(scalar_t)
#define point_t API_NS(point_t)
#define precomputed_s API_NS(precomputed_s)
#define IMAGINE_TWIST 0
#define COFACTOR 4

/* Comb config: number of combs, n, t, s. */
#define COMBS_N 5
#define COMBS_T 5
#define COMBS_S 18
#define CRYPTON_DECAF_WINDOW_BITS 5
#define CRYPTON_DECAF_WNAF_FIXED_TABLE_BITS 5
#define CRYPTON_DECAF_WNAF_VAR_TABLE_BITS 3

#define EDDSA_USE_SIGMA_ISOGENY 0

static const int EDWARDS_D = -39081;
static const scalar_t point_scalarmul_adjustment = {{{
    SC_LIMB(0xc873d6d54a7bb0cf), SC_LIMB(0xe933d8d723a70aad), SC_LIMB(0xbb124b65129c96fd), SC_LIMB(0x00000008335dc163)
}}}, precomputed_scalarmul_adjustment = {{{
    SC_LIMB(0xc873d6d54a7bb0cf), SC_LIMB(0xe933d8d723a70aad), SC_LIMB(0xbb124b65129c96fd), SC_LIMB(0x00000008335dc163)
}}};

const uint8_t crypton_decaf_x448_base_point[CRYPTON_DECAF_X448_PUBLIC_BYTES] = { 0x05 };

#if COFACTOR==8 || EDDSA_USE_SIGMA_ISOGENY
    static const gf SQRT_ONE_MINUS_D = {FIELD_LITERAL(
        /* NONE */
    )};
#endif

/* End of template stuff */

/* Sanity */
#if (COFACTOR == 8) && !IMAGINE_TWIST && !UNSAFE_CURVE_HAS_POINTS_AT_INFINITY
/* FUTURE MAGIC: Curve41417 doesn't have these properties. */
#error "Currently require IMAGINE_TWIST (and thus p=5 mod 8) for cofactor 8"
        /* OK, but why?
         * Two reasons: #1: There are bugs when COFACTOR == && IMAGINE_TWIST
         # #2: 
         */
#endif

#if IMAGINE_TWIST && (P_MOD_8 != 5)
    #error "Cannot use IMAGINE_TWIST except for p == 5 mod 8"
#endif

#if (COFACTOR != 8) && (COFACTOR != 4)
    #error "COFACTOR must be 4 or 8"
#endif
 
#if IMAGINE_TWIST
    extern const gf SQRT_MINUS_ONE;
#endif

#define WBITS CRYPTON_DECAF_WORD_BITS /* NB this may be different from ARCH_WORD_BITS */

extern const point_t API_NS(point_base);

/* Projective Niels coordinates */
typedef struct { gf a, b, c; } niels_s, niels_t[1];
typedef struct { niels_t n; gf z; } VECTOR_ALIGNED pniels_s, pniels_t[1];

/* Precomputed base */
struct precomputed_s { niels_t table [COMBS_N<<(COMBS_T-1)]; };

extern const gf API_NS(precomputed_base_as_fe)[];
const precomputed_s *API_NS(precomputed_base) =
    (const precomputed_s *) &API_NS(precomputed_base_as_fe);

const size_t API_NS(sizeof_precomputed_s) = sizeof(precomputed_s);
const size_t API_NS(alignof_precomputed_s) = sizeof(big_register_t);

/** Inverse. */
static void
crypton_gf_invert(gf y, const gf x, int assert_nonzero) {
    gf t1, t2;
    crypton_gf_sqr(t1, x); // o^2
    mask_t ret = crypton_gf_isr(t2, t1); // +-1/sqrt(o^2) = +-1/o
    (void)ret;
    if (assert_nonzero) assert(ret);
    crypton_gf_sqr(t1, t2);
    crypton_gf_mul(t2, t1, x); // not direct to y in case of alias.
    crypton_gf_copy(y, t2);
}

/** Return high bit of x = low bit of 2x mod p */
static mask_t crypton_gf_lobit(const gf x) {
    gf y;
    crypton_gf_copy(y,x);
    crypton_gf_strong_reduce(y);
    return -(y->limb[0]&1);
}

/** identity = (0,1) */
const point_t API_NS(point_identity) = {{{{{0}}},{{{1}}},{{{1}}},{{{0}}}}};

void API_NS(deisogenize) (
    crypton_gf_s *__restrict__ s,
    crypton_gf_s *__restrict__ minus_t_over_s,
    const point_t p,
    mask_t toggle_hibit_s,
    mask_t toggle_hibit_t_over_s,
    mask_t toggle_rotation
);

void API_NS(deisogenize) (
    crypton_gf_s *__restrict__ s,
    crypton_gf_s *__restrict__ minus_t_over_s,
    const point_t p,
    mask_t toggle_hibit_s,
    mask_t toggle_hibit_t_over_s,
    mask_t toggle_rotation
) {
#if COFACTOR == 4 && !IMAGINE_TWIST
    (void) toggle_rotation;
    
    gf b, d;
    crypton_gf_s *c = s, *a = minus_t_over_s;
    crypton_gf_mulw(a, p->y, 1-EDWARDS_D);
    crypton_gf_mul(c, a, p->t);     /* -dYT, with EDWARDS_D = d-1 */
    crypton_gf_mul(a, p->x, p->z); 
    crypton_gf_sub(d, c, a);  /* aXZ-dYT with a=-1 */
    crypton_gf_add(a, p->z, p->y); 
    crypton_gf_sub(b, p->z, p->y); 
    crypton_gf_mul(c, b, a);
    crypton_gf_mulw(b, c, -EDWARDS_D); /* (a-d)(Z+Y)(Z-Y) */
    mask_t ok = crypton_gf_isr (a,b); /* r in the paper */
    (void)ok; assert(ok | crypton_gf_eq(b,ZERO));
    crypton_gf_mulw (b, a, -EDWARDS_D); /* u in the paper */

    crypton_gf_mul(c,a,d); /* r(aZX-dYT) */
    crypton_gf_mul(a,b,p->z); /* uZ */
    crypton_gf_add(a,a,a); /* 2uZ */
    
    mask_t tg = toggle_hibit_t_over_s ^ ~crypton_gf_hibit(minus_t_over_s);
    crypton_gf_cond_neg(minus_t_over_s, tg); /* t/s <-? -t/s */
    crypton_gf_cond_neg(c, tg); /* u <- -u if negative. */
    
    crypton_gf_add(d,c,p->y);
    crypton_gf_mul(s,b,d);
    crypton_gf_cond_neg(s, toggle_hibit_s ^ crypton_gf_hibit(s));
#else
    /* More complicated because of rotation */
    /* MAGIC This code is wrong for certain non-Curve25519 curves;
     * check if it's because of Cofactor==8 or IMAGINE_TWIST */
    
    gf c, d;
    crypton_gf_s *b = s, *a = minus_t_over_s;

    #if IMAGINE_TWIST
        gf x, t;
        crypton_gf_div_qnr(x,p->x);
        crypton_gf_div_qnr(t,p->t);
        crypton_gf_add ( a, p->z, x );
        crypton_gf_sub ( b, p->z, x );
        crypton_gf_mul ( c, a, b ); /* "zx" = Z^2 - aX^2 = Z^2 - X^2 */
    #else
        const crypton_gf_s *x = p->x, *t = p->t;
        crypton_gf_sqr ( a, p->z );
        crypton_gf_sqr ( b, p->x );
        crypton_gf_add ( c, a, b ); /* "zx" = Z^2 - aX^2 = Z^2 + X^2 */
    #endif
    /* Here: c = "zx" in the SAGE code = Z^2 - aX^2 */
    
    crypton_gf_mul ( a, p->z, t ); /* "tz" = T*Z */
    crypton_gf_sqr ( b, a );
    crypton_gf_mul ( d, b, c ); /* (TZ)^2 * (Z^2-aX^2) */
    mask_t ok = crypton_gf_isr(b, d);
    (void)ok; assert(ok | crypton_gf_eq(d,ZERO));
    crypton_gf_mul ( d, b, a ); /* "osx" = 1 / sqrt(z^2-ax^2) */
    crypton_gf_mul ( a, b, c ); 
    crypton_gf_mul ( b, a, d ); /* 1/tz */

    mask_t rotate;
    #if (COFACTOR == 8)
        gf e;
        crypton_gf_sqr(e, p->z);
        crypton_gf_mul(a, e, b); /* z^2 / tz = z/t = 1/xy */
        rotate = crypton_gf_hibit(a) ^ toggle_rotation;
        /* Curve25519: cond select between zx * 1/tz or sqrt(1-d); y=-x */
        crypton_gf_mul ( a, b, c ); 
        crypton_gf_cond_sel ( a, a, SQRT_ONE_MINUS_D, rotate );
        crypton_gf_cond_sel ( e, p->y, x, rotate );
    #else
        const crypton_gf_s *e = x;
        (void)toggle_rotation;
        rotate = 0;
    #endif
    
    crypton_gf_mul ( c, a, d ); // new "osx"
    crypton_gf_mul ( a, c, p->z );
    crypton_gf_add ( minus_t_over_s, a, a ); // 2 * "osx" * Z
    crypton_gf_mul ( d, b, p->z );
    
    mask_t tg = toggle_hibit_t_over_s ^~ crypton_gf_hibit(minus_t_over_s);
    crypton_gf_cond_neg ( minus_t_over_s, tg );
    crypton_gf_cond_neg ( c, rotate ^ tg );
    crypton_gf_add ( d, d, c );
    crypton_gf_mul ( s, d, e ); /* here "x" = y unless rotate */
    crypton_gf_cond_neg ( s, toggle_hibit_s ^ crypton_gf_hibit(s) );
#endif
}

void API_NS(point_encode)( unsigned char ser[SER_BYTES], const point_t p ) {
    gf s, mtos;
    API_NS(deisogenize)(s,mtos,p,0,0,0);
    crypton_gf_serialize(ser,s,0);
}

crypton_decaf_error_t API_NS(point_decode) (
    point_t p,
    const unsigned char ser[SER_BYTES],
    crypton_decaf_bool_t allow_identity
) {
    gf s, a, b, c, d, e, f;
    mask_t succ = crypton_gf_deserialize(s, ser, 0);
    mask_t zero = crypton_gf_eq(s, ZERO);
    succ &= bool_to_mask(allow_identity) | ~zero;
    crypton_gf_sqr ( a, s ); /* s^2 */
#if IMAGINE_TWIST
    crypton_gf_sub ( f, ONE, a ); /* f = 1-as^2 = 1-s^2*/
#else
    crypton_gf_add ( f, ONE, a ); /* f = 1-as^2 = 1+s^2 */
#endif
    succ &= ~ crypton_gf_eq( f, ZERO );
    crypton_gf_sqr ( b, f );  /* (1-as^2)^2 = 1 - 2as^2 + a^2 s^4 */
    crypton_gf_mulw ( c, a, 4*IMAGINE_TWIST-4*EDWARDS_D ); 
    crypton_gf_add ( c, c, b ); /* t^2 = 1 + (2a-4d) s^2 + s^4 */
    crypton_gf_mul ( d, f, s ); /* s * (1-as^2) for denoms */
    crypton_gf_sqr ( e, d );    /* s^2 * (1-as^2)^2 */
    crypton_gf_mul ( b, c, e ); /* t^2 * s^2 * (1-as^2)^2 */
    
    succ &= crypton_gf_isr(e,b) | crypton_gf_eq(b,ZERO); /* e = 1/(t s (1-as^2)) */
    crypton_gf_mul ( b, e, d ); /* 1 / t */
    crypton_gf_mul ( d, e, c ); /* t / (s(1-as^2)) */
    crypton_gf_mul ( e, d, f ); /* t / s */
    mask_t negtos = crypton_gf_hibit(e);
    crypton_gf_cond_neg(b, negtos);
    crypton_gf_cond_neg(d, negtos);

#if IMAGINE_TWIST
    crypton_gf_add ( p->z, ONE, a); /* Z = 1+as^2 = 1-s^2 */
#else
    crypton_gf_sub ( p->z, ONE, a); /* Z = 1+as^2 = 1-s^2 */
#endif

#if COFACTOR == 8
    crypton_gf_mul ( a, p->z, d); /* t(1+s^2) / s(1-s^2) = 2/xy */
    succ &= ~crypton_gf_lobit(a); /* = ~crypton_gf_hibit(a/2), since crypton_gf_hibit(x) = crypton_gf_lobit(2x) */
#endif
    
    crypton_gf_mul ( a, f, b ); /* y = (1-s^2) / t */
    crypton_gf_mul ( p->y, p->z, a ); /* Y = yZ */
#if IMAGINE_TWIST
    crypton_gf_add ( b, s, s );
    crypton_gf_mul(p->x, b, SQRT_MINUS_ONE); /* Curve25519 */
#else
    crypton_gf_add ( p->x, s, s );
#endif
    crypton_gf_mul ( p->t, p->x, a ); /* T = 2s (1-as^2)/t */
    
#if UNSAFE_CURVE_HAS_POINTS_AT_INFINITY
    /* This can't happen for any of the supported configurations.
     *
     * If it can happen (because s=1), it's because the curve has points
     * at infinity, which means that there may be critical security bugs
     * elsewhere in the library.  In that case, it's better that you hit
     * the assertion in point_valid, which will happen in the test suite
     * since it tests s=1.
     *
     * This debugging option is to allow testing of IMAGINE_TWIST = 0 on
     * Ed25519, without hitting that assertion.  Don't use it in
     * production.
     */
    succ &= ~crypton_gf_eq(p->z,ZERO);
#endif
    
    p->y->limb[0] -= zero;
    assert(API_NS(point_valid)(p) | ~succ);
    
    return crypton_decaf_succeed_if(mask_to_bool(succ));
}

#if IMAGINE_TWIST
#define TWISTED_D (-(EDWARDS_D))
#else
#define TWISTED_D ((EDWARDS_D)-1)
#endif

#if TWISTED_D < 0
#define EFF_D (-(TWISTED_D))
#define NEG_D 1
#else
#define EFF_D TWISTED_D
#define NEG_D 0
#endif

void API_NS(point_sub) (
    point_t p,
    const point_t q,
    const point_t r
) {
    gf a, b, c, d;
    crypton_gf_sub_nr ( b, q->y, q->x ); /* 3+e */
    crypton_gf_sub_nr ( d, r->y, r->x ); /* 3+e */
    crypton_gf_add_nr ( c, r->y, r->x ); /* 2+e */
    crypton_gf_mul ( a, c, b );
    crypton_gf_add_nr ( b, q->y, q->x ); /* 2+e */
    crypton_gf_mul ( p->y, d, b );
    crypton_gf_mul ( b, r->t, q->t );
    crypton_gf_mulw ( p->x, b, 2*EFF_D );
    crypton_gf_add_nr ( b, a, p->y );    /* 2+e */
    crypton_gf_sub_nr ( c, p->y, a );    /* 3+e */
    crypton_gf_mul ( a, q->z, r->z );
    crypton_gf_add_nr ( a, a, a );       /* 2+e */
    if (GF_HEADROOM <= 3) crypton_gf_weak_reduce(a); /* or 1+e */
#if NEG_D
    crypton_gf_sub_nr ( p->y, a, p->x ); /* 4+e or 3+e */
    crypton_gf_add_nr ( a, a, p->x );    /* 3+e or 2+e */
#else
    crypton_gf_add_nr ( p->y, a, p->x ); /* 3+e or 2+e */
    crypton_gf_sub_nr ( a, a, p->x );    /* 4+e or 3+e */
#endif
    crypton_gf_mul ( p->z, a, p->y );
    crypton_gf_mul ( p->x, p->y, c );
    crypton_gf_mul ( p->y, a, b );
    crypton_gf_mul ( p->t, b, c );
}
    
void API_NS(point_add) (
    point_t p,
    const point_t q,
    const point_t r
) {
    gf a, b, c, d;
    crypton_gf_sub_nr ( b, q->y, q->x ); /* 3+e */
    crypton_gf_sub_nr ( c, r->y, r->x ); /* 3+e */
    crypton_gf_add_nr ( d, r->y, r->x ); /* 2+e */
    crypton_gf_mul ( a, c, b );
    crypton_gf_add_nr ( b, q->y, q->x ); /* 2+e */
    crypton_gf_mul ( p->y, d, b );
    crypton_gf_mul ( b, r->t, q->t );
    crypton_gf_mulw ( p->x, b, 2*EFF_D );
    crypton_gf_add_nr ( b, a, p->y );    /* 2+e */
    crypton_gf_sub_nr ( c, p->y, a );    /* 3+e */
    crypton_gf_mul ( a, q->z, r->z );
    crypton_gf_add_nr ( a, a, a );       /* 2+e */
    if (GF_HEADROOM <= 3) crypton_gf_weak_reduce(a); /* or 1+e */
#if NEG_D
    crypton_gf_add_nr ( p->y, a, p->x ); /* 3+e or 2+e */
    crypton_gf_sub_nr ( a, a, p->x );    /* 4+e or 3+e */
#else
    crypton_gf_sub_nr ( p->y, a, p->x ); /* 4+e or 3+e */
    crypton_gf_add_nr ( a, a, p->x );    /* 3+e or 2+e */
#endif
    crypton_gf_mul ( p->z, a, p->y );
    crypton_gf_mul ( p->x, p->y, c );
    crypton_gf_mul ( p->y, a, b );
    crypton_gf_mul ( p->t, b, c );
}

static CRYPTON_DECAF_NOINLINE void
point_double_internal (
    point_t p,
    const point_t q,
    int before_double
) {
    gf a, b, c, d;
    crypton_gf_sqr ( c, q->x );
    crypton_gf_sqr ( a, q->y );
    crypton_gf_add_nr ( d, c, a );             /* 2+e */
    crypton_gf_add_nr ( p->t, q->y, q->x );    /* 2+e */
    crypton_gf_sqr ( b, p->t );
    crypton_gf_subx_nr ( b, b, d, 3 );         /* 4+e */
    crypton_gf_sub_nr ( p->t, a, c );          /* 3+e */
    crypton_gf_sqr ( p->x, q->z );
    crypton_gf_add_nr ( p->z, p->x, p->x );    /* 2+e */
    crypton_gf_subx_nr ( a, p->z, p->t, 4 );   /* 6+e */
    if (GF_HEADROOM == 5) crypton_gf_weak_reduce(a); /* or 1+e */
    crypton_gf_mul ( p->x, a, b );
    crypton_gf_mul ( p->z, p->t, a );
    crypton_gf_mul ( p->y, p->t, d );
    if (!before_double) crypton_gf_mul ( p->t, b, d );
}

void API_NS(point_double)(point_t p, const point_t q) {
    point_double_internal(p,q,0);
}

void API_NS(point_negate) (
   point_t nega,
   const point_t a
) {
    crypton_gf_sub(nega->x, ZERO, a->x);
    crypton_gf_copy(nega->y, a->y);
    crypton_gf_copy(nega->z, a->z);
    crypton_gf_sub(nega->t, ZERO, a->t);
}

/* Operations on [p]niels */
static CRYPTON_DECAF_INLINE void
cond_neg_niels (
    niels_t n,
    mask_t neg
) {
    crypton_gf_cond_swap(n->a, n->b, neg);
    crypton_gf_cond_neg(n->c, neg);
}

static CRYPTON_DECAF_NOINLINE void pt_to_pniels (
    pniels_t b,
    const point_t a
) {
    crypton_gf_sub ( b->n->a, a->y, a->x );
    crypton_gf_add ( b->n->b, a->x, a->y );
    crypton_gf_mulw ( b->n->c, a->t, 2*TWISTED_D );
    crypton_gf_add ( b->z, a->z, a->z );
}

static CRYPTON_DECAF_NOINLINE void pniels_to_pt (
    point_t e,
    const pniels_t d
) {
    gf eu;
    crypton_gf_add ( eu, d->n->b, d->n->a );
    crypton_gf_sub ( e->y, d->n->b, d->n->a );
    crypton_gf_mul ( e->t, e->y, eu);
    crypton_gf_mul ( e->x, d->z, e->y );
    crypton_gf_mul ( e->y, d->z, eu );
    crypton_gf_sqr ( e->z, d->z );
}

static CRYPTON_DECAF_NOINLINE void
niels_to_pt (
    point_t e,
    const niels_t n
) {
    crypton_gf_add ( e->y, n->b, n->a );
    crypton_gf_sub ( e->x, n->b, n->a );
    crypton_gf_mul ( e->t, e->y, e->x );
    crypton_gf_copy ( e->z, ONE );
}

static CRYPTON_DECAF_NOINLINE void
add_niels_to_pt (
    point_t d,
    const niels_t e,
    int before_double
) {
    gf a, b, c;
    crypton_gf_sub_nr ( b, d->y, d->x ); /* 3+e */
    crypton_gf_mul ( a, e->a, b );
    crypton_gf_add_nr ( b, d->x, d->y ); /* 2+e */
    crypton_gf_mul ( d->y, e->b, b );
    crypton_gf_mul ( d->x, e->c, d->t );
    crypton_gf_add_nr ( c, a, d->y );    /* 2+e */
    crypton_gf_sub_nr ( b, d->y, a );    /* 3+e */
    crypton_gf_sub_nr ( d->y, d->z, d->x ); /* 3+e */
    crypton_gf_add_nr ( a, d->x, d->z ); /* 2+e */
    crypton_gf_mul ( d->z, a, d->y );
    crypton_gf_mul ( d->x, d->y, b );
    crypton_gf_mul ( d->y, a, c );
    if (!before_double) crypton_gf_mul ( d->t, b, c );
}

static CRYPTON_DECAF_NOINLINE void
sub_niels_from_pt (
    point_t d,
    const niels_t e,
    int before_double
) {
    gf a, b, c;
    crypton_gf_sub_nr ( b, d->y, d->x ); /* 3+e */
    crypton_gf_mul ( a, e->b, b );
    crypton_gf_add_nr ( b, d->x, d->y ); /* 2+e */
    crypton_gf_mul ( d->y, e->a, b );
    crypton_gf_mul ( d->x, e->c, d->t );
    crypton_gf_add_nr ( c, a, d->y );    /* 2+e */
    crypton_gf_sub_nr ( b, d->y, a );    /* 3+e */
    crypton_gf_add_nr ( d->y, d->z, d->x ); /* 2+e */
    crypton_gf_sub_nr ( a, d->z, d->x ); /* 3+e */
    crypton_gf_mul ( d->z, a, d->y );
    crypton_gf_mul ( d->x, d->y, b );
    crypton_gf_mul ( d->y, a, c );
    if (!before_double) crypton_gf_mul ( d->t, b, c );
}

static void
add_pniels_to_pt (
    point_t p,
    const pniels_t pn,
    int before_double
) {
    gf L0;
    crypton_gf_mul ( L0, p->z, pn->z );
    crypton_gf_copy ( p->z, L0 );
    add_niels_to_pt( p, pn->n, before_double );
}

static void
sub_pniels_from_pt (
    point_t p,
    const pniels_t pn,
    int before_double
) {
    gf L0;
    crypton_gf_mul ( L0, p->z, pn->z );
    crypton_gf_copy ( p->z, L0 );
    sub_niels_from_pt( p, pn->n, before_double );
}

static CRYPTON_DECAF_NOINLINE void
prepare_fixed_window(
    pniels_t *multiples,
    const point_t b,
    int ntable
) {
    point_t tmp;
    pniels_t pn;
    int i;
    
    point_double_internal(tmp, b, 0);
    pt_to_pniels(pn, tmp);
    pt_to_pniels(multiples[0], b);
    API_NS(point_copy)(tmp, b);
    for (i=1; i<ntable; i++) {
        add_pniels_to_pt(tmp, pn, 0);
        pt_to_pniels(multiples[i], tmp);
    }
    
    crypton_decaf_bzero(pn,sizeof(pn));
    crypton_decaf_bzero(tmp,sizeof(tmp));
}

void API_NS(point_scalarmul) (
    point_t a,
    const point_t b,
    const scalar_t scalar
) {
    const int WINDOW = CRYPTON_DECAF_WINDOW_BITS,
        WINDOW_MASK = (1<<WINDOW)-1,
        WINDOW_T_MASK = WINDOW_MASK >> 1,
        NTABLE = 1<<(WINDOW-1);
        
    scalar_t scalar1x;
    API_NS(scalar_add)(scalar1x, scalar, point_scalarmul_adjustment);
    API_NS(scalar_halve)(scalar1x,scalar1x);
    
    /* Set up a precomputed table with odd multiples of b. */
    pniels_t pn, multiples[NTABLE];
    point_t tmp;
    prepare_fixed_window(multiples, b, NTABLE);

    /* Initialize. */
    int i,j,first=1;
    i = SCALAR_BITS - ((SCALAR_BITS-1) % WINDOW) - 1;

    for (; i>=0; i-=WINDOW) {
        /* Fetch another block of bits */
        word_t bits = scalar1x->limb[i/WBITS] >> (i%WBITS);
        if (i%WBITS >= WBITS-WINDOW && i/WBITS<SCALAR_LIMBS-1) {
            bits ^= scalar1x->limb[i/WBITS+1] << (WBITS - (i%WBITS));
        }
        bits &= WINDOW_MASK;
        mask_t inv = (bits>>(WINDOW-1))-1;
        bits ^= inv;
    
        /* Add in from table.  Compute t only on last iteration. */
        constant_time_lookup(pn, multiples, sizeof(pn), NTABLE, bits & WINDOW_T_MASK);
        cond_neg_niels(pn->n, inv);
        if (first) {
            pniels_to_pt(tmp, pn);
            first = 0;
        } else {
           /* Using Hisil et al's lookahead method instead of extensible here
            * for no particular reason.  Double WINDOW times, but only compute t on
            * the last one.
            */
            for (j=0; j<WINDOW-1; j++)
                point_double_internal(tmp, tmp, -1);
            point_double_internal(tmp, tmp, 0);
            add_pniels_to_pt(tmp, pn, i ? -1 : 0);
        }
    }
    
    /* Write out the answer */
    API_NS(point_copy)(a,tmp);
    
    crypton_decaf_bzero(scalar1x,sizeof(scalar1x));
    crypton_decaf_bzero(pn,sizeof(pn));
    crypton_decaf_bzero(multiples,sizeof(multiples));
    crypton_decaf_bzero(tmp,sizeof(tmp));
}

void API_NS(point_double_scalarmul) (
    point_t a,
    const point_t b,
    const scalar_t scalarb,
    const point_t c,
    const scalar_t scalarc
) {
    const int WINDOW = CRYPTON_DECAF_WINDOW_BITS,
        WINDOW_MASK = (1<<WINDOW)-1,
        WINDOW_T_MASK = WINDOW_MASK >> 1,
        NTABLE = 1<<(WINDOW-1);
        
    scalar_t scalar1x, scalar2x;
    API_NS(scalar_add)(scalar1x, scalarb, point_scalarmul_adjustment);
    API_NS(scalar_halve)(scalar1x,scalar1x);
    API_NS(scalar_add)(scalar2x, scalarc, point_scalarmul_adjustment);
    API_NS(scalar_halve)(scalar2x,scalar2x);
    
    /* Set up a precomputed table with odd multiples of b. */
    pniels_t pn, multiples1[NTABLE], multiples2[NTABLE];
    point_t tmp;
    prepare_fixed_window(multiples1, b, NTABLE);
    prepare_fixed_window(multiples2, c, NTABLE);

    /* Initialize. */
    int i,j,first=1;
    i = SCALAR_BITS - ((SCALAR_BITS-1) % WINDOW) - 1;

    for (; i>=0; i-=WINDOW) {
        /* Fetch another block of bits */
        word_t bits1 = scalar1x->limb[i/WBITS] >> (i%WBITS),
                     bits2 = scalar2x->limb[i/WBITS] >> (i%WBITS);
        if (i%WBITS >= WBITS-WINDOW && i/WBITS<SCALAR_LIMBS-1) {
            bits1 ^= scalar1x->limb[i/WBITS+1] << (WBITS - (i%WBITS));
            bits2 ^= scalar2x->limb[i/WBITS+1] << (WBITS - (i%WBITS));
        }
        bits1 &= WINDOW_MASK;
        bits2 &= WINDOW_MASK;
        mask_t inv1 = (bits1>>(WINDOW-1))-1;
        mask_t inv2 = (bits2>>(WINDOW-1))-1;
        bits1 ^= inv1;
        bits2 ^= inv2;
    
        /* Add in from table.  Compute t only on last iteration. */
        constant_time_lookup(pn, multiples1, sizeof(pn), NTABLE, bits1 & WINDOW_T_MASK);
        cond_neg_niels(pn->n, inv1);
        if (first) {
            pniels_to_pt(tmp, pn);
            first = 0;
        } else {
           /* Using Hisil et al's lookahead method instead of extensible here
            * for no particular reason.  Double WINDOW times, but only compute t on
            * the last one.
            */
            for (j=0; j<WINDOW-1; j++)
                point_double_internal(tmp, tmp, -1);
            point_double_internal(tmp, tmp, 0);
            add_pniels_to_pt(tmp, pn, 0);
        }
        constant_time_lookup(pn, multiples2, sizeof(pn), NTABLE, bits2 & WINDOW_T_MASK);
        cond_neg_niels(pn->n, inv2);
        add_pniels_to_pt(tmp, pn, i?-1:0);
    }
    
    /* Write out the answer */
    API_NS(point_copy)(a,tmp);
    

    crypton_decaf_bzero(scalar1x,sizeof(scalar1x));
    crypton_decaf_bzero(scalar2x,sizeof(scalar2x));
    crypton_decaf_bzero(pn,sizeof(pn));
    crypton_decaf_bzero(multiples1,sizeof(multiples1));
    crypton_decaf_bzero(multiples2,sizeof(multiples2));
    crypton_decaf_bzero(tmp,sizeof(tmp));
}

void API_NS(point_dual_scalarmul) (
    point_t a1,
    point_t a2,
    const point_t b,
    const scalar_t scalar1,
    const scalar_t scalar2
) {
    const int WINDOW = CRYPTON_DECAF_WINDOW_BITS,
        WINDOW_MASK = (1<<WINDOW)-1,
        WINDOW_T_MASK = WINDOW_MASK >> 1,
        NTABLE = 1<<(WINDOW-1);
        
    scalar_t scalar1x, scalar2x;
    API_NS(scalar_add)(scalar1x, scalar1, point_scalarmul_adjustment);
    API_NS(scalar_halve)(scalar1x,scalar1x);
    API_NS(scalar_add)(scalar2x, scalar2, point_scalarmul_adjustment);
    API_NS(scalar_halve)(scalar2x,scalar2x);
    
    /* Set up a precomputed table with odd multiples of b. */
    point_t multiples1[NTABLE], multiples2[NTABLE], working, tmp;
    pniels_t pn;
    
    API_NS(point_copy)(working, b);

    /* Initialize. */
    int i,j;
    
    for (i=0; i<NTABLE; i++) {
        API_NS(point_copy)(multiples1[i], API_NS(point_identity));
        API_NS(point_copy)(multiples2[i], API_NS(point_identity));
    }

    for (i=0; i<SCALAR_BITS; i+=WINDOW) {   
        if (i) {
            for (j=0; j<WINDOW-1; j++)
                point_double_internal(working, working, -1);
            point_double_internal(working, working, 0);
        }
        
        /* Fetch another block of bits */
        word_t bits1 = scalar1x->limb[i/WBITS] >> (i%WBITS),
               bits2 = scalar2x->limb[i/WBITS] >> (i%WBITS);
        if (i%WBITS >= WBITS-WINDOW && i/WBITS<SCALAR_LIMBS-1) {
            bits1 ^= scalar1x->limb[i/WBITS+1] << (WBITS - (i%WBITS));
            bits2 ^= scalar2x->limb[i/WBITS+1] << (WBITS - (i%WBITS));
        }
        bits1 &= WINDOW_MASK;
        bits2 &= WINDOW_MASK;
        mask_t inv1 = (bits1>>(WINDOW-1))-1;
        mask_t inv2 = (bits2>>(WINDOW-1))-1;
        bits1 ^= inv1;
        bits2 ^= inv2;
        
        pt_to_pniels(pn, working);

        constant_time_lookup(tmp, multiples1, sizeof(tmp), NTABLE, bits1 & WINDOW_T_MASK);
        cond_neg_niels(pn->n, inv1);
        /* add_pniels_to_pt(multiples1[bits1 & WINDOW_T_MASK], pn, 0); */
        add_pniels_to_pt(tmp, pn, 0);
        constant_time_insert(multiples1, tmp, sizeof(tmp), NTABLE, bits1 & WINDOW_T_MASK);
        
        
        constant_time_lookup(tmp, multiples2, sizeof(tmp), NTABLE, bits2 & WINDOW_T_MASK);
        cond_neg_niels(pn->n, inv1^inv2);
        /* add_pniels_to_pt(multiples2[bits2 & WINDOW_T_MASK], pn, 0); */
        add_pniels_to_pt(tmp, pn, 0);
        constant_time_insert(multiples2, tmp, sizeof(tmp), NTABLE, bits2 & WINDOW_T_MASK);
    }
    
    if (NTABLE > 1) {
        API_NS(point_copy)(working, multiples1[NTABLE-1]);
        API_NS(point_copy)(tmp    , multiples2[NTABLE-1]);
    
        for (i=NTABLE-1; i>1; i--) {
            API_NS(point_add)(multiples1[i-1], multiples1[i-1], multiples1[i]);
            API_NS(point_add)(multiples2[i-1], multiples2[i-1], multiples2[i]);
            API_NS(point_add)(working, working, multiples1[i-1]);
            API_NS(point_add)(tmp,     tmp,     multiples2[i-1]);
        }
    
        API_NS(point_add)(multiples1[0], multiples1[0], multiples1[1]);
        API_NS(point_add)(multiples2[0], multiples2[0], multiples2[1]);
        point_double_internal(working, working, 0);
        point_double_internal(tmp,         tmp, 0);
        API_NS(point_add)(a1, working, multiples1[0]);
        API_NS(point_add)(a2, tmp,     multiples2[0]);
    } else {
        API_NS(point_copy)(a1, multiples1[0]);
        API_NS(point_copy)(a2, multiples2[0]);
    }

    crypton_decaf_bzero(scalar1x,sizeof(scalar1x));
    crypton_decaf_bzero(scalar2x,sizeof(scalar2x));
    crypton_decaf_bzero(pn,sizeof(pn));
    crypton_decaf_bzero(multiples1,sizeof(multiples1));
    crypton_decaf_bzero(multiples2,sizeof(multiples2));
    crypton_decaf_bzero(tmp,sizeof(tmp));
    crypton_decaf_bzero(working,sizeof(working));
}

crypton_decaf_bool_t API_NS(point_eq) ( const point_t p, const point_t q ) {
    /* equality mod 2-torsion compares x/y */
    gf a, b;
    crypton_gf_mul ( a, p->y, q->x );
    crypton_gf_mul ( b, q->y, p->x );
    mask_t succ = crypton_gf_eq(a,b);
    
    #if (COFACTOR == 8) && IMAGINE_TWIST
        crypton_gf_mul ( a, p->y, q->y );
        crypton_gf_mul ( b, q->x, p->x );
        #if !(IMAGINE_TWIST)
            crypton_gf_sub ( a, ZERO, a );
        #else
           /* Interesting note: the 4tor would normally be rotation.
            * But because of the *i twist, it's actually
            * (x,y) <-> (iy,ix)
            */
    
           /* No code, just a comment. */
        #endif
        succ |= crypton_gf_eq(a,b);
    #endif
    
    return mask_to_bool(succ);
}

crypton_decaf_bool_t API_NS(point_valid) (
    const point_t p
) {
    gf a,b,c;
    crypton_gf_mul(a,p->x,p->y);
    crypton_gf_mul(b,p->z,p->t);
    mask_t out = crypton_gf_eq(a,b);
    crypton_gf_sqr(a,p->x);
    crypton_gf_sqr(b,p->y);
    crypton_gf_sub(a,b,a);
    crypton_gf_sqr(b,p->t);
    crypton_gf_mulw(c,b,TWISTED_D);
    crypton_gf_sqr(b,p->z);
    crypton_gf_add(b,b,c);
    out &= crypton_gf_eq(a,b);
    out &= ~crypton_gf_eq(p->z,ZERO);
    return mask_to_bool(out);
}

void API_NS(point_debugging_torque) (
    point_t q,
    const point_t p
) {
#if COFACTOR == 8 && IMAGINE_TWIST
    gf tmp;
    crypton_gf_mul(tmp,p->x,SQRT_MINUS_ONE);
    crypton_gf_mul(q->x,p->y,SQRT_MINUS_ONE);
    crypton_gf_copy(q->y,tmp);
    crypton_gf_copy(q->z,p->z);
    crypton_gf_sub(q->t,ZERO,p->t);
#else
    crypton_gf_sub(q->x,ZERO,p->x);
    crypton_gf_sub(q->y,ZERO,p->y);
    crypton_gf_copy(q->z,p->z);
    crypton_gf_copy(q->t,p->t);
#endif
}

void API_NS(point_debugging_pscale) (
    point_t q,
    const point_t p,
    const uint8_t factor[SER_BYTES]
) {
    gf gfac,tmp;
    /* NB this means you'll never pscale by negative numbers for p521 */
    ignore_result(crypton_gf_deserialize(gfac,factor,0));
    crypton_gf_cond_sel(gfac,gfac,ONE,crypton_gf_eq(gfac,ZERO));
    crypton_gf_mul(tmp,p->x,gfac);
    crypton_gf_copy(q->x,tmp);
    crypton_gf_mul(tmp,p->y,gfac);
    crypton_gf_copy(q->y,tmp);
    crypton_gf_mul(tmp,p->z,gfac);
    crypton_gf_copy(q->z,tmp);
    crypton_gf_mul(tmp,p->t,gfac);
    crypton_gf_copy(q->t,tmp);
}

static void crypton_gf_batch_invert (
    gf *__restrict__ out,
    const gf *in,
    unsigned int n
) {
    gf t1;
    assert(n>1);
  
    crypton_gf_copy(out[1], in[0]);
    int i;
    for (i=1; i<(int) (n-1); i++) {
        crypton_gf_mul(out[i+1], out[i], in[i]);
    }
    crypton_gf_mul(out[0], out[n-1], in[n-1]);

    crypton_gf_invert(out[0], out[0], 1);

    for (i=n-1; i>0; i--) {
        crypton_gf_mul(t1, out[i], out[0]);
        crypton_gf_copy(out[i], t1);
        crypton_gf_mul(t1, out[0], in[i]);
        crypton_gf_copy(out[0], t1);
    }
}

static void batch_normalize_niels (
    niels_t *table,
    const gf *zs,
    gf *__restrict__ zis,
    int n
) {
    int i;
    gf product;
    crypton_gf_batch_invert(zis, zs, n);

    for (i=0; i<n; i++) {
        crypton_gf_mul(product, table[i]->a, zis[i]);
        crypton_gf_strong_reduce(product);
        crypton_gf_copy(table[i]->a, product);
        
        crypton_gf_mul(product, table[i]->b, zis[i]);
        crypton_gf_strong_reduce(product);
        crypton_gf_copy(table[i]->b, product);
        
        crypton_gf_mul(product, table[i]->c, zis[i]);
        crypton_gf_strong_reduce(product);
        crypton_gf_copy(table[i]->c, product);
    }
    
    crypton_decaf_bzero(product,sizeof(product));
}

void API_NS(precompute) (
    precomputed_s *table,
    const point_t base
) { 
    const unsigned int n = COMBS_N, t = COMBS_T, s = COMBS_S;
    assert(n*t*s >= SCALAR_BITS);
  
    point_t working, start, doubles[t-1];
    API_NS(point_copy)(working, base);
    pniels_t pn_tmp;
  
    gf zs[n<<(t-1)], zis[n<<(t-1)];
  
    unsigned int i,j,k;
    
    /* Compute n tables */
    for (i=0; i<n; i++) {

        /* Doubling phase */
        for (j=0; j<t; j++) {
            if (j) API_NS(point_add)(start, start, working);
            else API_NS(point_copy)(start, working);

            if (j==t-1 && i==n-1) break;

            point_double_internal(working, working,0);
            if (j<t-1) API_NS(point_copy)(doubles[j], working);

            for (k=0; k<s-1; k++)
                point_double_internal(working, working, k<s-2);
        }

        /* Gray-code phase */
        for (j=0;; j++) {
            int gray = j ^ (j>>1);
            int idx = (((i+1)<<(t-1))-1) ^ gray;

            pt_to_pniels(pn_tmp, start);
            memcpy(table->table[idx], pn_tmp->n, sizeof(pn_tmp->n));
            crypton_gf_copy(zs[idx], pn_tmp->z);
			
            if (j >= (1u<<(t-1)) - 1) break;
            int delta = (j+1) ^ ((j+1)>>1) ^ gray;

            for (k=0; delta>1; k++)
                delta >>=1;
            
            if (gray & (1<<k)) {
                API_NS(point_add)(start, start, doubles[k]);
            } else {
                API_NS(point_sub)(start, start, doubles[k]);
            }
        }
    }
    
    batch_normalize_niels(table->table,(const gf *)zs,zis,n<<(t-1));
    
    crypton_decaf_bzero(zs,sizeof(zs));
    crypton_decaf_bzero(zis,sizeof(zis));
    crypton_decaf_bzero(pn_tmp,sizeof(pn_tmp));
    crypton_decaf_bzero(working,sizeof(working));
    crypton_decaf_bzero(start,sizeof(start));
    crypton_decaf_bzero(doubles,sizeof(doubles));
}

static CRYPTON_DECAF_INLINE void
constant_time_lookup_niels (
    niels_s *__restrict__ ni,
    const niels_t *table,
    int nelts,
    int idx
) {
    constant_time_lookup(ni, table, sizeof(niels_s), nelts, idx);
}

void API_NS(precomputed_scalarmul) (
    point_t out,
    const precomputed_s *table,
    const scalar_t scalar
) {
    int i;
    unsigned j,k;
    const unsigned int n = COMBS_N, t = COMBS_T, s = COMBS_S;
    
    scalar_t scalar1x;
    API_NS(scalar_add)(scalar1x, scalar, precomputed_scalarmul_adjustment);
    API_NS(scalar_halve)(scalar1x,scalar1x);
    
    niels_t ni;
    
    for (i=s-1; i>=0; i--) {
        if (i != (int)s-1) point_double_internal(out,out,0);
        
        for (j=0; j<n; j++) {
            int tab = 0;
         
            for (k=0; k<t; k++) {
                unsigned int bit = i + s*(k + j*t);
                if (bit < SCALAR_BITS) {
                    tab |= (scalar1x->limb[bit/WBITS] >> (bit%WBITS) & 1) << k;
                }
            }
            
            mask_t invert = (tab>>(t-1))-1;
            tab ^= invert;
            tab &= (1<<(t-1)) - 1;

            constant_time_lookup_niels(ni, &table->table[j<<(t-1)], 1<<(t-1), tab);

            cond_neg_niels(ni, invert);
            if ((i!=(int)s-1)||j) {
                add_niels_to_pt(out, ni, j==n-1 && i);
            } else {
                niels_to_pt(out, ni);
            }
        }
    }
    
    crypton_decaf_bzero(ni,sizeof(ni));
    crypton_decaf_bzero(scalar1x,sizeof(scalar1x));
}

void API_NS(point_cond_sel) (
    point_t out,
    const point_t a,
    const point_t b,
    crypton_decaf_bool_t pick_b
) {
    constant_time_select(out,a,b,sizeof(point_t),bool_to_mask(pick_b),0);
}

/* FUTURE: restore Curve25519 Montgomery ladder? */
crypton_decaf_error_t API_NS(direct_scalarmul) (
    uint8_t scaled[SER_BYTES],
    const uint8_t base[SER_BYTES],
    const scalar_t scalar,
    crypton_decaf_bool_t allow_identity,
    crypton_decaf_bool_t short_circuit
) {
    point_t basep;
    crypton_decaf_error_t succ = API_NS(point_decode)(basep, base, allow_identity);
    if (short_circuit && succ != CRYPTON_DECAF_SUCCESS) return succ;
    API_NS(point_cond_sel)(basep, API_NS(point_base), basep, succ);
    API_NS(point_scalarmul)(basep, basep, scalar);
    API_NS(point_encode)(scaled, basep);
    API_NS(point_destroy)(basep);
    return succ;
}

void API_NS(point_mul_by_cofactor_and_encode_like_eddsa) (
    uint8_t enc[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const point_t p
) {
    
    /* The point is now on the twisted curve.  Move it to untwisted. */
    gf x, y, z, t;
    point_t q;
#if COFACTOR == 8
    API_NS(point_double)(q,p);
#else
    API_NS(point_copy)(q,p);
#endif
    
#if EDDSA_USE_SIGMA_ISOGENY
    {
        /* Use 4-isogeny like ed25519:
         *   2*x*y*sqrt(d/a-1)/(ax^2 + y^2 - 2)
         *   (y^2 - ax^2)/(y^2 + ax^2)
         * with a = -1, d = -EDWARDS_D:
         *   -2xysqrt(EDWARDS_D-1)/(2z^2-y^2+x^2)
         *   (y^2+x^2)/(y^2-x^2)
         */
        gf u;
        crypton_gf_sqr ( x, q->x ); // x^2
        crypton_gf_sqr ( t, q->y ); // y^2
        crypton_gf_add( u, x, t ); // x^2 + y^2
        crypton_gf_add( z, q->y, q->x );
        crypton_gf_sqr ( y, z);
        crypton_gf_sub ( y, u, y ); // -2xy
        crypton_gf_sub ( z, t, x ); // y^2 - x^2
        crypton_gf_sqr ( x, q->z );
        crypton_gf_add ( t, x, x);
        crypton_gf_sub ( t, t, z);  // 2z^2 - y^2 + x^2
        crypton_gf_mul ( x, y, z ); // 2xy(y^2-x^2)
        crypton_gf_mul ( y, u, t ); // (x^2+y^2)(2z^2-y^2+x^2)
        crypton_gf_mul ( u, z, t );
        crypton_gf_copy( z, u );
        crypton_gf_mul ( u, x, SQRT_ONE_MINUS_D );
        crypton_gf_copy( x, u );
        crypton_decaf_bzero(u,sizeof(u));
    }
#elif IMAGINE_TWIST
    {
        API_NS(point_double)(q,q);
        API_NS(point_double)(q,q);
        crypton_gf_mul_qnr(x, q->x);
        crypton_gf_copy(y, q->y);
        crypton_gf_copy(z, q->z);
    }
#else
    {
        /* 4-isogeny: 2xy/(y^+x^2), (y^2-x^2)/(2z^2-y^2+x^2) */
        gf u;
        crypton_gf_sqr ( x, q->x );
        crypton_gf_sqr ( t, q->y );
        crypton_gf_add( u, x, t );
        crypton_gf_add( z, q->y, q->x );
        crypton_gf_sqr ( y, z);
        crypton_gf_sub ( y, u, y );
        crypton_gf_sub ( z, t, x );
        crypton_gf_sqr ( x, q->z );
        crypton_gf_add ( t, x, x); 
        crypton_gf_sub ( t, t, z);
        crypton_gf_mul ( x, t, y );
        crypton_gf_mul ( y, z, u );
        crypton_gf_mul ( z, u, t );
        crypton_decaf_bzero(u,sizeof(u));
    }
#endif
    /* Affinize */
    crypton_gf_invert(z,z,1);
    crypton_gf_mul(t,x,z);
    crypton_gf_mul(x,y,z);
    
    /* Encode */
    enc[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES-1] = 0;
    crypton_gf_serialize(enc, x, 1);
    enc[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES-1] |= 0x80 & crypton_gf_lobit(t);

    crypton_decaf_bzero(x,sizeof(x));
    crypton_decaf_bzero(y,sizeof(y));
    crypton_decaf_bzero(z,sizeof(z));
    crypton_decaf_bzero(t,sizeof(t));
    API_NS(point_destroy)(q);
}


crypton_decaf_error_t API_NS(point_decode_like_eddsa_and_ignore_cofactor) (
    point_t p,
    const uint8_t enc[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES]
) {
    uint8_t enc2[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES];
    memcpy(enc2,enc,sizeof(enc2));

    mask_t low = ~word_is_zero(enc2[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES-1] & 0x80);
    enc2[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES-1] &= ~0x80;
    
    mask_t succ = crypton_gf_deserialize(p->y, enc2, 1);
#if 0 == 0
    succ &= word_is_zero(enc2[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES-1]);
#endif

    crypton_gf_sqr(p->x,p->y);
    crypton_gf_sub(p->z,ONE,p->x); /* num = 1-y^2 */
    #if EDDSA_USE_SIGMA_ISOGENY
        crypton_gf_mulw(p->t,p->z,EDWARDS_D); /* d-dy^2 */
        crypton_gf_mulw(p->x,p->z,EDWARDS_D-1); /* num = (1-y^2)(d-1) */
        crypton_gf_copy(p->z,p->x);
    #else
        crypton_gf_mulw(p->t,p->x,EDWARDS_D); /* dy^2 */
    #endif
    crypton_gf_sub(p->t,ONE,p->t); /* denom = 1-dy^2 or 1-d + dy^2 */
    
    crypton_gf_mul(p->x,p->z,p->t);
    succ &= crypton_gf_isr(p->t,p->x); /* 1/sqrt(num * denom) */
    
    crypton_gf_mul(p->x,p->t,p->z); /* sqrt(num / denom) */
    crypton_gf_cond_neg(p->x,~crypton_gf_lobit(p->x)^low);
    crypton_gf_copy(p->z,ONE);
  
    #if EDDSA_USE_SIGMA_ISOGENY
    {
       /* Use 4-isogeny like ed25519:
        *   2*x*y/sqrt(1-d/a)/(ax^2 + y^2 - 2)
        *   (y^2 - ax^2)/(y^2 + ax^2)
        * (MAGIC: above formula may be off by a factor of -a
        * or something somewhere; check it for other a)
        *
        * with a = -1, d = -EDWARDS_D:
        *   -2xy/sqrt(1-EDWARDS_D)/(2z^2-y^2+x^2)
        *   (y^2+x^2)/(y^2-x^2)
        */
        gf a, b, c, d;
        crypton_gf_sqr ( c, p->x );
        crypton_gf_sqr ( a, p->y );
        crypton_gf_add ( d, c, a ); // x^2 + y^2
        crypton_gf_add ( p->t, p->y, p->x );
        crypton_gf_sqr ( b, p->t );
        crypton_gf_sub ( b, b, d ); // 2xy
        crypton_gf_sub ( p->t, a, c ); // y^2 - x^2
        crypton_gf_sqr ( p->x, p->z );
        crypton_gf_add ( p->z, p->x, p->x );
        crypton_gf_sub ( a, p->z, p->t ); // 2z^2 - y^2 + x^2
        crypton_gf_mul ( c, a, SQRT_ONE_MINUS_D );
        crypton_gf_mul ( p->x, b, p->t); // (2xy)(y^2-x^2)
        crypton_gf_mul ( p->z, p->t, c ); // (y^2-x^2)sd(2z^2 - y^2 + x^2)
        crypton_gf_mul ( p->y, d, c ); // (y^2+x^2)sd(2z^2 - y^2 + x^2)
        crypton_gf_mul ( p->t, d, b );
        crypton_decaf_bzero(a,sizeof(a));
        crypton_decaf_bzero(b,sizeof(b));
        crypton_decaf_bzero(c,sizeof(c));
        crypton_decaf_bzero(d,sizeof(d));
    } 
    #elif IMAGINE_TWIST
    {
        crypton_gf_mul(p->t,p->x,SQRT_MINUS_ONE);
        crypton_gf_copy(p->x,p->t);
        crypton_gf_mul(p->t,p->x,p->y);
    }
    #else
    {
        /* 4-isogeny 2xy/(y^2-ax^2), (y^2+ax^2)/(2-y^2-ax^2) */
        gf a, b, c, d;
        crypton_gf_sqr ( c, p->x );
        crypton_gf_sqr ( a, p->y );
        crypton_gf_add ( d, c, a );
        crypton_gf_add ( p->t, p->y, p->x );
        crypton_gf_sqr ( b, p->t );
        crypton_gf_sub ( b, b, d );
        crypton_gf_sub ( p->t, a, c );
        crypton_gf_sqr ( p->x, p->z );
        crypton_gf_add ( p->z, p->x, p->x );
        crypton_gf_sub ( a, p->z, d );
        crypton_gf_mul ( p->x, a, b );
        crypton_gf_mul ( p->z, p->t, a );
        crypton_gf_mul ( p->y, p->t, d );
        crypton_gf_mul ( p->t, b, d );
        crypton_decaf_bzero(a,sizeof(a));
        crypton_decaf_bzero(b,sizeof(b));
        crypton_decaf_bzero(c,sizeof(c));
        crypton_decaf_bzero(d,sizeof(d));
    }
    #endif
    
    crypton_decaf_bzero(enc2,sizeof(enc2));
    assert(API_NS(point_valid)(p) || ~succ);
    return crypton_decaf_succeed_if(mask_to_bool(succ));
}

crypton_decaf_error_t crypton_decaf_x448 (
    uint8_t out[X_PUBLIC_BYTES],
    const uint8_t base[X_PUBLIC_BYTES],
    const uint8_t scalar[X_PRIVATE_BYTES]
) {
    gf x1, x2, z2, x3, z3, t1, t2;
    ignore_result(crypton_gf_deserialize(x1,base,1));
    crypton_gf_copy(x2,ONE);
    crypton_gf_copy(z2,ZERO);
    crypton_gf_copy(x3,x1);
    crypton_gf_copy(z3,ONE);
    
    int t;
    mask_t swap = 0;
    
    for (t = X_PRIVATE_BITS-1; t>=0; t--) {
        uint8_t sb = scalar[t/8];
        
        /* Scalar conditioning */
        if (t/8==0) sb &= -(uint8_t)COFACTOR;
        else if (t == X_PRIVATE_BITS-1) sb = -1;
        
        mask_t k_t = (sb>>(t%8)) & 1;
        k_t = -k_t; /* set to all 0s or all 1s */
        
        swap ^= k_t;
        crypton_gf_cond_swap(x2,x3,swap);
        crypton_gf_cond_swap(z2,z3,swap);
        swap = k_t;
        
        crypton_gf_add_nr(t1,x2,z2); /* A = x2 + z2 */        /* 2+e */
        crypton_gf_sub_nr(t2,x2,z2); /* B = x2 - z2 */        /* 3+e */
        crypton_gf_sub_nr(z2,x3,z3); /* D = x3 - z3 */        /* 3+e */
        crypton_gf_mul(x2,t1,z2);    /* DA */
        crypton_gf_add_nr(z2,z3,x3); /* C = x3 + z3 */        /* 2+e */
        crypton_gf_mul(x3,t2,z2);    /* CB */
        crypton_gf_sub_nr(z3,x2,x3); /* DA-CB */              /* 3+e */
        crypton_gf_sqr(z2,z3);       /* (DA-CB)^2 */
        crypton_gf_mul(z3,x1,z2);    /* z3 = x1(DA-CB)^2 */
        crypton_gf_add_nr(z2,x2,x3); /* (DA+CB) */            /* 2+e */
        crypton_gf_sqr(x3,z2);       /* x3 = (DA+CB)^2 */
        
        crypton_gf_sqr(z2,t1);       /* AA = A^2 */
        crypton_gf_sqr(t1,t2);       /* BB = B^2 */
        crypton_gf_mul(x2,z2,t1);    /* x2 = AA*BB */
        crypton_gf_sub_nr(t2,z2,t1); /* E = AA-BB */          /* 3+e */
        
        crypton_gf_mulw(t1,t2,-EDWARDS_D); /* E*-d = a24*E */
        crypton_gf_add_nr(t1,t1,z2); /* AA + a24*E */         /* 2+e */
        crypton_gf_mul(z2,t2,t1); /* z2 = E(AA+a24*E) */
    }
    
    /* Finish */
    crypton_gf_cond_swap(x2,x3,swap);
    crypton_gf_cond_swap(z2,z3,swap);
    crypton_gf_invert(z2,z2,0);
    crypton_gf_mul(x1,x2,z2);
    crypton_gf_serialize(out,x1,1);
    mask_t nz = ~crypton_gf_eq(x1,ZERO);
    
    crypton_decaf_bzero(x1,sizeof(x1));
    crypton_decaf_bzero(x2,sizeof(x2));
    crypton_decaf_bzero(z2,sizeof(z2));
    crypton_decaf_bzero(x3,sizeof(x3));
    crypton_decaf_bzero(z3,sizeof(z3));
    crypton_decaf_bzero(t1,sizeof(t1));
    crypton_decaf_bzero(t2,sizeof(t2));
    
    return crypton_decaf_succeed_if(mask_to_bool(nz));
}

/* Thanks Johan Pascal */
void crypton_decaf_ed448_convert_public_key_to_x448 (
    uint8_t x[CRYPTON_DECAF_X448_PUBLIC_BYTES],
    const uint8_t ed[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES]
) {
    gf y;
    {
        uint8_t enc2[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES];
        memcpy(enc2,ed,sizeof(enc2));

        /* retrieve y from the ed compressed point */
        enc2[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES-1] &= ~0x80;
        ignore_result(crypton_gf_deserialize(y, enc2, 0));
        crypton_decaf_bzero(enc2,sizeof(enc2));
    }
    
    {
        gf n,d;
        
#if EDDSA_USE_SIGMA_ISOGENY
        /* u = (1+y)/(1-y)*/
        crypton_gf_add(n, y, ONE); /* n = y+1 */
        crypton_gf_sub(d, ONE, y); /* d = 1-y */
        crypton_gf_invert(d, d, 0); /* d = 1/(1-y) */
        crypton_gf_mul(y, n, d); /* u = (y+1)/(1-y) */
        crypton_gf_serialize(x,y,1);
#else /* EDDSA_USE_SIGMA_ISOGENY */
        /* u = y^2 * (1-dy^2) / (1-y^2) */
        crypton_gf_sqr(n,y); /* y^2*/
        crypton_gf_sub(d,ONE,n); /* 1-y^2*/
        crypton_gf_invert(d,d,0); /* 1/(1-y^2)*/
        crypton_gf_mul(y,n,d); /* y^2 / (1-y^2) */
        crypton_gf_mulw(d,n,EDWARDS_D); /* dy^2*/
        crypton_gf_sub(d, ONE, d); /* 1-dy^2*/
        crypton_gf_mul(n, y, d); /* y^2 * (1-dy^2) / (1-y^2) */
        crypton_gf_serialize(x,n,1);
#endif /* EDDSA_USE_SIGMA_ISOGENY */
        
        crypton_decaf_bzero(y,sizeof(y));
        crypton_decaf_bzero(n,sizeof(n));
        crypton_decaf_bzero(d,sizeof(d));
    }
}

void crypton_decaf_x448_generate_key (
    uint8_t out[X_PUBLIC_BYTES],
    const uint8_t scalar[X_PRIVATE_BYTES]
) {
    crypton_decaf_x448_derive_public_key(out,scalar);
}

void crypton_decaf_x448_derive_public_key (
    uint8_t out[X_PUBLIC_BYTES],
    const uint8_t scalar[X_PRIVATE_BYTES]
) {
    /* Scalar conditioning */
    uint8_t scalar2[X_PRIVATE_BYTES];
    memcpy(scalar2,scalar,sizeof(scalar2));
    scalar2[0] &= -(uint8_t)COFACTOR;
    
    scalar2[X_PRIVATE_BYTES-1] &= ~(-1u<<((X_PRIVATE_BITS+7)%8));
    scalar2[X_PRIVATE_BYTES-1] |= 1<<((X_PRIVATE_BITS+7)%8);
    
    scalar_t the_scalar;
    API_NS(scalar_decode_long)(the_scalar,scalar2,sizeof(scalar2));
    
    /* We're gonna isogenize by 2, so divide by 2.
     *
     * Why by 2, even though it's a 4-isogeny?
     *
     * The isogeny map looks like
     * Montgomery <-2-> Jacobi <-2-> Edwards
     *
     * Since the Jacobi base point is the PREimage of the iso to
     * the Montgomery curve, and we're going
     * Jacobi -> Edwards -> Jacobi -> Montgomery,
     * we pick up only a factor of 2 over Jacobi -> Montgomery. 
     */
    API_NS(scalar_halve)(the_scalar,the_scalar);
    point_t p;
    API_NS(precomputed_scalarmul)(p,API_NS(precomputed_base),the_scalar);
    
    /* Isogenize to Montgomery curve.
     *
     * Why isn't this just a separate function, eg crypton_decaf_encode_like_x448?
     * Basically because in general it does the wrong thing if there is a cofactor
     * component in the input.  In this function though, there isn't a cofactor
     * component in the input.
     */
    crypton_gf_invert(p->t,p->x,0); /* 1/x */
    crypton_gf_mul(p->z,p->t,p->y); /* y/x */
    crypton_gf_sqr(p->y,p->z); /* (y/x)^2 */
#if IMAGINE_TWIST
    crypton_gf_sub(p->y,ZERO,p->y);
#endif
    crypton_gf_serialize(out,p->y,1);
        
    crypton_decaf_bzero(scalar2,sizeof(scalar2));
    API_NS(scalar_destroy)(the_scalar);
    API_NS(point_destroy)(p);
}

/**
 * @cond internal
 * Control for variable-time scalar multiply algorithms.
 */
struct smvt_control {
  int power, addend;
};

static int recode_wnaf (
    struct smvt_control *control, /* [nbits/(table_bits+1) + 3] */
    const scalar_t scalar,
    unsigned int table_bits
) {
    unsigned int table_size = SCALAR_BITS/(table_bits+1) + 3;
    int position = table_size - 1; /* at the end */
    
    /* place the end marker */
    control[position].power = -1;
    control[position].addend = 0;
    position--;

    /* PERF: Could negate scalar if it's large.  But then would need more cases
     * in the actual code that uses it, all for an expected reduction of like 1/5 op.
     * Probably not worth it.
     */
    
    uint64_t current = scalar->limb[0] & 0xFFFF;
    uint32_t mask = (1<<(table_bits+1))-1;

    unsigned int w;
    const unsigned int B_OVER_16 = sizeof(scalar->limb[0]) / 2;
    for (w = 1; w<(SCALAR_BITS-1)/16+3; w++) {
        if (w < (SCALAR_BITS-1)/16+1) {
            /* Refill the 16 high bits of current */
            current += (uint32_t)((scalar->limb[w/B_OVER_16]>>(16*(w%B_OVER_16)))<<16);
        }
        
        while (current & 0xFFFF) {
            assert(position >= 0);
            uint32_t pos = __builtin_ctz((uint32_t)current), odd = (uint32_t)current >> pos;
            int32_t delta = odd & mask;
            if (odd & 1<<(table_bits+1)) delta -= (1<<(table_bits+1));
            current -= delta << pos;
            control[position].power = pos + 16*(w-1);
            control[position].addend = delta;
            position--;
        }
        current >>= 16;
    }
    assert(current==0);
    
    position++;
    unsigned int n = table_size - position;
    unsigned int i;
    for (i=0; i<n; i++) {
        control[i] = control[i+position];
    }
    return n-1;
}

static void
prepare_wnaf_table(
    pniels_t *output,
    const point_t working,
    unsigned int tbits
) {
    point_t tmp;
    int i;
    pt_to_pniels(output[0], working);

    if (tbits == 0) return;

    API_NS(point_double)(tmp,working);
    pniels_t twop;
    pt_to_pniels(twop, tmp);

    add_pniels_to_pt(tmp, output[0],0);
    pt_to_pniels(output[1], tmp);

    for (i=2; i < 1<<tbits; i++) {
        add_pniels_to_pt(tmp, twop,0);
        pt_to_pniels(output[i], tmp);
    }
    
    API_NS(point_destroy)(tmp);
    crypton_decaf_bzero(twop,sizeof(twop));
}

extern const gf API_NS(precomputed_wnaf_as_fe)[];
static const niels_t *API_NS(wnaf_base) = (const niels_t *)API_NS(precomputed_wnaf_as_fe);
const size_t API_NS(sizeof_precomputed_wnafs)
    = sizeof(niels_t)<<CRYPTON_DECAF_WNAF_FIXED_TABLE_BITS;

void API_NS(precompute_wnafs) (
    niels_t out[1<<CRYPTON_DECAF_WNAF_FIXED_TABLE_BITS],
    const point_t base
);

void API_NS(precompute_wnafs) (
    niels_t out[1<<CRYPTON_DECAF_WNAF_FIXED_TABLE_BITS],
    const point_t base
) {
    pniels_t tmp[1<<CRYPTON_DECAF_WNAF_FIXED_TABLE_BITS];
    gf zs[1<<CRYPTON_DECAF_WNAF_FIXED_TABLE_BITS], zis[1<<CRYPTON_DECAF_WNAF_FIXED_TABLE_BITS];
    int i;
    prepare_wnaf_table(tmp,base,CRYPTON_DECAF_WNAF_FIXED_TABLE_BITS);
    for (i=0; i<1<<CRYPTON_DECAF_WNAF_FIXED_TABLE_BITS; i++) {
        memcpy(out[i], tmp[i]->n, sizeof(niels_t));
        crypton_gf_copy(zs[i], tmp[i]->z);
    }
    batch_normalize_niels(out, (const gf *)zs, zis, 1<<CRYPTON_DECAF_WNAF_FIXED_TABLE_BITS);
    
    crypton_decaf_bzero(tmp,sizeof(tmp));
    crypton_decaf_bzero(zs,sizeof(zs));
    crypton_decaf_bzero(zis,sizeof(zis));
}

void API_NS(base_double_scalarmul_non_secret) (
    point_t combo,
    const scalar_t scalar1,
    const point_t base2,
    const scalar_t scalar2
) {
    const int table_bits_var = CRYPTON_DECAF_WNAF_VAR_TABLE_BITS,
        table_bits_pre = CRYPTON_DECAF_WNAF_FIXED_TABLE_BITS;
    struct smvt_control control_var[SCALAR_BITS/(table_bits_var+1)+3];
    struct smvt_control control_pre[SCALAR_BITS/(table_bits_pre+1)+3];
    
    int ncb_pre = recode_wnaf(control_pre, scalar1, table_bits_pre);
    int ncb_var = recode_wnaf(control_var, scalar2, table_bits_var);
  
    pniels_t precmp_var[1<<table_bits_var];
    prepare_wnaf_table(precmp_var, base2, table_bits_var);
  
    int contp=0, contv=0, i = control_var[0].power;

    if (i < 0) {
        API_NS(point_copy)(combo, API_NS(point_identity));
        return;
    } else if (i > control_pre[0].power) {
        pniels_to_pt(combo, precmp_var[control_var[0].addend >> 1]);
        contv++;
    } else if (i == control_pre[0].power && i >=0 ) {
        pniels_to_pt(combo, precmp_var[control_var[0].addend >> 1]);
        add_niels_to_pt(combo, API_NS(wnaf_base)[control_pre[0].addend >> 1], i);
        contv++; contp++;
    } else {
        i = control_pre[0].power;
        niels_to_pt(combo, API_NS(wnaf_base)[control_pre[0].addend >> 1]);
        contp++;
    }
    
    for (i--; i >= 0; i--) {
        int cv = (i==control_var[contv].power), cp = (i==control_pre[contp].power);
        point_double_internal(combo,combo,i && !(cv||cp));

        if (cv) {
            assert(control_var[contv].addend);

            if (control_var[contv].addend > 0) {
                add_pniels_to_pt(combo, precmp_var[control_var[contv].addend >> 1], i&&!cp);
            } else {
                sub_pniels_from_pt(combo, precmp_var[(-control_var[contv].addend) >> 1], i&&!cp);
            }
            contv++;
        }

        if (cp) {
            assert(control_pre[contp].addend);

            if (control_pre[contp].addend > 0) {
                add_niels_to_pt(combo, API_NS(wnaf_base)[control_pre[contp].addend >> 1], i);
            } else {
                sub_niels_from_pt(combo, API_NS(wnaf_base)[(-control_pre[contp].addend) >> 1], i);
            }
            contp++;
        }
    }
    
    /* This function is non-secret, but whatever this is cheap. */
    crypton_decaf_bzero(control_var,sizeof(control_var));
    crypton_decaf_bzero(control_pre,sizeof(control_pre));
    crypton_decaf_bzero(precmp_var,sizeof(precmp_var));

    assert(contv == ncb_var); (void)ncb_var;
    assert(contp == ncb_pre); (void)ncb_pre;
}

void API_NS(point_destroy) (
    point_t point
) {
    crypton_decaf_bzero(point, sizeof(point_t));
}

void API_NS(precomputed_destroy) (
    precomputed_s *pre
) {
    crypton_decaf_bzero(pre, API_NS(sizeof_precomputed_s));
}
