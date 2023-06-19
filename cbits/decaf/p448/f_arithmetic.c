/**
 * @cond internal
 * @file f_arithmetic.c
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Field-specific arithmetic.
 */

#include "field.h"

mask_t crypton_gf_isr (
    gf a,
    const gf x
) {
    gf L0, L1, L2;
    crypton_gf_sqr  (L1,     x );
    crypton_gf_mul  (L2,     x,   L1 );
    crypton_gf_sqr  (L1,   L2 );
    crypton_gf_mul  (L2,     x,   L1 );
    crypton_gf_sqrn (L1,   L2,     3 );
    crypton_gf_mul  (L0,   L2,   L1 );
    crypton_gf_sqrn (L1,   L0,     3 );
    crypton_gf_mul  (L0,   L2,   L1 );
    crypton_gf_sqrn (L2,   L0,     9 );
    crypton_gf_mul  (L1,   L0,   L2 );
    crypton_gf_sqr  (L0,   L1 );
    crypton_gf_mul  (L2,     x,   L0 );
    crypton_gf_sqrn (L0,   L2,    18 );
    crypton_gf_mul  (L2,   L1,   L0 );
    crypton_gf_sqrn (L0,   L2,    37 );
    crypton_gf_mul  (L1,   L2,   L0 );
    crypton_gf_sqrn (L0,   L1,    37 );
    crypton_gf_mul  (L1,   L2,   L0 );
    crypton_gf_sqrn (L0,   L1,   111 );
    crypton_gf_mul  (L2,   L1,   L0 );
    crypton_gf_sqr  (L0,   L2 );
    crypton_gf_mul  (L1,     x,   L0 );
    crypton_gf_sqrn (L0,   L1,   223 );
    crypton_gf_mul  (L1,   L2,   L0 );
    crypton_gf_sqr  (L2, L1);
    crypton_gf_mul  (L0, L2, x);
    crypton_gf_copy(a,L1);
    return crypton_gf_eq(L0,ONE);
}
