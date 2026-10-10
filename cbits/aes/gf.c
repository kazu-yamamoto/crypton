/*
 * Copyright (c) 2012 Vincent Hanquez <vincent@snarc.org>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of his contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdint.h>
#include <crypton_cpu.h>
#include <aes/gf.h>
#include <aes/x86ni.h>
#include "bearssl/inner.h"

/* inplace GFMUL for xts mode */
void crypton_aes_generic_gf_mulx(block128 *a)
{
	const uint64_t gf_mask = cpu_to_le64(0x8000000000000000ULL);
	uint64_t r = ((a->q[1] & gf_mask) ? cpu_to_le64(0x87) : 0);
	a->q[1] = cpu_to_le64((le64_to_cpu(a->q[1]) << 1) | (a->q[0] & gf_mask ? 1 : 0));
	a->q[0] = cpu_to_le64(le64_to_cpu(a->q[0]) << 1) ^ r;
}


/*
 * GHASH, without a table.
 *
 * This was Shoup's method: the products of H with all sixteen 4-bit
 * polynomials, precomputed, and thirty-two lookups a block at indices taken
 * from the accumulator -- which is to say, thirty-two addresses derived from
 * a secret.  It is now BearSSL's ghash_ctmul64, which builds the GF(2^128)
 * multiply out of shifts, masks and integer multiplies and looks nothing up.
 * See cbits/bearssl/README.md.
 *
 * The table_4bit the interface names is sixteen blocks wide because the
 * table needed it.  This keeps H in the first and leaves the rest alone; the
 * PMULL and PCLMUL implementations keep their own powers of H in that same
 * space, so the width stays as it is.
 */

/* remember H */
void crypton_aes_generic_hinit(table_4bit htable, const block128 *h)
{
	block128_copy(&htable[0], h);
}

/*
 * br_ghash_ctmul64 computes y = (y ^ x) * H for each block x it is given, so
 * a block of zeros is the bare multiply this entry is asked for.
 */
void crypton_aes_generic_gf_mul(block128 *a, const table_4bit htable)
{
	static const uint8_t zero[16] = { 0 };

	br_ghash_ctmul64(a, &htable[0], zero, sizeof zero);
}

/*
 * Four GHASH steps at once, which here is one call rather than four: the
 * loop inside br_ghash_ctmul64 takes the blocks as they come.
 */
void crypton_aes_generic_gf_mul4(block128 *a, const block128 *blocks, const table_4bit htable)
{
	br_ghash_ctmul64(a, &htable[0], blocks, 4 * sizeof(block128));
}
