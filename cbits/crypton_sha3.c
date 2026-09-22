/*
 * Copyright (C) 2012 Vincent Hanquez <vincent@snarc.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <string.h>
#include "crypton_bitfn.h"
#include "crypton_align.h"
#include "crypton_sha3.h"

#define KECCAK_NB_ROUNDS 24

/* rounds constants */
static const uint64_t keccak_rndc[24] =
{
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

/* triangular numbers constants */
static const int keccak_rotc[24] =
	{ 1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44 };

static const int keccak_piln[24] =
	{ 10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1 };

/*
 * AArch64 has instructions for this permutation; see sha3_armv8.c.  They are
 * an ARMv8.2 extension, so ask before using them.  Two threads racing to
 * answer here both write the same value.
 */
#ifdef WITH_ARMV8_SHA3
extern void crypton_sha3_armv8_permute(uint64_t state[25]);
extern int crypton_sha3_armv8_available(void);

static int sha3_use_armv8 = -1;

/* Two threads racing to answer this both write the same value. */
static int sha3_armv8_ok(void)
{
	if (sha3_use_armv8 < 0)
		sha3_use_armv8 = crypton_sha3_armv8_available();
	return sha3_use_armv8;
}
#endif

#if defined(WITH_ARMV8_SHA3_ASM) && !defined(__AARCH64EB__)
/*
 * Keccak from CRYPTOGAMS, in cbits/asm/keccak1600-armv8-*.S, which takes a
 * run of blocks rather than one at a time and schedules the instructions
 * across the round it is in and the next.  The instructions are the same
 * ones the intrinsics beside it use; the arrangement is what is worth
 * about a tenth here.  It reads the message as bytes, so the run wants
 * neither alignment nor a copy.
 */
#define SHA3_ASM 1
/* the runtime question this file already asks decides whether it is used */
#define SHA3_ASM_OPTIONAL 1
extern size_t crypton_keccak_asm_absorb_cext(uint64_t state[25], const void *inp,
                                             size_t len, size_t bsz);
#define sha3_asm_absorb crypton_keccak_asm_absorb_cext
#endif

#ifdef WITH_X86_SHA3_ASM
/*
 * And the same module for x86-64, where there are no instructions for this
 * and what the assembly has over the C is the arrangement: the twenty-five
 * lanes live in registers across a round, where a compiler given the C
 * below spills them, and the rotations are folded into the operations that
 * consume them.  It needs nothing of the processor beyond the baseline, so
 * unlike the AArch64 one it is used wherever it is compiled in.
 */
#define SHA3_ASM 1
extern size_t crypton_keccak_asm_absorb(uint64_t state[25], const void *inp,
                                        size_t len, size_t bsz);
#define sha3_asm_absorb crypton_keccak_asm_absorb
#endif

static inline void sha3_do_chunk(uint64_t state[25], uint64_t buf[], int bufsz)
{
	int i, j, r;
	uint64_t tmp, bc[5];

	/* merge buf with state */
	for (i = 0; i < bufsz; i++)
		state[i] ^= le64_to_cpu(buf[i]);

#ifdef WITH_ARMV8_SHA3
	if (sha3_armv8_ok()) {
		crypton_sha3_armv8_permute(state);
		return;
	}
#endif

	/* run keccak rounds */
	for (r = 0; r < KECCAK_NB_ROUNDS; r++) {
		/* compute the parity of each columns */
		for (i = 0; i < 5; i++)
			bc[i] = state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20];

		for (i = 0; i < 5; i++) {
			tmp = bc[(i + 4) % 5] ^ rol64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				state[j + i] ^= tmp;
		}

		/* rho pi */
		tmp = state[1];
		for (i = 0; i < 24; i++) {
			j = keccak_piln[i];
			bc[0] = state[j];
			state[j] = rol64(tmp, keccak_rotc[i]);
			tmp = bc[0];
		}

		/* bitwise combine along rows using a = a xor (not b and c) */
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++)
				bc[i] = state[j + i];
			#define andn(b,c) (~(b) & (c))
			state[j + 0] ^= andn(bc[1], bc[2]);
			state[j + 1] ^= andn(bc[2], bc[3]);
			state[j + 2] ^= andn(bc[3], bc[4]);
			state[j + 3] ^= andn(bc[4], bc[0]);
			state[j + 4] ^= andn(bc[0], bc[1]);
			#undef andn
		}

		/* xor the round constant */
		state[0] ^= keccak_rndc[r];
	}
}

/*
 * Initialize a SHA-3 / SHAKE / cSHAKE context: hashlen is the security level
 * (and half the capacity) in bits.
 *
 * In case of cSHAKE, the message prefix with encoded N and S must be added with
 * crypton_sha3_update.
 */
void crypton_sha3_init(struct sha3_ctx *ctx, uint32_t hashlen)
{
	/* assert(hashlen >= SHA3_BITSIZE_MIN && hashlen <= SHA3_BITSIZE_MAX) */
	int bufsz = SHA3_BUF_SIZE(hashlen);
	memset(ctx, 0, sizeof(*ctx) + bufsz);
	ctx->bufsz = bufsz;
}

/* Update a SHA-3 / SHAKE / cSHAKE context */
void crypton_sha3_update(struct sha3_ctx *ctx, const uint8_t *data, uint32_t len)
{
	uint32_t to_fill;

	to_fill = ctx->bufsz - ctx->bufindex;

	if (ctx->bufindex == ctx->bufsz) {
		sha3_do_chunk(ctx->state, (uint64_t *) ctx->buf, ctx->bufsz / 8);
		ctx->bufindex = 0;
	}

	/* process partial buffer if there's enough data to make a block */
	if (ctx->bufindex && len >= to_fill) {
		memcpy(ctx->buf + ctx->bufindex, data, to_fill);
		sha3_do_chunk(ctx->state, (uint64_t *) ctx->buf, ctx->bufsz / 8);
		len -= to_fill;
		data += to_fill;
		ctx->bufindex = 0;
	}

#ifdef SHA3_ASM
	if (len >= ctx->bufsz
#ifdef SHA3_ASM_OPTIONAL
	    && sha3_armv8_ok()
#endif
	   ) {
		const size_t left = sha3_asm_absorb(ctx->state, data, len,
		                                    ctx->bufsz);

		data += len - left;
		len = (uint32_t) left;
	}
#endif

	if (need_alignment(data, 8)) {
		uint64_t tramp[SHA3_BUF_SIZE_MAX/8];
		ASSERT_ALIGNMENT(tramp, 8);
		for (; len >= ctx->bufsz; len -= ctx->bufsz, data += ctx->bufsz) {
			memcpy(tramp, data, ctx->bufsz);
			sha3_do_chunk(ctx->state, tramp, ctx->bufsz / 8);
		}
	} else {
		/* process as much ctx->bufsz-block */
		for (; len >= ctx->bufsz; len -= ctx->bufsz, data += ctx->bufsz)
			sha3_do_chunk(ctx->state, (uint64_t *) data, ctx->bufsz / 8);
	}


	/* append data into buf */
	if (len) {
		memcpy(ctx->buf + ctx->bufindex, data, len);
		ctx->bufindex += len;
	}
}

void crypton_sha3_finalize_with_pad_byte(struct sha3_ctx *ctx, uint8_t pad_byte)
{
	/* process full buffer if needed */
	if (ctx->bufindex == ctx->bufsz) {
		sha3_do_chunk(ctx->state, (uint64_t *) ctx->buf, ctx->bufsz / 8);
		ctx->bufindex = 0;
	}

	/* add the 10*1 padding */
	ctx->buf[ctx->bufindex++] = pad_byte;
	memset(ctx->buf + ctx->bufindex, 0, ctx->bufsz - ctx->bufindex);
	ctx->buf[ctx->bufsz - 1] |= 0x80;

	/* process */
	sha3_do_chunk(ctx->state, (uint64_t *) ctx->buf, ctx->bufsz / 8);
	ctx->bufindex = 0;
}

/*
 * Extract some bytes from a finalized SHA-3 / SHAKE / cSHAKE context.
 * May be called multiple times.
 */
void crypton_sha3_output(struct sha3_ctx *ctx, uint8_t *out, uint32_t len)
{
	uint64_t w[25];
	uint8_t *wptr = (uint8_t *) w;
	uint32_t still_avail;

	still_avail = ctx->bufsz - ctx->bufindex;

	if (ctx->bufindex == ctx->bufsz) {
		/* squeeze the sponge again, without any input */
		sha3_do_chunk(ctx->state, NULL, 0);
		ctx->bufindex = 0;
	}

	/* use bytes already available if this block is fully consumed */
	if (ctx->bufindex && len >= still_avail) {
		cpu_to_le64_array(w, ctx->state, 25);
		memcpy(out, wptr + ctx->bufindex, still_avail);
		sha3_do_chunk(ctx->state, NULL, 0);
		len -= still_avail;
		out += still_avail;
		ctx->bufindex = 0;
	}

	/* output as much ctx->bufsz-block */
	for (; len > ctx->bufsz; len -= ctx->bufsz, out += ctx->bufsz) {
		cpu_to_le64_array(w, ctx->state, 25);
		memcpy(out, w, ctx->bufsz);
		sha3_do_chunk(ctx->state, NULL, 0);
	}

	/* output from partial buffer */
	if (len) {
		cpu_to_le64_array(w, ctx->state, 25);
		memcpy(out, wptr + ctx->bufindex, len);
		ctx->bufindex += len;
	}
}

/* Finalize a SHA-3 context and return the digest value */
void crypton_sha3_finalize(struct sha3_ctx *ctx, uint32_t hashlen, uint8_t *out)
{
	crypton_sha3_finalize_with_pad_byte(ctx, 0x06);
	crypton_sha3_output(ctx, out, hashlen / 8);
}

/* Finalize a SHAKE context. Output is read using crypton_sha3_output. */
void crypton_sha3_finalize_shake(struct sha3_ctx *ctx)
{
	crypton_sha3_finalize_with_pad_byte(ctx, 0x1F);
}

/* Finalize a cSHAKE context. Output is read using crypton_sha3_output. */
void crypton_sha3_finalize_cshake(struct sha3_ctx *ctx)
{
	crypton_sha3_finalize_with_pad_byte(ctx, 0x04);
}

void crypton_keccak_init(struct sha3_ctx *ctx, uint32_t hashlen)
{
	crypton_sha3_init(ctx, hashlen);
}

void crypton_keccak_update(struct sha3_ctx *ctx, uint8_t *data, uint32_t len)
{
	crypton_sha3_update(ctx, data, len);
}

void crypton_keccak_finalize(struct sha3_ctx *ctx, uint32_t hashlen, uint8_t *out)
{
	crypton_sha3_finalize_with_pad_byte(ctx, 1);
	crypton_sha3_output(ctx, out, hashlen / 8);
}
