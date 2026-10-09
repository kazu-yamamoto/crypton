/*
 *	Copyright (C) 2012 Vincent Hanquez <tab@snarc.org>
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
 *
 */
#ifndef CPU_H
#define CPU_H

#include <stdint.h>

#if defined(__i386__) || defined(__x86_64__)
#define ARCH_X86
#define USE_AESNI
#endif

/* vector extensions beyond the x86-64 baseline, as cpuid reports them and
 * the OS allows them */
#define CRYPTON_X86_SSSE3  1
#define CRYPTON_X86_AVX2   2
#define CRYPTON_X86_PCLMUL 4
/* the SHA extensions, and the SSSE3 and SSE4.1 the code around them uses */
#define CRYPTON_X86_SHA_NI 8
/* the 128-bit half of AVX, which is what the vendored assembly is written
 * in, and the byte-swapping load it reads the message with */
#define CRYPTON_X86_AVX    16
#define CRYPTON_X86_MOVBE  32
/* MULX, ADCX and ADOX together: the two independent carry chains the
 * vendored s2n-bignum assembly wants.  They are general-purpose register
 * instructions, so unlike the vector ones above they ask nothing of the
 * operating system. */
#define CRYPTON_X86_ADX    64
/* The AES and carry-less multiply instructions in their 256-bit form, which
 * do two blocks where the 128-bit ones do one.  They are VEX-encoded and use
 * the vector registers AVX2 already needs the operating system to save, so
 * they ask nothing further of it -- but AVX2 itself is asked about, since
 * without it there is nowhere to put them. */
#define CRYPTON_X86_VAES   128
/* The same pair in their 512-bit form, four blocks to an instruction.  These
 * are EVEX-encoded and need the AVX-512 state as well, which is three more
 * bits of XCR0 than AVX2 wants: the mask registers and the two upper halves
 * of the vector registers. */
#define CRYPTON_X86_VAES512 256
#ifdef ARCH_X86
uint32_t crypton_x86_simd_features(void);
#endif

/*
 * What the vendored AArch64 assembly asks about the processor, in the way
 * OpenSSL asks it and with OpenSSL's bit numbering.  NEON is not optional
 * on AArch64 and is set from the start; the SHA-256 instructions are, so
 * the bit for them is set once the runtime check has answered.  See
 * cbits/crypton_cpu.c and cbits/asm/README.md.
 */
/*
 * And what the vendored x86-64 assembly asks, which is cpuid's own words in
 * the order OpenSSL keeps them: [0] is leaf 1 EDX, [1] leaf 1 ECX and [2]
 * leaf 7 EBX, with the bits for what the operating system will not preserve
 * cleared.  Filled on first use; see cbits/crypton_cpu.c.
 */
#if defined(WITH_X86_POLY1305_ASM) || defined(WITH_X86_CHACHA_ASM) \
    || defined(WITH_X86_SHA256_ASM) || defined(WITH_X86_SHA512_ASM)
#define CRYPTON_X86_ASM 1
extern unsigned int crypton_ia32cap_P[4];
void crypton_x86_ia32cap_resolve(void);
#endif

#if defined(WITH_ARMV8_CHACHA_ASM) || defined(WITH_ARMV8_POLY1305_ASM) \
    || defined(WITH_ARMV8_SHA1_ASM) || defined(WITH_ARMV8_SHA256_ASM)
#define CRYPTON_ARM_ASM 1
#define CRYPTON_ARMCAP_NEON   1
#define CRYPTON_ARMCAP_SHA1   (1 << 3)
#define CRYPTON_ARMCAP_SHA256 (1 << 4)
extern unsigned int crypton_armcap_P;
#endif

/*
 * Which of the optional ARMv8 instruction sets this processor has.
 *
 * Asked here rather than in each file that wants one.  Five files used to
 * carry the same three-way conditional -- Apple, Linux, and otherwise zero
 * -- and the "otherwise" is not a statement about the processor but about
 * which systems someone had thought of.  It is what left FreeBSD running
 * the table-driven AES and the C SHA on hardware that has the
 * instructions.  In one place the next system is added once.
 */
#if defined(__aarch64__)
#define CRYPTON_ARM_AES    (1u << 0)
#define CRYPTON_ARM_PMULL  (1u << 1)
#define CRYPTON_ARM_SHA1   (1u << 2)
#define CRYPTON_ARM_SHA2   (1u << 3)
#define CRYPTON_ARM_SHA512 (1u << 4)
#define CRYPTON_ARM_SHA3   (1u << 5)
unsigned int crypton_arm_features(void);
#endif

/*
 * The two slots of the array crypton_aes.c fills and crypton_aes_cpu_init
 * hands out.  Here rather than in that file because crypton_cpu.c reads
 * them too, to answer for Crypto.System.CPU.
 */
#define CPU_AESNI        0
#define CPU_PCLMUL       1
#define CPU_OPTION_COUNT 2

/*
 * One question at a time, numbered the way Crypto.System.CPU numbers its
 * ProcessorOption rather than the way any array here is indexed.  The
 * numbering is the module's to choose and this answers for it; reading an
 * array by the Haskell constructor's Enum index is what kept that type at
 * three names.  Returns 1 if the processor has it and crypton was built to
 * use it, 0 otherwise -- including for anything this does not know, so an
 * older library answers a newer caller rather than failing to link.
 */
int crypton_cpu_option(unsigned int option);

#ifdef USE_AESNI
void crypton_aesni_initialize_hw(void (*init_table)(int, int));
#else
#define crypton_aesni_initialize_hw(init_table) 	(0)
#endif

#endif
