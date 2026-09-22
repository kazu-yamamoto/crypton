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
#if defined(WITH_ARMV8_CHACHA_ASM) || defined(WITH_ARMV8_POLY1305_ASM) \
    || defined(WITH_ARMV8_SHA256_ASM)
#define CRYPTON_ARM_ASM 1
#define CRYPTON_ARMCAP_NEON   1
#define CRYPTON_ARMCAP_SHA256 (1 << 4)
extern unsigned int crypton_armcap_P;
#endif

#ifdef USE_AESNI
void crypton_aesni_initialize_hw(void (*init_table)(int, int));
#else
#define crypton_aesni_initialize_hw(init_table) 	(0)
#endif

#endif
