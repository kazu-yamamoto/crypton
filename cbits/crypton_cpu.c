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
#include "crypton_cpu.h"
#include <stdint.h>

/*
 * What the vendored AArch64 assembly asks about the processor, in the way
 * OpenSSL asks it.  NEON is not optional on AArch64, so the answer is yes;
 * the ChaCha20 module reads this to decide whether to use its vector path,
 * and the Poly1305 module to decide which pair of functions to hand back
 * from its initialisation.  Hidden, so that the reference to it from the
 * assembly resolves at link time in a shared object as well as a static
 * one.
 */
#if defined(WITH_ARMV8_CHACHA_ASM) || defined(WITH_ARMV8_POLY1305_ASM)
#define CRYPTON_ARMV7_NEON 1
__attribute__((visibility("hidden"))) unsigned int crypton_armcap_P =
    CRYPTON_ARMV7_NEON;
#endif

#ifdef ARCH_X86
static void cpuid(uint32_t info, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
	*eax = info;
	asm volatile
		(
#ifdef __x86_64__
		 "mov %%rbx, %%rdi;"
#else
		 "mov %%ebx, %%edi;"
#endif
		 "cpuid;"
		 "mov %%ebx, %%esi;"
#ifdef __x86_64__
		 "mov %%rdi, %%rbx;"
#else
		 "mov %%edi, %%ebx;"
#endif
		 :"+a" (*eax), "=S" (*ebx), "=c" (*ecx), "=d" (*edx)
		 : :"edi");
}

/*
 * What the machine will let us use beyond the x86-64 baseline.  XGETBV is
 * spelled out in bytes because it predates some assemblers that are still
 * in use.
 */
static void cpuid_count(uint32_t info, uint32_t sub, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
	*eax = info;
	*ecx = sub;
	__asm__ volatile
		(
#ifdef __x86_64__
		 "mov %%rbx, %%rdi;"
#else
		 "mov %%ebx, %%edi;"
#endif
		 "cpuid;"
		 "mov %%ebx, %%esi;"
#ifdef __x86_64__
		 "mov %%rdi, %%rbx;"
#else
		 "mov %%edi, %%ebx;"
#endif
		 :"+a" (*eax), "=S" (*ebx), "+c" (*ecx), "=d" (*edx)
		 : :"edi");
}

static uint64_t xcr0(void)
{
	uint32_t lo, hi;

	__asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a" (lo), "=d" (hi) : "c" (0));
	return ((uint64_t) hi << 32) | lo;
}

uint32_t crypton_x86_simd_features(void)
{
	static int resolved = 0;
	static uint32_t features = 0;

	if (!resolved) {
		uint32_t eax, ebx, ecx, edx, leaf1, maxleaf, f = 0;

		cpuid(0, &eax, &ebx, &ecx, &edx);
		maxleaf = eax;

		cpuid(1, &eax, &ebx, &ecx, &edx);
		leaf1 = ecx;
		if (leaf1 & (1 << 9))
			f |= CRYPTON_X86_SSSE3;
		if (leaf1 & (1 << 1))
			f |= CRYPTON_X86_PCLMUL;
		if (leaf1 & (1 << 22))
			f |= CRYPTON_X86_MOVBE;
		/* AVX asks the same three things as AVX2 below: the
		 * processor has it, OSXSAVE is on, and the operating system
		 * says it saves the registers */
		if ((leaf1 & (1 << 28)) && (leaf1 & (1 << 27))
		    && ((xcr0() & 6) == 6))
			f |= CRYPTON_X86_AVX;

		/* leaf 7 answers for both of the rest, and a processor that
		 * does not have it answers for the highest leaf it does have
		 * instead, so ask what that is first */
		if (maxleaf >= 7) {
			cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
			/* the SHA extensions work in registers the SSE state
			 * already covers, so they need nothing of the
			 * operating system.  The code that uses them also
			 * wants SSSE3 and SSE4.1, which every processor that
			 * has them has, but ask rather than assume */
			if ((ebx & (1 << 29)) && (leaf1 & (1 << 9))
			    && (leaf1 & (1 << 19)))
				f |= CRYPTON_X86_SHA_NI;
			/* AVX2 has the wider registers, which takes three
			 * things agreeing: the CPU has it, OSXSAVE is on, and
			 * XCR0 says the operating system saves them --
			 * without that last one the upper halves are lost
			 * across a context switch */
			if ((ebx & (1 << 5)) && (leaf1 & (1 << 27))
			    && (leaf1 & (1 << 28)) && ((xcr0() & 6) == 6))
				f |= CRYPTON_X86_AVX2;
		}
		features = f;
		resolved = 1;
	}
	return features;
}

#ifdef USE_AESNI
void crypton_aesni_initialize_hw(void (*init_table)(int, int))
{
	static int inited = 0;
	if (inited == 0) {
		uint32_t eax, ebx, ecx, edx;
		int aesni, pclmul;

		inited = 1;
		cpuid(1, &eax, &ebx, &ecx, &edx);
		aesni = (ecx & 0x02000000);
		pclmul = (ecx & 0x00000001);
		init_table(aesni, pclmul);
	}
}
#else
#define crypton_aesni_initialize_hw(init_table) 	(0)
#endif

#endif
