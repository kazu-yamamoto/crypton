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
 * What the machine will let us use beyond the x86-64 baseline.  AVX2 needs
 * three things to agree: the CPU has it, the CPU has XSAVE enabled by the
 * OS, and the OS has said it will save the wider registers -- without that
 * last one the upper halves are lost across a context switch.  XGETBV is
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
		uint32_t eax, ebx, ecx, edx, f = 0;

		cpuid(1, &eax, &ebx, &ecx, &edx);
		if (ecx & (1 << 9))
			f |= CRYPTON_X86_SSSE3;
		if (ecx & (1 << 1))
			f |= CRYPTON_X86_PCLMUL;
		/* OSXSAVE, then AVX, then the XCR0 bits for the SSE and AVX
		 * register state, and only then ask leaf 7 about AVX2 */
		if ((ecx & (1 << 27)) && (ecx & (1 << 28)) && ((xcr0() & 6) == 6)) {
			cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
			if (ebx & (1 << 5))
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
