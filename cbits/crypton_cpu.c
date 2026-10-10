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
 * PE has no way to say "hidden": every symbol in an object is local to the
 * image unless something exports it, which is what hidden asks for
 * elsewhere, so nothing is lost by dropping the attribute here.  Saying it
 * anyway is not harmless -- the gcc that GHC 9.2 ships for Windows parses
 * the attribute, discards it and warns, and it is the only warning crypton's
 * own code produces anywhere in the CI matrix.  Measured on mingw gcc 13.2.0
 * and clang 14.0.6 (the compiler GHC 9.4 and later ship): gcc warns for
 * "hidden" and is silent for "default", clang is silent for both, which is
 * why the vendored decaf and argon2 headers ask for "default" unnoticed.
 */
#if defined(_WIN32) || defined(__CYGWIN__)
#define CRYPTON_HIDDEN
#else
#define CRYPTON_HIDDEN __attribute__((visibility("hidden")))
#endif

/*
 * The word the assembly reads; crypton_cpu.h says what is in it.  Hidden,
 * so that the reference to it from the assembly resolves at link time in a
 * shared object as well as a static one.  The SHA-256 bit is set by
 * cbits/crypton_sha256.c once it has asked whether the processor has those
 * instructions.
 */
#ifdef CRYPTON_ARM_ASM
CRYPTON_HIDDEN unsigned int crypton_armcap_P =
    CRYPTON_ARMCAP_NEON;
#endif

#if defined(__aarch64__)
#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#elif defined(__FreeBSD__)
#include <sys/auxv.h>
#endif

/*
 * The HWCAP bit positions are the ARM ELF ABI's, so every system that
 * reports through the auxiliary vector agrees on them.  What differs is
 * AT_HWCAP itself -- 16 on Linux, 25 on FreeBSD -- and that comes from each
 * system's own header, which is why the tag is never written out here.
 * Defined only where the system's headers did not define them, the way
 * compiler-rt does it, so that a system which reports through the auxiliary
 * vector without shipping the ARM names still compiles.
 */
#ifndef HWCAP_AES
#define HWCAP_AES    (1 << 3)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL  (1 << 4)
#endif
#ifndef HWCAP_SHA1
#define HWCAP_SHA1   (1 << 5)
#endif
#ifndef HWCAP_SHA2
#define HWCAP_SHA2   (1 << 6)
#endif
#ifndef HWCAP_SHA3
#define HWCAP_SHA3   (1 << 17)
#endif
#ifndef HWCAP_SHA512
#define HWCAP_SHA512 (1 << 21)
#endif

#if defined(__APPLE__)
static int apple_has(const char *name)
{
	int v = 0;
	size_t n = sizeof(v);

	if (sysctlbyname(name, &v, &n, NULL, 0) != 0)
		return 0;
	return v != 0;
}
#endif

/*
 * Systems still answering zero, and what each would need:
 *
 *   OpenBSD, NetBSD   sysctl on machdep.id_aa64isar0, which hands out the
 *                     ID_AA64ISAR0_EL1 fields rather than a HWCAP word, so
 *                     it is a different shape of answer rather than another
 *                     tag.
 *   Windows on ARM    IsProcessorFeaturePresent with
 *                     PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE, which covers
 *                     AES, PMULL, SHA-1 and SHA-256 as one bit and says
 *                     nothing about SHA-512 or SHA-3.  An ARM64 Windows
 *                     guest answers 1 to it, but GHC has no native ARM64
 *                     Windows target: there it builds x86-64 and the
 *                     emulator reports AES-NI, so this file is not reached.
 *
 * Neither is written here because neither can be built and run to see it
 * work, and an untested answer about whether a machine has AES is worse
 * than the honest zero it replaces.
 */
unsigned int crypton_arm_features(void)
{
	static unsigned int features;
	static int resolved;

	if (!resolved) {
		unsigned int f = 0;
#if defined(__APPLE__)
		/* AES, PMULL, SHA-1 and SHA-256 are not optional on Apple
		 * silicon.  The two later ones are. */
		f = CRYPTON_ARM_AES | CRYPTON_ARM_PMULL
		  | CRYPTON_ARM_SHA1 | CRYPTON_ARM_SHA2;
		if (apple_has("hw.optional.arm.FEAT_SHA512"))
			f |= CRYPTON_ARM_SHA512;
		if (apple_has("hw.optional.arm.FEAT_SHA3"))
			f |= CRYPTON_ARM_SHA3;
#else
		unsigned long cap = 0;

#if defined(__linux__)
		cap = getauxval(AT_HWCAP);
#elif defined(__FreeBSD__)
		if (elf_aux_info(AT_HWCAP, &cap, sizeof(cap)) != 0)
			cap = 0;
#endif
		if (cap & HWCAP_AES)    f |= CRYPTON_ARM_AES;
		if (cap & HWCAP_PMULL)  f |= CRYPTON_ARM_PMULL;
		if (cap & HWCAP_SHA1)   f |= CRYPTON_ARM_SHA1;
		if (cap & HWCAP_SHA2)   f |= CRYPTON_ARM_SHA2;
		if (cap & HWCAP_SHA512) f |= CRYPTON_ARM_SHA512;
		if (cap & HWCAP_SHA3)   f |= CRYPTON_ARM_SHA3;
#endif
		features = f;
		resolved = 1;
	}
	return features;
}
#endif /* __aarch64__ */

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

#ifdef CRYPTON_X86_ASM
CRYPTON_HIDDEN unsigned int crypton_ia32cap_P[4];

/*
 * The AVX-512 bits of leaf 7 EBX -- F, DQ, IFMA, PF, ER, CD, BW and VL,
 * which is every bit from 16 up except 21's neighbours and 29, the SHA
 * extensions, which are not AVX-512 and are wanted.  They are cleared
 * whatever the processor says: the code they would select in the vendored
 * assembly cannot be run, let alone measured, on any machine here, and
 * shipping a path nothing has executed is not worth the few per cent it
 * might be worth.  Turning them on is a one-line change for whoever has
 * the hardware.
 */
#define IA32CAP_AVX512 \
	((1u << 16) | (1u << 17) | (1u << 21) | (1u << 26) | (1u << 27) \
	 | (1u << 28) | (1u << 30) | (1u << 31))

/*
 * cpuid as the assembly reads it, with the two bits it dispatches on -- AVX
 * in leaf 1 and AVX2 in leaf 7 -- left set only where the answer already
 * agreed that the operating system saves the registers.  Two threads racing
 * here write the same values.
 */
void crypton_x86_ia32cap_resolve(void)
{
	static int resolved = 0;

	if (!resolved) {
		uint32_t eax, ebx, ecx, edx, maxleaf;
		uint32_t f = crypton_x86_simd_features();
		uint32_t leaf1_ecx, leaf7_ebx = 0;
		int intel;

		cpuid(0, &eax, &ebx, &ecx, &edx);
		maxleaf = eax;
		/* "GenuineIntel", which OpenSSL records in a bit of leaf 1
		 * EDX that cpuid leaves reserved: some of the assembly asks,
		 * having found a path worth taking on one make and not the
		 * other */
		intel = (ebx == 0x756e6547 && edx == 0x49656e69
		         && ecx == 0x6c65746e);

		cpuid(1, &eax, &ebx, &ecx, &edx);
		crypton_ia32cap_P[0] = intel ? (edx | (1u << 30)) : edx;
		leaf1_ecx = ecx;
		if (!(f & CRYPTON_X86_AVX))
			leaf1_ecx &= ~(1u << 28);
		/*
		 * Bit 11 is not leaf 1's to give.  The assembly reads it as
		 * AMD's XOP, which lives in leaf 0x80000001, and OpenSSL
		 * clears whatever leaf 1 put there before merging the real
		 * flag into the place -- on Intel that is SDBG, the silicon
		 * debug interface, reported since Broadwell, and reading it
		 * as XOP sends SHA-512 and ChaCha20 into a vprotq and a
		 * SIGILL.  It is cleared and left clear: nothing here can run
		 * XOP to test it, and no processor still in service has it,
		 * AMD having carried it from Bulldozer to Excavator and Zen
		 * having dropped it.  That is the reason the AVX-512 bits
		 * above are cleared too.
		 */
		leaf1_ecx &= ~(1u << 11);
		crypton_ia32cap_P[1] = leaf1_ecx;

		if (maxleaf >= 7) {
			cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
			leaf7_ebx = ebx;
		}
		if (!(f & CRYPTON_X86_AVX2))
			leaf7_ebx &= ~(1u << 5);
		crypton_ia32cap_P[2] = leaf7_ebx & ~IA32CAP_AVX512;

		resolved = 1;
	}
}
#endif

uint32_t crypton_x86_simd_features(void)
{
	static int resolved = 0;
	static uint32_t features = 0;

	if (!resolved) {
		uint32_t eax, ebx, ecx, edx, leaf1, maxleaf, family, f = 0;
		int amd;

		cpuid(0, &eax, &ebx, &ecx, &edx);
		maxleaf = eax;
		/* "AuthenticAMD" arrives as EBX, EDX, ECX in that order */
		amd = (ebx == 0x68747541 && edx == 0x69746e65
		       && ecx == 0x444d4163);

		cpuid(1, &eax, &ebx, &ecx, &edx);
		leaf1 = ecx;
		/* the family is the base one, and the extended field is
		 * added to it only when the base reads 0xf, which is how
		 * every AMD Zen part reports */
		family = (eax >> 8) & 0xf;
		if (family == 0xf)
			family += (eax >> 20) & 0xff;
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
			/* BMI2 for MULX and ADX for ADCX/ADOX.  Both are
			 * wanted together and neither touches vector state,
			 * so there is nothing to ask the operating system */
			if ((ebx & (1 << 8)) && (ebx & (1 << 19)))
				f |= CRYPTON_X86_ADX;
			/* VAES and VPCLMULQDQ, leaf 7 ECX bits 9 and 10.
			 * They are wanted together -- one without the other
			 * leaves half of AES-GCM narrow -- and they need the
			 * wide registers, so AVX2 has to have answered first,
			 * which settles the operating system's part. */
			if ((ecx & (1 << 9)) && (ecx & (1 << 10))
			    && (f & CRYPTON_X86_AVX2))
				f |= CRYPTON_X86_VAES;
			/* The same two instructions in their 512-bit form,
			 * which wants AVX-512 F, BW and VL as well -- and
			 * three more bits of XCR0, for the mask registers and
			 * the two upper halves of the vector state.  A
			 * machine can report the instructions and still fault
			 * on them when the operating system has not said it
			 * saves that state, which is what those bits are. */
			if ((f & CRYPTON_X86_VAES)
			    && (ebx & (1 << 16)) && (ebx & (1u << 30))
			    && (ebx & (1u << 31))
			    && ((xcr0() & 0xe6) == 0xe6)
			    /* Not on Zen 4, which is AMD family 19h with
			     * AVX-512: there the 512-bit instructions are two
			     * 256-bit passes through a 256-bit datapath, so
			     * they carry the wider encoding for none of the
			     * throughput, and AES-GCM measures 0.6 to 3
			     * per cent slower than the 256-bit path.  Zen 5
			     * is family 1Ah and does have the wide datapath,
			     * where the same code is half as fast again;
			     * Zen 3, the other family 19h part, has no
			     * AVX-512 at all and never reaches here. */
			    && !(amd && family == 0x19))
				f |= CRYPTON_X86_VAES512;
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
