/*
 * Asking for an AArch64 extension on one function.
 *
 * The instructions these files use are extensions, so a translation unit
 * compiled for the baseline may not emit them, and the function that does has
 * to say which extension it needs.  The two compilers spell that differently
 * and did not always:
 *
 *   clang          target("+crypto")            for as long as it matters
 *   GCC 13 and up  target("+crypto")            as well
 *   GCC before 13  target("arch=armv8-a+crypto")  -- the bare "+feature" form
 *                  is not understood, and the extension never reaches the
 *                  function, so an always_inline intrinsic that needs it
 *                  fails to inline and the build stops
 *
 * That last case is #273: gcc 12.2 on an aarch64 Linux could not build
 * cbits/sha3_armv8.c at all.  Naming the architecture as well as the
 * extension is understood by every version of both compilers, so GCC is given
 * that spelling and clang keeps the shorter one, which leaves whatever
 * baseline the caller chose alone.
 */
#ifndef CRYPTON_ARMV8_TARGET_H
#define CRYPTON_ARMV8_TARGET_H

#ifdef WITH_TARGET_ATTRIBUTES
#if defined(__clang__)
#define CRYPTON_TARGET_ARMV8_CRYPTO __attribute__((target("+crypto")))
#define CRYPTON_TARGET_ARMV8_SHA3 __attribute__((target("+sha3")))
#else
#define CRYPTON_TARGET_ARMV8_CRYPTO \
	__attribute__((target("arch=armv8-a+crypto")))
#define CRYPTON_TARGET_ARMV8_SHA3 \
	__attribute__((target("arch=armv8.2-a+sha3")))
#endif
#else
#define CRYPTON_TARGET_ARMV8_CRYPTO
#define CRYPTON_TARGET_ARMV8_SHA3
#endif

#endif
