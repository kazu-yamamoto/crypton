/*
 * What crypton asks of the vendored mldsa-native, in one place.  The tree
 * under cbits/mldsa is upstream's and is overwritten by import.sh, so every
 * choice crypton makes is made here instead of by editing it.
 *
 * Included first by both crypton_mldsa.c and crypton_mldsa_asm.S, so it must
 * hold nothing the assembler cannot read: directives, and C behind
 * __ASSEMBLER__.
 */
#ifndef CRYPTON_MLDSA_H
#define CRYPTON_MLDSA_H

/*
 * The symbols are crypton's own, not the default PQCP_MLDSA_NATIVE_*.  An
 * application is free to link another copy of mldsa-native -- through some
 * other library, or its own -- and two copies answering to one set of names
 * is a problem the linker resolves silently and in nobody's favour.  With
 * MLD_CONFIG_MULTILEVEL_BUILD the level is appended, so the entry points
 * are crypton_mldsa44_*, crypton_mldsa65_* and crypton_mldsa87_*.
 */
#define MLD_CONFIG_NAMESPACE_PREFIX crypton_mldsa
#define MLD_CONFIG_MULTILEVEL_BUILD

/*
 * No randomised API, so no randombytes() to provide.  Randomness is drawn
 * in Haskell through MonadRandom, the way every other key in crypton is
 * generated, and the deterministic entry points are what the FFI calls.
 * That also keeps the C free of any opinion about where entropy comes from.
 */
#define MLD_CONFIG_NO_RANDOMIZED_API

/*
 * The hand-written backends, where crypton.cabal says the architecture has
 * them.  Without this the portable C is built, which is correct everywhere
 * and is what every other architecture gets.
 */
#ifdef CRYPTON_MLDSA_NATIVE_BACKEND
#define MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
#define MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202

/*
 * Which of the backend's instructions this processor actually has.
 *
 * Without this both packages decide at compile time: the backend is built
 * because the architecture has the instructions in principle, and is then
 * called with no check.  Upstream says so plainly -- if the machine that
 * runs the binary may differ from the one that built it, this function
 * MUST be provided -- and crypton is a library whose builds are copied
 * between machines and shipped by distributions.  Without it a binary
 * built on a host with AVX2 dies with SIGILL on one without (#316).
 *
 * The dispatch sites are upstream's; each falls back to the portable C
 * when this answers no.  The answers come from crypton's own detection,
 * the same that AES-NI, PCLMUL and the s2n-bignum variants use.
 */
#define MLD_CONFIG_CUSTOM_CAPABILITY_FUNC
#ifndef __ASSEMBLER__
#include "src/sys.h"
#include "crypton_cpu.h"

static MLD_INLINE int mld_sys_check_capability(mld_sys_cap cap)
{
#if defined(__x86_64__)
    if (cap == MLD_SYS_CAP_X86_64_AVX2)
        return (crypton_x86_simd_features() & CRYPTON_X86_AVX2) != 0;
#elif defined(__aarch64__)
    /* NEON is not optional on AArch64; the Keccak instructions are. */
    if (cap == MLD_SYS_CAP_AARCH64_NEON)
        return 1;
    if (cap == MLD_SYS_CAP_AARCH64_SHA3)
        return (crypton_arm_features() & CRYPTON_ARM_SHA3) != 0;
#endif
    (void)cap;
    return 0;
}
#endif /* !__ASSEMBLER__ */
#endif

#endif /* CRYPTON_MLDSA_H */
