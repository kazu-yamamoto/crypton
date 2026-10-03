/*
 * What crypton asks of the vendored mldsa-native, in one place.  The tree
 * under cbits/mldsa is upstream's and is overwritten by import.sh, so every
 * choice crypton makes is made here instead of by editing it.
 *
 * Included first by both crypton_mldsa.c and crypton_mldsa_asm.S, so it must
 * hold nothing but preprocessor directives.
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
#endif

#endif /* CRYPTON_MLDSA_H */
