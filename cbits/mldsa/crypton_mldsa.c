/*
 * All three ML-DSA parameter sets in one translation unit.
 *
 * mldsa-native is built for one parameter set at a time; a build wanting
 * several includes the amalgamation once per set, with the level-independent
 * half kept by exactly one of them.  This is the same shape as
 * cbits/aes/armv8.c, which includes cbits/aes/armv8_impl.c three times for
 * the three AES key sizes.
 *
 * NOTE, as there: cabal does not know that this file depends on the tree it
 * includes.  After changing anything under cbits/mldsa, touch this file, or
 * the build will quietly keep the object it already has.
 */
#include "crypton_mldsa.h"

#define MLD_CONFIG_MULTILEVEL_WITH_SHARED 1
#define MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa_native.c"
#undef MLD_CONFIG_MULTILEVEL_WITH_SHARED
#undef MLD_CONFIG_PARAMETER_SET

#define MLD_CONFIG_MULTILEVEL_NO_SHARED
#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa_native.c"
#undef MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#undef MLD_CONFIG_PARAMETER_SET

#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
