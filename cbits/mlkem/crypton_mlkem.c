/*
 * All three ML-KEM parameter sets in one translation unit.
 *
 * mlkem-native is built for one parameter set at a time; a build wanting
 * several includes the amalgamation once per set, with the level-independent
 * half kept by exactly one of them.  This is the same shape as
 * cbits/aes/armv8.c, which includes cbits/aes/armv8_impl.c three times for
 * the three AES key sizes.
 *
 * NOTE, as there: cabal does not know that this file depends on the tree it
 * includes.  After changing anything under cbits/mlkem, touch this file, or
 * the build will quietly keep the object it already has.
 */
#include "crypton_mlkem.h"

#define MLK_CONFIG_MULTILEVEL_WITH_SHARED 1
#define MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLK_CONFIG_PARAMETER_SET 512
#include "mlkem_native.c"
#undef MLK_CONFIG_MULTILEVEL_WITH_SHARED
#undef MLK_CONFIG_PARAMETER_SET

#define MLK_CONFIG_MULTILEVEL_NO_SHARED
#define MLK_CONFIG_PARAMETER_SET 768
#include "mlkem_native.c"
#undef MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#undef MLK_CONFIG_PARAMETER_SET

#define MLK_CONFIG_PARAMETER_SET 1024
#include "mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
