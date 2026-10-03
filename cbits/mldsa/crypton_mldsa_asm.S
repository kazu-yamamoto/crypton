/*
 * The assembly half, which is level-independent: it is included once, with
 * the shared directives kept, and covers all three parameter sets.  See the
 * comment at the top of mldsa_native_asm.S.
 *
 * Built only where crypton.cabal defines CRYPTON_MLDSA_NATIVE_BACKEND; on
 * every other architecture this file is not in asm-sources at all.
 */
#include "crypton_mldsa.h"

#define MLD_CONFIG_MULTILEVEL_WITH_SHARED 1
#define MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa_native_asm.S"
