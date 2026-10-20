/*
 * crypton's, not s2n-bignum's: what the vendored assembly needs on Windows,
 * kept out of the vendored files so that import.sh can replace them as it
 * always has.
 *
 * Every file in this directory includes "_internal_s2n_bignum_x86_att.h",
 * and a quoted include looks first in the directory of the file that asks
 * for it -- so this is the one each of them gets, and it hands on to
 * upstream's own in cbits/s2n/include.  On Linux and macOS it changes
 * nothing.
 *
 * On Windows, two things.  The ELF directives .type and .size are refused by
 * the COFF assemblers -- gcc's says "junk at end of line" and clang's
 * "expected absolute expression" -- and there is nothing in a PE object for
 * them to say, so they are emptied, as upstream does for Mach-O.  And the
 * calling convention is Microsoft's, not System V's: each file carries a
 * prologue that moves its arguments into the registers it was written
 * for, under WINDOWS_ABI, which upstream leaves to the build to define.
 */
/* By a path from this file rather than by #include_next: clang, finding
 * this file next to the one that asked for it, starts #include_next from
 * the top of the search and finds this file again, without end. */
#include "../include/_internal_s2n_bignum_x86_att.h"

#if defined(_WIN32)
#  undef S2N_BN_FUNCTION_TYPE_DIRECTIVE
#  define S2N_BN_FUNCTION_TYPE_DIRECTIVE(name) /* not used in COFF */
#  undef S2N_BN_SIZE_DIRECTIVE
#  define S2N_BN_SIZE_DIRECTIVE(name) /* not used in COFF */
#  ifndef WINDOWS_ABI
#    define WINDOWS_ABI 1
#  endif
#endif
