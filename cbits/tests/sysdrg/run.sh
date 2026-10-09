#!/bin/sh
# Does the generator behind MonadRandom IO survive the things that break a
# generator: a second thread, a reseed, and a fork?
#
# None of this can be asked from Haskell alone.  A forkIO thread is not an
# operating system thread, and the Haskell test suite cannot fork the way a
# child process must for the question to mean anything.
#
# Usage: cbits/tests/sysdrg/run.sh [build-dir]
set -eu

cbits=$(cd "$(dirname "$0")/../.." && pwd)
out=${1:-$(mktemp -d)}

${CC:-cc} -O2 -Wall -Wextra -DCRYPTON_SYSDRG_TESTING -I"$cbits" -o "$out/sysdrg" \
    "$cbits/tests/sysdrg/sysdrg.c" \
    "$cbits/crypton_sysdrg.c" \
    "$cbits/crypton_sysrandom.c" \
    "$cbits/crypton_chacha.c" \
    "$cbits/crypton_sha512.c"

"$out/sysdrg"
