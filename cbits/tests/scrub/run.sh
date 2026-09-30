#!/bin/sh
# What is left on the stack after a secret has been through it.
#
# The stack below a returning function is not erased -- it is simply no longer
# addressed -- so whatever a primitive kept there stays until something else
# writes over it, and a later core file or swapped page carries it away.
#
# The driver paints the stack, runs each primitive on an unmistakable secret,
# copies the painted region away before anything can disturb it, and looks for
# the pattern.  The first probe keeps the secret on purpose and has to be
# found; if it is not, the search is looking somewhere the calls do not use
# and no other result counts.
#
# Not run under the sanitizers: reading the stack below the current frame is
# exactly what this does, and ASan calls that an error.
#
# Usage: cbits/tests/scrub/run.sh [build-dir]
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
out=${1:-$(mktemp -d)}
cc=${CC:-cc}
mkdir -p "$out"
cd "$root"

$cc -O2 -Icbits -Icbits/include64 -o "$out/scrub" cbits/tests/scrub/scrub.c \
	cbits/crypton_sha256.c cbits/crypton_sha512.c cbits/crypton_chacha.c \
	cbits/crypton_poly1305.c cbits/crypton_powm.c

"$out/scrub"
