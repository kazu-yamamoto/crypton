#!/bin/sh
# Does this C give the same answers on a big-endian machine?
#
# s390x and ppc64 are among the architectures the cabal file builds for, and
# neither is in the matrix.  Eighteen files read their input through the
# loaders in crypton_align.h -- rewritten from word-typed casts to memcpy in
# #256 -- and eight more decide something from the byte order themselves.
#
# The two sides cannot be compared in one run the way the 32-bit harness
# compares two builds, because the machine doing the comparing has only one
# byte order.  So the answers are frozen: vectors.txt is what this code gives
# on a little-endian host, and check mode reads it back.
#
# Usage: cbits/tests/endian/run.sh [generate] [build-dir]
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
mode=check
if [ "${1:-}" = generate ]; then mode=generate; shift; fi
out=${1:-$(mktemp -d)}
cc=${CC:-cc}
mkdir -p "$out"
cd "$root"

srcs="cbits/crypton_md4.c cbits/crypton_md5.c cbits/crypton_sha1.c
      cbits/crypton_sha256.c cbits/crypton_sha512.c cbits/crypton_sha3.c
      cbits/crypton_ripemd.c cbits/crypton_skein256.c cbits/crypton_skein512.c
      cbits/crypton_tiger.c cbits/crypton_whirlpool.c
      cbits/crypton_chacha.c cbits/crypton_salsa.c cbits/crypton_poly1305.c"

# Generating is done under the sanitizers, since a driver that writes out of
# bounds would otherwise freeze whatever it happened to leave behind.  That
# is not hypothetical: sha3's context ends in a flexible buffer and the first
# draft of the driver put it on the stack as a plain struct.
san=
if [ "$mode" = generate ]; then
	san="-fsanitize=address,undefined -fno-sanitize-recover=all"
fi

# shellcheck disable=SC2086
$cc -O2 -g $san -Icbits -Icbits/include64 -o "$out/endian" \
	cbits/tests/endian/endian.c $srcs

if [ "$mode" = generate ]; then
	"$out/endian" generate cbits/tests/endian/vectors.txt
	echo "wrote $(wc -l < cbits/tests/endian/vectors.txt | tr -d ' ') answers"
	echo "commit cbits/tests/endian/vectors.txt"
else
	"$out/endian" check cbits/tests/endian/vectors.txt
fi
