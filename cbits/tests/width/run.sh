#!/bin/sh
# The three implementations that only a 32-bit architecture receives, asked
# the same questions as the 64-bit ones they stand in for.
#
#   cbits/include32/p256          against  cbits/include64/p256
#   cbits/curve25519-donna.c      against  curve25519-donna-c64.c
#   cbits/decaf/p448/arch_32      against  cbits/decaf/p448/arch_ref64
#
# No job in the matrix is 32-bit, so until this ran, none of the left column
# had ever been compiled, let alone executed.  The two sides of each pair
# define the same symbols, so they cannot share a binary: each driver is built
# twice and the two outputs compared.
#
# With a compiler that can target 32-bit x86 -- gcc-multilib on the Linux
# runner -- the 32-bit side is built a second time as a real 32-bit binary,
# which is the only way to see what the narrower int, size_t and pointer do.
#
# Usage: cbits/tests/width/run.sh [build-dir]
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
out=${1:-$(mktemp -d)}
cc=${CC:-cc}
mkdir -p "$out"
cd "$root"

D=cbits/decaf
decaf_common="$D/ed448goldilocks/decaf_all.c $D/ed448goldilocks/eddsa.c
              $D/ed448goldilocks/scalar.c $D/p448/f_arithmetic.c
              $D/p448/f_generic.c $D/utils.c cbits/crypton_sha3.c"

# name, the flags and sources for the 64-bit side, then for the 32-bit side
build() {
	# shellcheck disable=SC2086
	$cc -O2 -Wno-deprecated-declarations $EXTRA -o "$out/$1" $2 2>&1 |
		grep -vE "^$|deprecated" || true
	test -x "$out/$1" || { echo "did not build: $1"; exit 1; }
}

status=0
compare() {
	if cmp -s "$out/$1.txt" "$out/$2.txt"; then
		echo "ok   $3 ($(wc -l < "$out/$1.txt" | tr -d ' ') lines)"
	else
		echo "FAIL $3"
		diff "$out/$1.txt" "$out/$2.txt" | head -20
		status=1
	fi
}

for width in 64 32; do
	case $width in
	64) p256_inc=cbits/include64; donna=cbits/curve25519/curve25519-donna-c64.c; arch=arch_ref64 ;;
	32) p256_inc=cbits/include32; donna=cbits/curve25519/curve25519-donna.c;     arch=arch_32    ;;
	esac

	# decaf decides its word size twice and from two different things: the
	# field limbs from ARCH_WORD_BITS, which follows the arch directory
	# picked above, and the scalar limbs from CRYPTON_DECAF_WORD_BITS, which
	# common.h reads off the host compiler.  On a 32-bit machine -- the only
	# place cabal asks for arch_32 -- both come out 32.  Here the host is
	# 64-bit whichever side is being built, so say which is wanted rather
	# than compile a half-32-bit-half-64-bit library and compare that.

	EXTRA="-Icbits -I$p256_inc"
	build "p256_$width" "cbits/tests/width/p256_width.c cbits/p256/p256.c cbits/p256/p256_ec.c"

	EXTRA="-Icbits"
	build "x25519_$width" "cbits/tests/width/x25519_width.c $donna"

	EXTRA="-DCRYPTON_DECAF_WORD_BITS=$width -Icbits -I$D/include -I$D/p448 -I$D/include/$arch -I$D/p448/$arch"
	build "ed448_$width" "cbits/tests/width/ed448_width.c $decaf_common $D/p448/$arch/f_impl.c"

	for t in p256 x25519 ed448; do
		"$out/${t}_$width" > "$out/${t}_$width.txt"
	done
done

for t in p256 x25519 ed448; do
	compare "${t}_64" "${t}_32" "$t: the 32-bit implementation answers what the 64-bit one answers"
done

# The same sources again, this time actually narrow.  Only the 32-bit side is
# tried: the 64-bit P-256 wants __uint128_t, which a 32-bit target has not got,
# which is the whole reason the 32-bit side exists.
printf 'int main(void){return 0;}\n' > "$out/probe.c"
if $cc -m32 -o "$out/probe" "$out/probe.c" 2>/dev/null && "$out/probe"; then
	EXTRA="-m32 -Icbits -Icbits/include32"
	build p256_m32 "cbits/tests/width/p256_width.c cbits/p256/p256.c cbits/p256/p256_ec.c"
	EXTRA="-m32 -Icbits"
	build x25519_m32 "cbits/tests/width/x25519_width.c cbits/curve25519/curve25519-donna.c"
	EXTRA="-m32 -DCRYPTON_DECAF_WORD_BITS=32 -Icbits -I$D/include -I$D/p448 -I$D/include/arch_32 -I$D/p448/arch_32"
	build ed448_m32 "cbits/tests/width/ed448_width.c $decaf_common $D/p448/arch_32/f_impl.c"

	for t in p256 x25519 ed448; do
		"$out/${t}_m32" > "$out/${t}_m32.txt"
		compare "${t}_32" "${t}_m32" "$t: a 32-bit host answers what a 64-bit host answers"
	done
else
	echo "skip $cc cannot build and run a 32-bit binary here; the comparison above still ran"
fi

exit $status
