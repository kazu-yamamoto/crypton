#!/bin/sh
# AES and GHASH against their references, the two differential tests that
# used to be run by hand:
#
#   cbits/tests/bearssl_diff.c  the portable AES and GHASH against the BearSSL
#                               they are written on, natively
#   cbits/tests/ppc8_diff.c     the POWER8 path against the portable one,
#                               cross-compiled and run under qemu-ppc64le
#
# Both were documented as something to run -- the first after re-importing
# BearSSL, the second whenever the POWER8 code changed -- and whether anyone
# had was not recorded anywhere.  Each is also run with an argument, which
# makes it corrupt results on purpose, and that run has to fail: a
# differential test that cannot fail has said nothing.
#
# The POWER8 half wants a powerpc64le cross compiler and qemu-ppc64le, and
# says skip where they are not installed.
#
# Usage: cbits/tests/aesdiff/run.sh [build-dir]
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
out=${1:-$(mktemp -d)}
cc=${CC:-cc}
mkdir -p "$out"
cd "$root"

status=0

# A function called without a declaration is an error here, not a warning.
# The POWER8 test was found calling four that way, its declarations having
# left a header while nothing built it; a warning in a log nobody reads is
# how that lasted.
strict=-Werror=implicit-function-declaration

# both ways: clean has to pass and sabotaged has to fail
judge() {
	name=$1; shift
	if "$@" > "$out/$name.log" 2>&1; then
		if "$@" sabotage > "$out/$name.sabotage.log" 2>&1; then
			echo "FAIL $name: the sabotaged run passed too, so this comparison"
			echo "     cannot fail and has checked nothing"
			status=1
		else
			echo "ok   $name: $(tail -1 "$out/$name.log"), and the sabotaged run fails"
		fi
	else
		echo "FAIL $name"
		tail -15 "$out/$name.log" | sed 's/^/    /'
		status=1
	fi
}

bearssl_src="cbits/tests/bearssl_diff.c cbits/crypton_aes.c cbits/aes/generic.c
             cbits/aes/gf.c $(ls cbits/bearssl/*.c)"
# shellcheck disable=SC2086
$cc -O2 $strict -Icbits -Icbits/aes -o "$out/bearssl_diff" $bearssl_src
judge bearssl_diff "$out/bearssl_diff"

ppc_cc=powerpc64le-linux-gnu-gcc
qemu=qemu-ppc64le-static
command -v "$qemu" > /dev/null 2>&1 || qemu=qemu-ppc64le
if command -v "$ppc_cc" > /dev/null 2>&1 && command -v "$qemu" > /dev/null 2>&1; then
	ppc_src="cbits/tests/ppc8_diff.c cbits/crypton_aes.c cbits/aes/generic.c
	         cbits/aes/gf.c cbits/aes/ppc8.c cbits/crypton_cpu.c
	         cbits/asm/aesp8-ppc-linux64le.S cbits/asm/ghashp8-ppc-linux64le.S
	         $(ls cbits/bearssl/*.c)"
	# shellcheck disable=SC2086
	"$ppc_cc" -O2 -static $strict -Icbits -Icbits/aes -DWITH_PPC8_CRYPTO \
	    -o "$out/ppc8_diff" $ppc_src
	judge ppc8_diff "$qemu" "$out/ppc8_diff"
else
	echo "skip ppc8_diff: no $ppc_cc or qemu-ppc64le here"
fi

exit $status
