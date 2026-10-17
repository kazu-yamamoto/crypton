#!/bin/sh
# The window the secure exponentiation walks the exponent in.
#
# Four bits is what ships, and four is the one width that divides a byte.
# Five and six do not: a window falls across a byte boundary and the walk has
# to read two.  Each width answers the same vectors and the three sets of
# answers have to agree, since the width is not supposed to be visible in
# them.  Dropping the straddling read passes at four and fails at five and
# six, which is the calibration.
#
# The widths cannot see a fault they all share, so a modulus small enough to
# raise to a power by repeated multiplication is answered that way too.
#
# WINDOW_BITS used to be defined three times at the same value -- here, in
# cbits/crypton_ecc.c and in cbits/crypton_bignum.h -- and a redefinition to
# the same value is silent, so a build asking for five got four and said so
# nowhere.  The driver prints the width it was built with, so that cannot
# happen again unnoticed.
#
# Usage: cbits/tests/powm/run.sh [build-dir]
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
out=${1:-$(mktemp -d)}
cc=${CC:-cc}
mkdir -p "$out"
cd "$root"

src="cbits/tests/powm/powm_diff.c cbits/crypton_powm.c"
inc="-Icbits -Icbits/include64"

# On x86-64 the exponentiation asks the processor what it has, which lives in
# crypton_cpu.c, which in turn wants one symbol out of the AES build that
# nothing here calls.  The ct harness already carries a stand-in for it.
case $(uname -m) in
x86_64|amd64) src="$src cbits/crypton_cpu.c cbits/tests/ct/cpu_stub.c" ;;
esac

status=0

# The window the secure exponentiation walks in is four bits as it ships.
# Five and six are the widths that have been argued about, and unlike four
# they do not divide a byte, so the walk has to read across one.  Each width
# answers the same vectors and the three answers have to agree: the width is
# not supposed to be visible in them.
for w in 4 5 6; do
	# shellcheck disable=SC2086
	$cc -O2 -DPOWM_WINDOW_BITS=$w $inc \
	    -o "$out/powm_w$w" $src
	if r=$("$out/powm_w$w"); then
		echo "ok   ${r#ok   }"
	else
		echo "FAIL window of $w bits"
		echo "$r" | head -8
		status=1
	fi
	"$out/powm_w$w" dump > "$out/dump_w$w.txt"
done

for w in 5 6; do
	if cmp -s "$out/dump_w4.txt" "$out/dump_w$w.txt"; then
		echo "ok   a window of $w bits answers what four bits answers" \
		     "($(wc -l < "$out/dump_w4.txt" | tr -d ' ') vectors)"
	else
		echo "FAIL a window of $w bits answers differently"
		diff "$out/dump_w4.txt" "$out/dump_w$w.txt" | head -6
		status=1
	fi
done

exit $status
