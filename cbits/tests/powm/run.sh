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
# The public-exponent exponentiation declines on every machine where what the
# caller already has is faster, which is most of them and all of the ones
# this can be developed on.  CRYPTON_POWM_PUB_ALWAYS makes it accept, so its
# arithmetic is exercised wherever this runs rather than only where it ships.
inc="-Icbits -Icbits/include64 -Icbits/s2n/include -DCRYPTON_POWM_PUB_ALWAYS"

# The assembly that computes R^2 is built in where the library would build
# it, so that the two ways of computing that constant can be compared.  The
# define is the library's own.
case $(uname -m) in
aarch64|arm64)
	src="$src cbits/s2n/arm/bignum_montifier.S"
	inc="$inc -DCRYPTON_S2N_BIGNUM" ;;
x86_64|amd64)
	# the define also turns on the exponentiation's own s2n path, which
	# wants the five routines its inner step borrows -- so they are built
	# in too, and the walk here is the one the library ships.  Whether
	# they run is a question about ADX the code asks at run time.
	src="$src cbits/s2n/x86_att/bignum_montifier.S
	           cbits/s2n/x86_att/bignum_kmul_16_32.S
	           cbits/s2n/x86_att/bignum_kmul_32_64.S
	           cbits/s2n/x86_att/bignum_ksqr_16_32.S
	           cbits/s2n/x86_att/bignum_ksqr_32_64.S
	           cbits/s2n/x86_att/bignum_emontredc_8n.S
	           cbits/s2n/x86_att/bignum_mul.S
	           cbits/s2n/x86_att/bignum_sqr.S"
	inc="$inc -DCRYPTON_S2N_BIGNUM" ;;
esac

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

# The same vectors once more, from the C alone: no CRYPTON_S2N_BIGNUM, so
# neither the montifier nor, on x86-64, the exponentiation's s2n-bignum
# multiplication.  Every other comparison here runs both of its sides
# through the same multiplication.  Most faults in it -- or in the glue that
# pads a 24-limb operand for it -- still show there, since the two sides call
# it in different orders and come out wrong differently; but a fault that is
# wrong the same way on both sides, as computing consistently modulo the
# wrong number would be, agrees with itself and passes.  Nothing else in the
# test suite reaches 24 limbs at all.  This comparison does not depend on the
# multiplication being right to see that it is wrong.  On a machine without
# ADX the x86-64 build above takes the C as well; -DCRYPTON_CPU_TESTING_ADX,
# where the instructions are known to run, is what makes it differ.  On
# AArch64, -DCRYPTON_NO_MONT_SQR keeps the generated squaring out of it too.
csrc="cbits/tests/powm/powm_diff.c cbits/crypton_powm.c"
case $(uname -m) in
x86_64|amd64) csrc="$csrc cbits/crypton_cpu.c cbits/tests/ct/cpu_stub.c" ;;
esac
# shellcheck disable=SC2086
$cc -O2 -DCRYPTON_POWM_PUB_ALWAYS -DCRYPTON_NO_MONT_SQR -Icbits -Icbits/include64 \
    -o "$out/powm_c" $csrc
"$out/powm_c" dump > "$out/dump_c.txt"
if cmp -s "$out/dump_w4.txt" "$out/dump_c.txt"; then
	echo "ok   the vendored assembly answers what the C alone answers" \
	     "($(wc -l < "$out/dump_c.txt" | tr -d ' ') vectors)"
else
	echo "FAIL the vendored assembly answers differently from the C"
	diff "$out/dump_w4.txt" "$out/dump_c.txt" | head -6
	status=1
fi

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
