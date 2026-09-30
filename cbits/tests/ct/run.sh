#!/bin/sh
# Does the code that handles a secret run in time independent of it?
#
# memcheck already follows undefined bytes through arithmetic and reports the
# moment one decides a branch or an address.  That is the same question, so
# each driver declares its secret undefined and runs under valgrind: every
# report names a place where the secret reached a branch or an index.
# The technique is Adam Langley's ctgrind.
#
# Without valgrind the drivers are still built and run, which says only that
# the plumbing is right -- it checks nothing about timing, and says so.
#
# Usage: cbits/tests/ct/run.sh [build-dir]
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
out=${1:-$(mktemp -d)}
cc=${CC:-cc}
mkdir -p "$out"
cd "$root"

D=cbits/decaf
decaf_src="$D/ed448goldilocks/decaf_all.c $D/ed448goldilocks/eddsa.c
           $D/ed448goldilocks/scalar.c $D/p448/f_arithmetic.c
           $D/p448/f_generic.c $D/utils.c $D/p448/arch_ref64/f_impl.c
           cbits/crypton_sha3.c"
decaf_inc="-DCRYPTON_DECAF_WORD_BITS=64 -I$D/include -I$D/p448
           -I$D/include/arch_ref64 -I$D/p448/arch_ref64"

# The generic C, not whatever the machine happens to offer.  A build that
# takes AES-NI reports nothing from the AES driver and says nothing about the
# table-driven code every other machine runs.
aes_src="cbits/crypton_aes.c cbits/aes/generic.c cbits/aes/gf.c"

status=0
have_valgrind=no
ct_define=
if command -v valgrind > /dev/null 2>&1; then
	have_valgrind=yes
	ct_define=-DCRYPTON_CT_VALGRIND
fi

run_one() {
	name=$1; srcs=$2; inc=$3
	# shellcheck disable=SC2086
	$cc -O2 -g $ct_define -Icbits -Icbits/include64 $inc \
		-o "$out/$name" "cbits/tests/ct/ct_$name.c" $srcs 2> "$out/$name.cc" || {
		echo "FAIL $name did not build"; sed -n '1,12p' "$out/$name.cc"; status=1; return
	}
	if [ "$have_valgrind" = no ]; then
		"$out/$name" > /dev/null 2>&1 && echo "built $name (no valgrind here; nothing checked)" \
			|| { echo "FAIL $name did not run"; status=1; }
		return
	fi
	valgrind --error-exitcode=0 --track-origins=yes --num-callers=20 \
		--log-file="$out/$name.log" "$out/$name" > /dev/null 2>&1 || true
	n=$(grep -c "^==[0-9]*== \(Conditional jump\|Use of uninitialised\)" "$out/$name.log" || true)
	if [ "$name" = canary ]; then
		canary_reports=$n
		if [ "$n" -eq 0 ]; then
			echo "FAIL canary: the deliberately leaky driver reported nothing,"
			echo "     so the marking is not reaching the code and no result below counts"
			status=1
		else
			echo "ok   canary: reported $n, so the marking works"
		fi
		return
	fi
	if [ "$n" -eq 0 ]; then
		echo "ok   $name: the secret decided nothing"
	else
		echo "REPORT $name: $n place(s) where the secret decided a branch or an address"
		sed -n '/Conditional jump\|Use of uninitialised/,/^==[0-9]*== $/p' "$out/$name.log" |
			head -40 | sed 's/^/    /'
		status=1
	fi
}

# The calibration first: it must report, or nothing below means anything.
canary_reports=0
run_one canary  "" ""

run_one powm    "cbits/crypton_powm.c" ""
run_one p256    "cbits/p256/p256.c cbits/p256/p256_ec.c" ""
run_one x25519  "cbits/curve25519/curve25519-donna-c64.c" ""
run_one ed25519 "cbits/ed25519/ed25519.c cbits/crypton_sha512.c" "-Icbits/ed25519"
run_one decaf   "$decaf_src" "$decaf_inc"
run_one chapoly "cbits/crypton_chacha.c cbits/crypton_poly1305.c" ""
run_one aes     "$aes_src" ""

if [ "$have_valgrind" = no ]; then
	echo "skip no valgrind here, so none of the above was checked"
	exit 0
fi
exit $status
