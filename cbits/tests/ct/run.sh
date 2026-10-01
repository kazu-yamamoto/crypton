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

# And, on AArch64, the same driver again against the instructions.  That one
# has to be silent; this one has to report.  Either going the wrong way says
# the run is not measuring what it claims to.
armv8_src="$aes_src cbits/aes/armv8.c cbits/crypton_cpu.c"
armv8_inc="-DWITH_ARMV8_CRYPTO -march=armv8-a+crypto -Icbits/aes"

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
	# Which places did it name?  Only the frame the report is against -- the
	# "at" line -- is the place; the "by" lines below it are how the code got
	# there and are not themselves branching on anything.  A site is
	# "file:line", and the ones listed in known.txt are understood.
	sites=$(sed -n 's/^==[0-9]*==    at 0x[0-9A-Fa-f]*: [A-Za-z_0-9]* (\([^)]*\))$/\1/p' \
		"$out/$name.log" | grep -v '^ct_' | sort -u)
	unknown=
	for site in $sites; do
		file=${site%%:*}
		if grep -q "^$site[[:space:]]" cbits/tests/ct/known.txt ||
		   grep -q "^$file[[:space:]]" cbits/tests/ct/known.txt; then
			continue
		fi
		unknown="$unknown $site"
	done

	case $name in
	canary)
		# the calibration: silence here would mean the marking never reached
		# the code, and every other zero in this run would be worthless
		if [ "$n" -eq 0 ]; then
			echo "FAIL canary: the deliberately leaky driver reported nothing,"
			echo "     so the marking is not reaching the code and nothing below counts"
			status=1
		else
			echo "ok   canary: reported $n, so the marking works"
		fi
		;;
	aes)
		# Silence would mean the build took an accelerated path and so
		# measured nothing; the tables reporting is the point.
		if [ "$n" -eq 0 ]; then
			echo "FAIL aes: reported nothing, so this build did not take the"
			echo "     table-driven code the driver exists to measure"
			status=1
		else
			echo "note aes: $n report(s), from $(echo "$sites" | tr '\n' ' ')"
		fi
		;;
	aes_armv8)
		# The opposite demand, and known.txt does not apply: the entries in
		# it are for the tables, and this build is not supposed to reach
		# them.  Anything at all here is a finding, including a table site,
		# which would mean the dispatch did not pick the instructions.
		if [ "$n" -eq 0 ]; then
			echo "ok   aes_armv8: the instructions decided nothing"
		else
			echo "FAIL aes_armv8: $n report(s) from the AArch64 AES or GHASH,"
			echo "     which look nothing up and should branch on nothing:"
			for site in $sites; do echo "         $site"; done
			sed -n '/Conditional jump\|Use of uninitialised/,/^==[0-9]*== $/p' \
				"$out/$name.log" | head -30 | sed 's/^/    /'
			status=1
		fi
		;;
	*)
		if [ "$n" -eq 0 ]; then
			echo "ok   $name: the secret decided nothing"
		elif [ -z "$unknown" ]; then
			echo "ok   $name: $n report(s), all known -- $(echo "$sites" | tr '\n' ' ')"
		else
			echo "REPORT $name: the secret decided a branch or an address"
			echo "       somewhere not listed in cbits/tests/ct/known.txt:"
			for site in $unknown; do echo "         $site"; done
			sed -n '/Conditional jump\|Use of uninitialised/,/^==[0-9]*== $/p' \
				"$out/$name.log" | head -30 | sed 's/^/    /'
			status=1
		fi
		;;
	esac
}

# The calibration first: it must report, or nothing below means anything.
run_one canary  "" ""

run_one powm    "cbits/crypton_powm.c" ""
run_one p256    "cbits/p256/p256.c cbits/p256/p256_ec.c" ""
run_one x25519  "cbits/curve25519/curve25519-donna-c64.c" ""
run_one ed25519 "cbits/ed25519/ed25519.c cbits/crypton_sha512.c" "-Icbits/ed25519"
run_one decaf   "$decaf_src" "$decaf_inc"
run_one chapoly "cbits/crypton_chacha.c cbits/crypton_poly1305.c" ""
run_one aes     "$aes_src" ""

# Only where the instructions exist.  Elsewhere there is nothing to measure
# and the build would not even compile.
case $(uname -m) in
aarch64 | arm64)
	run_one aes_armv8 "$armv8_src" "$armv8_inc"
	;;
esac

if [ "$have_valgrind" = no ]; then
	echo "skip no valgrind here, so none of the above was checked"
	exit 0
fi
exit $status
