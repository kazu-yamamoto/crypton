#!/bin/sh
# Watching for a primitive that has fallen off its accelerated path.
#
# #274 took SHA-256 from 3396 MB/s to 644 on an Apple M4 and shipped, because
# the answers were right and only the speed was wrong.  No test can catch
# that; this is what does.
#
# What it checks is ratios between primitives measured in the same run, not
# absolute throughput, because the runner is not the same machine twice --
# see cbits/tests/perf/floors.txt.  A ratio is only useful against a cliff;
# this will not notice a few per cent, and is not meant to.
#
# The last thing it does is build the library again with the AES acceleration
# turned off and check that the AES line then fails.  Without that, a run
# where the measurement had quietly stopped working would look exactly like a
# run where everything was fast.
#
# Usage: cbits/tests/perf/run.sh [build-dir]
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
out=${1:-$(mktemp -d)}
cc=${CC:-cc}
mkdir -p "$out"
cd "$root"

# The harness links against the library as cabal built it, so that what is
# measured is the configuration the package actually ships.
build_harness() {
	builddir=$1; bin=$2; shift 2
	cabal build lib:crypton --builddir="$builddir" -v0 "$@" > /dev/null
	archive=$(find "$builddir" -name 'libHScrypton-*.a' | head -1)
	test -n "$archive" || { echo "no library archive under $builddir"; exit 1; }
	$cc -O3 -Icbits -Icbits/include64 -Icbits/include32 \
		-o "$bin" cbits/tests/perf/throughput.c "$archive" 2>/dev/null ||
		$cc -O3 -Icbits -Icbits/include64 \
			-o "$bin" cbits/tests/perf/throughput.c "$archive"
}

measure() {
	best=0
	for _ in 1 2 3; do
		v=$("$1" "$2" 2>/dev/null || echo 0)
		best=$(awk -v a="$best" -v b="$v" 'BEGIN{print (b>a)?b:a}')
	done
	echo "$best"
}

# Every ratio in floors.txt, against the binary named.  Prints one line each
# and returns the number that were under the floor.
check() {
	bin=$1; label=$2; quiet=${3:-no}
	bad=0
	while read -r fast slow floor _rest; do
		case "$fast" in ''|\#*) continue ;; esac
		a=$(measure "$bin" "$fast")
		b=$(measure "$bin" "$slow")
		r=$(awk -v a="$a" -v b="$b" 'BEGIN{printf "%.2f", (b>0)?a/b:0}')
		under=$(awk -v r="$r" -v f="$floor" 'BEGIN{print (r<f)?1:0}')
		if [ "$under" = 1 ]; then
			bad=$((bad + 1))
			[ "$quiet" = yes ] ||
				printf 'BELOW %-10s %-11s %s / %s = %s, floor %s\n' \
					"$fast" "$slow" "$a" "$b" "$r" "$floor"
		else
			[ "$quiet" = yes ] ||
				printf 'ok    %-10s %-11s %s / %s = %s, floor %s\n' \
					"$fast" "$slow" "$a" "$b" "$r" "$floor"
		fi
	done < cbits/tests/perf/floors.txt
	return $bad
}

build_harness "$out/dist-perf" "$out/throughput"
set +e
check "$out/throughput" "as shipped"
failed=$?
set -e

# The calibration: with the AES acceleration compiled out, the AES line has to
# fail.  If it does not, the measurement is not reaching the library and
# nothing above meant anything.
echo "--- with -f-support_aesni, the AES line must fail ---"
build_harness "$out/dist-noaes" "$out/throughput-noaes" -f-support_aesni
set +e
check "$out/throughput-noaes" "no AES" yes
noaes=$?
set -e
if [ "$noaes" -eq 0 ]; then
	echo "FAIL the build without AES acceleration passed every floor, so this"
	echo "     job is not measuring the library and its result means nothing"
	exit 1
fi
echo "ok    the detector notices a primitive taken off its fast path"

if [ "$failed" -ne 0 ]; then
	echo ""
	echo "$failed ratio(s) under the floor: a primitive has lost its"
	echo "accelerated path, as in #274.  The floors are in"
	echo "cbits/tests/perf/floors.txt with what each one is for."
	exit 1
fi
