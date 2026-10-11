#!/bin/sh
# The harnesses the README's tables are measured with, one pair per crypton
# version: a C one for the bulk algorithms and a Haskell one for the public
# key operations.
#
#   BENCH_VERS=1.1.5,2.2.0 BENCH_BIN=/tmp/bench bench/build.sh
#
# Both are built by cabal rather than by a hand-written compile line, so that
# the C is configured as the package ships it.  -O3 for the C of every
# version: crypton 1.1.5 asks for -optc-O3 as the current one does, and
# compiling the old tree at -O2 flatters the new one by about a tenth on code
# that did not change.
#
# The version that matches this tree's cabal file is taken from the tree; any
# other is fetched from Hackage.
set -eu

vers=${BENCH_VERS:-1.1.5,2.2.0}
out=${BENCH_BIN:-/tmp/bench}
here=$(cd "$(dirname "$0")/.." && pwd)
local_ver=$(sed -n 's/^version:[[:space:]]*//p' "$here/crypton.cabal" | head -1)

rm -rf "$out"
mkdir -p "$out"
cabal update >/dev/null 2>&1 || true

for v in $(echo "$vers" | tr ',' ' '); do
    if [ "$v" = "$local_ver" ]; then
        tree=$here
    else
        rm -rf "/tmp/crypton-$v"
        (cd /tmp && cabal get "crypton-$v" >/dev/null)
        tree=/tmp/crypton-$v
    fi
    echo "crypton $v from $tree"

    rm -rf "/tmp/db-$v"
    (cd "$tree" && cabal build lib:crypton --builddir="/tmp/db-$v" -v0)
    a=$(find "/tmp/db-$v" -name "libHScrypton-$v-inplace.a" | head -1)
    [ -n "$a" ] || { echo "no library archive for crypton $v" >&2; exit 1; }
    cc -O3 -I"$tree/cbits" -I"$tree/cbits/include64" \
       -o "$out/bulk-$v" "$here/bench/bulk.c" "$a"

    d=/tmp/pk-$v
    rm -rf "$d"
    mkdir -p "$d"
    cp "$here/bench/PK.hs" "$d/"
    sed "s/crypton\$/crypton == $v/" "$here/bench/pk.cabal" > "$d/pk.cabal"
    printf 'packages: . %s\n' "$tree" > "$d/cabal.project"
    (cd "$d" && cabal build -v0)
    cp "$(cd "$d" && cabal list-bin pkbench)" "$out/pk-bin-$v"
done

ls -l "$out"
