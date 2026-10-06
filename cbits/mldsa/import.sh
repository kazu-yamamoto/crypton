#!/bin/sh
# Re-import the vendored parts of the PQ Code Package's mldsa-native.
#
# The files are kept unmodified.  Everything crypton decides -- which
# parameter sets exist, what the symbols are called, that there is no
# randomised API -- is decided in cbits/mldsa/crypton_mldsa.c and in
# crypton.cabal, not by editing anything here.  Run this from cbits/mldsa:
#
#     ./import.sh [tag-or-commit]
#
# and commit the result together with the COMMIT line it writes, so that the
# tree always says which upstream revision it holds.
set -eu

REPO=https://github.com/pq-code-package/mldsa-native
REV=${1:-v2.0.0}
HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

git clone -q "$REPO" "$TMP/u"
git -C "$TMP/u" checkout -q "$REV"

rm -rf "$HERE/src"
cp "$TMP/u/mldsa/mldsa_native.c" "$HERE/"
cp "$TMP/u/mldsa/mldsa_native.h" "$HERE/"
cp "$TMP/u/mldsa/mldsa_native_asm.S" "$HERE/"
cp "$TMP/u/mldsa/mldsa_native_config.h" "$HERE/"
cp -R "$TMP/u/mldsa/src" "$HERE/src"
cp "$TMP/u/LICENSE" "$HERE/LICENSE"

# The 32-bit Armv8.1-M Keccak, for an architecture crypton does not build
# for.  Every reference to it is behind an MLD_SYS_ guard that cannot be true
# on the ones it does, so dropping it changes no build and keeps unreachable
# assembly out of the release tarball.
rm -rf "$HERE/src/fips202/native/armv81m"

git -C "$TMP/u" rev-parse HEAD > "$HERE/COMMIT"
git -C "$TMP/u" describe --tags --exact-match 2>/dev/null >> "$HERE/COMMIT" || true
echo "imported $(head -1 "$HERE/COMMIT")"
