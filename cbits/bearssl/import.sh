#!/bin/sh
# Re-import the vendored parts of BearSSL.
#
# Only the five files crypton calls are kept, and they are kept unmodified,
# so that `diff` against a new release is readable.  What they want from
# upstream's two-thousand-line src/inner.h is supplied by the inner.h here,
# which is crypton's and is NOT overwritten by this script.  Run this from
# cbits/bearssl:
#
#     ./import.sh [version]
#
# and commit the result together with the VERSION line it writes, so that
# the tree always says which upstream release it holds.
set -eu

VER=${1:-0.6}
HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -sSL "https://bearssl.org/bearssl-$VER.tar.gz" -o "$TMP/b.tgz"
tar xzf "$TMP/b.tgz" -C "$TMP"
SRC="$TMP/bearssl-$VER"

cp "$SRC/LICENSE.txt"                    "$HERE/LICENSE"
cp "$SRC/src/symcipher/aes_ct64.c"       "$HERE/"
cp "$SRC/src/symcipher/aes_ct64_enc.c"   "$HERE/"
cp "$SRC/src/symcipher/aes_ct64_dec.c"   "$HERE/"
cp "$SRC/src/hash/ghash_ctmul64.c"       "$HERE/"
cp "$SRC/src/codec/dec32le.c"            "$HERE/"
echo "$VER" > "$HERE/VERSION"

echo "imported BearSSL $VER"
echo "now run the differential test in cbits/tests/bearssl_diff.c"
