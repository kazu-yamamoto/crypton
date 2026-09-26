#!/bin/sh
# Re-import the vendored parts of AWS's s2n-bignum.
#
# Only the files crypton calls are kept, and they are kept unmodified -- the
# dispatch that chooses between the two variants of each is in
# cbits/p256/p256_s2n.c, not in here.  Run this from cbits/s2n:
#
#     ./import.sh [commit]
#
# and commit the result together with the COMMIT line it writes, so that the
# tree always says which upstream revision it holds.
set -eu

REPO=https://github.com/awslabs/s2n-bignum
REV=${1:-main}
HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

git clone -q "$REPO" "$TMP/s2n"
git -C "$TMP/s2n" checkout -q "$REV"

# The headers every vendored file includes.
for h in _internal_s2n_bignum_arm.h _internal_s2n_bignum_x86_att.h; do
	cp "$TMP/s2n/include/$h" "$HERE/include/$h"
done
cp "$TMP/s2n/LICENSE" "$HERE/LICENSE"

# P-256 variable-point scalar multiplication, both variants of each: on ARM
# the _alt form is the fast one on Apple silicon, on x86-64 it is the
# fallback for processors without ADX.
for f in p256_scalarmul p256_scalarmul_alt; do
	cp "$TMP/s2n/arm/p256/$f.S"      "$HERE/arm/$f.S"
	cp "$TMP/s2n/x86_att/p256/$f.S"  "$HERE/x86_att/$f.S"
done

git -C "$TMP/s2n" rev-parse HEAD > "$HERE/COMMIT"
echo "imported $(cat "$HERE/COMMIT")"
