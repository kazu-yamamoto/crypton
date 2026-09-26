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

# Both variants of each routine are taken, since which one is faster is not
# the same question on the two architectures -- see README.md.  Where the
# upstream tree has no separate _alt file the plain one defines both symbols,
# so "copy it if it is there" gets the right set either way.
take() {
	curve=$1
	name=$2
	for arch in arm x86_att; do
		for v in "" _alt; do
			src="$TMP/s2n/$arch/$curve/$name$v.S"
			if [ -f "$src" ]; then
				cp "$src" "$HERE/$arch/$name$v.S"
			fi
		done
	done
}

# P-256: variable-point scalar multiplication, affine in and out, and the
# fixed-base one, which reads a table of its own that
# cbits/p256/gen_base_table.py builds.
take p256 p256_scalarmul
take p256 p256_scalarmulbase

# P-384 and P-521 have no affine wrapper upstream, so the Montgomery and
# Jacobian conversions are built here out of these; the glue is in
# cbits/crypton_ecc_s2n.c.
take p384 p384_montjscalarmul
take p384 bignum_tomont_p384
take p384 bignum_deamont_p384
take p384 bignum_montmul_p384
take p384 bignum_montsqr_p384
take p384 bignum_montinv_p384

take p521 p521_jscalarmul
take p521 bignum_mul_p521
take p521 bignum_sqr_p521
take p521 bignum_inv_p521

git -C "$TMP/s2n" rev-parse HEAD > "$HERE/COMMIT"
echo "imported $(cat "$HERE/COMMIT")"
