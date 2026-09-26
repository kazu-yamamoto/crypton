# s2n-bignum

Assembly for the NIST prime curves from AWS's
[s2n-bignum](https://github.com/awslabs/s2n-bignum), vendored here.

`COMMIT` holds the upstream revision these files came from, and `import.sh`
fetches them again.  The files are unmodified: the choice between the two
variants of each routine is made in crypton's own C, not by editing theirs.

## Why

crypton's P-256 is portable C, and on the two architectures s2n-bignum
covers, hand-written assembly beats it by a lot.  Measured against crypton's
own code in the same process, agreeing with it on every scalar tried:

| | crypton | s2n-bignum |
| --- | ---: | ---: |
| Apple M4 | 52.9 us | **20.6** |
| x86-64 with ADX (EPYC 9V74) | 175.9 | **54.5** |
| x86-64 without ADX (Haswell) | 156.1 | **59.4** |

Each routine also carries a machine-checked proof in HOL-Light that it
computes what it says, and is written in a constant-time style.

## Licence

`Apache-2.0 OR ISC OR MIT-0`, one of which is on every file and all three in
`LICENSE`.  crypton is BSD-3, so it takes these under **ISC** -- the MIT-0
option would do as well, and the Apache one is the reason OpenSSL's and
BoringSSL's `ecp_nistz256`, which is Apache-2.0 only, cannot be used here.

## Which variant

Both forms of each routine are vendored, because which one is faster is not
the same question on the two architectures:

* **On ARM**, `_alt` is written for parts with high multiplier throughput,
  which is what Apple silicon is, and it wins there by 30-40%.  The plain
  form is for parts that pipeline `UMULH` less well.  There is no feature bit
  for this, so the choice is made at compile time on `__APPLE__`.
* **On x86-64**, the plain form uses `MULX`, `ADCX` and `ADOX`, and `_alt` is
  the fallback for processors without them.  That *is* a feature bit, so the
  choice is made at run time, from `crypton_x86_simd_features()`.

## What is not here

s2n-bignum has only x86-64 and AArch64, so crypton's C stays and is what
every other architecture uses.  `p384_montjscalarmul` and `p521_jscalarmul`
have no affine wrapper upstream; crypton's is in `cbits/p256/p256_s2n.c`'s
sibling for those curves.  There is no fixed-base routine for P-384 or
P-521 at all, so signing on those curves keeps crypton's comb.
