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
| x86-64, ADX not advertised | 156.1 | **59.4** |

The third row is the `_alt` path, which is what crypton picks where `CPUID`
does not report ADX.  It was measured on a KVM guest whose `CPUID` says so
while the host underneath runs ADX instructions anyway, so it says what the
two implementations cost relative to each other on that path, not what an
actual pre-Broadwell part would do.

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

## RSA

`crypton_powm.c`'s modular exponentiation also borrows from here, but only its
innermost step and only on x86-64: `bignum_kmul_16_32`, `bignum_ksqr_16_32`,
`bignum_kmul_32_64`, `bignum_ksqr_32_64` and `bignum_emontredc_8n` replace the
C's Montgomery multiplication and square.  The window, the table and its masked
scan are crypton's throughout.  Sixteen limbs is 1024 bits and thirty-two is
2048: the halves a CRT exponentiation works in for RSA-2048 and RSA-4096, and
the whole thing without CRT.  The reduction wants ADX, so the choice is made at
run time like the other x86-64 ones.

It is twice the C, because the C cannot form the two carry chains `ADCX` and
`ADOX` give.  Measured on an EPYC 7763 at 1024 bits:

| | C | s2n-bignum |
| --- | ---: | ---: |
| multiplication | 0.4832 us | **0.2479** |
| square | 0.3984 | **0.1994** |

**Nothing is vendored for AArch64**, where the same measurement puts the C
about 5% ahead of the assembly.  That leaves crypton's RSA on Apple silicon at
about half OpenSSL's speed, and the reason is assembly and not the C: BearSSL's
`i62` -- 62-bit limbs in 64-bit words, so that a multiply-accumulate fits an
`__int128` with no carry chain at all, and a five-bit window against crypton's
four, which is as far as portable C is known to go -- was built and measured
against crypton's C on an M4, alternately and with the order swapped.
One RSA-2048 CRT private operation, best of five each: **626.4 us for crypton,
668.0 for BearSSL**.  There is no portable C left to find; closing that gap
means writing the AArch64 Montgomery multiplication in assembly, or finding one
under a licence this library can take.

## What is not here

s2n-bignum has only x86-64 and AArch64, so crypton's C stays and is what
every other architecture uses.  `p384_montjscalarmul` and `p521_jscalarmul`
have no affine wrapper upstream; crypton's is in `cbits/p256/p256_s2n.c`'s
sibling for those curves.  There is no fixed-base routine for P-384 or
P-521 at all, so signing on those curves keeps crypton's comb.
