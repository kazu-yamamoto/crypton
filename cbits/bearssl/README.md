# BearSSL

Constant-time AES and GHASH from [BearSSL](https://bearssl.org/), vendored
here.  `VERSION` holds the upstream release these files came from, and
`import.sh` fetches them again.

## Why

crypton's portable AES and GHASH are table-driven, and both index their
tables with a secret: `cbits/aes/generic.c` with a byte of the state, in
every round and in the key expansion, and `cbits/aes/gf.c` with a nibble of
the GHASH accumulator.  Both are variable-time by construction, and the
cache-timing attacks on that shape of code are old and well documented.

The processors that have AES instructions do not run any of it -- crypton
asks them first.  What runs it is everything else: ppc64le and s390x, where
the instructions exist but crypton has no path to them; 32-bit ARM, where
the same is true; riscv64 and loongarch64; and the boards that genuinely
have no AES instructions at all, of which the Raspberry Pi 3 and 4 are by
some distance the largest population.

BearSSL's answer is bitslicing.  `aes_ct64` holds four blocks interleaved
across eight 64-bit words and computes the S-box as boolean algebra, so
there is no table and no address derived from a secret; `ghash_ctmul64`
builds the GF(2^128) multiply out of shifts, masks and integer multiplies
rather than a table of H.  Both are plain C99 and assume nothing beyond
`uint64_t`.

## What is here

| file | from |
| --- | --- |
| `aes_ct64.c` | `src/symcipher/aes_ct64.c` |
| `aes_ct64_enc.c` | `src/symcipher/aes_ct64_enc.c` |
| `aes_ct64_dec.c` | `src/symcipher/aes_ct64_dec.c` |
| `ghash_ctmul64.c` | `src/hash/ghash_ctmul64.c` |
| `dec32le.c` | `src/codec/dec32le.c`, for `br_range_dec32le` |
| `LICENSE` | `LICENSE.txt` -- MIT, (c) 2016 Thomas Pornin |

`inner.h` is **crypton's, not upstream's**.  Each of those five opens with
`#include "inner.h"`, and upstream's is some two thousand lines declaring
the whole library; these five want six things from it.  So this one gives
those six and nothing else, which is what lets the five stay byte for byte
what upstream ships.  `import.sh` does not overwrite it.

The byte-order helpers in it are written rather than copied, in their plain
portable form without upstream's unaligned-access fast paths, so that no
platform configuration comes with them.

## Keeping it honest

`cbits/tests/bearssl_diff.c` checks this against the implementation it
replaces: the FIPS-197 vectors first, so that agreement means AES and not
merely that both sides compute the same wrong thing, then a run of random
keys and blocks, then GHASH against the 4-bit table.  Given any argument it
corrupts three results on purpose and the comparison has to notice -- a
differential test that cannot fail has said nothing.
