# mldsa-native

ML-DSA (FIPS 204) from the PQ Code Package, vendored here and built for all
three parameter sets.

## Where it comes from

<https://github.com/pq-code-package/mldsa-native>.  `COMMIT` holds the
revision this tree is at; `import.sh` puts it there and is how the tree is
refreshed.  Nothing here is edited by hand -- every choice crypton makes is
made in `crypton_mldsa.h`, `crypton_mldsa.c` and `crypton.cabal`, so that a
re-import is a straight overwrite.

## Licence

`Apache-2.0 OR ISC OR MIT`, the same three-way form as `cbits/s2n` and by
some of the same authors.  crypton takes it under ISC, which is already in
the package's `license:` field.  `LICENSE` is the upstream file and is
listed in `license-files:`.

## What is taken and what is not

The whole of `mldsa/`, less the backends for architectures crypton does not
build for: the 32-bit
`src/fips202/native/armv81m`.  (Unlike mlkem-native, this one ships only the
AArch64 and x86-64 arithmetic backends, so there is nothing else to drop.)  Every reference to those is behind an
`MLD_SYS_` guard that cannot be true on the architectures crypton does
build for, so dropping them changes no build and keeps a few dozen files of
unreachable assembly out of the release tarball.  To take one back, delete
its line from `import.sh` and add its directory to `extra-source-files:`.

## How it is built

Upstream builds for one parameter set at a time.  `crypton_mldsa.c`
includes the amalgamation once per set -- the level-independent half kept by
exactly one of them -- which is how a single crypton offers ML-DSA-44, 65
and 87.  `crypton_mldsa_asm.S` does the same for the assembly, which is
level-independent and so is included once.

This is the shape `cbits/aes/armv8.c` already uses for the three AES key
sizes, and it has the same hazard: **cabal does not know that the wrapper
depends on the tree it includes.**  After changing anything under
`cbits/mldsa`, touch `crypton_mldsa.c`, or the build keeps the object it
already has and the change is not tested.

The hand-written backends are selected by `CRYPTON_MLDSA_NATIVE_BACKEND`,
which `crypton.cabal` defines on x86-64 and AArch64 other than Windows --
the same exclusion, and for the same reasons, as `cbits/s2n`.  Everywhere
else the portable C is built, which is the same code and passes the same
tests.

There is no randomised API: `MLD_CONFIG_NO_RANDOMIZED_API` is set, no
`randombytes()` is needed, and randomness is drawn in Haskell through
`MonadRandom` as it is for every other key crypton generates.

The symbols are `crypton_mldsa44_*`, `crypton_mldsa65_*` and
`crypton_mldsa87_*` rather than upstream's defaults, so that an
application linking another copy of mldsa-native -- through some other
library, or its own -- does not present the linker with two sets of
functions answering to one set of names.
