![GitHub Actions status](https://github.com/kazu-yamamoto/crypton/workflows/Haskell%20CI/badge.svg)

crypton
==========

`crypton` is a fork from `cryptonite` with the original author's permission.


`crypton` is a low-level cryptography library. To achieve high
performance, it utilizes C and assembly language to define FFI
bindings, structuring them in a way that makes them easy to use.


Side channels
-------------

### AES

AES is where this matters most, and which implementation runs is decided at
runtime from what the processor has.

On x86-64 with AES-NI and carry-less multiply, on AArch64 and on 32-bit ARM
with the ARMv8 cryptographic extension, and on ppc64le with the vector
instructions PowerISA 2.07 brought to POWER8, AES and GHASH are instructions
rather than software.  crypton's AES and AES-GCM then make no branch and no
memory access that depends on the key or on the data: the secrets stay in
vector registers and never reach one a branch can test.  Every x86-64 part
since about 2010 and every AArch64 part in ordinary use has these, and the
ppc64le path is little-endian only.

Where none of them is there, crypton computes AES and GHASH without a table.
The portable AES is bitsliced -- the S-box is boolean algebra over four
blocks held across eight 64-bit words -- and the GF(2^128) multiply is built
from shifts, masks and integer multiplies.  Neither looks anything up, so
neither derives an address from a secret, and **the portable path is constant
time as well**.  The code is BearSSL's, under MIT, in `cbits/bearssl`.

The constant-time harness in `cbits/tests/ct` runs the same driver against
the portable implementation and against each architecture's instructions, and
every one of them is required to report nothing at all.

So the answer does not depend on the machine any more, and what is left to
ask is whether AES is fast on it.  `hasAESAcceleration` and
`hasGHASHAcceleration` answer that without naming an architecture.
`processorOptions` says what was found, in the processor's own names --
`AESNI` and `PCLMUL` on x86, `ARMAES` and `ARMPMULL` on AArch64 and 32-bit
ARM, `PPCAES` and `PPCVPMSUM` on ppc64le -- along with everything else it was
asked about, which is unrelated to this.

    ghci> import Crypto.System.CPU
    ghci> hasAESAcceleration
    True
    ghci> processorOptions           -- on an x86-64 machine
    [AESNI,PCLMUL,SSSE3,AVX,AVX2,SHANI,MOVBE,ADX,VAES]
    ghci> processorOptions           -- and on an AArch64 one
    [NEON,ARMAES,ARMPMULL,ARMSHA1,ARMSHA2,ARMSHA512]

### RSA

RSA is the other place to know about, and there the choice is the caller's.
The private key operations in `Crypto.PubKey.RSA.PKCS15`, `.OAEP` and `.PSS`
take a `Maybe Blinder`, and `Nothing` is no harder to write than the safe
form:

    decrypt     :: Maybe Blinder -> PrivateKey -> ByteString -> ...
    decryptSafer :: MonadRandom m => PrivateKey -> ByteString -> m ...

The exponent itself is not what is at risk.  `expSafe` keeps the *value* of an
exponent out of the work it does, so the private exponent does not leak
through the exponentiation.  What a blinder covers is the other side: without
one, the operation runs on the ciphertext the caller was handed, so how long
it takes depends on a number an attacker may have chosen and can vary.  That
is what a remote timing attack on RSA needs.  With a blinder the input is
multiplied by a random value first and the result divided out afterwards, so
the timing carries nothing an attacker can steer.

`decryptSafer` and `signSafer` generate the blinder themselves and are the
ones to reach for.  Pass `Nothing` only where the input is not attacker
controlled and you have decided that it is not.

The RSA rows in the tables below are the unblinded path.  A blinder costs one
more exponentiation, by the public exponent, which is the cheap direction:
measured on the M4, signing goes from about 460 to about 476 microseconds,
under four per cent.

Performance
-----------

The algorithms a TLS connection uses, measured against the last release
before the rewrite and against OpenSSL on the same machine.  Throughput is
over 16 KiB messages; the public key operations are one operation each; every
figure is the best of several runs, and crypton and OpenSSL are run
alternately so that neither gets the quieter machine.

Bulk encryption and hashing are measured through crypton's C layer, as
`openssl speed` measures OpenSSL's.  The public key operations are measured
through crypton's Haskell API, since that is where ECDSA and RSA live and it
is what a program actually calls; the Haskell layer adds well under a
microsecond, which the X25519 and ECDH P-256 rows confirm by agreeing with a
C-level measurement to within a percent.  Both releases of crypton are built
the same way -- `-optc-O3`, which is what each asks for -- and by
`cabal build`, since a copy of the sources compiled by hand does not measure
what a program linking the library gets, and leaves out whole implementations
without saying so.  Each column of a table comes from one run on the machine
named above it.

### x86-64

An AMD EPYC 7763, which has AES-NI, PCLMULQDQ, AVX2, ADX, VAES, VPCLMULQDQ
and the SHA extensions, against OpenSSL 4.0.3.

Throughput in MB/s, **higher is better**:

| | crypton 1.1.5 | crypton 2.2.0 | OpenSSL | 2.2.0 / OpenSSL |
| --- | ---: | ---: | ---: | ---: |
| AES-128-GCM | 1335 | **6034** | 4050 | 1.49 |
| AES-256-GCM | 1093 | **5484** | 3783 | 1.45 |
| ChaCha20-Poly1305 | 399 | 2198 | 2213 | 0.99 |
| SHA-1 | 729 | 1695 | 1673 | 1.01 |
| SHA-256 | 290 | 1585 | 1571 | 1.01 |
| SHA-512 | 449 | 770 | 752 | 1.02 |
| SHA3-256 | 109 | 422 | 425 | 0.99 |

Time per operation in microseconds, **lower is better**:

| | crypton 1.1.5 | crypton 2.2.0 | OpenSSL | OpenSSL / 2.2.0 |
| --- | ---: | ---: | ---: | ---: |
| X25519 | 44.63 | 28.29 | 36.52 | 1.29 |
| ECDH P-256 | 164.8 | 50.85 | 51.63 | 1.02 |
| ECDH P-384 | 2255 | **164.8** | 835.4 | 5.07 |
| Ed25519 sign | 29.27 | 18.54 | 33.63 | 1.81 |
| Ed25519 verify | 48.44 | 51.80 | 109.8 | 2.12 |
| ECDSA P-256 sign | 81.91 | 18.81 | 21.81 | 1.16 |
| ECDSA P-256 verify | 233.1 | 70.00 | 67.57 | 0.97 |
| ECDSA P-384 sign | 2287 | **300.0** | 878.7 | 2.93 |
| ECDSA P-384 verify | 2673 | **468.3** | 723.3 | 1.54 |
| RSA-2048 sign/decrypt | 759.2 | 617.8 | 659.8 | 1.07 |
| RSA-2048 verify/encrypt | 33.07 | 30.08 | 18.87 | 0.63 |

### AArch64

An Apple M4, which has the AES, PMULL, SHA-1, SHA-2, SHA-512 and SHA-3
instructions, against OpenSSL 4.0.3.

Throughput in MB/s, **higher is better**:

| | crypton 1.1.5 | crypton 2.2.0 | OpenSSL | 2.2.0 / OpenSSL |
| --- | ---: | ---: | ---: | ---: |
| AES-128-GCM | 129 | **11847** | 10770 | 1.10 |
| AES-256-GCM | 98 | **9770** | 9187 | 1.06 |
| ChaCha20-Poly1305 | 778 | 2312 | 2257 | 1.02 |
| SHA-1 | 1237 | 3393 | 3368 | 1.01 |
| SHA-256 | 485 | 3398 | 3370 | 1.01 |
| SHA-512 | 740 | 1882 | 1878 | 1.00 |
| SHA3-256 | 552 | 1081 | 1079 | 1.00 |

Time per operation in microseconds, **lower is better**:

| | crypton 1.1.5 | crypton 2.2.0 | OpenSSL | OpenSSL / 2.2.0 |
| --- | ---: | ---: | ---: | ---: |
| X25519 | 17.62 | **11.92** | 15.35 | 1.29 |
| ECDH P-256 | 66.93 | **20.32** | 24.53 | 1.21 |
| ECDH P-384 | 3308 | **73.17** | 371.1 | 5.07 |
| Ed25519 sign | 13.67 | **7.967** | 13.25 | 1.66 |
| Ed25519 verify | 18.25 | 18.22 | 35.18 | 1.93 |
| ECDSA P-256 sign | 32.33 | **7.00** | 10.82 | 1.55 |
| ECDSA P-256 verify | 95.78 | **27.42** | 32.69 | 1.19 |
| ECDSA P-384 sign | 3244 | **124.3** | 394.6 | 3.17 |
| ECDSA P-384 verify | 3900 | **203.2** | 327.4 | 1.61 |
| RSA-2048 sign/decrypt | 447.6 | 458.1 | 322.0 | 0.70 |
| RSA-2048 verify/encrypt | 18.20 | 15.15 | 8.450 | 0.56 |

### What the numbers say

There are two changes behind the 1.1.5 column and the 2.2.0 one, not a
single steady improvement.

The first, in 2.0.0, was a rewrite: the bulk algorithms moved into C, the
curves other than P-256 moved out of Haskell `Integer` arithmetic, and
everything that touches a secret was made to take the same time whatever the
secret is.  1.1.5 had no AArch64 code of its own at all, which is why AES-GCM
there is close to a hundred times what it was, and on x86-64 it had AES-NI
and nothing else.

The second, from 2.1.0 onwards, is assembly, for the operations where C
cannot reach.  Which of the two a row owes its gain to is not the same
everywhere: ECDSA P-384 signing took nineteenfold from the rewrite and a
further fifth from the assembly, while X25519 waited for the assembly
entirely and ECDH P-384 is almost all of it.

Most of that assembly is not crypton's.  The prime curves, the inverse modulo
a group order, X25519, and RSA's Montgomery multiplication on x86-64 go
through [s2n-bignum](https://github.com/awslabs/s2n-bignum), vendored in
`cbits/s2n`.  Every routine in it carries a machine-checked proof in
HOL-Light that it computes what it says, and is written in a constant-time
style.  It is `Apache-2.0 OR ISC OR MIT-0`, and crypton takes it under ISC.

That licence is why any of this was possible.  The obvious assembly to reach
for is OpenSSL's and BoringSSL's `ecp_nistz256`, and it cannot be used here:
it is Apache-2.0 only, and Intel and CloudFlare hold copyright in it besides
OpenSSL, so nobody is in a position to relicense it.

Where crypton is behind, which is now the RSA rows on both architectures and
ECDSA P-256 verification on x86-64, there is one reason.  The AES-GCM rows
were the other half of this section until 2.1.5; they are ahead on both
machines now, and what the instructions do is still worth setting out.

*RSA.*  2.0.0 made signing slower than 1.1.5 on purpose: its modular
exponentiation stopped indexing a table with the bits of the exponent, and
hiding the exponent is what the difference bought.  On x86-64 that cost is
more than repaid -- s2n-bignum's Montgomery multiplication is twice the C's,
because the C cannot form the two carry chains `ADCX` and `ADOX` give, and
2.2.0 signs in less than 1.1.5 took while keeping what 2.0.0 gained.  On
AArch64 there is nothing to use: s2n-bignum has no generic routine for it,
and the same five that help on x86-64 measure level with the C there, so the
C stays and the gap with it.  No portable C closes that gap either -- the
measurements are in
[#275](https://github.com/kazu-yamamoto/crypton/issues/275).  Verification
does not move much either way: its exponent is 65537, seventeen bits, and
there is no exponentiation to speak of.

*The wide AES instructions.*  `VAES` and `VPCLMULQDQ` do two blocks where
`AES-NI` and `PCLMULQDQ` do one, and four in their 512-bit form.  crypton uses
the 256-bit form where the processor has it, which is Zen 3 and Ice Lake
onwards, and the 512-bit form where that is worth having, which is Ice Lake and
Zen 5 onwards.  There was nothing to borrow: the wide AES-GCM in OpenSSL,
BoringSSL and AWS-LC is Apache-2.0 and s2n-bignum has no GCM, so both files are
crypton's own.

Having the 256-bit one is where the 1.49 in the x86-64 table comes from, and
it is narrower than it sounds.  The EPYC 7763 is Zen 3: VAES and VPCLMULQDQ,
no AVX-512.  OpenSSL's x86-64 AES-GCM is `aesni-gcm-x86_64.pl`, which is
128-bit -- its `vaesenc`s are the VEX encoding of `AESENC` on `xmm`, and
there is not one `ymm` in the file -- or `aes-gcm-avx512.pl`, which wants
`AVX512VAES`.  There is no rung between them, so on this processor OpenSSL
takes a block at a time where crypton takes two.  The same idea as theirs,
one step further down the feature ladder; not a better one.

The 512-bit path arrived after 2.1.2, so it is in the 2.2.0 column -- but
neither machine in the tables above has AVX-512, so neither column shows it.
On the runners that do, measured over 16 KiB in MB/s: an EPYC 9V45 (Zen 5)
goes from 9616 to 14268 with it, a Xeon 6973P-C from 8095 to 9848, a Xeon
8573C from 6983 to 8447.  OpenSSL on those machines is ahead still -- 25760
on the first of them -- because it interleaves the GHASH with the AES where
crypton does them in turn.  Zen 4 keeps the 256-bit path: its 512-bit
instructions are two passes through a 256-bit datapath, so the wider encoding
buys nothing there and costs a little.

AArch64 has no counterpart to any of these: one AES block and one GHASH
multiplication at a time is all the instruction set offers.  Its AES-GCM
rows were 0.85 and 0.87 until 2.1.5, for that reason.  What closed it was
not width but the GHASH's representation -- H is twisted once at key setup
so that GCM's bit reflection is already undone, which turns a reduction of
some twenty-five shifts and XORs into two PMULL and six EOR and makes
Karatsuba worth taking.  The scheme is ARM's, from the BSD-3-Clause part of
[AArch64cryptolib](https://github.com/ARM-software/AArch64cryptolib),
written out in crypton's own intrinsics.  The AES there is ahead of
OpenSSL's and always was; it was the GHASH beside it that was behind.

One row wants a word of its own: crypton's `Ed25519.sign` derives the public
key from the secret key every time it signs, so that a caller who passes a
public key that does not match cannot be made to leak the private one.  That
costs a second scalar multiplication, which OpenSSL's signing does not pay --
and the row is still 1.66 on AArch64 and 1.81 on x86-64, so the safety is had
for nothing here rather than paid for.

Ed25519 verification wants one too, for a less happy reason.  On x86-64 the
row is about eight per cent slower than it was, and the step is at 2.1.8:
2.1.5, 2.1.6 and 2.1.7 all measure near 48 microseconds there, and
2.1.8, 2.1.10 and 2.2.0 all measure near 52.  Nothing in Ed25519 changed
across that step.  No commit touches `cbits/ed25519` between those releases,
the compiled `ed25519.o` is byte for byte the same object either side of it,
and AArch64 did not move at all.  What 2.1.8 did was vendor ML-KEM and
ML-DSA, some seventy thousand lines of C that Ed25519 never calls.  The same
instructions, put somewhere else; signing, which is the same file and a
different routine, is where it was.  The row is still better than twice
OpenSSL's, and there is nothing in Ed25519 to fix.

SHA-1 is in the tables because a number of protocols and file formats still
ask for it, not because it is a good choice for anything new.  The algorithms
that nothing should ask for any more -- MD5, 3DES, RC4, CBC mode -- are left
out.

ML-KEM and ML-DSA are left out too, though 2.1.8 brought both and they are
fast -- `mlkem-native` and `mldsa-native`, from the PQ Code Package.  No
comparison is reported here: the implementations to measure against are
still developing.
