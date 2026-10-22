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

The RSA rows in the tables below are the unblinded path.  A fresh blinder
costs one more exponentiation, by the public exponent, which is the cheap
direction: measured on the M4, signing goes from about 316 to about 331
microseconds, under five per cent.  `signSafer` and `decryptSafer` pay less
than that from 2.2.4: they keep the blinder of a key they have seen and
square it for the next use, as OpenSSL does, drawing a fresh one every 32
uses.  `Crypto.PubKey.RSA.Blinded` gives a caller the same thing to hold, a
`BlindedKey` passed along from one operation to the next.

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

| | crypton 1.1.5 | crypton 2.2.4 | OpenSSL | 2.2.4 / OpenSSL |
| --- | ---: | ---: | ---: | ---: |
| AES-128-GCM | 1335 | **6041** | 4066 | 1.49 |
| AES-256-GCM | 1093 | **5492** | 3766 | 1.46 |
| ChaCha20-Poly1305 | 399 | 2195 | 2222 | 0.99 |
| SHA-1 | 727 | 1663 | 1672 | 0.99 |
| SHA-256 | 289 | 1585 | 1576 | 1.01 |
| SHA-512 | 448 | 770 | 749 | 1.03 |
| SHA3-256 | 109 | 421 | 429 | 0.98 |

Time per operation in microseconds, **lower is better**:

| | crypton 1.1.5 | crypton 2.2.4 | OpenSSL | OpenSSL / 2.2.4 |
| --- | ---: | ---: | ---: | ---: |
| X25519 | 44.38 | 28.29 | 36.61 | 1.29 |
| ECDH P-256 | 164.0 | 51.31 | 51.70 | 1.01 |
| ECDH P-384 | 2242 | **164.3** | 836.1 | 5.09 |
| Ed25519 sign | 43.86 | 18.50 | 33.74 | 1.82 |
| Ed25519 verify | 48.30 | 48.43 | 109.8 | 2.27 |
| ECDSA P-256 sign | 81.80 | 19.72 | 21.84 | 1.11 |
| ECDSA P-256 verify | 231.8 | 70.47 | 67.55 | 0.96 |
| ECDSA P-384 sign | 2267 | **305.2** | 879.5 | 2.88 |
| ECDSA P-384 verify | 2698 | **473.6** | 725.2 | 1.53 |
| RSA-2048 sign/decrypt | 760.1 | 612.3 | 659.6 | 1.08 |
| RSA-2048 verify/encrypt | 33.61 | 23.50 | 18.88 | 0.80 |
| RSA-3072 sign/decrypt | 2499 | 2324 | 2012 | 0.87 |
| RSA-3072 verify/encrypt | 66.80 | 61.91 | 40.14 | 0.65 |

### AArch64

An Apple M4, which has the AES, PMULL, SHA-1, SHA-2, SHA-512 and SHA-3
instructions, against OpenSSL 4.0.3.

Throughput in MB/s, **higher is better**:

| | crypton 1.1.5 | crypton 2.2.4 | OpenSSL | 2.2.4 / OpenSSL |
| --- | ---: | ---: | ---: | ---: |
| AES-128-GCM | 131 | **12052** | 10922 | 1.10 |
| AES-256-GCM | 99 | **10192** | 9208 | 1.11 |
| ChaCha20-Poly1305 | 783 | 2342 | 2261 | 1.04 |
| SHA-1 | 1234 | 3383 | 3347 | 1.01 |
| SHA-256 | 486 | 3392 | 3354 | 1.01 |
| SHA-512 | 742 | 1869 | 1860 | 1.00 |
| SHA3-256 | 552 | 1096 | 1092 | 1.00 |

Time per operation in microseconds, **lower is better**:

| | crypton 1.1.5 | crypton 2.2.4 | OpenSSL | OpenSSL / 2.2.4 |
| --- | ---: | ---: | ---: | ---: |
| X25519 | 17.92 | **12.02** | 15.32 | 1.28 |
| ECDH P-256 | 67.50 | **19.05** | 24.36 | 1.28 |
| ECDH P-384 | 3256 | **71.78** | 373.1 | 5.20 |
| Ed25519 sign | 13.38 | **7.717** | 13.31 | 1.72 |
| Ed25519 verify | 18.32 | 18.18 | 34.77 | 1.91 |
| ECDSA P-256 sign | 31.08 | **6.500** | 10.66 | 1.64 |
| ECDSA P-256 verify | 94.27 | **26.58** | 32.25 | 1.21 |
| ECDSA P-384 sign | 3225 | **124.0** | 394.2 | 3.18 |
| ECDSA P-384 verify | 3866 | **203.4** | 332.3 | 1.63 |
| RSA-2048 sign/decrypt | 451.3 | 318.4 | 321.5 | 1.01 |
| RSA-2048 verify/encrypt | 18.15 | 11.12 | 8.405 | 0.76 |
| RSA-3072 sign/decrypt | 1473 | 937.4 | 931.1 | 0.99 |
| RSA-3072 verify/encrypt | 47.95 | 43.63 | 17.89 | 0.41 |

### What the numbers say

There are two changes behind the 1.1.5 column and the 2.2.4 one, not a
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

crypton is behind in a few rows now: RSA verification on both architectures,
and RSA-3072 signing and ECDSA P-256 verification on x86-64.  The AES-GCM rows
were the other half of this section until 2.1.5; they are ahead on both
machines now, and what the instructions do is still worth setting out.

*RSA.*  2.0.0 made signing slower than 1.1.5 on purpose: its modular
exponentiation stopped indexing a table with the bits of the exponent, and
hiding the exponent is what the difference bought.  2.2.4 has repaid that
cost on both machines, by different means.  On x86-64 s2n-bignum's
Montgomery multiplication is twice the C's, because the C cannot form the two
carry chains `ADCX` and `ADOX` give, and 2.2.4 signs in less than 1.1.5
took, at 3072 bits as well as 2048.  On AArch64 s2n-bignum's routines measure
no better than the C, so the gain there is the C's own: the multiplication
and squaring for each key size are generated and unrolled, with the
reduction folded into each column as in Koç, Acar and Kaliski's FIPS method,
and signing is level with OpenSSL.  The measurements are in
[#275](https://github.com/kazu-yamamoto/crypton/issues/275).

On processors with AVX-512 IFMA, Intel Xeons from Ice Lake and AMD from Zen 4,
2.2.4 computes the two halves of the CRT together in 52-bit digits, Gueron and
Krasnov's method and the one OpenSSL takes there.  Neither machine above has
IFMA, so neither table shows it.

Verification's exponent is 65537, seventeen bits, so there is little
exponentiation to speed up and the work around it counts.  2.2.4 keeps R^2,
the Montgomery constant of a modulus, for the moduli it has seen, which is
most of what the RSA-2048 verification rows gained.

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

The 512-bit path arrived after 2.1.2, so it is in the 2.2.4 column -- but
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
and the row is still 1.72 on AArch64 and 1.82 on x86-64, so the safety is had
for nothing here rather than paid for.

Ed25519 verification wanted one too, for an unhappier reason, and 2.2.1
settles it.  On x86-64 the row was about eight per cent slower from 2.1.8
onwards: 2.1.5, 2.1.6 and 2.1.7 all measure near 48 microseconds there,
2.1.8, 2.1.10 and 2.2.0 all measure near 52, and 2.2.1 is near 48 again.
Nothing in Ed25519 ever changed -- no commit touches `cbits/ed25519` across
any of it, and AArch64 never moved, the compiled `ed25519.o` there being
byte for byte the same object either side of 2.1.8.  What moved was a line
in this package's cabal file.  The ML-KEM and ML-DSA backends that 2.1.8
vendored want `-mavx2 -mbmi2`, and they were given as `cc-options` inside an
`if arch(x86_64)` block -- but cc-options in a conditional belong to the
component and not to the block, so every C file in the library was compiled
with AVX2 allowed, `cbits/ed25519` among them, and what the compiler made of
it that way is slower on this machine than what it replaced.  Signing, which
is the same file and a different routine, is where it always was.  2.2.1
narrowed the flags to the assembly that asked for them, which is also what
stopped a binary built on one x86-64 machine from dying on another, and the
row came back.

SHA-1 is in the tables because a number of protocols and file formats still
ask for it, not because it is a good choice for anything new.  The algorithms
that nothing should ask for any more -- MD5, 3DES, RC4, CBC mode -- are left
out.

ML-KEM and ML-DSA are left out too, though 2.1.8 brought both and they are
fast -- `mlkem-native` and `mldsa-native`, from the PQ Code Package.  No
comparison is reported here: the implementations to measure against are
still developing.
