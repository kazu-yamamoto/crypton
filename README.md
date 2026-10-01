![GitHub Actions status](https://github.com/kazu-yamamoto/crypton/workflows/Haskell%20CI/badge.svg)

crypton
==========

`crypton` is a fork from `cryptonite` with the original author's permission.


`crypton` is a low-level cryptography library. To achieve high
performance, it utilizes C and assembly language to define FFI
bindings, structuring them in a way that makes them easy to use.


Side channels
-------------

AES is where this matters most, and which implementation runs is decided at
runtime from what the processor has.

On x86-64 with AES-NI and carry-less multiply, and on AArch64 with the ARMv8
cryptographic extension, AES and GHASH are instructions rather than tables.
crypton's AES and AES-GCM then make no branch and no memory access that
depends on the key or on the data: the secrets stay in vector registers and
never reach one a branch can test, which the generated code is checked
against.  Every x86-64 part since about 2010 and every AArch64 part in
ordinary use has these.

Where neither is present crypton falls back to a table-driven AES, which
indexes a 256-byte substitution table with data derived from the key and the
input.  **That is not constant time**, and on a machine where an attacker can
observe the cache it is open to a timing attack.  The fallback exists so that
the library builds and runs everywhere; it is not meant for a setting where
that matters.

`Crypto.System.CPU.processorOptions` says which is in use.  `AESNI` in that
list means the instruction path, and `PCLMUL` that GHASH has its instruction
too; without `AESNI` it is the tables.  The list also reports `RDRAND`, which
is unrelated to this.

    ghci> import Crypto.System.CPU
    ghci> processorOptions
    [AESNI,PCLMUL]

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

| | crypton 1.1.5 | crypton 2.1.4 | OpenSSL | 2.1.4 / OpenSSL |
| --- | ---: | ---: | ---: | ---: |
| AES-128-GCM | 1335 | **6038** | 4070 | 1.48 |
| AES-256-GCM | 1093 | **5461** | 3774 | 1.45 |
| ChaCha20-Poly1305 | 399 | 2195 | 2213 | 0.99 |
| SHA-1 | 729 | 1679 | 1682 | 1.00 |
| SHA-256 | 290 | 1585 | 1571 | 1.01 |
| SHA-512 | 449 | 770 | 750 | 1.03 |
| SHA3-256 | 109 | 422 | 425 | 0.99 |

Time per operation in microseconds, **lower is better**:

| | crypton 1.1.5 | crypton 2.1.4 | OpenSSL | OpenSSL / 2.1.4 |
| --- | ---: | ---: | ---: | ---: |
| X25519 | 43.89 | 28.47 | 36.61 | 1.29 |
| ECDH P-256 | 164.7 | 50.34 | 51.66 | 1.03 |
| ECDH P-384 | 2237 | **163.4** | 835.4 | 5.11 |
| Ed25519 sign | 28.90 | 18.69 | 33.68 | 1.80 |
| Ed25519 verify | 47.81 | 47.77 | 111.2 | 2.33 |
| ECDSA P-256 sign | 81.05 | 18.73 | 21.88 | 1.17 |
| ECDSA P-256 verify | 232.6 | 70.27 | 67.51 | 0.96 |
| ECDSA P-384 sign | 2260 | **302.9** | 879.1 | 2.90 |
| ECDSA P-384 verify | 2668 | **467.8** | 725.2 | 1.55 |
| RSA-2048 sign/decrypt | 758.5 | 611.2 | 659.0 | 1.08 |
| RSA-2048 verify/encrypt | 32.79 | 30.01 | 18.85 | 0.63 |

### AArch64

An Apple M4, which has the AES, PMULL, SHA-1, SHA-2, SHA-512 and SHA-3
instructions, against OpenSSL 4.0.3.

Throughput in MB/s, **higher is better**:

| | crypton 1.1.5 | crypton 2.1.4 | OpenSSL | 2.1.4 / OpenSSL |
| --- | ---: | ---: | ---: | ---: |
| AES-128-GCM | 131 | 9487 | 11111 | 0.85 |
| AES-256-GCM | 98 | 8149 | 9371 | 0.87 |
| ChaCha20-Poly1305 | 786 | 2321 | 2304 | 1.01 |
| SHA-1 | 1255 | 3382 | 3366 | 1.00 |
| SHA-256 | 483 | 3396 | 3366 | 1.01 |
| SHA-512 | 735 | 1878 | 1888 | 0.99 |
| SHA3-256 | 557 | 1105 | 1100 | 1.00 |

Time per operation in microseconds, **lower is better**:

| | crypton 1.1.5 | crypton 2.1.4 | OpenSSL | OpenSSL / 2.1.4 |
| --- | ---: | ---: | ---: | ---: |
| X25519 | 17.45 | **11.12** | 15.35 | 1.38 |
| ECDH P-256 | 67.18 | **19.58** | 24.53 | 1.25 |
| ECDH P-384 | 3192 | **72.35** | 373.5 | 5.16 |
| Ed25519 sign | 13.13 | **7.60** | 13.26 | 1.75 |
| Ed25519 verify | 18.02 | 17.93 | 34.97 | 1.95 |
| ECDSA P-256 sign | 32.08 | **6.88** | 11.02 | 1.60 |
| ECDSA P-256 verify | 96.07 | **27.42** | 32.77 | 1.20 |
| ECDSA P-384 sign | 3253 | **124.2** | 396.8 | 3.19 |
| ECDSA P-384 verify | 3912 | **203.7** | 333.3 | 1.64 |
| RSA-2048 sign/decrypt | 452.0 | 465.3 | 321.3 | 0.69 |
| RSA-2048 verify/encrypt | 18.23 | 15.27 | 8.44 | 0.55 |

### What the numbers say

There are two changes behind the 1.1.5 column and the 2.1.4 one, not a
single steady improvement.

The first, in 2.0.0, was a rewrite: the bulk algorithms moved into C, the
curves other than P-256 moved out of Haskell `Integer` arithmetic, and
everything that touches a secret was made to take the same time whatever the
secret is.  1.1.5 had no AArch64 code of its own at all, which is why AES-GCM
there is seventy times what it was, and on x86-64 it had AES-NI and nothing
else.

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

Where crypton is behind, which is now one row on one architecture and the
AES-GCM rows on the other, it is behind for two reasons.

*RSA.*  2.0.0 made signing slower than 1.1.5 on purpose: its modular
exponentiation stopped indexing a table with the bits of the exponent, and
hiding the exponent is what the difference bought.  On x86-64 that cost is
more than repaid -- s2n-bignum's Montgomery multiplication is twice the C's,
because the C cannot form the two carry chains `ADCX` and `ADOX` give, and
2.1.4 signs in less than 1.1.5 took while keeping what 2.0.0 gained.  On
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

Having the 256-bit one is where the 1.48 in the x86-64 table comes from, and
it is narrower than it sounds.  The EPYC 7763 is Zen 3: VAES and VPCLMULQDQ,
no AVX-512.  OpenSSL's x86-64 AES-GCM is `aesni-gcm-x86_64.pl`, which is
128-bit -- its `vaesenc`s are the VEX encoding of `AESENC` on `xmm`, and
there is not one `ymm` in the file -- or `aes-gcm-avx512.pl`, which wants
`AVX512VAES`.  There is no rung between them, so on this processor OpenSSL
takes a block at a time where crypton takes two.  The same idea as theirs,
one step further down the feature ladder; not a better one.

The 512-bit path arrived after 2.1.2, so it is in the 2.1.4 column -- but
neither machine in the tables above has AVX-512, so neither column shows it.
On the runners that do, measured over 16 KiB in MB/s: an EPYC 9V45 (Zen 5)
goes from 9616 to 14268 with it, a Xeon 6973P-C from 8095 to 9848, a Xeon
8573C from 6983 to 8447.  OpenSSL on those machines is ahead still -- 25760
on the first of them -- because it interleaves the GHASH with the AES where
crypton does them in turn.  Zen 4 keeps the 256-bit path: its 512-bit
instructions are two passes through a 256-bit datapath, so the wider encoding
buys nothing there and costs a little.

AArch64 has no counterpart to any of these, which is where the 0.85 on its
AES-GCM rows comes from -- and, the other way about, why the x86-64 rows are
at 1.48 and 1.45.

One row wants a word of its own: crypton's `Ed25519.sign` derives the public
key from the secret key every time it signs, so that a caller who passes a
public key that does not match cannot be made to leak the private one.  That
costs a second scalar multiplication, which OpenSSL's signing does not pay --
and the row is still 1.75 on AArch64 and 1.80 on x86-64, so the safety is had
for nothing here rather than paid for.

SHA-1 is in the tables because a number of protocols and file formats still
ask for it, not because it is a good choice for anything new.  The algorithms
that nothing should ask for any more -- MD5, 3DES, RC4, CBC mode -- are left
out.
