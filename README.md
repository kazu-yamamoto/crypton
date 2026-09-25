![GitHub Actions status](https://github.com/kazu-yamamoto/crypton/workflows/Haskell%20CI/badge.svg)

crypton
==========

Crypton is a fork from cryptonite with the original author's permission.

Crypton is a haskell repository of cryptographic primitives. Each crypto
algorithm has specificities that are hard to wrap in common APIs and types,
so instead of trying to provide a common ground for algorithms, this package
provides a non-consistent low-level API.

If you have no idea what you're doing, please do not use this directly.
Instead, rely on higher level protocols or implementations.

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

Performance
-----------

The algorithms a TLS connection uses, measured against the previous release
and against OpenSSL on the same machine.  Throughput is over 16 KiB messages;
the public key operations are one operation each; every figure is the best of
several runs, and crypton and OpenSSL are run alternately so that neither gets
the quieter machine.

The columns read 2.0.0 and are what 2.1.0 measures on every row but two.  The
only C 2.1.0 changed is AES-GCM's and P-256's, and of those only P-256 is on
a path these tables take: measured on the same EPYC 7763, ECDH P-256 goes
164.3 to 159.5 microseconds and ECDSA P-256 verification 231.1 to 226.2, so
those two rows are about 3% better than they read here.  ECDSA P-256 signing
does not move, being the base-point path.  What 2.1.0 did to AES-GCM was add
a one-call interface beside the one measured here -- key expanded once,
additional data, payload and tag together -- which is worth 3.6 times at 100
bytes and nothing at 16 KiB, so it does not show in a 16 KiB throughput
figure at all.

Bulk encryption and hashing are measured through crypton's C layer, as
`openssl speed` measures OpenSSL's.  The public key operations are measured
through crypton's Haskell API, since that is where ECDSA and RSA live and it
is what a program actually calls; the Haskell layer adds well under a
microsecond, which the X25519 and ECDH P-256 rows confirm by agreeing with a
C-level measurement to within a percent.  Both releases of crypton are built
the same way -- `-optc-O3`, which is what both of them ask for -- and each
column of a table comes from one run on the machine named above it.

### x86-64

An AMD EPYC 7763, which has AES-NI, PCLMULQDQ, AVX2, ADX and the SHA
extensions, against OpenSSL 3.0.13.

Throughput in MB/s, **higher is better**:

| | crypton 1.1.5 | crypton 2.0.0 | OpenSSL | 2.0.0 / OpenSSL |
| --- | ---: | ---: | ---: | ---: |
| AES-128-GCM | 1331 | 4118 | 4264 | 0.97 |
| AES-256-GCM | 1090 | 3810 | 3951 | 0.96 |
| ChaCha20-Poly1305 | 398 | 2195 | 2191 | 1.00 |
| SHA-1 | 738 | 1678 | 1672 | 1.00 |
| SHA-256 | 286 | 1585 | 1570 | 1.01 |
| SHA-512 | 448 | 769 | 746 | 1.03 |
| SHA3-256 | 109 | 421 | 426 | 0.99 |

Time per operation in microseconds, **lower is better** -- so the last column
divides OpenSSL's time by crypton's, and is again better the larger it is:

| | crypton 1.1.5 | crypton 2.0.0 | OpenSSL | OpenSSL / 2.0.0 |
| --- | ---: | ---: | ---: | ---: |
| X25519 | 43.57 | 43.52 | 36.58 | 0.84 |
| ECDH P-256 | 163.8 | 163.7 | 52.36 | 0.32 |
| ECDH P-384 | 2241 | 1101 | 857.1 | 0.78 |
| Ed25519 sign | 28.52 | 28.25 | 43.49 | 1.54 |
| Ed25519 verify | 46.06 | 46.16 | 119.3 | 2.59 |
| ECDSA P-256 sign | 76.04 | 75.02 | 22.91 | 0.31 |
| ECDSA P-256 verify | 229.2 | 228.5 | 67.98 | 0.30 |
| ECDSA P-384 sign | 2271 | 387.6 | 904.3 | 2.33 |
| ECDSA P-384 verify | 2667 | 1493 | 746.2 | 0.50 |
| RSA-2048 sign/decrypt | 759.8 | 1311 | 660.1 | 0.50 |
| RSA-2048 verify/encrypt | 31.62 | 28.59 | 18.63 | 0.65 |

### AArch64

An Apple M4, which has the AES, PMULL, SHA-1, SHA-2, SHA-512 and SHA-3
instructions, against OpenSSL 3.6.4.

Throughput in MB/s, **higher is better**:

| | crypton 1.1.5 | crypton 2.0.0 | OpenSSL | 2.0.0 / OpenSSL |
| --- | ---: | ---: | ---: | ---: |
| AES-128-GCM | 126 | 8702 | 10719 | 0.81 |
| AES-256-GCM | 98 | 7648 | 9154 | 0.84 |
| ChaCha20-Poly1305 | 758 | 2323 | 2244 | 1.04 |
| SHA-1 | 1199 | 3380 | 3346 | 1.01 |
| SHA-256 | 467 | 3394 | 3352 | 1.01 |
| SHA-512 | 723 | 1868 | 1851 | 1.01 |
| SHA3-256 | 548 | 1091 | 1054 | 1.04 |

Time per operation in microseconds, **lower is better**; the last column again
divides OpenSSL's time by crypton's:

| | crypton 1.1.5 | crypton 2.0.0 | OpenSSL | OpenSSL / 2.0.0 |
| --- | ---: | ---: | ---: | ---: |
| X25519 | 18.44 | 18.41 | 18.41 | 1.00 |
| ECDH P-256 | 69.46 | 56.24 | 24.68 | 0.44 |
| ECDH P-384 | 3252 | 511.1 | 379.7 | 0.74 |
| Ed25519 sign | 13.75 | 13.14 | 15.90 | 1.21 |
| Ed25519 verify | 18.17 | 18.04 | 39.27 | 2.18 |
| ECDSA P-256 sign | 32.56 | 27.91 | 11.05 | 0.40 |
| ECDSA P-256 verify | 96.50 | 80.19 | 32.82 | 0.41 |
| ECDSA P-384 sign | 3219 | 169.3 | 403.4 | 2.38 |
| ECDSA P-384 verify | 3807 | 688.1 | 335.1 | 0.49 |
| RSA-2048 sign/decrypt | 451.8 | 605.4 | 325.0 | 0.54 |
| RSA-2048 verify/encrypt | 18.32 | 15.28 | 8.50 | 0.56 |

### What the numbers say

1.1.5 had no AArch64 code of its own at all, which is why AES-GCM there is
sixty-nine times what it was.  On x86-64 it had AES-NI and nothing else.  The
curves over a prime field other than P-256 moved from Haskell `Integer`
arithmetic into C, which is the nineteenfold change in ECDSA P-384 signing on
the M4.  X25519 and Ed25519 are unchanged between the two releases, and the
rows say so: where they differ by half a percent, that is the measurement and
not the code.  P-256 is unchanged on x86-64 and a fifth faster on AArch64,
which is the paragraph below.

Where crypton is behind, it is behind for three separate reasons.

*P-256.*  crypton's field arithmetic is C where OpenSSL's is hand-written
assembly, and that is what is left of the difference: the two differ by about
the same factor on every P-256 row, and nothing above the field -- a wider
window, a different addition formula, another field representation -- recovers
a useful part of it.

The AArch64 rows are better than the x86-64 ones because of where a field
multiplication's latency goes.  It ends in a carry chain the width of the
number, and the curve arithmetic has independent products that could cover
that chain -- but only if the compiler inlines the reduction instead of
calling it, since a call is a fence.  Asking it to costs code and pays where
there are registers enough to hold two chains at once: a quarter on AArch64,
where there are thirty-one, and nothing on x86-64, where there are fifteen and
the same request makes it slower.  So x86-64 is left to the compiler's own
judgement and stays at 0.3.

*RSA signing.*  2.0.0 is slower than 1.1.5 here on purpose.  Its modular
exponentiation no longer indexes a table with the bits of the exponent, and
hiding the exponent is what the difference buys.  What is left of the gap
against OpenSSL is the Montgomery multiplication, which is assembly there and
C here.

*The AVX-512 instructions.*  Neither machine above has them.  On one that does
-- an EPYC 9V74, measured the same way -- OpenSSL uses them for AES-GCM and
ChaCha20 and reaches 12003 and 3789 MB/s, against 4745 and 2372 for crypton,
whose vendored assembly is generated without them.  Those ratios are 0.40 and
0.63 rather than 0.97 and 1.00.  Nothing else in either table moves by more
than a few percent between the two processors.

One row wants a word of its own: crypton's `Ed25519.sign` derives the public
key from the secret key every time it signs, so that a caller who passes a
public key that does not match cannot be made to leak the private one.  That
costs a second scalar multiplication, which OpenSSL's signing does not pay.

SHA-1 is in the tables because a number of protocols and file formats still
ask for it, not because it is a good choice for anything new.  The algorithms
that nothing should ask for any more -- MD5, 3DES, RC4, CBC mode -- are left
out.
