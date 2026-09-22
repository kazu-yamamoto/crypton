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

Performance
-----------

The algorithms a TLS connection uses, measured against the previous release
and against OpenSSL on the same machine.  Throughput is over 16 KiB messages;
the public key operations are one operation each; every figure is the best of
several runs.

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
| AES-128-GCM | 1330 | 4117 | 4260 | 0.97 |
| AES-256-GCM | 1089 | 3810 | 3948 | 0.97 |
| ChaCha20-Poly1305 | 398 | 2193 | 2175 | 1.01 |
| SHA-1 | 737 | 1678 | 1673 | 1.00 |
| SHA-256 | 285 | 1585 | 1570 | 1.01 |
| SHA-512 | 449 | 769 | 748 | 1.03 |
| SHA3-256 | 109 | 421 | 426 | 0.99 |

Time per operation in microseconds, **lower is better** -- so the last column
divides OpenSSL's time by crypton's, and is again better the larger it is:

| | crypton 1.1.5 | crypton 2.0.0 | OpenSSL | OpenSSL / 2.0.0 |
| --- | ---: | ---: | ---: | ---: |
| X25519 | 43.55 | 43.62 | 36.59 | 0.84 |
| ECDH P-256 | 163.4 | 163.4 | 51.89 | 0.32 |
| ECDH P-384 | 2236 | 1117 | 855.9 | 0.77 |
| Ed25519 sign | 28.54 | 28.24 | 43.86 | 1.55 |
| Ed25519 verify | 46.13 | 46.04 | 118.3 | 2.57 |
| ECDSA P-256 sign | 76.12 | 76.46 | 22.85 | 0.30 |
| ECDSA P-256 verify | 229.2 | 229.5 | 67.91 | 0.30 |
| ECDSA P-384 sign | 2272 | 394.2 | 902.3 | 2.29 |
| ECDSA P-384 verify | 2656 | 1517 | 739.3 | 0.49 |
| RSA-2048 sign/decrypt | 759.7 | 1336 | 659.5 | 0.49 |
| RSA-2048 verify/encrypt | 31.83 | 31.81 | 18.65 | 0.59 |

### AArch64

An Apple M4, which has the AES, PMULL, SHA-1, SHA-2, SHA-512 and SHA-3
instructions, against OpenSSL 3.6.4.

Throughput in MB/s, **higher is better**:

| | crypton 1.1.5 | crypton 2.0.0 | OpenSSL | 2.0.0 / OpenSSL |
| --- | ---: | ---: | ---: | ---: |
| AES-128-GCM | 125 | 8375 | 10634 | 0.79 |
| AES-256-GCM | 96 | 7403 | 9121 | 0.81 |
| ChaCha20-Poly1305 | 751 | 2214 | 2239 | 0.99 |
| SHA-1 | 1178 | 3270 | 2993 | 1.09 |
| SHA-256 | 458 | 3256 | 3325 | 0.98 |
| SHA-512 | 710 | 1767 | 1803 | 0.98 |
| SHA3-256 | 539 | 1062 | 1047 | 1.01 |

Time per operation in microseconds, **lower is better**; the last column again
divides OpenSSL's time by crypton's:

| | crypton 1.1.5 | crypton 2.0.0 | OpenSSL | OpenSSL / 2.0.0 |
| --- | ---: | ---: | ---: | ---: |
| X25519 | 18.48 | 18.43 | 18.39 | 1.00 |
| ECDH P-256 | 69.24 | 69.72 | 24.66 | 0.35 |
| ECDH P-384 | 3359 | 521.1 | 377.2 | 0.72 |
| Ed25519 sign | 13.73 | 13.14 | 16.22 | 1.23 |
| Ed25519 verify | 18.26 | 18.10 | 39.54 | 2.18 |
| ECDSA P-256 sign | 32.63 | 32.61 | 10.87 | 0.33 |
| ECDSA P-256 verify | 96.63 | 96.76 | 32.71 | 0.34 |
| ECDSA P-384 sign | 3313 | 176.0 | 395.1 | 2.24 |
| ECDSA P-384 verify | 3944 | 712.6 | 331.0 | 0.46 |
| RSA-2048 sign/decrypt | 456.3 | 619.8 | 324.6 | 0.52 |
| RSA-2048 verify/encrypt | 18.30 | 18.44 | 8.49 | 0.46 |

### What the numbers say

1.1.5 had no AArch64 code of its own at all, which is why AES-GCM there is
sixty-seven times what it was.  On x86-64 it had AES-NI and nothing else.  The
curves over a prime field other than P-256 moved from Haskell `Integer`
arithmetic into C, which is the eighteenfold change in ECDSA P-384 signing on
the M4.  X25519, P-256 and Ed25519 are unchanged between the two releases, and
the rows say so: where they differ by half a percent, that is the measurement
and not the code.

Where crypton is behind, it is behind for three separate reasons.

*P-256.*  crypton's field arithmetic is C where OpenSSL's is hand-written
assembly, and that is the whole of the difference: the two differ by about the
same factor on every P-256 row, and nothing above the field -- a wider window,
a different addition formula, another field representation -- recovers a useful
part of it.

*RSA signing.*  2.0.0 is slower than 1.1.5 here on purpose.  Its modular
exponentiation no longer indexes a table with the bits of the exponent, and
hiding the exponent is what the difference buys.

*The AVX-512 instructions.*  Neither machine above has them.  On one that does
-- an EPYC 9V74, measured the same way -- OpenSSL uses them for AES-GCM and
ChaCha20 and reaches 12003 and 3789 MB/s, against 4745 and 2372 for crypton,
whose vendored assembly is generated without them.  Those ratios are 0.40 and
0.63 rather than 0.97 and 1.01.  Nothing else in either table moves by more
than a few percent between the two processors.

One row wants a word of its own: crypton's `Ed25519.sign` derives the public
key from the secret key every time it signs, so that a caller who passes a
public key that does not match cannot be made to leak the private one.  That
costs a second scalar multiplication, which OpenSSL's signing does not pay.

SHA-1 is in the tables because a number of protocols and file formats still
ask for it, not because it is a good choice for anything new.  The algorithms
that nothing should ask for any more -- MD5, 3DES, RC4, CBC mode -- are left
out.
