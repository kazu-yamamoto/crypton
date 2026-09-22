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
the public key operations are one operation each.  crypton is measured through
its C layer, as `openssl speed` measures OpenSSL's, and each column is the
best of five runs.

### x86-64

An AMD EPYC 7763, which has AES-NI, PCLMULQDQ, AVX2, ADX and the SHA
extensions, against OpenSSL 3.0.13.

Throughput in MB/s, **higher is better**:

| | crypton 1.1.5 | crypton 2.0.0 | OpenSSL | 2.0.0 ÷ OpenSSL |
| --- | ---: | ---: | ---: | ---: |
| AES-128-GCM | 1334 | 4122 | 4264 | 0.97 |
| AES-256-GCM | 1094 | 3810 | 3953 | 0.96 |
| ChaCha20-Poly1305 | 340 | 2195 | 2192 | 1.00 |
| SHA-256 | 278 | 1585 | 1570 | 1.01 |
| SHA-512 | 440 | 770 | 748 | 1.03 |
| SHA3-256 | 73 | 421 | 426 | 0.99 |

Time per operation in microseconds, **lower is better** -- so the last column
divides OpenSSL's time by crypton's, and is again better the larger it is:

| | crypton 1.1.5 | crypton 2.0.0 | OpenSSL | OpenSSL ÷ 2.0.0 |
| --- | ---: | ---: | ---: | ---: |
| X25519 | 49.80 | 43.28 | 36.51 | 0.84 |
| ECDH P-256 | 200.1 | 163.2 | 51.91 | 0.32 |
| Ed25519 sign | 14.87 | 14.38 | 43.75 | 3.04 |
| Ed25519 verify | 45.86 | 45.29 | 118.0 | 2.61 |

### AArch64

An Apple M4, which has the AES, PMULL, SHA-2, SHA-512 and SHA-3 instructions,
against OpenSSL 3.6.4.

Throughput in MB/s, **higher is better**:

| | crypton 1.1.5 | crypton 2.0.0 | OpenSSL | 2.0.0 ÷ OpenSSL |
| --- | ---: | ---: | ---: | ---: |
| AES-128-GCM | 126 | 8599 | 10730 | 0.80 |
| AES-256-GCM | 97 | 7579 | 9144 | 0.83 |
| ChaCha20-Poly1305 | 758 | 2290 | 2239 | 1.02 |
| SHA-256 | 468 | 3388 | 3342 | 1.01 |
| SHA-512 | 725 | 1873 | 1819 | 1.03 |
| SHA3-256 | 271 | 1081 | 1051 | 1.03 |

Time per operation in microseconds, **lower is better**; the last column again
divides OpenSSL's time by crypton's:

| | crypton 1.1.5 | crypton 2.0.0 | OpenSSL | OpenSSL ÷ 2.0.0 |
| --- | ---: | ---: | ---: | ---: |
| X25519 | 18.17 | 18.18 | 18.48 | 1.02 |
| ECDH P-256 | 77.06 | 68.58 | 24.64 | 0.36 |
| Ed25519 sign | 7.32 | 6.61 | 15.92 | 2.41 |
| Ed25519 verify | 18.12 | 17.61 | 39.65 | 2.25 |

### What the numbers say

1.1.5 had no AArch64 code of its own at all, which is why AES-GCM there is
sixty-eight times what it was.  On x86-64 it had AES-NI and nothing else.

What is left is where crypton is behind: P-256, whose field arithmetic is C
where OpenSSL's is hand-written assembly; AES-GCM on AArch64, where OpenSSL
interleaves the multiply with the rounds at instruction granularity; and
X25519 on x86-64, where OpenSSL uses the ADX instructions and this does not.

Algorithms no longer recommended -- MD5, SHA-1, 3DES, RC4, CBC mode -- are
left out of these tables.
