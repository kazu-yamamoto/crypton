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
measured on the M4, signing goes from about 601 to about 620 microseconds,
three per cent.

Performance
-----------

The algorithms a TLS connection uses, measured against the two releases
behind this one and against OpenSSL on the same machine.  Throughput is over
16 KiB messages; the public key operations are one operation each; every
figure is the best of several runs, and crypton and OpenSSL are run
alternately so that neither gets the quieter machine.

Bulk encryption and hashing are measured through crypton's C layer, as
`openssl speed` measures OpenSSL's.  The public key operations are measured
through crypton's Haskell API, since that is where ECDSA and RSA live and it
is what a program actually calls; the Haskell layer adds well under a
microsecond, which the X25519 and ECDH P-256 rows confirm by agreeing with a
C-level measurement to within a percent.  All three releases of crypton are
built the same way -- `-optc-O3`, which is what each asks for -- and by
`cabal build`, since a copy of the sources compiled by hand does not measure
what a program linking the library gets.  Each column of a table comes from
one run on the machine named above it.

### x86-64

An AMD EPYC 7763, which has AES-NI, PCLMULQDQ, AVX2, ADX, VAES, VPCLMULQDQ
and the SHA extensions, against OpenSSL 3.0.13.

Throughput in MB/s, **higher is better**:

| | crypton 1.1.5 | crypton 2.0.1 | crypton 2.1.2 | OpenSSL | 2.1.2 / OpenSSL |
| --- | ---: | ---: | ---: | ---: | ---: |
| AES-128-GCM | 1335 | 4243 | **6041** | 4287 | 1.41 |
| AES-256-GCM | 1093 | 3932 | **5463** | 3954 | 1.38 |
| ChaCha20-Poly1305 | 399 | 2196 | 2195 | 2192 | 1.00 |
| SHA-1 | 729 | 1662 | 1680 | 1681 | 1.00 |
| SHA-256 | 289 | 1586 | 1586 | 1570 | 1.01 |
| SHA-512 | 449 | 770 | 770 | 748 | 1.03 |
| SHA3-256 | 109 | 422 | 421 | 427 | 0.99 |

Time per operation in microseconds, **lower is better**:

| | crypton 1.1.5 | crypton 2.0.1 | crypton 2.1.2 | OpenSSL | OpenSSL / 2.1.2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| X25519 | 44.40 | 44.15 | **28.35** | 36.50 | 1.29 |
| ECDH P-256 | 164.2 | 164.1 | **50.49** | 51.84 | 1.03 |
| ECDH P-384 | 2220 | 1116 | **164.5** | 855.8 | 5.20 |
| Ed25519 sign | 28.99 | 28.51 | 28.66 | 43.72 | 1.53 |
| Ed25519 verify | 48.14 | 47.81 | 47.54 | 117.2 | 2.47 |
| ECDSA P-256 sign | 81.43 | 80.79 | **18.62** | 22.45 | 1.21 |
| ECDSA P-256 verify | 231.8 | 230.7 | **79.67** | 67.73 | 0.85 |
| ECDSA P-384 sign | 2241 | 397.6 | **330.8** | 899.7 | 2.72 |
| ECDSA P-384 verify | 2655 | 1519 | **500.5** | 734.5 | 1.47 |
| RSA-2048 sign/decrypt | 758.3 | 1327 | **773.2** | 659.0 | 0.85 |
| RSA-2048 verify/encrypt | 33.28 | 30.05 | 29.80 | 18.62 | 0.62 |

### AArch64

An Apple M4, which has the AES, PMULL, SHA-1, SHA-2, SHA-512 and SHA-3
instructions, against OpenSSL 3.6.4.

Throughput in MB/s, **higher is better**:

| | crypton 1.1.5 | crypton 2.0.1 | crypton 2.1.2 | OpenSSL | 2.1.2 / OpenSSL |
| --- | ---: | ---: | ---: | ---: | ---: |
| AES-128-GCM | 127 | 8926 | 8731 | 10763 | 0.81 |
| AES-256-GCM | 98 | 7601 | 7712 | 9155 | 0.84 |
| ChaCha20-Poly1305 | 758 | 2247 | 2239 | 2248 | 1.00 |
| SHA-1 | 1201 | 3307 | 3314 | 3296 | 1.01 |
| SHA-256 | 472 | 3299 | 3245 | 3210 | 1.01 |
| SHA-512 | 726 | 1766 | 1798 | 1794 | 1.00 |
| SHA3-256 | 550 | 1076 | 1076 | 1054 | 1.02 |

Time per operation in microseconds, **lower is better**:

| | crypton 1.1.5 | crypton 2.0.1 | crypton 2.1.2 | OpenSSL | OpenSSL / 2.1.2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| X25519 | 18.25 | 18.27 | **12.05** | 18.27 | 1.52 |
| ECDH P-256 | 69.07 | 56.23 | **20.70** | 24.62 | 1.19 |
| ECDH P-384 | 3333 | 512.3 | **73.33** | 370.9 | 5.06 |
| Ed25519 sign | 13.63 | 13.05 | 13.03 | 15.72 | 1.21 |
| Ed25519 verify | 18.28 | 18.18 | 18.15 | 39.02 | 2.15 |
| ECDSA P-256 sign | 32.35 | 27.80 | **6.98** | 11.02 | 1.58 |
| ECDSA P-256 verify | 95.77 | 79.48 | **31.93** | 32.66 | 1.02 |
| ECDSA P-384 sign | 3232 | 170.5 | **140.4** | 392.6 | 2.80 |
| ECDSA P-384 verify | 3905 | 686.4 | **219.0** | 328.1 | 1.50 |
| RSA-2048 sign/decrypt | 449.3 | 601.8 | 600.2 | 322.8 | 0.54 |
| RSA-2048 verify/encrypt | 18.22 | 15.17 | 15.17 | 8.45 | 0.56 |

### What the numbers say

There are two changes in these tables, not one.  1.1.5 to 2.0.1 was a
rewrite: the bulk algorithms moved into C, the curves other than P-256 moved
out of Haskell `Integer` arithmetic, and everything that touches a secret was
made to take the same time whatever the secret is.  1.1.5 had no AArch64 code
of its own at all, which is why AES-GCM there is seventy times what it was,
and on x86-64 it had AES-NI and nothing else.

2.0.1 to 2.1.2 is assembly, for the operations where C cannot reach.  The two
columns beside each other say which change did what: ECDSA P-384 signing, for
instance, got its nineteenfold from the first and a further fifth from the
second, while X25519 waited for the second entirely.

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

Where crypton is still behind, it is behind for two reasons.

*RSA.*  2.0.0 made signing slower than 1.1.5 on purpose: its modular
exponentiation stopped indexing a table with the bits of the exponent, and
hiding the exponent is what the difference bought.  On x86-64 that cost is
now repaid -- s2n-bignum's Montgomery multiplication is twice the C's,
because the C cannot form the two carry chains `ADCX` and `ADOX` give, and
2.1.2 signs in about what 1.1.5 took while keeping what 2.0.0 gained.  On
AArch64 the C measures faster than that assembly, so none is used and the gap
stays.  Verification does not move either way: its exponent is 65537,
seventeen bits, and there is no exponentiation to speak of.

*The wide AES instructions.*  `VAES` and `VPCLMULQDQ` do two blocks where
`AES-NI` and `PCLMULQDQ` do one, and crypton uses them where the processor
has them, which is Zen 3 and Ice Lake onwards.  There was nothing to borrow:
the wide AES-GCM in OpenSSL, BoringSSL and AWS-LC is Apache-2.0 and
s2n-bignum has no GCM, so `cbits/aes/gcm_vaes_x86.c` is crypton's own.
AVX-512 is a separate thing and is still not used -- on a machine that has
it, OpenSSL reaches about 12000 MB/s on AES-128-GCM where crypton reaches
about 6000.  AArch64 has no counterpart to these instructions at all, which
is where the 0.8 on its AES-GCM rows comes from.

One row wants a word of its own: crypton's `Ed25519.sign` derives the public
key from the secret key every time it signs, so that a caller who passes a
public key that does not match cannot be made to leak the private one.  That
costs a second scalar multiplication, which OpenSSL's signing does not pay.

SHA-1 is in the tables because a number of protocols and file formats still
ask for it, not because it is a good choice for anything new.  The algorithms
that nothing should ask for any more -- MD5, 3DES, RC4, CBC mode -- are left
out.
