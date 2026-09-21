# CHANGELOG for crypton

## 2.0.0

* perf(bignum): start the doubling for `R^2 mod m` at the highest power of two
  under the modulus rather than at one, which for a modulus that fills its
  limbs is half the steps.  Two to three percent of a curve operation, and
  every curve operation and every `expSafe` pays for it once.  Folding instead
  of Montgomery for the primes shaped `2^k - c` was written and measured
  alongside it and is not here: it is slower in this representation, 87.8 ns
  against 76.8 for a 521-bit multiplication, because the shift down by `k`
  costs more than the reduction pass it replaces when `k` does not land on a
  limb boundary
  [#147](https://github.com/kazu-yamamoto/crypton/pull/147)
* perf(ecc): keep a table of the multiples of each curve's base point, which
  is the point signing and making a key multiply and the only one worth a
  table.  A multiplication with it is one addition per four bits and no
  doublings: secp256k1 211.1 to 59.8 us, secp384r1 519.3 to 144.2, secp521r1
  1047.7 to 283.0, and ECDSA P-384 signing 556.4 to 179.9 on both elliptic
  curve APIs, which share the table.  A table is built when a curve is first
  asked for one -- 2.8 ms for secp256k1, 5.5 for secp384r1, 10.6 for secp521r1
  -- and is 221 KB and 456 KB for the last two, so it pays for itself after
  about fifteen multiplications
  [#146](https://github.com/kazu-yamamoto/crypton/pull/146)
* perf(bignum): take the limbs four and two at a time as well as eight in the
  loop every modular multiplication is built out of.  Four and six limbs, which
  is what most of the curves want, fell entirely to the one-at-a-time tail
  before: a field multiplication at six limbs goes from about 58 to 49 ns,
  secp384r1 scalar multiplication from 596.7 to 519.3 us and ECDSA P-384
  signing from 645.0 to 556.4.  Specialising the sizes further, which is what a
  generated implementation would do, measures about 4% more and is not here
  [#145](https://github.com/kazu-yamamoto/crypton/pull/145)
* fix(rsa): keep the blinding factor out of the extended Euclidean algorithm.
  The blinder is a random number and its inverse, and the inverse went through
  an algorithm whose steps follow the number handed to it -- the number the
  blinding rests on, and unlike the other inverses this one is worked out once
  per operation rather than once per key.  `n` being composite leaves no
  Fermat to fall back on, so the algorithm is handed the factor multiplied by
  sixteen fresh random bytes and its answer multiplied by them again, which
  leaves the inverse wanted and shows the algorithm nothing to do with it.  In
  IO, where every draw of randomness goes to the system, `generateBlinder`
  goes from 74 to about 120 us and a PKCS#1 v1.5 `signSafer` from 719 to about
  765; under a DRG the caller carries, 24.7 to 24.9
  [#144](https://github.com/kazu-yamamoto/crypton/pull/144)
* fix(rsa): work `qinv` out without the extended Euclidean algorithm.  Making
  a key inverts one prime modulo the other and both of them are the key
  itself, so that inverse is now Fermat's little theorem through `expSafe`,
  which the other prime being prime allows: 308.6 us against 10.1, on a key
  that takes tens of milliseconds to make.  Making a key cannot be constant
  time -- the search for the primes takes as long as it takes -- but what that
  leaks is about the search rather than about the primes it settles on, and
  the haddock now says which is which
  [#143](https://github.com/kazu-yamamoto/crypton/pull/143)
* perf(ecc): a ladder for the curves over a binary field.  These were the last
  multiplication whose cost followed the scalar: an affine double-and-add, one
  addition for every bit that was set and none for the others, which on
  sect283k1 ran from 9665 us for a scalar with two bits set to 17958 for one
  with 270.  It is now Montgomery's ladder, which carries the multiples of two
  consecutive numbers -- their difference being the point is what lets it
  carry only their x coordinates -- and spends one addition and one doubling
  on every bit whichever way it goes, working the y out at the end from the
  two x it is left with, so one division does for the whole multiplication
  where the affine code had one per step.  The multiplication is now flat, and
  quicker: sect163k1 4428 to 3431 us, sect233r1 9304 to 6806, sect283k1 13797
  to 10181, sect409k1 30826 to 20584, sect571r1 61931 to 40469.  Uniform is
  not constant time -- these are `Integer` operations, whose cost follows the
  values -- and the point with no x, which is its own negation, keeps the code
  that was there
  [#142](https://github.com/kazu-yamamoto/crypton/pull/142)
* perf(ecc): multiply points in C on curves over a prime field.  P-256 has had
  a C implementation all along; every other prime curve -- P-384, P-521,
  secp256k1 and the rest -- multiplied points with `Integer` arithmetic, which
  cannot be constant time, since what an `Integer` operation costs follows the
  value it is given.  The C walks four bits of scalar at a time, taking the
  multiple to add from a table of sixteen that it reads by touching every
  entry and keeping one with a mask, and its addition and doubling are the
  complete formulas of Renes, Costello and Batina, which answer for every pair
  of points with no case to choose between.  A P-384 multiplication goes from
  1557 to 585 us and no longer follows the scalar, ECDSA P-384 signing from
  1700 to 636 us, P-521 from 1942 to 1123.  Binary curves are unchanged, and a
  point that is not on the curve keeps the answer the Haskell gives it
  [#141](https://github.com/kazu-yamamoto/crypton/pull/141)
* fix(ecc): add at every bit in the prime-curve multiplication, which laziness
  was skipping.  The multiplication adds at every bit, set or not, so that its
  cost follows the width of the curve's order rather than the scalar -- but
  the addition was a binding only one branch of the following `if` used, so at
  a bit that was not set it stayed a thunk and was never worked out.  The cost
  followed the number of bits set in the scalar, which is the nonce when
  signing and the private key in ECDH: on P-384, 765.8 us for a scalar with
  two bits set against 1671.5 for one with 383, in a straight line between.
  Both copies of the multiplication had it, so both elliptic curve APIs were
  affected on every prime curve but P-256
  [#140](https://github.com/kazu-yamamoto/crypton/pull/140)
* fix(ecdsa): keep the P-256 signature out of `Integer` arithmetic.  The
  scalar handed to the C implementation was reduced with `mod`, a division,
  whose steps follow the number being divided -- the nonce when signing, the
  private key in ECDH.  Twice the order is more than 256 bits hold, so a
  scalar that fits is brought under the order by one masked subtraction
  instead.  The second half of a signature, `kInv * (z + r * d)`, was
  `Integer` arithmetic as well, and now goes through `scalarAdd` and
  `scalarMul`, which on P-256 are the C implementation's fixed-width
  arithmetic.  What is left on that curve is the conversion between `Integer`
  and fixed-width scalars, which is also what it costs: signing goes from 34.1
  to 39.3 us, and ECDH and the other curves are unchanged
  [#139](https://github.com/kazu-yamamoto/crypton/pull/139)
* fix(dsa,ecdsa): invert the signing nonce without a side channel.  Both
  inverted it with the extended Euclidean algorithm, whose step count and
  branches follow the bits of what it is given -- and a handful of signatures
  whose nonces are partly known give the private key away, so the nonce is
  worth as much as the key.  `Crypto.Number.ModArithmetic.inverseSafe` works
  the inverse out with Fermat's little theorem through `expSafe` instead,
  falling back on `inverse` when the modulus turns out not to be prime, so
  every answer is the one it was.  On P-256 the C implementation does it.
  Signing costs a little more: ECDSA P-256 30.6 to 34.1 us, ECDSA P-384 678.7
  to 703.4, DSA-2048 422.5 to 437.1.  Verification inverts a value that
  arrives in the signature and is left alone
  [#138](https://github.com/kazu-yamamoto/crypton/pull/138)
* perf(number): square, and multiply, faster in `expSafe`.  The product and
  the Montgomery reduction are now a full product followed by a reduction
  rather than interleaved, built out of one loop that takes its limbs eight at
  a time, and squaring works out only the products on one side of the diagonal
  and doubles their sum.  At 2048 bits the constant-time exponentiation goes
  from 3.59 to 2.15 ms, which is 1.4x GMP's own rather than 2.4x; RSA-2048
  signing goes from 0.80 to 0.63 ms and DH-2048 `getShared` from 2.43 to 1.67
  [#137](https://github.com/kazu-yamamoto/crypton/pull/137)
* fix(number): make `expSafe` hide the exponent again.  It asked integer-gmp
  for `powModSecInteger` and fell back on the ordinary `powModInteger` when
  that was missing; since integer-gmp 1.1 it is always missing, so on every
  GHC this package supports `expSafe` was the same windowed exponentiation as
  `expFast`, table indexed by the exponent's bits, for RSA, DSA, DH, ElGamal
  and Rabin alike.  It now goes to C: four bits of exponent at a time, the
  table of sixteen read by touching every entry and keeping one with a mask,
  and a Montgomery multiplication whose final subtraction is masked too.  The
  exponent's length is still visible, rounded up to a whole 64-bit word, which
  is what GMP's own `mpz_powm_sec` lets slip.  Hiding the exponent costs 1.6x
  at 512 bits and 2.4x at 2048: RSA-2048 signing goes from 0.46 to 0.80 ms and
  DH-2048 `getShared` from 1.04 to 2.43
  [#136](https://github.com/kazu-yamamoto/crypton/pull/136)
* perf(prime): stop running a Fermat test that Miller-Rabin subsumes.  Every
  candidate was tested to base 2 before the Miller-Rabin rounds, which begin
  with the same base and prove more; the primes it passed paid for it twice
  and the composites it caught were nearly all caught by trial division first.
  RSA-2048 key generation goes from 55.0 to 32.8 ms
  [#135](https://github.com/kazu-yamamoto/crypton/pull/135)
* perf(f2m): reduce the binary field by folding the top back in rather than
  taking a step per bit of excess, square a byte at a time through a table of
  the patterns a byte spreads into, and take four bits of a multiplier at a
  time rather than one.  On the 283-bit field, squaring goes from 5440 to 2068
  ns and multiplication from 7526 to 4086.  A scalar multiplication there is
  still affine, so it inverts once per addition, which is where its time now
  goes
  [#134](https://github.com/kazu-yamamoto/crypton/pull/134)
* perf(ecc): fold instead of dividing in the generic prime-curve arithmetic,
  and add the point being multiplied as the affine point it is.  These primes
  are `2^k - c` with `c` far smaller, so the top half of a product folds back
  in with a shift, a multiplication and an addition, where dividing costs four
  times as much -- above 256 bits, below which the folding costs more than it
  saves.  P-521 scalar multiplication goes from 892 to 492 us and P-384 from
  684 to 572
  [#133](https://github.com/kazu-yamamoto/crypton/pull/133)
* perf(ecc): route P-256 through the C implementation the library already had.
  `Crypto.PubKey.ECDSA` reached `cbits/p256`; `Crypto.PubKey.ECC.*`, the older
  and more widely used API, never did.  ECDSA signing goes from 590 to 28.7 us,
  verification from 726 to 91.4, and `getShared` from 1177 to 96.  On P-256
  that multiplication is now constant time, where the generic code branches on
  the scalar at every bit
  [#132](https://github.com/kazu-yamamoto/crypton/pull/132)
* Breaking change: perf(camellia): put Camellia in C, 40 to 321 MiB/s.  The
  round function ran a byte at a time in Haskell; generating the tables that
  take a byte straight to its contribution gained 14%, and the rest was the
  language.  Input that is not a whole number of blocks now raises, where the
  tail of the answer used to be uninitialised memory
  [#131](https://github.com/kazu-yamamoto/crypton/pull/131)
* Breaking change: perf(twofish): walk the blocks once and carry them in words
  rather than appending each result to what came before and going through lists
  per block.  2 MiB goes from 0.14 to 56 MiB/s, and the rate no longer falls as
  the message grows.  Input that is not a whole number of blocks now raises,
  where it used to come back longer than it went in
  [#130](https://github.com/kazu-yamamoto/crypton/pull/130)
* perf(modes): cut the message without copying the rest of it in the generic
  block cipher modes, which every cipher but AES uses, and hand whole slices to
  the cipher in the modes whose blocks do not depend on one another.  Camellia
  in CBC goes from 1.8 to 22.9 MiB/s at 1 MiB, DES CBC decryption from 0.5 to
  83, and every figure is now flat in the message length where it used to fall
  [#129](https://github.com/kazu-yamamoto/crypton/pull/129)
* Breaking change: perf(des): put DES in C.  It was carried over lists of
  `Bool`, one cons cell per bit, with the key schedule recomputed for every
  block: 0.04 MiB/s, and 3DES 0.013, against 105 and 41 for OpenSSL.  They are
  now 112 and 37.  Input that is not a whole number of blocks now raises, where
  the tail of the answer used to be uninitialised memory
  [#128](https://github.com/kazu-yamamoto/crypton/pull/128)
* perf(cmac): slice the message rather than copying what is left of it once per
  block, and chain through CBC, which is what CMAC's chaining is.  A MAC over
  4 MiB goes from 0.36 to 1628 MiB/s, which is the speed of AES-CBC itself
  [#127](https://github.com/kazu-yamamoto/crypton/pull/127)
* fix(rabin): decode OAEP without early exits, as
  `Crypto.PubKey.RSA.OAEP.unpad` has since #91.  The difference is not
  measurable against the cost of mask generation, and is structural: the scan
  across the padding no longer depends on the data
  [#126](https://github.com/kazu-yamamoto/crypton/pull/126)
* Breaking change: fix(rabin): refuse a ciphertext or a signature that is not
  below the modulus, and a ciphertext carrying a leading zero octet.  Squaring
  and the square roots that undo it work modulo n, so Basic and Rabin-Williams
  decrypted `c + n` to whatever `c` decrypted to, and all three schemes verified
  `s + n`, and `-s`, wherever they verified `s`.  `Basic.signWith` also refuses a
  padding whose first octet is zero, which the signature cannot carry: about one
  signature in 256 was one its own `verify` rejected
  [#125](https://github.com/kazu-yamamoto/crypton/pull/125)
* fix(prime): derive the Miller-Rabin witnesses from the number being tested and
  from a secret drawn once per process.  They came from one generator made once
  and shared by every call, so the witnesses for one number were the witnesses
  for every number, and testing a number again told the caller nothing it had
  not already been told.  This is the path every GHC since 9.0 takes, integer-gmp
  1.1 having no Miller-Rabin of its own
  [#124](https://github.com/kazu-yamamoto/crypton/pull/124)
* docs(elgamal): say what `signWith` requires of its ephemeral value: the range
  is 1 to p-2, not the "between 0 and p-1" the haddock claimed, and the value is
  a private key that a signature discloses if it is reused or revealed
  [#123](https://github.com/kazu-yamamoto/crypton/pull/123)
* Breaking change: fix(afis): give `split` and `merge` one answer for a parameter
  they cannot use.  They had four between them, including a division by zero for
  an expand count of zero and, for a count of one, handing the diffused data back
  as though it were the secret
  [#122](https://github.com/kazu-yamamoto/crypton/pull/122)
* Breaking change: fix(rsa): refuse a ciphertext or a signature whose integer
  representative is not below the modulus, which RFC 8017 requires in sections
  5.1.2 and 5.2.2.  `PKCS15.decrypt` and `OAEP.decrypt` decrypted `c + n` to the
  same message as `c`, and `PSS.verifyDigest` accepted `s + n` wherever it
  accepted `s`
  [#121](https://github.com/kazu-yamamoto/crypton/pull/121)
* fix(otp): search the HOTP resynchronization window without early exits.  The
  time taken read out both where in the window the client's counter was found
  and how many of the submitted values were right -- the second of which the
  answer itself does not give, being `Nothing` either way.  A call now costs one
  HMAC per counter in the window plus one per extra value, every time
  [#120](https://github.com/kazu-yamamoto/crypton/pull/120)
* Breaking change: fix(kdf): report a refused parameter as a `CryptoError` rather
  than as an `ErrorCall` carrying a string, with a `'`-suffixed variant of each
  entry point returning `CryptoFailable`.  PBKDF2 had no validation at all: a
  negative output length reached `memSet` and killed the process with SIGBUS, and
  an iteration count of zero returned 32 bytes of zeroes
  [#119](https://github.com/kazu-yamamoto/crypton/pull/119)
* perf(xts): take eight blocks at a time on AArch64 and x86-64, and dispatch XTS
  decryption through the branch table, which it had never used.  AArch64 goes
  from 1200 to 7742 MiB/s encrypting and 1166 to 7763 decrypting, x86-64 from
  1220 to 3464 and from 594 to 3461
  [#118](https://github.com/kazu-yamamoto/crypton/pull/118)
* perf(poly1305): take four blocks at a time with AVX2 on x86-64, folding the
  lanes back together weighted by the powers of r.  1347 to 4137 MiB/s
  [#117](https://github.com/kazu-yamamoto/crypton/pull/117)
* perf(ecc): work in Jacobian coordinates in both generic prime-field scalar
  multiplications, and say in `Crypto.ECC` which curves branch on a secret
  scalar.  P-384 and P-521 ECDSA are 2.3x: signing goes from 3.36 to 1.46 ms and
  from 5.96 to 2.61 ms.  P-256, which has its own C implementation, is unaffected
  [#116](https://github.com/kazu-yamamoto/crypton/pull/116)
* Breaking change: fix(padding): bound PKCS#7 padding by the block rather than by
  the whole input, which had let a block of sixteen accept a claim of twenty, and
  refuse a `ZERO` size of zero rather than dividing by it.  What `ZERO` can and
  cannot undo is now written down
  [#115](https://github.com/kazu-yamamoto/crypton/pull/115)
* perf(gcm): give x86 its own GCM decryption loop.  It fell to the generic one,
  which calls the block function once per block, and ran at a quarter the speed
  of encryption; both directions now take eight blocks at a time and fold their
  GHASH into one reduction.  AES-256-GCM decryption goes from 561 to 2733 MiB/s
  and AES-128 from 667 to 3150
  [#114](https://github.com/kazu-yamamoto/crypton/pull/114)
* perf(chacha): take eight blocks at a time with AVX2 where the machine has it,
  with the cpuid and XGETBV checks that decide.  ChaCha20 on x86-64 goes from
  900 to 2074 MiB/s
  [#113](https://github.com/kazu-yamamoto/crypton/pull/113)
* perf(chacha): do four blocks at a time with SSE2 on x86-64, where the cipher
  had no vector code at all.  ChaCha20 goes from 493 to 900 MiB/s
  [#112](https://github.com/kazu-yamamoto/crypton/pull/112)
* perf(chacha): do four blocks at a time with NEON on AArch64.  ChaCha20 goes
  from 1025 to 1955 MiB/s
  [#111](https://github.com/kazu-yamamoto/crypton/pull/111)
* feat(sha512): use the ARMv8.2 SHA-512 instructions on AArch64, which SHA-384
  and the truncated SHA-512/t variants share.  Hashing 1 MiB goes from 1.53 ms
  to 597 us.  The extension is optional, so it is asked for at runtime on both
  Apple and Linux rather than assumed
  [#110](https://github.com/kazu-yamamoto/crypton/pull/110)
* perf(gcm): drive GCM from AArch64 rather than the generic loop, with a group
  of eight blocks folding into a single GHASH reduction.  AES-128-GCM goes from
  4030 to 8266 MiB/s and AES-256 from 4043 to 7172
  [#109](https://github.com/kazu-yamamoto/crypton/pull/109)
* perf(aes): specialise the AArch64 code by key size and interleave eight
  blocks, and give CTR its own loop.  AES-256 ECB goes from 3886 to 15991
  MiB/s, CTR from 2935 to 13567 and CBC decryption from 4366 to 15807
  [#108](https://github.com/kazu-yamamoto/crypton/pull/108)

* perf(aes): build the AES-NI paths on Windows, which was missing from the list of
  systems that compile them.  Windows builds have been doing AES, and GHASH with it,
  in the generic C
  [#107](https://github.com/kazu-yamamoto/crypton/pull/107)
* fix(armv8): compile the AArch64 sources on a toolchain whose baseline lacks the
  crypto extensions.  They had not built with GCC on AArch64 Linux since #100; CI now
  builds and tests there
  [#106](https://github.com/kazu-yamamoto/crypton/pull/106)
* perf(gcm): fold four GHASH blocks into one reduction.  AES-256-GCM is 1.6x at 1 KiB
  and 2.6x at 64 KiB on Apple silicon, and the x86 paths gain the same structure
  [#105](https://github.com/kazu-yamamoto/crypton/pull/105)
* perf(sha256): use the ARMv8 SHA-2 instructions on AArch64.  SHA-256 and SHA-224 are
  5.5x
  [#104](https://github.com/kazu-yamamoto/crypton/pull/104)
* ci: keep the macOS jobs from queueing behind each other, and supersede a branch's
  earlier run
  [#103](https://github.com/kazu-yamamoto/crypton/pull/103)
* perf(aes): use PMULL for GHASH on AArch64
  [#102](https://github.com/kazu-yamamoto/crypton/pull/102)
* ci: ask cabal where its caches live rather than assuming, and keep the build
  products in the cache
  [#101](https://github.com/kazu-yamamoto/crypton/pull/101)
* perf(aes): use the ARMv8 cryptographic extensions on AArch64.  With the GHASH work
  in #102 and #105, AES-256-ECB goes from 121 to 2992 MiB/s and AES-256-GCM from 92 to
  2318 MiB/s on Apple silicon
  [#100](https://github.com/kazu-yamamoto/crypton/pull/100)
* build(bench): move the benchmarks from gauge, which is no longer maintained, to
  tasty-bench, and let them resolve on a current GHC
  [#99](https://github.com/kazu-yamamoto/crypton/pull/99)
* Breaking change: fix(padding): reject a `PKCS7` block size outside 1..255.  `pad`
  raises and `unpad` returns `Nothing`, where both previously narrowed the size to a
  `Word8` and silently agreed on the wrong value
  [#98](https://github.com/kazu-yamamoto/crypton/pull/98)
* feat(elgamal): fix `Crypto.PubKey.ElGamal` and expose it
  [#97](https://github.com/kazu-yamamoto/crypton/pull/97)
* docs(bcrypt): say that only the first 72 bytes of a password count
  [#96](https://github.com/kazu-yamamoto/crypton/pull/96)
* test: move the test suite from tasty to hspec, with hspec-discover.  `cabal-version`
  is now 2.0
  [#95](https://github.com/kazu-yamamoto/crypton/pull/95)

* feat(aead): add `aeadSimpleDecrypt'`, which takes the tag length as its own argument instead of reading it off the supplied tag
  [#94](https://github.com/kazu-yamamoto/crypton/pull/94)
* Breaking change: feat(dh): add `getShared'` to `Crypto.PubKey.DH` and `Crypto.PubKey.ECC.DH`, reporting a rejected peer value as `CryptoFailable`; `getShared` is now defined in terms of it and so raises a `CryptoError` rather than an `ErrorCall`
  [#93](https://github.com/kazu-yamamoto/crypton/pull/93)
* fix(otp): compare TOTP candidates without an early exit
  [#92](https://github.com/kazu-yamamoto/crypton/pull/92)
* fix(rsa): drop the early exits from PKCS#1 v1.5 and OAEP unpadding
  [#91](https://github.com/kazu-yamamoto/crypton/pull/91)
* Breaking change: fix(argon2): report invalid options as `CryptoFailed` rather than raising, adding `CryptoError_ParameterInvalid` to `CryptoError`
  [#90](https://github.com/kazu-yamamoto/crypton/pull/90)
* Breaking change: fix(dh): validate the peer public number, and size the shared secret from `p` rather than `params_bits`
  [#89](https://github.com/kazu-yamamoto/crypton/pull/89)
* fix(dsa): do not crash on values that are not invertible modulo `q`
  [#88](https://github.com/kazu-yamamoto/crypton/pull/88)
* Breaking change: fix(ecdh): validate the peer point before the exchange
  [#87](https://github.com/kazu-yamamoto/crypton/pull/87)
* Breaking change: fix(pkcs15): reject PKCS#1 v1.5 signatures of the wrong length or out of range
  [#86](https://github.com/kazu-yamamoto/crypton/pull/86)
* Breaking change: fix(otp): require a digest long enough for RFC 4226 dynamic truncation, which was reading past the end of the MAC
  [#85](https://github.com/kazu-yamamoto/crypton/pull/85)
* fix(ecc): accept zero-x P-256 shared secret
  [#84](https://github.com/kazu-yamamoto/crypton/pull/84)
* fix(p256): accept valid edge-case points
  [#83](https://github.com/kazu-yamamoto/crypton/pull/83)
* Breaking change: fix(hkdf): enforce output length limit
  [#82](https://github.com/kazu-yamamoto/crypton/pull/82)
* Breaking change: fix(ed25519): reject non-canonical signatures
  [#81](https://github.com/kazu-yamamoto/crypton/pull/81)
* Support GHC 9.14; `tested-with` now covers 9.10.2, 9.12.4 and 9.14.1
  [#74](https://github.com/kazu-yamamoto/crypton/pull/74)

### API changes

* New exports: `Crypto.OTP.minimumDigestSize`, `Crypto.PubKey.DH.getShared'`,
  `Crypto.PubKey.ECC.DH.getShared'`, `Crypto.Cipher.Types.AEAD.aeadSimpleDecrypt'`,
  `Crypto.Number.ModArithmetic.inverseSafe`, `Crypto.PubKey.ECC.Prim.scalarInverse`,
  `scalarAdd` and `scalarMul`, `Crypto.PubKey.ECC.P256.scalarReduce`,
  and the whole of `Crypto.PubKey.ElGamal`, which was present but not exposed.
  The KDFs gained a variant of each entry point that can refuse its parameters,
  returning `CryptoFailable` instead of raising: `Crypto.KDF.Scrypt.generate'`,
  `Crypto.KDF.BCrypt.bcrypt'`, `Crypto.KDF.BCryptPBKDF.generate'` and
  `hashInternal'`, `Crypto.KDF.HKDF.expand'`, `Crypto.KDF.PBKDF2.generate'` and
  `fastPBKDF2_SHA1'`, `fastPBKDF2_SHA256'` and `fastPBKDF2_SHA512'`, and
  `Crypto.Data.AFIS.split'` and `merge'`.  These are additions and break nothing.
* Breaking change: `CryptoError_ParameterInvalid` is added to `CryptoError`.  It is
  appended, so the `Enum` values of the existing constructors are unchanged, but an
  exhaustive `case` without a wildcard will warn.  Adding a constructor to an exported
  datatype is what requires a major version bump under the PVP, which would have been
  1.2.0; this release goes to 2.0.0.  Everything else below changes behaviour rather
  than types.
* Breaking change: `getShared` in both DH modules raises a `CryptoError` where it
  previously raised an `ErrorCall`, since it is now defined in terms of `getShared'`.
  The same is now true of `Crypto.KDF.Scrypt.generate`, `Crypto.KDF.BCrypt.bcrypt`,
  `Crypto.KDF.BCryptPBKDF.generate` and `hashInternal`, and `Crypto.Data.AFIS.split`
  and `merge`, each of which is defined in terms of the variant above.
* Breaking change: input that used to be accepted is now rejected -- a digest shorter
  than 20 bytes in `Crypto.OTP.hotp`, a signature of the wrong length or out of range
  in `Crypto.PubKey.RSA.PKCS15.verify`, an off-curve peer point or a peer public number
  outside `1 < y < p-1` in `getShared`, an output beyond 255 blocks in
  `Crypto.KDF.HKDF.expand`, a non-canonical Ed25519 signature, and `Options` the
  implementation refuses in `Crypto.KDF.Argon2.hash`.
* Breaking change: a value at or above the modulus is now rejected where it used to be
  reduced and accepted -- a ciphertext in `Crypto.PubKey.RSA.PKCS15.decrypt` and
  `Crypto.PubKey.RSA.OAEP.decrypt`, a signature in `Crypto.PubKey.RSA.PSS.verify`, and
  both, along with a negated signature and a ciphertext with a leading zero octet, in
  the three `Crypto.PubKey.Rabin.*` schemes.
* Breaking change: parameters that used to be accepted are now refused -- an iteration
  count below one or a negative output length in `Crypto.KDF.PBKDF2`, an expand count
  below two or a secret of no bytes in `Crypto.Data.AFIS`, a `PKCS7` claim longer than
  the block and a `ZERO` size of zero in `Crypto.Data.Padding`, and a signature padding
  whose first octet is zero in `Crypto.PubKey.Rabin.Basic.signWith`.
* Breaking change: DES, 3DES, Twofish and Camellia now raise on input that is not a
  whole number of blocks, as AES already did.  Before, DES and Camellia returned an
  answer whose tail was never written -- uninitialised memory -- and Twofish returned
  more than it was given, the missing bytes read as zero.
* Breaking change: `Crypto.Data.Padding.pad` raises on a `PKCS7` block size outside
  1..255, and `unpad` returns `Nothing` for one, where both used to narrow the size to
  a `Word8` and hand back something other than what was padded.
* No exported function changed its signature.

## 1.1.5

* fix(aead): reject undersized tags
  [#80](https://github.com/kazu-yamamoto/crypton/pull/80)
* fix(aes): refuse a zero-length AES-GCM IV
  [#79](https://github.com/kazu-yamamoto/crypton/pull/79)
* fix(p256): prevent crashes when validating valid points
  [#78](https://github.com/kazu-yamamoto/crypton/pull/78)
* feat(asn1): add SHA-3 HashAlgorithmASN1 instances for PKCS#1 v1.5
  [#77](https://github.com/kazu-yamamoto/crypton/pull/77)
* OCB3 conformance
  [#76](https://github.com/kazu-yamamoto/crypton/pull/76)

## 1.1.4

* Generic instance for RSA PublicKey and PrivateKey

## 1.1.3

* Ensure that `pointAdd` in `PubKey.ECC.P256` treats the point at infinity as the additive identity.
  [#73](https://github.com/kazu-yamamoto/crypton/pull/73)

## 1.1.2

* Preparing `ram` v0.22.
* Generalizing RSA encrypt/decrypt to manipulate ScrubbedBytes directly.

## 1.1.1

* On iOS, ScrubbedBytes based hashing is used for seedNew. On other
  plateforms, entropy is used directly as used to be.
  [#71](https://github.com/kazu-yamamoto/crypton/pull/71)

## 1.1.0

* Removing "basement" and "memory".
  [#67](https://github.com/kazu-yamamoto/crypton/pull/67)


## 1.0.7

* Stop depending on basement, use upstream dependencies instead
* Stop transitively depending on basement by depending on ram.

## 1.0.6

* Fix test failures on less common 64-bit arches.
  [#65](https://github.com/kazu-yamamoto/crypton/pull/65)

## 1.0.5

* Setter/Getter for ChaCha counter.
  [#63](https://github.com/kazu-yamamoto/crypton/pull/63)
* Add simple interface to generate full blocks
  [#60](https://github.com/kazu-yamamoto/crypton/pull/60)
* Avoid `ghc-prim` dependency.
  [#61](https://github.com/kazu-yamamoto/crypton/pull/61)

## 1.0.4

* Ed448.sign: avoid extra re-derive of public key.
  [#48](https://github.com/kazu-yamamoto/crypton/pull/48)

## 1.0.3

* Make sign of Ed25519/Ed448 safer. The public key parameter is
  ignored and its public key is generated from the secret key
  parameter to prevent Double Public Key Signing Function Oracle
  Attack.
  [#47](https://github.com/kazu-yamamoto/crypton/pull/47)

## 1.0.2

* Deterministic Nonce Generation for ECDSA
  [#46](https://github.com/kazu-yamamoto/crypton/pull/46)
* ECDSA Signature Normalization.
  [#45](https://github.com/kazu-yamamoto/crypton/pull/45)
* Add Full Test Suite from RFC 6979.
  [#44](https://github.com/kazu-yamamoto/crypton/pull/44)
* ECDSA with Public Key Recovery.
  [#43](https://github.com/kazu-yamamoto/crypton/pull/43)
* Providing necessary features for HPKE.
  [#42](https://github.com/kazu-yamamoto/crypton/pull/42)

## 1.0.1

* Update decaf library.
  [#38](https://github.com/kazu-yamamoto/crypton/pull/38)
* Add TypeOperators language extension to EdDSA.hs.
  [#36](https://github.com/kazu-yamamoto/crypton/pull/36)

## 1.0.0

* Versions follow the standard version policy.
* Removing pthread stuff.
  [#32](https://github.com/kazu-yamamoto/crypton/pull/32)

## 0.34

* Hashing getRandomBytes before using as Seed for ChaChaDRG
  [#24](https://github.com/kazu-yamamoto/crypton/pull/24)
* Add support for XChaCha and XChaChaPoly1305
  [#18](https://github.com/kazu-yamamoto/crypton/pull/18)
* Strict byteArray of IV c
  [#16](https://github.com/kazu-yamamoto/crypton/pull/16)

## 0.33

* Add "crypton_" prefix to the final C symbols.
  [#9](https://github.com/kazu-yamamoto/crypton/pull/9)

## 0.32

* All C symbols now have the "crypton_" prefix.
  [#7](https://github.com/kazu-yamamoto/crypton/pull/7)
  [#8](https://github.com/kazu-yamamoto/crypton/pull/8)

## 0.31

* Crypton is forked from cryptonite with the original authors permission.
* Ignoring exceptons from hClose to read the next entropy
  [#1](https://github.com/kazu-yamamoto/crypton/pull/1)
* Enabling the support_pclmuldq flag by default.

## 0.30

* Fix some C symbol blake2b prefix to be cryptonite_ prefix (fix mixing with other C library)
* add hmac-lazy
* Fix compilation with GHC 9.2
* Drop support for GHC8.0, GHC8.2, GHC8.4, GHC8.6

## 0.29

* advance compilation with gmp breakage due to change upstream
* Add native EdDSA support

## 0.28

* Add hash constant time capability
* Prevent possible overflow during hashing by hashing in 4GB chunks

## 0.27

* Optimise AES GCM and CCM
* Optimise P256R1 implementation
* Various AES-NI building improvements
* Add better ECDSA support
* Add XSalsa derive
* Implement square roots for ECC binary curve
* Various tests and benchmarks

## 0.26

* Add Rabin cryptosystem (and variants)
* Add bcrypt_pbkdf key derivation function
* Optimize Blowfish implementation
* Add KMAC (Keccak Message Authentication Code)
* Add ECDSA sign/verify digest APIs
* Hash algorithms with runtime output length
* Update blake2 to latest upstream version
* RSA-PSS with arbitrary key size
* SHAKE with output length not divisible by 8
* Add Read and Data instances for Digest type
* Improve P256 scalar primitives
* Fix hash truncation bug in DSA
* Fix cost parsing for bcrypt
* Fix ECC failures on arm64
* Correction to PKCS#1 v1.5 padding
* Use powModSecInteger when available
* Drop GHC 7.8 and GHC 7.10 support, refer to pkg-guidelines
* Optimise GCM mode
* Add little endian serialization of integer

## 0.25

* Improve digest binary conversion efficiency
* AES CCM support
* Add MonadFailure instance for CryptoFailable
* Various misc improvements on documentation
* Edwards25519 lowlevel arithmetic support
* P256 add point negation
* Improvement in ECC (benchmark, better normalization)
* Blake2 improvements to context size
* Use gauge instead of criterion
* Use haskell-ci for CI scripts
* Improve Digest memory representation to be 2 less Ints and one less boxing
  moving from `UArray` to `Block`

## 0.24

* Ed25519: generateSecret & Documentation updates
* Repair tutorial
* RSA: Allow signing digest directly
* IV add: fix overflow behavior
* P256: validate point when decoding
* Compilation fix with deepseq disabled
* Improve Curve448 and use decaf for Ed448
* Compilation flag blake2 sse merged in sse support
* Process unaligned data better in hashes and AES, on architecture needing alignment
* Drop support for ghc 7.6
* Add ability to create random generator Seed from binary data and
  loosen constraint on ChaChaDRG seed from ByteArray to ByteArrayAccess.
* Add 3 associated types with the HashAlgorithm class, to get
  access to the constant for BlockSize, DigestSize and ContextSize at the type level.
  the related function that this replaced will be deprecated in later release, and
  eventually removed.

API CHANGES:

* Improve ECDH safety to return failure for bad inputs (e.g. public point in small order subgroup).
  To go back to previous behavior you can replace `ecdh` by `ecdhRaw`. It's recommended to
  use `ecdh` and handle the error appropriately.
* Users defining their own HashAlgorithm needs to define the
  HashBlockSize, HashDigest, HashInternalContextSize associated types

## 0.23

* Digest memory usage improvement by using unpinned memory
* Fix generateBetween to generate within the right bounds
* Add pure Twofish implementation
* Fix memory allocation in P256 when using a temp point
* Consolidate hash benchmark code
* Add Nat-length Blake2 support (GHC > 8.0)
* Update tutorial

## 0.22

* Add Argon2 (Password Hashing Competition winner) hash function
* Update blake2 to latest upstream version
* Add extra blake2 hashing size
* Add faster PBKDF2 functions for SHA1/SHA256/SHA512
* Add SHAKE128 and SHAKE256
* Cleanup prime generation, and add tests
* Add Time-based One Time Password (TOTP) and HMAC-based One Time Password (HOTP)
* Rename Ed448 module name to Curve448, old module name still valid for now

## 0.21

* Drop automated tests with GHC 7.0, GHC 7.4, GHC 7.6. support dropped, but probably still working.
* Improve non-aligned support in C sources, ChaCha and SHA3 now probably work on arch without support for unaligned access. not complete or tested.
* Add another ECC framework that is more flexible, allowing different implementations to work instead of
  the existing Pure haskell NIST implementation.
* Add ECIES basic primitives
* Add XSalsa20 stream cipher
* Process partial buffer correctly with Poly1305

## 0.20

* Fixed hash truncation used in ECDSA signature & verification (Olivier Chéron)
* Fix ECDH when scalar and coordinate bit sizes differ (Olivier Chéron)
* Speed up ECDSA verification using Shamir's trick (Olivier Chéron)
* Fix rdrand on windows

## 0.19

* Add tutorial (Yann Esposito)
* Derive Show instance for better interaction with Show pretty printer (Eric Mertens)

## 0.18

* Re-used standard rdrand instructions instead of bytedump of rdrand instruction
* Improvement to F2m, including lots of tests (Andrew Lelechenko)
* Add error check on salt length in bcrypt

## 0.17

* Add Miyaguchi-Preneel construction (Kei Hibino)
* Fix buffer length in scrypt (Luke Taylor)
* build fixes for i686 and arm related to rdrand

## 0.16

* Fix basepoint for Ed448

* Enable 64-bit Curve25519 implementation

## 0.15

* Fix serialization of DH and ECDH

## 0.14

* Reduce size of SHA3 context instead of allocating all-size fit memory. save
  up to 72 bytes of memory per context for SHA3-512.
* Add a Seed capability to the main DRG, to be able to debug/reproduce randomized program
  where you would want to disable the randomness.
* Add support for Cipher-based Message Authentication Code (CMAC) (Kei Hibino)
* *CHANGE* Change the `SharedKey` for `Crypto.PubKey.DH` and `Crypto.PubKey.ECC.DH`,
  from an Integer newtype to a ScrubbedBytes newtype. Prevent mistake where the
  bytes representation is generated without the right padding (when needed).
* *CHANGE* Keep The field size in bits, in the `Params` in `Crypto.PubKey.DH`,
  moving from 2 elements to 3 elements in the structure.

## 0.13

* *SECURITY* Fix buffer overflow issue in SHA384, copying 16 extra bytes from
  the SHA512 context to the destination memory pointer leading to memory
  corruption, segfault. (Mikael Bung)

## 0.12

* Fix compilation issue with Ed448 on 32 bits machine.

## 0.11

* Truncate hashing correctly for DSA
* Add support for HKDF (RFC 5869)
* Add support for Ed448
* Extends support for Blake2s to 224 bits version.
* Compilation workaround for old distribution (RHEL 4.1)
* Compilation fix for AIX
* Compilation fix with AESNI and ghci compiling C source in a weird order.
* Fix example compilation, typo, and warning

## 0.10

* Add reference implementation of blake2 for non-SSE2 platform
* Add support\_blake2\_sse flag

## 0.9

* Quiet down unused module imports
* Move Curve25519 over to Crypto.Error instead of using Either String.
* Add documentation for ChaChaPoly1305
* Add missing documentation for various modules
* Add a way to create Poly1305 Auth tag.
* Added support for the BLAKE2 family of hash algorithms
* Fix endianness of incrementNonce function for ChaChaPoly1305

## 0.8

* Add support for ChaChaPoly1305 Nonce Increment (John Galt)
* Move repository to the haskell-crypto organisation

## 0.7

* Add PKCS5 / PKCS7 padding and unpadding methods
* Fix ChaChaPoly1305 Decryption
* Add support for BCrypt (Luke Taylor)

## 0.6

* Add ChaChaPoly1305 AE cipher
* Add instructions in README for building on old OSX
* Fix blocking /dev/random Andrey Sverdlichenko

## 0.5

* Fix all strays exports to all be under the cryptonite prefix.

## 0.4

* Add a System DRG that represent a referentially transparent of evaluated bytes
  while using lazy evaluation for future entropy values.

## 0.3

* Allow drgNew to run in any MonadRandom, providing cascading initialization
* Remove Crypto.PubKey.HashDescr in favor of just having the algorithm
  specified in PKCS15 RSA function.
* Fix documentation in cipher sub section (Luke Taylor)
* Cleanup AES dead functions (Luke Taylor)
* Fix Show instance of Digest to display without quotes similar to cryptohash
* Use scrubbed bytes instead of bytes for P256 scalar

## 0.2

* Fix P256 compilation and exactness, + add tests
* Add a raw memory number serialization capability (i2osp, os2ip)
* Improve tests for number serialization
* Improve tests for ECC arithmetics
* Add Ord instance for Digest (Nicolas Di Prima)
* Fix entropy compilation on windows 64 bits.

## 0.1

* Initial release
