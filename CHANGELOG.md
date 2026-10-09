# CHANGELOG for crypton

## 2.2.0

* feat: name every processor feature crypton dispatches on, not three of them
* fix: an AArch64 machine no longer reports AESNI and PCLMUL
* feat(rsa): PKCS#1 v1.5 operations that take a digest, and ones that take a DigestInfo
* chore(rsa): deprecate `sign`, `signSafer` and `verify` in favour of them
* feat(dsa): sign and verify over a digest
* feat(elgamal): sign and verify over a digest
* feat(rabin): Rabin-Williams and Modified Rabin sign and verify over a digest

## 2.1.8

* chore: stop hiding foldl' from Prelude
  [#294](https://github.com/kazu-yamamoto/crypton/pull/294)
* chore: ask for hidden visibility only where the format has it
  [#295](https://github.com/kazu-yamamoto/crypton/pull/295)
* feat: ML-KEM and ML-DSA, through mlkem-native and mldsa-native
  [#297](https://github.com/kazu-yamamoto/crypton/pull/297)

## 2.1.7

RSA-PSS verification was accepting an encoding RFC 8017 says to refuse.  It
is a conformance fault rather than a forgery: producing such a signature takes
the private key, so a third party holding a valid signature cannot turn it
into one of these.

* chore(p256): drop two declarations nothing defines
  [#292](https://github.com/kazu-yamamoto/crypton/pull/292)
* fix(pss): refuse an encoding with a bit set outside emBits
  [#293](https://github.com/kazu-yamamoto/crypton/pull/293)

## 2.1.6

The `license:` field now says what the tree holds -- `BSD-3-Clause AND MIT
AND ISC` -- and `license-files:` lists all five texts.  **Nothing is required
of a user that was not required before**; the field was simply incomplete.

* Carry the MIT notice for the parts that follow fusion, and say what the tree holds
  [#267](https://github.com/kazu-yamamoto/crypton/pull/267)
* fix: two preconditions the Haskell layer did not enforce
  [#288](https://github.com/kazu-yamamoto/crypton/pull/288)
* fix(x86): stop casting a packed block to __m128i *
  [#289](https://github.com/kazu-yamamoto/crypton/pull/289)
* fix(c): say that the digest pointers are never null
  [#290](https://github.com/kazu-yamamoto/crypton/pull/290)
* fix(pbkdf2): refuse a digest larger than its block at compile time
  [#291](https://github.com/kazu-yamamoto/crypton/pull/291)

## 2.1.5

2.1.3 and 2.1.4 cannot be built with GCC 14 or newer.  This release is
that fix.

* Watch for a primitive fallen off its fast path
  [#277](https://github.com/kazu-yamamoto/crypton/pull/277)
* The performance tables for 2.1.4
  [#278](https://github.com/kazu-yamamoto/crypton/pull/278)
* The x86-64 table, on the machine the README names
  [#279](https://github.com/kazu-yamamoto/crypton/pull/279)
* perf(armv8): GHASH against a twisted H, a quarter faster
  [#281](https://github.com/kazu-yamamoto/crypton/pull/281)
* ct: run the constant-time harness on AArch64, and put its AES to it
  [#283](https://github.com/kazu-yamamoto/crypton/pull/283)
* Fix crypton_sha1_x86_do_chunk signature
  [#284](https://github.com/kazu-yamamoto/crypton/pull/284)
* ci: build the C with a compiler stricter than this matrix has
  [#285](https://github.com/kazu-yamamoto/crypton/pull/285)

## 2.1.4

2.1.3 could not be built from Hackage in the default configuration, and is
deprecated there.  This release is that fix.

* Add p256 header files to cabal extra-source-files
  [#271](https://github.com/kazu-yamamoto/crypton/pull/271)
* Build what is published, not only what is checked out
  [#272](https://github.com/kazu-yamamoto/crypton/pull/272)
* SHA-256 on AArch64 is 5.4x slower in 2.1.3 than in 2.1.2
  [#274](https://github.com/kazu-yamamoto/crypton/pull/274)
* The target attribute spelling gcc before 13 understands
  [#276](https://github.com/kazu-yamamoto/crypton/pull/276)

## 2.1.3

* fix(aead): reject missing and oversized authentication tags
  [#233](https://github.com/kazu-yamamoto/crypton/pull/233)
* fix(chacha): remove redundant Word8 import
  [#234](https://github.com/kazu-yamamoto/crypton/pull/234)
* test(number): cover the two modulus sizes the assembly runs at
  [#235](https://github.com/kazu-yamamoto/crypton/pull/235)
* perf(rsa): swap the buffers instead of copying them back
  [#236](https://github.com/kazu-yamamoto/crypton/pull/236)
* perf(rsa): scan the exponentiation's table four limbs at a time
  [#237](https://github.com/kazu-yamamoto/crypton/pull/237)
* fix(gcm): write the field doubling from its definition
  [#238](https://github.com/kazu-yamamoto/crypton/pull/238)
* doc(gcm): carry the MIT notice for the parts that follow fusion
  [#239](https://github.com/kazu-yamamoto/crypton/pull/239)
* perf(ed25519): the base point multiplication through s2n-bignum
  [#240](https://github.com/kazu-yamamoto/crypton/pull/240)
* perf(gcm): AES-GCM through the 512-bit VAES and VPCLMULQDQ
  [#241](https://github.com/kazu-yamamoto/crypton/pull/241)
* doc: the README said AVX-512 was not used, and it is
  [#242](https://github.com/kazu-yamamoto/crypton/pull/242)
* perf(ecdsa): P-256 verification multiplies both scalars at once
  [#243](https://github.com/kazu-yamamoto/crypton/pull/243)
* perf(rsa): four limbs and two carry chains on AArch64
  [#244](https://github.com/kazu-yamamoto/crypton/pull/244)
* perf(rsa): write out the ragged end of the AArch64 row
  [#245](https://github.com/kazu-yamamoto/crypton/pull/245)
* perf(rsa): build R^2 by squaring, not by doubling
  [#246](https://github.com/kazu-yamamoto/crypton/pull/246)
* perf(rsa): stop clearing the scratch a Montgomery multiply writes over
  [#247](https://github.com/kazu-yamamoto/crypton/pull/247)
* doc(gcm): write down what the AArch64 GHASH is short of
  [#248](https://github.com/kazu-yamamoto/crypton/pull/248)
* security(aes): refuse a nonce of no bytes in Crypto.Cipher.AES.GCM
  [#250](https://github.com/kazu-yamamoto/crypton/pull/250)
* ci: build and test the C the other architectures use
  [#251](https://github.com/kazu-yamamoto/crypton/pull/251)
* perf(p256): five teeth to a comb block, over the signed representation
  [#252](https://github.com/kazu-yamamoto/crypton/pull/252)
* security(cipher): stop truncating message lengths on the way to the C
  [#253](https://github.com/kazu-yamamoto/crypton/pull/253)
* fix(c): two left shifts the standard leaves undefined
  [#254](https://github.com/kazu-yamamoto/crypton/pull/254)
* ci: run the C under the sanitizers
  [#255](https://github.com/kazu-yamamoto/crypton/pull/255)
* fix(c): read words out of a block rather than pointing at it
  [#256](https://github.com/kazu-yamamoto/crypton/pull/256)
* fix(internal): drop an import nothing uses any more
  [#257](https://github.com/kazu-yamamoto/crypton/pull/257)
* fix(c): decide the dispatch table once, not on every key
  [#258](https://github.com/kazu-yamamoto/crypton/pull/258)
* Fix the three cabal flag settings that were broken
  [#259](https://github.com/kazu-yamamoto/crypton/pull/259)
* Run the C that only 32-bit architectures get, and fix what that found
  [#260](https://github.com/kazu-yamamoto/crypton/pull/260)
* Let the last addition of each scalar multiplication be a complete one
  [#261](https://github.com/kazu-yamamoto/crypton/pull/261)
* Ask whether the secrets decide anything
  [#262](https://github.com/kazu-yamamoto/crypton/pull/262)
* Ask a big-endian machine the same questions
  [#263](https://github.com/kazu-yamamoto/crypton/pull/263)
* Ask what the secrets leave behind
  [#264](https://github.com/kazu-yamamoto/crypton/pull/264)
* Stop taking eighteen runner slots to test three things
  [#265](https://github.com/kazu-yamamoto/crypton/pull/265)
* Make the scrubs ones the compiler cannot drop, and finish round ten
  [#266](https://github.com/kazu-yamamoto/crypton/pull/266)
* Feed the parsers bytes nobody chose
  [#268](https://github.com/kazu-yamamoto/crypton/pull/268)

## 2.1.2

* perf(p256): 255 squarings for the field inversion, not 287
  [#223](https://github.com/kazu-yamamoto/crypton/pull/223)
* perf(p256): ECDH through s2n-bignum, 2.7x
  [#224](https://github.com/kazu-yamamoto/crypton/pull/224)
* perf(ecc): P-384 and P-521 through s2n-bignum, 7x and 9x
  [#225](https://github.com/kazu-yamamoto/crypton/pull/225)
* perf(p256): ECDSA signing 2.4x and verification 2.2x
  [#226](https://github.com/kazu-yamamoto/crypton/pull/226)
* perf(rsa): the Montgomery multiplication through s2n-bignum on x86-64
  [#227](https://github.com/kazu-yamamoto/crypton/pull/227)
* perf(ecdsa): invert modulo the order in division steps, not an exponentiation
  [#228](https://github.com/kazu-yamamoto/crypton/pull/228)
* perf(x25519): X25519 through s2n-bignum, and a table for key generation
  [#229](https://github.com/kazu-yamamoto/crypton/pull/229)
* perf(gcm): AES-GCM through VAES and VPCLMULQDQ
  [#230](https://github.com/kazu-yamamoto/crypton/pull/230)
* perf(gcm): compile the wide loop once per key length
  [#231](https://github.com/kazu-yamamoto/crypton/pull/231)

## 2.1.1

* feat(ecdsa): RFC 6979 deterministic nonces for Crypto.PubKey.ECDSA
  [#219](https://github.com/kazu-yamamoto/crypton/pull/219)
* feat(gcm): a decrypt that hands back the tag instead of comparing it
  [#220](https://github.com/kazu-yamamoto/crypton/pull/220)
* feat(chachapoly): ChaCha20-Poly1305 a message at a time
  [#221](https://github.com/kazu-yamamoto/crypton/pull/221)
* docs(rsa): say in the haddock what the optional blinder covers
  [#222](https://github.com/kazu-yamamoto/crypton/pull/222)

## 2.1.0

* fix(cpu): stop reading Intel's SDBG bit as AMD's XOP
  [#204](https://github.com/kazu-yamamoto/crypton/pull/204)
* fix(bench): build the benchmark against the checked ChaCha20-Poly1305 key
  [#205](https://github.com/kazu-yamamoto/crypton/pull/205)
* ci: key the cache on the package version
  [#206](https://github.com/kazu-yamamoto/crypton/pull/206)
* ci: build the benchmarks
  [#207](https://github.com/kazu-yamamoto/crypton/pull/207)
* perf(gcm): a fused AES-GCM for x86-64
  [#208](https://github.com/kazu-yamamoto/crypton/pull/208)
* perf(gcm): a fused AES-GCM for AArch64
  [#209](https://github.com/kazu-yamamoto/crypton/pull/209)
* perf(gcm): build the counter in vector registers
  [#210](https://github.com/kazu-yamamoto/crypton/pull/210)
* perf(gcm): a spare lane for E(K,Y0), and a cheaper short block
  [#211](https://github.com/kazu-yamamoto/crypton/pull/211)
* perf(gcm): unroll the tail pass, and take its blocks from registers
  [#212](https://github.com/kazu-yamamoto/crypton/pull/212)
* perf(gcm): read a short block where it lies
  [#213](https://github.com/kazu-yamamoto/crypton/pull/213)
* perf(gcm): the length block and the counter, in registers
  [#214](https://github.com/kazu-yamamoto/crypton/pull/214)
* perf(gcm): let the one-call interface specialise
  [#215](https://github.com/kazu-yamamoto/crypton/pull/215)
* perf(gcm): decryption takes the fused path too
  [#216](https://github.com/kazu-yamamoto/crypton/pull/216)
* perf(gcm): GHASH takes the ciphertext from the output buffer
  [#217](https://github.com/kazu-yamamoto/crypton/pull/217)
* perf(p256): a signed five-bit window for the variable-point multiply
  [#218](https://github.com/kazu-yamamoto/crypton/pull/218)

## 2.0.1

* feat(hash): Skein with the digest size as a type parameter
  [#197](https://github.com/kazu-yamamoto/crypton/pull/197)
* fix(chachapoly1305): take a checked key, so that initializing cannot fail
  [#198](https://github.com/kazu-yamamoto/crypton/pull/198)
* feat(aes): Crypto.Cipher.AES.GCM, for many short messages under one key
  [#199](https://github.com/kazu-yamamoto/crypton/pull/199)
* build: say which platforms the fallback AES sources are for
  [#200](https://github.com/kazu-yamamoto/crypton/pull/200)
* feat(aes): encryptWithMask, for the QUIC header protection mask
  [#201](https://github.com/kazu-yamamoto/crypton/pull/201)
* fix(cpu): stop reading Intel's SDBG bit as AMD's XOP
  [#203](https://github.com/kazu-yamamoto/crypton/pull/203)

## 2.0.0

**Breaking changes.**  Input that used to be accepted is now refused: a value
at or above an RSA or Rabin modulus, a signature of the wrong length or out of
range, a digest too short for HOTP's dynamic truncation, a non-canonical
Ed25519 signature, a PKCS#7 block size outside 1..255, and block cipher input
that is not a whole number of blocks.  A refused KDF, Argon2 or bcrypt
parameter is reported as a `CryptoError` rather than raised as an `ErrorCall`,
and `CryptoError_ParameterInvalid` is appended to `CryptoError`;
`tryGetShared` is added beside `getShared`.  No exported function changed its
signature.

**Deprecated.**  The eighteen curves over a binary field in
`Crypto.ECC.Simple.Types`.  They are obsolete, they are the curves whose
cofactor is not 1, and they will go in a later major version.  Prefer a prime
curve, or X25519.

* Add GHC 9.14 to CI
  [#74](https://github.com/kazu-yamamoto/crypton/pull/74)
* fix(ed25519): reject non-canonical signatures
  [#81](https://github.com/kazu-yamamoto/crypton/pull/81)
* fix(hkdf): enforce RFC 5869 output limit
  [#82](https://github.com/kazu-yamamoto/crypton/pull/82)
* fix(p256): accept valid edge-case points
  [#83](https://github.com/kazu-yamamoto/crypton/pull/83)
* fix(ecc): accept zero-x P-256 shared secrets
  [#84](https://github.com/kazu-yamamoto/crypton/pull/84)
* fix(otp): require a digest long enough for dynamic truncation
  [#85](https://github.com/kazu-yamamoto/crypton/pull/85)
* fix(pkcs15): reject malformed PKCS#1 v1.5 signatures
  [#86](https://github.com/kazu-yamamoto/crypton/pull/86)
* fix(ecdh): validate the peer point before the exchange
  [#87](https://github.com/kazu-yamamoto/crypton/pull/87)
* fix(dsa): do not crash on non-invertible values
  [#88](https://github.com/kazu-yamamoto/crypton/pull/88)
* fix(dh): validate the peer public number
  [#89](https://github.com/kazu-yamamoto/crypton/pull/89)
* fix(argon2): report invalid options as CryptoFailed
  [#90](https://github.com/kazu-yamamoto/crypton/pull/90)
* fix(rsa): drop the early exits from PKCS#1 v1.5 and OAEP unpadding
  [#91](https://github.com/kazu-yamamoto/crypton/pull/91)
* fix(otp): compare TOTP candidates without an early exit
  [#92](https://github.com/kazu-yamamoto/crypton/pull/92)
* feat(dh): add getShared' reporting rejections as CryptoFailable
  [#93](https://github.com/kazu-yamamoto/crypton/pull/93)
* feat(aead): add aeadSimpleDecrypt' taking the tag length
  [#94](https://github.com/kazu-yamamoto/crypton/pull/94)
* test: move the suite to hspec, with hspec-discover
  [#95](https://github.com/kazu-yamamoto/crypton/pull/95)
* docs(bcrypt): say that only the first 72 bytes of a password count
  [#96](https://github.com/kazu-yamamoto/crypton/pull/96)
* feat(elgamal): fix and expose Crypto.PubKey.ElGamal
  [#97](https://github.com/kazu-yamamoto/crypton/pull/97)
* fix(padding): reject a PKCS7 block size outside 1..255
  [#98](https://github.com/kazu-yamamoto/crypton/pull/98)
* build(bench): move the benchmarks from gauge to tasty-bench
  [#99](https://github.com/kazu-yamamoto/crypton/pull/99)
* feat(aes): use the ARMv8 cryptographic extensions on AArch64
  [#100](https://github.com/kazu-yamamoto/crypton/pull/100)
* ci: stop throwing the cache away, and keep the build products in it
  [#101](https://github.com/kazu-yamamoto/crypton/pull/101)
* feat(aes): use PMULL for GHASH on AArch64
  [#102](https://github.com/kazu-yamamoto/crypton/pull/102)
* ci: cut the macOS queueing and supersede stale branch runs
  [#103](https://github.com/kazu-yamamoto/crypton/pull/103)
* feat(sha256): use the ARMv8 SHA-2 instructions on AArch64
  [#104](https://github.com/kazu-yamamoto/crypton/pull/104)
* perf(gcm): fold four GHASH blocks into one reduction
  [#105](https://github.com/kazu-yamamoto/crypton/pull/105)
* ci: build and test on aarch64 Linux
  [#106](https://github.com/kazu-yamamoto/crypton/pull/106)
* fix(cabal): build the AES-NI paths on Windows too
  [#107](https://github.com/kazu-yamamoto/crypton/pull/107)
* perf(aes): specialise by key size and interleave eight blocks on AArch64
  [#108](https://github.com/kazu-yamamoto/crypton/pull/108)
* perf(gcm): drive GCM from AArch64 rather than the generic loop
  [#109](https://github.com/kazu-yamamoto/crypton/pull/109)
* feat(sha512): use the ARMv8.2 SHA-512 instructions on AArch64
  [#110](https://github.com/kazu-yamamoto/crypton/pull/110)
* perf(chacha): do four blocks at a time with NEON on AArch64
  [#111](https://github.com/kazu-yamamoto/crypton/pull/111)
* perf(chacha): do four blocks at a time with SSE2 on x86-64
  [#112](https://github.com/kazu-yamamoto/crypton/pull/112)
* perf(chacha): take eight blocks with AVX2 where the machine has it
  [#113](https://github.com/kazu-yamamoto/crypton/pull/113)
* perf(gcm): give x86 its own decryption loop, and eight blocks either way
  [#114](https://github.com/kazu-yamamoto/crypton/pull/114)
* fix(padding): bound PKCS7 padding by the block, and check ZERO's size
  [#115](https://github.com/kazu-yamamoto/crypton/pull/115)
* ecc: say which curves branch on a secret scalar, and work in Jacobian coordinates
  [#116](https://github.com/kazu-yamamoto/crypton/pull/116)
* perf(poly1305): take four blocks at a time with AVX2 on x86-64
  [#117](https://github.com/kazu-yamamoto/crypton/pull/117)
* perf(xts): drive XTS eight blocks at a time, and dispatch its decryption
  [#118](https://github.com/kazu-yamamoto/crypton/pull/118)
* Report refused KDF parameters as CryptoError, and fix a PBKDF2 SIGBUS
  [#119](https://github.com/kazu-yamamoto/crypton/pull/119)
* Search the HOTP resynchronization window without early exits
  [#120](https://github.com/kazu-yamamoto/crypton/pull/120)
* Refuse an RSA representative that is not below the modulus
  [#121](https://github.com/kazu-yamamoto/crypton/pull/121)
* Give AFIS one answer for a parameter it cannot use
  [#122](https://github.com/kazu-yamamoto/crypton/pull/122)
* Say what ElGamal's signWith requires of k
  [#123](https://github.com/kazu-yamamoto/crypton/pull/123)
* Draw Miller-Rabin witnesses per number, not once per process
  [#124](https://github.com/kazu-yamamoto/crypton/pull/124)
* Refuse Rabin values that are not below the modulus, and keep the padding that was signed
  [#125](https://github.com/kazu-yamamoto/crypton/pull/125)
* Decode Rabin's OAEP without early exits
  [#126](https://github.com/kazu-yamamoto/crypton/pull/126)
* Make CMAC linear, and chain it through CBC
  [#127](https://github.com/kazu-yamamoto/crypton/pull/127)
* Put DES in C
  [#128](https://github.com/kazu-yamamoto/crypton/pull/128)
* Make the generic block cipher modes linear, and bulk where the blocks allow
  [#129](https://github.com/kazu-yamamoto/crypton/pull/129)
* Walk Twofish's blocks once, and carry them in words
  [#130](https://github.com/kazu-yamamoto/crypton/pull/130)
* Put Camellia in C
  [#131](https://github.com/kazu-yamamoto/crypton/pull/131)
* Route P-256 through the C implementation it already had
  [#132](https://github.com/kazu-yamamoto/crypton/pull/132)
* Fold instead of dividing in the generic curve arithmetic
  [#133](https://github.com/kazu-yamamoto/crypton/pull/133)
* Reduce the binary field by folding, and work a byte and a nibble at a time
  [#134](https://github.com/kazu-yamamoto/crypton/pull/134)
* Stop running a Fermat test Miller-Rabin subsumes
  [#135](https://github.com/kazu-yamamoto/crypton/pull/135)
* Make expSafe hide the exponent again
  [#136](https://github.com/kazu-yamamoto/crypton/pull/136)
* Square, and multiply, faster in expSafe
  [#137](https://github.com/kazu-yamamoto/crypton/pull/137)
* Invert the signing nonce without a side channel
  [#138](https://github.com/kazu-yamamoto/crypton/pull/138)
* Keep the P-256 signature out of Integer arithmetic
  [#139](https://github.com/kazu-yamamoto/crypton/pull/139)
* Add at every bit in the prime-curve multiplication, which laziness was skipping
  [#140](https://github.com/kazu-yamamoto/crypton/pull/140)
* Multiply points in C on curves over a prime field
  [#141](https://github.com/kazu-yamamoto/crypton/pull/141)
* A ladder for the curves over a binary field
  [#142](https://github.com/kazu-yamamoto/crypton/pull/142)
* Work RSA's qinv out without the extended Euclidean algorithm
  [#143](https://github.com/kazu-yamamoto/crypton/pull/143)
* Keep the RSA blinding factor out of the extended algorithm
  [#144](https://github.com/kazu-yamamoto/crypton/pull/144)
* Unroll the inner loop at four and two as well
  [#145](https://github.com/kazu-yamamoto/crypton/pull/145)
* Keep a table for each curve's base point
  [#146](https://github.com/kazu-yamamoto/crypton/pull/146)
* Start R squared at the top of the modulus, and why folding did not pay
  [#147](https://github.com/kazu-yamamoto/crypton/pull/147)
* Do the binary field arithmetic in C
  [#148](https://github.com/kazu-yamamoto/crypton/pull/148)
* Use the x86 carry-less multiply where the processor has it
  [#149](https://github.com/kazu-yamamoto/crypton/pull/149)
* Close the two testing gaps: one multiplication for both APIs, one place for each buffer's size
  [#150](https://github.com/kazu-yamamoto/crypton/pull/150)
* Ask aarch64 for its carry-less multiply as well
  [#151](https://github.com/kazu-yamamoto/crypton/pull/151)
* Work the RSA private exponent out without the extended algorithm
  [#152](https://github.com/kazu-yamamoto/crypton/pull/152)
* Fewer Miller-Rabin rounds for a candidate nobody chose
  [#153](https://github.com/kazu-yamamoto/crypton/pull/153)
* Blowfish, and the key setup bcrypt wraps it in, in C
  [#154](https://github.com/kazu-yamamoto/crypton/pull/154)
* perf(sha256): use the Intel SHA extensions on x86-64
  [#155](https://github.com/kazu-yamamoto/crypton/pull/155)
* perf(aes): AES-192 through the processor's AES instructions
  [#156](https://github.com/kazu-yamamoto/crypton/pull/156)
* perf(aes): build the AArch64 key schedule with AESE, not the S-box table
  [#157](https://github.com/kazu-yamamoto/crypton/pull/157)
* test(aes): run the XTS vectors, and OCB and CCM at 192 and 256 bits
  [#158](https://github.com/kazu-yamamoto/crypton/pull/158)
* perf(ocb): drive OCB through the ECB paths a group at a time
  [#159](https://github.com/kazu-yamamoto/crypton/pull/159)
* perf(gcm): take the GHASH of the group before, alongside this group's rounds
  [#160](https://github.com/kazu-yamamoto/crypton/pull/160)
* perf(sha): compute the message schedule in vector registers on x86
  [#161](https://github.com/kazu-yamamoto/crypton/pull/161)
* perf(chacha): combine as the keystream comes out of the registers
  [#162](https://github.com/kazu-yamamoto/crypton/pull/162)
* perf(poly1305): shorten the carry chain and stop spilling the loop
  [#163](https://github.com/kazu-yamamoto/crypton/pull/163)
* docs(sidechannel): say what the prime-field modules keep from the clock
  [#164](https://github.com/kazu-yamamoto/crypton/pull/164)
* perf(sha1): use the Intel SHA extensions on x86-64
  [#165](https://github.com/kazu-yamamoto/crypton/pull/165)
* refactor(aes): drop the keystream generator nobody can call
  [#166](https://github.com/kazu-yamamoto/crypton/pull/166)
* build: compile the C at -O3
  [#167](https://github.com/kazu-yamamoto/crypton/pull/167)
* perf(modes): stop the generic cipher modes allocating per byte
  [#168](https://github.com/kazu-yamamoto/crypton/pull/168)
* perf(poly1305): four blocks at a time with NEON
  [#169](https://github.com/kazu-yamamoto/crypton/pull/169)
* perf(sha1): use the ARMv8 SHA-1 instructions
  [#170](https://github.com/kazu-yamamoto/crypton/pull/170)
* perf(sha3): use the ARMv8.2 SHA-3 instructions
  [#171](https://github.com/kazu-yamamoto/crypton/pull/171)
* perf(gcm): the CRYPTOGAMS stitched AES-GCM on x86-64
  [#172](https://github.com/kazu-yamamoto/crypton/pull/172)
* perf(chacha): the CRYPTOGAMS ChaCha20 on AArch64
  [#173](https://github.com/kazu-yamamoto/crypton/pull/173)
* perf(poly1305): the CRYPTOGAMS Poly1305 on AArch64
  [#174](https://github.com/kazu-yamamoto/crypton/pull/174)
* perf(sha256): the CRYPTOGAMS SHA-256 on AArch64
  [#175](https://github.com/kazu-yamamoto/crypton/pull/175)
* perf(poly1305): the CRYPTOGAMS Poly1305 on x86-64 too
  [#176](https://github.com/kazu-yamamoto/crypton/pull/176)
* perf(chacha): the CRYPTOGAMS ChaCha20 on x86-64 too
  [#177](https://github.com/kazu-yamamoto/crypton/pull/177)
* perf(sha2): the CRYPTOGAMS SHA-256 and SHA-512 on x86-64
  [#178](https://github.com/kazu-yamamoto/crypton/pull/178)
* perf(sha1): hand the SHA-1 block loop a run of blocks, not one at a time
  [#179](https://github.com/kazu-yamamoto/crypton/pull/179)
* perf(xts): double the tweak in the integer registers
  [#180](https://github.com/kazu-yamamoto/crypton/pull/180)
* perf(sha3): take the CRYPTOGAMS Keccak for AArch64
  [#181](https://github.com/kazu-yamamoto/crypton/pull/181)
* perf(sha1): take the CRYPTOGAMS SHA-1 for AArch64
  [#182](https://github.com/kazu-yamamoto/crypton/pull/182)
* docs: put the performance tables in the README
  [#183](https://github.com/kazu-yamamoto/crypton/pull/183)
* perf(sha3): take the CRYPTOGAMS Keccak for x86-64 as well
  [#184](https://github.com/kazu-yamamoto/crypton/pull/184)
* docs: rebuild the performance tables
  [#185](https://github.com/kazu-yamamoto/crypton/pull/185)
* perf(ecc): stop sharing the doublings in the double multiplication
  [#186](https://github.com/kazu-yamamoto/crypton/pull/186)
* perf(number): count bytes from the bit count, not from base 256
  [#187](https://github.com/kazu-yamamoto/crypton/pull/187)
* perf(p256): inline the field arithmetic on AArch64
  [#188](https://github.com/kazu-yamamoto/crypton/pull/188)
* fix(api): name the reporting variants try..., not with an apostrophe
  [#189](https://github.com/kazu-yamamoto/crypton/pull/189)
* fix(ecc): require a public point to be in the prime-order subgroup
  [#190](https://github.com/kazu-yamamoto/crypton/pull/190)
* fix(pubkey): stop printing private keys, and add Crypto.Debug
  [#191](https://github.com/kazu-yamamoto/crypton/pull/191)
* fix(poly1305): take a checked key, so that initializing cannot fail
  [#192](https://github.com/kazu-yamamoto/crypton/pull/192)
* fix(bcrypt): refuse a cost bcrypt does not have rather than substituting one
  [#194](https://github.com/kazu-yamamoto/crypton/pull/194)
* chore: build without a warning
  [#195](https://github.com/kazu-yamamoto/crypton/pull/195)
* docs: build the documentation without a warning
  [#196](https://github.com/kazu-yamamoto/crypton/pull/196)

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

