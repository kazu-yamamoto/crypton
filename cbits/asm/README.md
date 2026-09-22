# Vendored assembly

## What is here

Two modules from [CRYPTOGAMS](https://github.com/dot-asm/cryptogams), by Andy
Polyakov, checked in unmodified together with the translators they need:

| generator | what it is |
| --- | --- |
| `aesni-gcm-x86_64.pl` | AES-NI/PCLMULQDQ stitched AES-GCM for x86-64 |
| `chacha-x86_64.pl` | ChaCha20 for x86-64 |
| `poly1305-x86_64.pl` | Poly1305 for x86-64 |
| `sha512-x86_64.pl` | SHA-256 and SHA-512 for x86-64 (one generator, two outputs, as on AArch64) |
| `chacha-armv8.pl` | ChaCha20 for AArch64 |
| `poly1305-armv8.pl` | Poly1305 for AArch64 |
| `sha1-armv8.pl` | SHA-1 for AArch64 |
| `sha512-armv8.pl` | SHA-256 for AArch64 (the generator emits SHA-512 or SHA-256 according to the name it is given, and only the latter is wanted) |
| `keccak1600-armv8.pl` | Keccak for AArch64 |

`x86_64-xlate.pl`, `arm-xlate.pl` and `arm_arch.h` are the machinery those
modules use.  `generate.sh` runs the generators to produce the `.S` files, which are
what crypton actually compiles -- one per object format, since the calling
convention and the assembler syntax differ.  The names of the entry points are
changed on the way through, and the ELF output is given the note that says the
code does not want an executable stack.

Keeping the generated files in the tree means building crypton needs no perl.

## Why

Both do something the compiler will not do with intrinsics.

**AES-GCM.** Counter-mode AES and GHASH do not compete for the same execution
ports, so a loop that interleaves them at instruction granularity runs both in
the time one of them would take.  Written in C the interleaving does not
survive: given the AES rounds and the multiplies of a group of blocks, GCC and
Clang schedule all the multiplies after all the rounds, which is the sum of the
two rather than the maximum.

**ChaCha20.** On AArch64 the vector registers hold four ChaCha states and there
is no room for a fifth, so further parallelism has to come from the integer
side: that module runs a fifth block through the general registers alongside
four in the vector ones, and above 512 bytes two alongside six.  Which register
holds which word is the whole trick, and that is not something C says.  The
x86-64 module is worth taking for a different reason -- it has vector code for
lengths the C here still takes a block at a time, so a 256-byte message more
than doubles -- and is a few per cent ahead in bulk besides.

**Poly1305.** One multiplication modulo 2^130 - 5 depends on the one before it,
so what there is to win is in how the multiplies and the carries are laid
against each other, and in keeping the accumulator in whichever base costs
less: these modules work in base 2^64 while the message is short and switch to
base 2^26 for the vector loop, which is a decision no compiler will make for
you.  On AArch64 that is twice the speed of the C here at 16 KiB and three and
a half times at 64 bytes; on x86-64, a quarter faster at 16 KiB and nearly
three times at 64.

The x86-64 module also has paths for AVX-512, which are **not** taken.  What
the generator emits is chosen from the version of the assembler it is told
about, and `generate.sh` tells it one that predates AVX-512: no machine here
can run those paths, an assembler old enough to be in use cannot always
assemble them, and a path nothing has executed is not worth the few per cent
it might be worth.

**SHA-1, SHA-256, SHA-512 and Keccak.** On AArch64 the instructions are the same ones the
intrinsics here already use.  What the module does is schedule them across a
whole run of blocks instead of one at a time, and keep the message schedule of
the next block moving while the rounds of this one are still going, which a
per-block C function cannot do at all.  A quarter faster, and it needs no
alignment and no copy since it reads the message as bytes.  The x86-64 module
is the same idea with more paths to choose from -- the SHA extensions, AVX2,
AVX, SSSE3 -- and is about a fifth faster than the C on a machine with AVX2
and no SHA extensions.  The AArch64 SHA-1 and Keccak modules are the same
story again -- the instructions are the ones the intrinsics here use, and what
the modules add is the arrangement: the schedule of the next four SHA-1 rounds
against the rounds of this one, and one Keccak round against the next.

## Interfaces

    size_t crypton_gcm_asm_encrypt(const void *in, void *out, size_t len,
                                   const void *key, unsigned char ivec[16],
                                   void *Xi);
    size_t crypton_gcm_asm_decrypt(... the same ...);

Both return the number of bytes processed, which is a multiple of 96 and may be
zero: encryption wants at least 288 bytes to start, decryption at least 96.
Whatever is left over is the caller's to finish.

`key` is the AES key schedule in the layout the OpenSSL assembly expects -- the
round keys, and at offset 240 one less than the number of rounds, which is what
OpenSSL's own AES-NI key setup puts there -- and `Xi` points at the running
GHASH state, with the table of powers of H, in the layout `gcm_init_avx` leaves
behind, 32 bytes past it.  `cbits/aes/gcm_x86_asm.c` builds both, and the
multiplication that fills that table is written there in C rather than taken
from `ghash-x86_64.pl`: it runs once per message, so it is not worth a second
vendored file, and the one in OpenSSL is under a licence this package does not
use.

The code needs AES-NI, PCLMULQDQ, AVX and MOVBE, which
`crypton_x86_simd_features()` is asked about before any of it is called.

    void crypton_chacha20_ctr32(unsigned char *out, const unsigned char *in,
                                size_t len, const unsigned int key[8],
                                const unsigned int counter[4]);

Twenty rounds, the constants that go with a 256-bit key, and a 32-bit counter
which it does not write back: the caller advances it by the number of blocks.
Any length is accepted; the AArch64 module's vector path starts at 192 bytes,
the x86-64 one's rather lower.  They ask `crypton_armcap_P` and
`crypton_ia32cap_P` respectively what the processor has, and
`cbits/crypton_chacha.c` calls them only for the states they fit -- twenty
rounds, a 256-bit key, and only as many blocks as the 32-bit counter has room
for.

    int  crypton_poly1305_asm_init(void *ctx, const unsigned char key[16],
                                   void *func[2]);
    void crypton_poly1305_asm_blocks(void *ctx, const unsigned char *inp,
                                     size_t len, unsigned int padbit);
    void crypton_poly1305_asm_emit(void *ctx, unsigned char mac[16],
                                   const unsigned int nonce[4]);

`ctx` is 192 bytes of state the module keeps for itself -- its accumulator, the
clamped key and the powers of it -- and `key` is the first half of the Poly1305
key, the second half being handed to `emit` as `nonce`.  `padbit` is the bit
above each block, set for the blocks of the message and clear for the padded
last one.  `len` is a whole number of blocks.

Initialisation hands back through `func` the pair of functions its own dispatch
would use, the vector entry point not being exported, and
`cbits/crypton_poly1305.c` calls those.  It reads `crypton_armcap_P` to choose
between them; `cbits/crypton_cpu.c` defines that.

The x86-64 Poly1305 module presents the same three functions, and reads
`crypton_ia32cap_P` -- cpuid's own words, in the order OpenSSL keeps them --
where the AArch64 one reads `crypton_armcap_P`.  `cbits/crypton_cpu.c` fills
it, with the bits for anything the operating system will not preserve cleared,
and the AVX-512 ones cleared whatever the processor says.

    void crypton_sha1_asm_block_data_order(unsigned int state[5],
                                           const void *data, size_t blocks);
    void crypton_sha256_asm_block_data_order(unsigned int state[8],
                                             const void *data, size_t blocks);
    size_t crypton_keccak_asm_absorb_cext(unsigned long long state[25],
                                          const void *inp, size_t len,
                                          size_t bsz);

The state is the words of the digest in host order and `blocks` whole blocks of
64 bytes.  Each entry point picks between the SHA-2 instructions, NEON and
plain integer code from `crypton_armcap_P`, whose SHA-1 and SHA-256 bits
`cbits/crypton_sha1.c` and `cbits/crypton_sha256.c` set once they have asked
the operating system whether the processor has them -- they are optional in
ARMv8.0.

Keccak's absorb takes the state as its twenty-five lanes, `bsz` as the rate in
bytes, and answers with what was left over; the `_cext` entry point is the one
that uses the SHA-3 instructions, and `cbits/crypton_sha3.c` calls it only
where its own runtime check has found them.

## Licence

`LICENSE.cryptogams` is the licence the CRYPTOGAMS files are distributed under.
It is the three-clause BSD licence, with the GNU General Public Licence offered
as an alternative; crypton takes the former, which is the licence of the rest
of this package.
