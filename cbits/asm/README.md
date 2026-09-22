# Vendored assembly

## What is here

Two modules from [CRYPTOGAMS](https://github.com/dot-asm/cryptogams), by Andy
Polyakov, checked in unmodified together with the translators they need:

| generator | what it is |
| --- | --- |
| `aesni-gcm-x86_64.pl` | AES-NI/PCLMULQDQ stitched AES-GCM for x86-64 |
| `chacha-armv8.pl` | ChaCha20 for AArch64 |
| `poly1305-armv8.pl` | Poly1305 for AArch64 |

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

**ChaCha20.** The vector registers hold four ChaCha states and there is no room
for a fifth, so further parallelism has to come from the integer side.  This
module runs a fifth block through the general registers alongside four in the
vector ones, and above 512 bytes two alongside six.  Which register holds which
word is the whole trick, and that is not something C says.

**Poly1305.** One multiplication modulo 2^130 - 5 depends on the one before it,
so what there is to win is in how the multiplies and the carries are laid
against each other, and in keeping the accumulator in whichever base costs
less: this module works in base 2^64 while the message is short and switches to
base 2^26 for the four-way vector loop, which is a decision no compiler will
make for you.  It is twice the speed of the C here at 16 KiB and three and a
half times at 64 bytes.

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
Any length is accepted, but the vector path starts at 192 bytes.  It asks
`crypton_armcap_P` whether the processor has NEON, which on AArch64 it always
does, and `cbits/crypton_chacha.c` defines that and calls this only for the
states it fits.

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

## Licence

`LICENSE.cryptogams` is the licence the CRYPTOGAMS files are distributed under.
It is the three-clause BSD licence, with the GNU General Public Licence offered
as an alternative; crypton takes the former, which is the licence of the rest
of this package.
