# Vendored assembly

## What is here

`aesni-gcm-x86_64.pl` is the AES-NI/PCLMULQDQ stitched AES-GCM module from
[CRYPTOGAMS](https://github.com/dot-asm/cryptogams), by Andy Polyakov.  It is
checked in unmodified, together with `x86_64-xlate.pl`, the translator it
needs.  `generate.sh` runs the one over the other to produce the three `.S`
files, which are what crypton actually compiles; the names of the two entry
points are changed on the way through, and the ELF output is given the note
that says the code does not want an executable stack.

Keeping the generated files in the tree means building crypton needs no perl.

## Why

Counter-mode AES and GHASH do not compete for the same execution ports, so a
loop that interleaves them at instruction granularity runs both in the time
one of them would take.  Written in C with intrinsics the interleaving does
not survive the compiler: given the AES rounds and the multiplies of a group
of blocks, GCC and Clang schedule all the multiplies after all the rounds,
which is the sum of the two rather than the maximum.  This module is what
OpenSSL uses to get its AES-GCM numbers, and reaching them was the point.

## Interface

    size_t crypton_gcm_asm_encrypt(const void *in, void *out, size_t len,
                                   const void *key, unsigned char ivec[16],
                                   void *Xi);
    size_t crypton_gcm_asm_decrypt(... the same ...);

Both return the number of bytes processed, which is a multiple of 96 and may
be zero: encryption wants at least 288 bytes to start, decryption at least 96.
Whatever is left over is the caller's to finish.

`key` is the AES key schedule in the layout the OpenSSL assembly expects --
the round keys, and at offset 240 one less than the number of rounds, which
is what OpenSSL's own AES-NI key setup puts there -- and `Xi` points at
the running GHASH state, with the table of powers of H, in the layout
`gcm_init_avx` leaves behind, 32 bytes past it.  `cbits/aes/gcm_x86_asm.c`
builds both, and the multiplication that fills that table is written there in
C rather than taken from `ghash-x86_64.pl`: it runs once per message, so it is
not worth a second vendored file, and the one in OpenSSL is under a licence
this package does not use.

The code needs AES-NI, PCLMULQDQ, AVX and MOVBE, which `crypton_x86_simd_features()`
is asked about before any of it is called.

## Licence

`LICENSE.cryptogams` is the licence the CRYPTOGAMS files are distributed
under.  It is the three-clause BSD licence, with the GNU General Public
Licence offered as an alternative; crypton takes the former, which is the
licence of the rest of this package.
