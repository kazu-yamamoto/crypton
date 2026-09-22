#!/bin/sh
#
# Regenerate the assembly checked in beside this script.
#
# The .pl files come from the CRYPTOGAMS distribution, unmodified:
#
#   https://github.com/dot-asm/cryptogams
#     x86_64/aesni-gcm-x86_64.pl	x86_64/x86_64-xlate.pl
#     arm/chacha-armv8.pl		arm/arm-xlate.pl
#     arm/arm_arch.h
#
# The .pl files are the generator, not the product: each one emits
# assembly for a given "flavour", which is the calling convention and the
# object format together.  The output is checked in so that building
# crypton needs no perl.
#
# Two things are done to the output here.  The entry points are renamed:
# a program that links both crypton and OpenSSL would otherwise have two
# definitions of, say, aesni_gcm_encrypt, and the linker is entitled to
# refuse that.  The same goes for OPENSSL_armcap_P, which the ChaCha
# module reads to find out whether the processor has NEON, and which
# crypton defines for itself in cbits/crypton_chacha.c.  And the ELF
# output of the x86-64 module is given the note that says the code does
# not want an executable stack, which the generator leaves to the caller.
#
# Run this on a GNU/Linux host.  The mingw64 flavour asks the compiler
# what __USER_LABEL_PREFIX__ is for its target, and a compiler for a
# platform that decorates symbols -- Apple's, for one -- answers for
# itself rather than for Windows, which would leave every entry point in
# that file with a leading underscore that nothing looks for.
#
# Usage: cd cbits/asm && ./generate.sh

set -e

for flavour in elf macosx mingw64; do
	perl aesni-gcm-x86_64.pl $flavour tmp-$flavour.S
	sed -e 's/aesni_gcm_/crypton_gcm_asm_/g' \
	    -e 's/aesni_ctr32_/crypton_gcm_asm_ctr32_/g' \
	    tmp-$flavour.S > aesni-gcm-x86_64-$flavour.S
	rm -f tmp-$flavour.S
done

cat >> aesni-gcm-x86_64-elf.S <<'NOTE'

.section	.note.GNU-stack,"",@progbits
NOTE

for flavour in linux64 ios64; do
	perl chacha-armv8.pl $flavour tmp-$flavour.S
	sed -e 's/ChaCha20_ctr32/crypton_chacha20_ctr32/g' \
	    -e 's/ChaCha20_512_neon/crypton_chacha20_512_neon/g' \
	    -e 's/ChaCha20_neon/crypton_chacha20_neon/g' \
	    -e 's/OPENSSL_armcap_P/crypton_armcap_P/g' \
	    tmp-$flavour.S > chacha-armv8-$flavour.S
	rm -f tmp-$flavour.S
done

cat >> chacha-armv8-linux64.S <<'NOTE'

.section	.note.GNU-stack,"",%progbits
NOTE
