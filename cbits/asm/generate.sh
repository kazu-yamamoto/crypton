#!/bin/sh
#
# Regenerate the assembly checked in beside this script.
#
# The .pl files come from the CRYPTOGAMS distribution, unmodified:
#
#   https://github.com/dot-asm/cryptogams
#     x86_64/aesni-gcm-x86_64.pl
#     x86_64/x86_64-xlate.pl
#
# They are the generator, not the product: each one emits assembly for a
# given "flavour", which is the calling convention and object format
# together.  The output is checked in so that building crypton needs no
# perl.
#
# Two things are done to the output here.  The entry points are renamed:
# a program that links both crypton and OpenSSL would otherwise have two
# definitions of aesni_gcm_encrypt, and the linker is entitled to refuse
# that.  And the ELF output is given the note that says the code does not
# want an executable stack, which the generator leaves to the caller.
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
