#!/bin/sh
#
# Regenerate the assembly checked in beside this script.
#
# The .pl files come from the CRYPTOGAMS distribution, unmodified:
#
#   https://github.com/dot-asm/cryptogams
#     x86_64/aesni-gcm-x86_64.pl	x86_64/chacha-x86_64.pl
#     x86_64/poly1305-x86_64.pl	x86_64/sha512-x86_64.pl
#     x86_64/keccak1600-x86_64.pl	x86_64/x86_64-xlate.pl
#     arm/chacha-armv8.pl		arm/poly1305-armv8.pl
#     arm/sha1-armv8.pl		arm/sha512-armv8.pl
#     arm/keccak1600-armv8.pl	arm/arm-xlate.pl
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

# The x86-64 generators choose what to emit from the version of the
# assembler they are told about, so they are told one, rather than left to
# ask whatever compiler happens to be here: the checked-in files should not
# depend on the host that produced them.  2.24 predates AVX-512, which is
# the point -- the Poly1305 module has paths for it, and this does not take
# them, no machine here being able to run them, and a path nothing has
# executed not being worth the few per cent it might be worth.  It leaves
# both modules with everything through AVX2.
cat > tmp-cc <<'SHIM'
#!/bin/sh
case "$*" in
*-Wa,-v*) echo "GNU assembler version 2.24" ;;
esac
exit 0
SHIM
chmod +x tmp-cc
CC=./tmp-cc
export CC

for flavour in elf macosx mingw64; do
	perl aesni-gcm-x86_64.pl $flavour tmp-$flavour.S
	sed -e 's/aesni_gcm_/crypton_gcm_asm_/g' \
	    -e 's/aesni_ctr32_/crypton_gcm_asm_ctr32_/g' \
	    tmp-$flavour.S > aesni-gcm-x86_64-$flavour.S

	perl poly1305-x86_64.pl $flavour tmp-$flavour.S
	sed -e 's/poly1305_/crypton_poly1305_asm_/g' \
	    -e 's/xor128_/crypton_xor128_/g' \
	    -e 's/OPENSSL_ia32cap_P/crypton_ia32cap_P/g' \
	    tmp-$flavour.S > poly1305-x86_64-$flavour.S

	perl chacha-x86_64.pl $flavour tmp-$flavour.S
	sed -e 's/ChaCha20_/crypton_chacha20_asm_/g' \
	    -e 's/OPENSSL_ia32cap_P/crypton_ia32cap_P/g' \
	    tmp-$flavour.S > chacha-x86_64-$flavour.S

	# as on AArch64, this generator emits SHA-512 or SHA-256 according
	# to the name it is given, and both are wanted here
	perl sha512-x86_64.pl $flavour tmp-$flavour.S
	sed -e 's/sha256_block_/crypton_sha256_asm_block_/g' \
	    -e 's/OPENSSL_ia32cap_P/crypton_ia32cap_P/g' \
	    tmp-$flavour.S > sha256-x86_64-$flavour.S

	perl keccak1600-x86_64.pl $flavour tmp-k-$flavour.S
	sed -e 's/SHA3_absorb/crypton_keccak_asm_absorb/g' \
	    -e 's/SHA3_squeeze/crypton_keccak_asm_squeeze/g' \
	    -e 's/KeccakF1600/crypton_keccak_asm_f1600/g' \
	    tmp-k-$flavour.S > keccak1600-x86_64-$flavour.S

	perl sha512-x86_64.pl $flavour tmp-512-$flavour.S
	sed -e 's/sha512_block_/crypton_sha512_asm_block_/g' \
	    -e 's/OPENSSL_ia32cap_P/crypton_ia32cap_P/g' \
	    tmp-512-$flavour.S > sha512-x86_64-$flavour.S
	rm -f tmp-$flavour.S tmp-512-$flavour.S tmp-k-$flavour.S
done

for f in aesni-gcm-x86_64-elf.S poly1305-x86_64-elf.S chacha-x86_64-elf.S \
	 sha256-x86_64-elf.S sha512-x86_64-elf.S keccak1600-x86_64-elf.S; do
	cat >> $f <<-NOTE

	.section	.note.GNU-stack,"",@progbits
	NOTE
done

unset CC
rm -f tmp-cc

for flavour in linux64 ios64; do
	perl chacha-armv8.pl $flavour tmp-$flavour.S
	sed -e 's/ChaCha20_/crypton_chacha20_asm_/g' \
	    -e 's/OPENSSL_armcap_P/crypton_armcap_P/g' \
	    tmp-$flavour.S > chacha-armv8-$flavour.S

	perl poly1305-armv8.pl $flavour tmp-$flavour.S
	sed -e 's/poly1305_/crypton_poly1305_asm_/g' \
	    -e 's/OPENSSL_armcap_P/crypton_armcap_P/g' \
	    tmp-$flavour.S > poly1305-armv8-$flavour.S

	# the same generator emits SHA-512 or SHA-256 according to the name
	# it is given, and only the SHA-256 one is wanted here
	perl sha512-armv8.pl $flavour tmp-$flavour.S
	sed -e 's/sha256_block_/crypton_sha256_asm_block_/g' \
	    -e 's/OPENSSL_armcap_P/crypton_armcap_P/g' \
	    tmp-$flavour.S > sha256-armv8-$flavour.S

	perl sha1-armv8.pl $flavour tmp-$flavour.S
	sed -e 's/sha1_block_/crypton_sha1_asm_block_/g' \
	    -e 's/OPENSSL_armcap_P/crypton_armcap_P/g' \
	    tmp-$flavour.S > sha1-armv8-$flavour.S

	perl keccak1600-armv8.pl $flavour tmp-$flavour.S
	sed -e 's/SHA3_absorb/crypton_keccak_asm_absorb/g' \
	    -e 's/SHA3_squeeze/crypton_keccak_asm_squeeze/g' \
	    tmp-$flavour.S > keccak1600-armv8-$flavour.S
	rm -f tmp-$flavour.S
done

cat >> chacha-armv8-linux64.S <<'NOTE'

.section	.note.GNU-stack,"",%progbits
NOTE

cat >> poly1305-armv8-linux64.S <<'NOTE'

.section	.note.GNU-stack,"",%progbits
NOTE

for f in sha1-armv8-linux64.S sha256-armv8-linux64.S \
	 keccak1600-armv8-linux64.S; do
	cat >> $f <<-NOTE

	.section	.note.GNU-stack,"",%progbits
	NOTE
done
