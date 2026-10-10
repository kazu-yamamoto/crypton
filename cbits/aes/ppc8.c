/*
 * AES and GHASH using the PowerISA 2.07 vector instructions, first
 * implemented by POWER8.
 *
 * The instructions themselves come from CRYPTOGAMS, assembled from
 * cbits/asm/aesp8-ppc-*.S and cbits/asm/ghashp8-ppc-*.S; what is here is the
 * glue that puts them behind crypton's branch table.  Nothing in this file
 * branches or indexes on a key or on data.
 *
 * == Where the key schedule lives
 *
 * The assembly takes OpenSSL's AES_KEY -- sixty round-key words and a round
 * count, 244 bytes -- and its set_decrypt_key writes a second, complete one
 * rather than sharing ends with the first the way cbits/aes/armv8.c does.
 * Two of those are 488 bytes and aes_key.data is 448, so both do not fit.
 *
 * So the forward schedule is kept there, with the key the caller gave after
 * it, and the inverse is built on the stack by the operations that need it.
 * Those are all bulk -- ECB, CBC and XTS decryption -- so it is one key
 * schedule per call rather than per block.  Single-block decryption pays for
 * one too, and is reached by nothing that runs in a loop: OCB and CCM drive
 * the block function in the encrypting direction.
 */

#include <stdint.h>
#include <string.h>
#include <crypton_aes.h>
#include <crypton_bitfn.h>
#include "aes/block128.h"
#include "aes/gf.h"
#include "aes/ppc8.h"

/* OpenSSL's AES_KEY, which is what the assembly was written against */
typedef struct {
	unsigned int rd_key[60];
	int rounds;
} p8_key;

int  crypton_aes_p8_set_encrypt_key(const unsigned char *, int, p8_key *);
int  crypton_aes_p8_set_decrypt_key(const unsigned char *, int, p8_key *);
void crypton_aes_p8_encrypt(const unsigned char *, unsigned char *, const p8_key *);
void crypton_aes_p8_decrypt(const unsigned char *, unsigned char *, const p8_key *);
void crypton_aes_p8_cbc_encrypt(const unsigned char *, unsigned char *, size_t,
                                const p8_key *, unsigned char *, int);
void crypton_aes_p8_ctr32_encrypt_blocks(const unsigned char *, unsigned char *,
                                         size_t, const p8_key *,
                                         const unsigned char *);
void crypton_aes_p8_xts_encrypt(const unsigned char *, unsigned char *, size_t,
                                const p8_key *, const p8_key *,
                                const unsigned char *);
void crypton_aes_p8_xts_decrypt(const unsigned char *, unsigned char *, size_t,
                                const p8_key *, const p8_key *,
                                const unsigned char *);
/* void * rather than uint64_t *: the assembly loads these with lvx_u and so
 * does not want the alignment a uint64_t pointer would promise, and
 * block128 is packed. */
void crypton_gcm_init_p8(void *Htable, const void *H);
void crypton_gcm_gmult_p8(void *Xi, const void *Htable);
void crypton_gcm_ghash_p8(void *Xi, const void *Htable,
                          const unsigned char *inp, size_t len);

#define FORWARD(k)  ((p8_key *) (void *) (k)->data)
#define USERKEY(k)  ((uint8_t *) (k)->data + sizeof(p8_key))
#define USERLEN(k)  (*((uint8_t *) (k)->data + sizeof(p8_key) + 32))

static void inverse(p8_key *dk, aes_key *key)
{
	crypton_aes_p8_set_decrypt_key(USERKEY(key), USERLEN(key) * 8, dk);
}

void crypton_aes_ppc8_init(aes_key *key, uint8_t *origkey, uint8_t size)
{
	if (size != 16 && size != 24 && size != 32)
		return;
	crypton_aes_p8_set_encrypt_key(origkey, size * 8, FORWARD(key));
	memcpy(USERKEY(key), origkey, size);
	USERLEN(key) = size;
}

void crypton_aes_ppc8_encrypt_block(aes_block *output, aes_key *key, aes_block *input)
{
	crypton_aes_p8_encrypt((const unsigned char *) input,
	                       (unsigned char *) output, FORWARD(key));
}

void crypton_aes_ppc8_decrypt_block(aes_block *output, aes_key *key, aes_block *input)
{
	p8_key dk;

	inverse(&dk, key);
	crypton_aes_p8_decrypt((const unsigned char *) input,
	                       (unsigned char *) output, &dk);
	memset(&dk, 0, sizeof dk);
}

/* The assembly has no ECB entry: it is the block function in a loop, which
 * is what the generic implementation does too. */
void crypton_aes_ppc8_encrypt_ecb(aes_block *output, aes_key *key, aes_block *input,
                                  uint32_t nb_blocks)
{
	for (; nb_blocks-- > 0; input++, output++)
		crypton_aes_p8_encrypt((const unsigned char *) input,
		                       (unsigned char *) output, FORWARD(key));
}

void crypton_aes_ppc8_decrypt_ecb(aes_block *output, aes_key *key, aes_block *input,
                                  uint32_t nb_blocks)
{
	p8_key dk;

	inverse(&dk, key);
	for (; nb_blocks-- > 0; input++, output++)
		crypton_aes_p8_decrypt((const unsigned char *) input,
		                       (unsigned char *) output, &dk);
	memset(&dk, 0, sizeof dk);
}

void crypton_aes_ppc8_encrypt_cbc(aes_block *output, aes_key *key, aes_block *iv,
                                  aes_block *input, uint32_t nb_blocks)
{
	uint8_t ivbuf[16];

	/* a copy, because the assembly writes the last block back through this
	 * pointer and the callers of this entry do not expect their IV touched */
	memcpy(ivbuf, iv, 16);
	crypton_aes_p8_cbc_encrypt((const unsigned char *) input,
	                           (unsigned char *) output,
	                           (size_t) nb_blocks * 16, FORWARD(key), ivbuf, 1);
}

void crypton_aes_ppc8_decrypt_cbc(aes_block *output, aes_key *key, aes_block *iv,
                                  aes_block *input, uint32_t nb_blocks)
{
	p8_key dk;
	uint8_t ivbuf[16];

	inverse(&dk, key);
	memcpy(ivbuf, iv, 16);
	crypton_aes_p8_cbc_encrypt((const unsigned char *) input,
	                           (unsigned char *) output,
	                           (size_t) nb_blocks * 16, &dk, ivbuf, 0);
	memset(&dk, 0, sizeof dk);
}

/*
 * CTR, which is where the two counters have to be reconciled.
 *
 * crypton counts with block128_inc_be, over the whole 128 bits; the assembly
 * counts over the low 32 only.  They agree until that word wraps, so the
 * work is handed over in runs that stop there, and the carry into the upper
 * bits is done here.  This is the same arrangement OpenSSL makes for the
 * same reason.
 */
void crypton_aes_ppc8_encrypt_ctr(uint8_t *output, aes_key *key, aes_block *iv,
                                  uint8_t *input, uint32_t len)
{
	block128 ctr;
	uint32_t nb_blocks = len / 16;
	uint32_t tail = len % 16;
	uint32_t i;

	block128_copy(&ctr, iv);

	while (nb_blocks > 0) {
		uint64_t low = (uint64_t) be32_to_cpu(ctr.d[3]);
		uint64_t room = 0x100000000ULL - low;   /* blocks before it wraps */
		uint32_t n;

		/* room is 2^32 when the word is at zero, which does not fit the
		 * type the comparison would narrow it to -- and a zero n here
		 * would not advance */
		if (room > (uint64_t) nb_blocks)
			room = (uint64_t) nb_blocks;
		n = (uint32_t) room;

		crypton_aes_p8_ctr32_encrypt_blocks((const unsigned char *) input,
		                                    (unsigned char *) output,
		                                    n, FORWARD(key),
		                                    (const unsigned char *) &ctr);
		/* the assembly does not write the counter back */
		for (i = 0; i < n; i++)
			block128_inc_be(&ctr);

		output += (size_t) n * 16;
		input += (size_t) n * 16;
		nb_blocks -= n;
	}

	if (tail != 0) {
		block128 ks;

		crypton_aes_p8_encrypt((const unsigned char *) &ctr,
		                       (unsigned char *) &ks, FORWARD(key));
		for (i = 0; i < tail; i++)
			output[i] = ks.b[i] ^ input[i];
	}
}

/*
 * XTS.  The assembly encrypts the tweak with its second key, unless that key
 * is NULL, in which case it takes the tweak already encrypted -- which is
 * what this needs, because crypton's entry also carries a starting point and
 * the tweak has to be advanced that many doublings before any block is
 * enciphered.
 */
static void xts_tweak(block128 *tweak, aes_key *k2, aes_block *dataunit,
                      uint32_t spoint)
{
	block128_copy(tweak, dataunit);
	crypton_aes_p8_encrypt((const unsigned char *) tweak,
	                       (unsigned char *) tweak, FORWARD(k2));
	while (spoint-- > 0)
		crypton_aes_generic_gf_mulx(tweak);
}

void crypton_aes_ppc8_encrypt_xts(aes_block *output, aes_key *k1, aes_key *k2,
                                  aes_block *dataunit, uint32_t spoint,
                                  aes_block *input, uint32_t nb_blocks)
{
	block128 tweak;

	xts_tweak(&tweak, k2, dataunit, spoint);
	crypton_aes_p8_xts_encrypt((const unsigned char *) input,
	                           (unsigned char *) output,
	                           (size_t) nb_blocks * 16, FORWARD(k1), NULL,
	                           (const unsigned char *) &tweak);
}

void crypton_aes_ppc8_decrypt_xts(aes_block *output, aes_key *k1, aes_key *k2,
                                  aes_block *dataunit, uint32_t spoint,
                                  aes_block *input, uint32_t nb_blocks)
{
	block128 tweak;
	p8_key dk;

	/* the tweak is enciphered with k2 forwards either way */
	xts_tweak(&tweak, k2, dataunit, spoint);
	inverse(&dk, k1);
	crypton_aes_p8_xts_decrypt((const unsigned char *) input,
	                           (unsigned char *) output,
	                           (size_t) nb_blocks * 16, &dk, NULL,
	                           (const unsigned char *) &tweak);
	memset(&dk, 0, sizeof dk);
}

/*
 * GHASH.  The table the assembly builds is 192 bytes, which fits the sixteen
 * blocks the interface names.
 *
 * The two arguments do not take the same convention, which is worth saying
 * because it does not look like an accident until it is checked.  H arrives
 * here as the sixteen bytes GCM defines, and gcm_init_p8 wants those as a
 * pair of host-order words -- so they are swapped on a little-endian machine
 * and left alone on a big-endian one, which be64_to_cpu does.  The
 * accumulator is the byte string throughout, in and out, and is passed as it
 * stands.  OpenSSL makes the same pair of choices.
 *
 * Checked rather than assumed: against crypton's own GHASH, over two
 * different H and with a non-zero accumulator, so that neither a symmetric
 * value nor a zero start could hide a wrong one.
 */
void crypton_aes_ppc8_hinit(table_4bit htable, const block128 *h)
{
	uint64_t H[2];

	memcpy(H, h, sizeof H);
	H[0] = be64_to_cpu(H[0]);
	H[1] = be64_to_cpu(H[1]);
	crypton_gcm_init_p8(htable, H);
}

void crypton_aes_ppc8_gf_mul(block128 *a, const table_4bit htable)
{
	crypton_gcm_gmult_p8(a, htable);
}

void crypton_aes_ppc8_gf_mul4(block128 *a, const block128 *blocks,
                              const table_4bit htable)
{
	crypton_gcm_ghash_p8(a, htable, (const unsigned char *) blocks,
	                     4 * sizeof(block128));
}

int crypton_aes_ppc8_available(void)
{
	return (crypton_ppc_features() & CRYPTON_PPC_VCRYPTO) != 0;
}
