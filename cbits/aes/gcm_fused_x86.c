/*
 * A fused AES-GCM for x86-64, written to the design Kazuho Oku sets out in
 * "QUICむけにAES-GCM実装を最適化した話": keep AES-NI issuing every clock and
 * fit everything else -- the additional data, the tag, the QUIC header
 * protection mask -- into the gaps it leaves.  Written in C with intrinsics
 * rather than assembly, for the same reason he gives: the scheduling is what
 * is complicated here, and it has to stay readable to stay correct.
 *
 * The powers of H are built once per key, so the additional data, the
 * ciphertext and the length block are absorbed against them in batches that
 * share one reduction, rather than each block paying for a reduction of its
 * own.  How many powers, and so how large a batch, is
 * CRYPTON_GCM_FUSED_POWERS in crypton_aes.h.
 *
 * Only messages shorter than CRYPTON_GCM_FUSED_MAX_MESSAGE come here.  Above
 * that the stitched assembly in cbits/asm is faster, and crypton_aes.c sends
 * them there instead; below it, that assembly will not start at all.
 */

#include <crypton_cpu.h>

#ifdef WITH_GCM_FUSED

#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>
#include <smmintrin.h>
#include <tmmintrin.h>

#include <crypton_aes.h>
#include <aes/gcm_fused_x86.h>

/*
 * aes_key is a struct of bytes, so its round keys sit wherever the members
 * before them leave them -- eight bytes in, as it happens.  A __m128i *
 * pointed at that gets an aligned load and a fault, so each round key is
 * fetched with an unaligned load instead.  Copying them somewhere aligned
 * would cost a copy per call, which at these message lengths is a tenth of
 * the whole; the load is free from L1 and the round key is fetched once for
 * all six lanes.
 */
#define RK(p, i) \
    _mm_loadu_si128((const __m128i *) ((const uint8_t *) (p) + 16 * (size_t) (i)))

/* a full sixteen-byte reversal: mask bytes 15,14,...,0 */
static const __m128i BSWAP = {0x08090a0b0c0d0e0fLL, 0x0001020304050607LL};

#define TGT __attribute__((target("aes,pclmul,sse4.1")))

/* the two halves of a value added together: the term Karatsuba needs, and it
 * does not depend on what the value is multiplied by */
TGT static inline __m128i fold(__m128i a)
{
    return _mm_xor_si128(a, _mm_unpackhi_epi64(a, a));
}

/* GCM numbers the bits of a field element the other way round from the way
 * the carry-less multiply does.  Pre-shifting H is what saves the correction
 * after every multiply; the bit that falls off the top is the one the
 * polynomial reduces. */
TGT static __m128i twist(__m128i h)
{
    const __m128i poly = _mm_set_epi64x(0xc200000000000000ULL, 1);
    __m128i carried = _mm_slli_si128(_mm_srli_epi64(h, 63), 8);
    __m128i top = _mm_shuffle_epi32(h, 0xff);
    __m128i reduce = _mm_cmpgt_epi32(_mm_setzero_si128(), top);

    h = _mm_or_si128(_mm_slli_epi64(h, 1), carried);
    return _mm_xor_si128(h, _mm_and_si128(reduce, poly));
}

/* one reduction of a 256-bit product back into the field */
TGT static __m128i reduce256(__m128i lo, __m128i hi)
{
    const __m128i poly = _mm_set_epi64x(0xc200000000000000ULL, 1);
    __m128i t;

    t = _mm_clmulepi64_si128(lo, poly, 0x10);
    lo = _mm_xor_si128(_mm_shuffle_epi32(lo, 0x4e), t);
    t = _mm_clmulepi64_si128(lo, poly, 0x10);
    lo = _mm_xor_si128(_mm_shuffle_epi32(lo, 0x4e), t);
    return _mm_xor_si128(hi, lo);
}

/*
 * One multiply in exactly the form the hot loop uses it: the left operand
 * plain, the right one already twisted.  Building the table with the same
 * multiply that consumes it is the only way the two conventions cannot drift
 * apart.
 */
TGT static __m128i mul_twisted(__m128i a, __m128i ht)
{
    __m128i lo = _mm_clmulepi64_si128(a, ht, 0x00);
    __m128i hi = _mm_clmulepi64_si128(a, ht, 0x11);
    __m128i mid = _mm_clmulepi64_si128(fold(a), fold(ht), 0x00);

    mid = _mm_xor_si128(mid, _mm_xor_si128(lo, hi));
    lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));
    return reduce256(lo, hi);
}

TGT void crypton_gcm_fused_key_init(aes_gcm_fused *fk, const aes_key *key)
{
    const uint8_t *rk = key->data;
    const int rounds = key->nbr;
    __m128i h, p;
    int i;

    /* H = E_K(0) */
    h = RK(rk, 0);
    for (i = 1; i < rounds; i++) h = _mm_aesenc_si128(h, RK(rk, i));
    h = _mm_aesenclast_si128(h, RK(rk, rounds));
    h = _mm_shuffle_epi8(h, BSWAP);

    {
        __m128i ht = twist(h);
        p = h;
        for (i = 0; i < CRYPTON_GCM_FUSED_POWERS; i++) {
            __m128i t = twist(p);
            _mm_storeu_si128((__m128i *) &fk->p[i].h, t);
            _mm_storeu_si128((__m128i *) &fk->p[i].r, fold(t));
            p = mul_twisted(p, ht);
        }
    }
}

/*
 * The running product.  Three plain locals and a macro, not a struct behind
 * a pointer: taking the address of the accumulators is enough to keep them
 * out of registers, and then every multiply reloads and restores them.  That
 * is the same mistake as reaching a table through an index the compiler
 * cannot fold, and it costs more here because it is on the inner path.
 */
#define GHASH_DECL __m128i glo = _mm_setzero_si128(),                        \
                            ghi = _mm_setzero_si128(),                       \
                            gmid = _mm_setzero_si128(),                      \
                            gtag = _mm_setzero_si128();                      \
                   int gidx = 0, gblen = 0, gbpos = 0

/*
 * Absorb one block.  Blocks are taken in batches of at most CRYPTON_GCM_FUSED_POWERS: the
 * first of a batch carries in the value the batch before it reduced to, the
 * rest go in against descending powers, and the batch ends with the one
 * reduction they share.  With the batch as long as the message this is
 * picotls's single reduction; with it fixed, the state stays a fixed size.
 */
#define GHASH_ONE(blk, unused_power)                                         \
    do {                                                                     \
        __m128i _b = (blk);                                                  \
        __m128i _h, _r;                                                      \
        if (gbpos == 0) {                                                    \
            int _left = gtotal - gidx;                                       \
            gblen = _left < CRYPTON_GCM_FUSED_POWERS ? _left : CRYPTON_GCM_FUSED_POWERS;             \
            _b = _mm_xor_si128(_b, gtag);                                    \
            glo = ghi = gmid = _mm_setzero_si128();                          \
        }                                                                    \
        _h = _mm_loadu_si128((const __m128i *) &fk->p[gblen-gbpos-1].h);     \
        _r = _mm_loadu_si128((const __m128i *) &fk->p[gblen-gbpos-1].r);     \
        glo = _mm_xor_si128(glo, _mm_clmulepi64_si128(_b, _h, 0x00));        \
        ghi = _mm_xor_si128(ghi, _mm_clmulepi64_si128(_b, _h, 0x11));        \
        gmid = _mm_xor_si128(gmid,                                           \
                   _mm_clmulepi64_si128(fold(_b), _r, 0x00));                \
        gidx++; gbpos++;                                                     \
        if (gbpos == gblen) {                                                \
            gtag = ghash_reduce(glo, ghi, gmid);                             \
            gbpos = 0;                                                       \
        }                                                                    \
    } while (0)

TGT static __m128i ghash_reduce(__m128i glo, __m128i ghi, __m128i gmid)
{
    __m128i mid = _mm_xor_si128(gmid, _mm_xor_si128(glo, ghi));
    __m128i lo = _mm_xor_si128(glo, _mm_slli_si128(mid, 8));
    __m128i hi = _mm_xor_si128(ghi, _mm_srli_si128(mid, 8));

    return reduce256(lo, hi);
}

/* zero every byte from n onwards, so a partial block can be fed to GHASH
 * without being written out and read back */
TGT static __m128i clampn(__m128i v, size_t n)
{
    const __m128i idx = {0x0706050403020100LL, 0x0f0e0d0c0b0a0908LL};
    return _mm_and_si128(v, _mm_cmpgt_epi8(_mm_set1_epi8((char) n), idx));
}

/*
 * A short block, zero padded.  The padding is not optional: the additional
 * data goes to GHASH straight from here, where a whole block would have
 * zeros above its length and anything else changes the tag.
 */
TGT static __m128i loadn(const uint8_t *p, size_t n)
{
    uint8_t buf[16] = {0};
    memcpy(buf, p, n);
    return _mm_loadu_si128((const __m128i *) buf);
}

TGT static void storen(uint8_t *p, __m128i v, size_t n)
{
    uint8_t buf[16];
    _mm_storeu_si128((__m128i *) buf, v);
    memcpy(p, buf, n);
}

/* One block.  The ten rounds of the common case are written out for the
 * same reason the six-wide group is: a loop over a round count that lives in
 * the key leaves every round key fetched through an index the compiler
 * cannot fold, and adds a branch to a chain that is already latency-bound. */
TGT static __m128i aes_one_block(const uint8_t *rk, int rounds, __m128i v)
{
    const uint8_t *k = rk;
    int i;

    if (rounds == 10) {
        v = _mm_xor_si128(v, RK(k, 0));
        v = _mm_aesenc_si128(v, RK(k, 1));
        v = _mm_aesenc_si128(v, RK(k, 2));
        v = _mm_aesenc_si128(v, RK(k, 3));
        v = _mm_aesenc_si128(v, RK(k, 4));
        v = _mm_aesenc_si128(v, RK(k, 5));
        v = _mm_aesenc_si128(v, RK(k, 6));
        v = _mm_aesenc_si128(v, RK(k, 7));
        v = _mm_aesenc_si128(v, RK(k, 8));
        v = _mm_aesenc_si128(v, RK(k, 9));
        return _mm_aesenclast_si128(v, RK(k, 10));
    }
    v = _mm_xor_si128(v, RK(k, 0));
    for (i = 1; i < rounds; i++) v = _mm_aesenc_si128(v, RK(k, i));
    return _mm_aesenclast_si128(v, RK(k, rounds));
}

/*
 * Six blocks at once, with lane 5 free to run a different key schedule from
 * the rest.  Which schedule that lane uses is chosen once, into a pointer,
 * rather than tested inside the rounds, and the six live in named variables
 * rather than an array -- an array indexed by a running variable goes to
 * memory, and then every round is a load and a store instead of a register
 * to register operation, which is the whole of what this is trying to avoid.
 *
 * Lanes beyond what the caller needs still run.  Six are in flight whatever
 * the message length, so the spare ones cost nothing, and that is exactly
 * why the header protection mask and E(K,Y0) are worth putting in them
 * instead of giving each a dependent chain of its own.
 */
#define WIDE6(alt)                                                           \
    do {                                                                     \
        const uint8_t *ak = (alt);                                           \
        int r;                                                               \
        t0 = _mm_xor_si128(t0, RK(rk, 0));                                   \
        t1 = _mm_xor_si128(t1, RK(rk, 0));                                   \
        t2 = _mm_xor_si128(t2, RK(rk, 0));                                   \
        t3 = _mm_xor_si128(t3, RK(rk, 0));                                   \
        t4 = _mm_xor_si128(t4, RK(rk, 0));                                   \
        t5 = _mm_xor_si128(t5, RK(ak, 0));                                       \
        for (r = 1; r < rounds; r++) {                                   \
            __m128i k = RK(rk, r);                                           \
            t0 = _mm_aesenc_si128(t0, k);                                    \
            t1 = _mm_aesenc_si128(t1, k);                                    \
            t2 = _mm_aesenc_si128(t2, k);                                    \
            t3 = _mm_aesenc_si128(t3, k);                                    \
            t4 = _mm_aesenc_si128(t4, k);                                    \
            t5 = _mm_aesenc_si128(t5, RK(ak, r));                                \
            GSTEP();                                                         \
        }                                                                    \
        {                                                                    \
            __m128i k = RK(rk, rounds);                                  \
            t0 = _mm_aesenclast_si128(t0, k);                                \
            t1 = _mm_aesenclast_si128(t1, k);                                \
            t2 = _mm_aesenclast_si128(t2, k);                                \
            t3 = _mm_aesenclast_si128(t3, k);                                \
            t4 = _mm_aesenclast_si128(t4, k);                                \
            t5 = _mm_aesenclast_si128(t5, RK(ak, rounds));                   \
        }                                                                    \
    } while (0)

/*
 * v2: six blocks of AES in flight at once, so the ten rounds of one block no
 * longer wait on each other -- AES-NI is pipelined and will take one
 * instruction a clock as long as the instructions in flight are independent.
 * The GHASH multiplies of the group just finished are issued between the
 * rounds of the group now running, which is the stitching: they do not want
 * the same execution port, so held against each other they cost about what
 * the rounds alone cost.
 */

/*
 * The counter block, built without leaving the vector registers.
 *
 * GCM counts in the low 32 bits of the block, big endian, and wraps there.
 * ctr holds the block with its bytes reversed, so those four bytes are the
 * low lane and _mm_add_epi32 steps them without carrying into the nonce
 * above -- which is the wrap GCM asks for.  A shuffle puts the bytes back.
 *
 * The obvious way -- increment a uint32_t, byte swap it, pinsrd it in --
 * costs a move from a general register to a vector one for every lane, six
 * to a group, and those do not come free.
 */
#define CTR6(j)                                                              \
    do {                                                                     \
        ctr = _mm_add_epi32(ctr, one32);                                     \
        b##j = _mm_xor_si128(_mm_shuffle_epi8(ctr, BSWAP), RK(rk, 0));       \
    } while (0)

#define ROUND6(r)                                                            \
    do {                                                                     \
        __m128i k = RK(rk, r);                                               \
        b0 = _mm_aesenc_si128(b0, k);                                        \
        b1 = _mm_aesenc_si128(b1, k);                                        \
        b2 = _mm_aesenc_si128(b2, k);                                        \
        b3 = _mm_aesenc_si128(b3, k);                                        \
        b4 = _mm_aesenc_si128(b4, k);                                        \
        b5 = _mm_aesenc_si128(b5, k);                                        \
    } while (0)

#define LAST6(r)                                                             \
    do {                                                                     \
        __m128i k = RK(rk, r);                                               \
        b0 = _mm_aesenclast_si128(b0, k);                                    \
        b1 = _mm_aesenclast_si128(b1, k);                                    \
        b2 = _mm_aesenclast_si128(b2, k);                                    \
        b3 = _mm_aesenclast_si128(b3, k);                                    \
        b4 = _mm_aesenclast_si128(b4, k);                                    \
        b5 = _mm_aesenclast_si128(b5, k);                                    \
    } while (0)

/* one GHASH multiply, taken from a queue of blocks waiting to be absorbed,
 * to be issued in the gaps between AES rounds */
/* A ring, so that a block queued while others are still waiting costs an
 * index and not a move: the queue is walked from both ends and never
 * compacted. */
#define GQ_MASK 15

#define GPUSH(v)                                                             \
    do { gq[gw] = (v); gw++; gn++; } while (0)

#define GSTEP()                                                              \
    do {                                                                     \
        if (gn > 0) {                                                        \
            GHASH_ONE(gq[gi], gp);                                   \
            gi++; gp--; gn--;                                                \
        }                                                                    \
    } while (0)

/* the same at a slot the compiler can see, for the unrolled group below */
/*
 * One queued block, at a slot the compiler can see and with nothing to test
 * before it.  A test here would end the basic block, and the scheduler works
 * inside one: six tests turn the group into twelve blocks and the multiplies
 * can no longer be moved up among the rounds, which is the whole point of
 * writing them there.  The group below is entered only when the queue is
 * full, so there is nothing to test.
 */
#define GAT(j) GHASH_ONE(gq[j], gp - (j))

TGT void crypton_gcm_fused_encrypt(uint8_t *out, const aes_gcm_fused *fk,
                                   const aes_key *key, const uint8_t *nonce,
                                   const uint8_t *aad, size_t aadlen,
                                   const uint8_t *in, size_t inlen, size_t taglen,
                                   const aes_key *hpkey, size_t sampleoff,
                                   uint8_t *mask)
{
    const uint8_t *rk = key->data;
    const uint8_t *hprk = hpkey != 0 ? hpkey->data : rk;
    const int rounds = key->nbr;
    const int hprounds = hpkey != 0 ? hpkey->nbr : rounds;
    GHASH_DECL;
    __m128i ctrbase, ctr, one32, ek0, tag, b0, b1, b2, b3, b4, b5;
    const int ntail_pre = (int) ((inlen % 96 + 15) / 16);
    int lane_ek0;
    __m128i gq[6];
    unsigned gi = 0, gw = 0;
    int gn = 0;
    size_t nblk = (aadlen + 15) / 16 + (inlen + 15) / 16 + 1;
    const int gtotal = (int) nblk;
    int gp = (int) nblk;
    size_t i;
    size_t done;
    int lane_mask = 0;

    /* Y0 built in a register.  Going through sixteen bytes of stack to
     * assemble twelve bytes of nonce and a counter puts a store and a load
     * on the front of a function whose whole fixed cost is a few tens of
     * clocks.  Three four-byte loads cannot read past the nonce. */
    {
        uint32_t n0, n1, n2;
        memcpy(&n0, nonce, 4);
        memcpy(&n1, nonce + 4, 4);
        memcpy(&n2, nonce + 8, 4);
        ctrbase = _mm_set_epi32((int) __builtin_bswap32(1),
                                (int) n2, (int) n1, (int) n0);
        ctr = _mm_shuffle_epi8(ctrbase, BSWAP);
        one32 = _mm_set_epi32(0, 0, 0, 1);
    }
    /*
     * E(K,Y0), which the tag is masked with.  When the message leaves a tail
     * that is four blocks or fewer, the pass below has lanes to spare and it
     * rides in one of them; a chain of its own costs ten rounds that nothing
     * overlaps, which at 100 bytes measured 9.3 of 78.9 nanoseconds.  This
     * is what picotls's fusion does with its bits5.
     */
    lane_ek0 = ntail_pre > 0 && ntail_pre <= 4;
    if (!lane_ek0)
        ek0 = aes_one_block(rk, rounds, ctrbase);

    /* The additional data goes in first and takes the highest powers, but it
     * is only queued here: absorbing it takes multiplies, and the multiplies
     * belong in the gaps between the AES rounds below rather than in front
     * of them where nothing else is running. */
    /*
     * The additional data goes in first and takes the highest powers.  It is
     * absorbed here rather than queued: what the queue is for is giving the
     * rounds below something to interleave with, and a queue that sometimes
     * holds the header and sometimes does not forces a test before every
     * multiply -- which is what stopped the interleaving from happening at
     * all.  See the peeled first group below.
     */
    {
        size_t nfull = aadlen / 16;
        size_t rest = aadlen % 16;

        for (i = 0; i < nfull; i++)
            GHASH_ONE(_mm_shuffle_epi8(
                _mm_loadu_si128((const __m128i *) (aad + i * 16)), BSWAP), 0);
        if (rest)
            GHASH_ONE(_mm_shuffle_epi8(loadn(aad + nfull * 16, rest), BSWAP), 0);
    }

    /* Whole groups of six.  The rounds are written out rather than looped:
     * the number of them is a value in the key, so a loop over it leaves the
     * compiler fetching each round key through an index it cannot fold, and
     * the six lanes go to memory with them.  Written out, the whole group
     * stays in registers, and the six multiplies of the group before can be
     * placed between the rounds by hand -- which is the stitching: AES-NI
     * and PCLMULQDQ do not contend for the same port, so the multiplies are
     * very nearly free.
     */
    done = 0;
    if (rounds == 10) {
        if (done + 96 <= inlen) {
            const uint8_t *p = in + done;
            uint8_t *q = out + done;

            CTR6(0); CTR6(1); CTR6(2); CTR6(3); CTR6(4); CTR6(5);
            ROUND6(1);
            ROUND6(2);
            ROUND6(3);
            ROUND6(4);
            ROUND6(5);
            ROUND6(6);
            ROUND6(7);
            ROUND6(8);
            ROUND6(9);
            LAST6(10);
            gn = 0; gi = 0; gw = 0;

            b0 = _mm_xor_si128(b0, _mm_loadu_si128((const __m128i *) p));
            b1 = _mm_xor_si128(b1, _mm_loadu_si128((const __m128i *) (p + 16)));
            b2 = _mm_xor_si128(b2, _mm_loadu_si128((const __m128i *) (p + 32)));
            b3 = _mm_xor_si128(b3, _mm_loadu_si128((const __m128i *) (p + 48)));
            b4 = _mm_xor_si128(b4, _mm_loadu_si128((const __m128i *) (p + 64)));
            b5 = _mm_xor_si128(b5, _mm_loadu_si128((const __m128i *) (p + 80)));
            _mm_storeu_si128((__m128i *) q, b0);
            _mm_storeu_si128((__m128i *) (q + 16), b1);
            _mm_storeu_si128((__m128i *) (q + 32), b2);
            _mm_storeu_si128((__m128i *) (q + 48), b3);
            _mm_storeu_si128((__m128i *) (q + 64), b4);
            _mm_storeu_si128((__m128i *) (q + 80), b5);

            gq[0] = _mm_shuffle_epi8(b0, BSWAP);
            gq[1] = _mm_shuffle_epi8(b1, BSWAP);
            gq[2] = _mm_shuffle_epi8(b2, BSWAP);
            gq[3] = _mm_shuffle_epi8(b3, BSWAP);
            gq[4] = _mm_shuffle_epi8(b4, BSWAP);
            gq[5] = _mm_shuffle_epi8(b5, BSWAP);
            gn = 6;
            done += 96;
        }
        for (; done + 96 <= inlen; done += 96) {
            const uint8_t *p = in + done;
            uint8_t *q = out + done;

            CTR6(0); CTR6(1); CTR6(2); CTR6(3); CTR6(4); CTR6(5);
            ROUND6(1); GAT(0);
            ROUND6(2); GAT(1);
            ROUND6(3); GAT(2);
            ROUND6(4); GAT(3);
            ROUND6(5); GAT(4);
            ROUND6(6); GAT(5);
            ROUND6(7);
            ROUND6(8);
            ROUND6(9);
            LAST6(10);
            gp -= 6;

            b0 = _mm_xor_si128(b0, _mm_loadu_si128((const __m128i *) p));
            b1 = _mm_xor_si128(b1, _mm_loadu_si128((const __m128i *) (p + 16)));
            b2 = _mm_xor_si128(b2, _mm_loadu_si128((const __m128i *) (p + 32)));
            b3 = _mm_xor_si128(b3, _mm_loadu_si128((const __m128i *) (p + 48)));
            b4 = _mm_xor_si128(b4, _mm_loadu_si128((const __m128i *) (p + 64)));
            b5 = _mm_xor_si128(b5, _mm_loadu_si128((const __m128i *) (p + 80)));
            _mm_storeu_si128((__m128i *) q, b0);
            _mm_storeu_si128((__m128i *) (q + 16), b1);
            _mm_storeu_si128((__m128i *) (q + 32), b2);
            _mm_storeu_si128((__m128i *) (q + 48), b3);
            _mm_storeu_si128((__m128i *) (q + 64), b4);
            _mm_storeu_si128((__m128i *) (q + 80), b5);

            /* straight from the registers the last round left them in: the
             * queue existed only to hold them until the next group's rounds
             * could hide the multiplies, and that is 192 bytes of store and
             * load per 96 bytes of payload */
            gq[0] = _mm_shuffle_epi8(b0, BSWAP);
            gq[1] = _mm_shuffle_epi8(b1, BSWAP);
            gq[2] = _mm_shuffle_epi8(b2, BSWAP);
            gq[3] = _mm_shuffle_epi8(b3, BSWAP);
            gq[4] = _mm_shuffle_epi8(b4, BSWAP);
            gq[5] = _mm_shuffle_epi8(b5, BSWAP);
            gn = 6;
        }

    } else {
        for (done = 0; done + 96 <= inlen; done += 96) {
                const uint8_t *p = in + done;
                uint8_t *q = out + done;
                int r;

                CTR6(0); CTR6(1); CTR6(2); CTR6(3); CTR6(4); CTR6(5);
                for (r = 1; r < rounds; r++) {
                    ROUND6(r);
                    GSTEP();
                }
                LAST6(rounds);

                b0 = _mm_xor_si128(b0, _mm_loadu_si128((const __m128i *) p));
                b1 = _mm_xor_si128(b1, _mm_loadu_si128((const __m128i *) (p + 16)));
                b2 = _mm_xor_si128(b2, _mm_loadu_si128((const __m128i *) (p + 32)));
                b3 = _mm_xor_si128(b3, _mm_loadu_si128((const __m128i *) (p + 48)));
                b4 = _mm_xor_si128(b4, _mm_loadu_si128((const __m128i *) (p + 64)));
                b5 = _mm_xor_si128(b5, _mm_loadu_si128((const __m128i *) (p + 80)));
                _mm_storeu_si128((__m128i *) q, b0);
                _mm_storeu_si128((__m128i *) (q + 16), b1);
                _mm_storeu_si128((__m128i *) (q + 32), b2);
                _mm_storeu_si128((__m128i *) (q + 48), b3);
                _mm_storeu_si128((__m128i *) (q + 64), b4);
                _mm_storeu_si128((__m128i *) (q + 80), b5);

                while (gn > 0) GSTEP();
                gi = 0; gw = 0;
                gq[0] = _mm_shuffle_epi8(b0, BSWAP);
                gq[1] = _mm_shuffle_epi8(b1, BSWAP);
                gq[2] = _mm_shuffle_epi8(b2, BSWAP);
                gq[3] = _mm_shuffle_epi8(b3, BSWAP);
                gq[4] = _mm_shuffle_epi8(b4, BSWAP);
                gq[5] = _mm_shuffle_epi8(b5, BSWAP);
                gn = 6;
        }
    }

    /* The tail.  E(K,Y0) is not computed here but at the top, on a chain of
     * its own: it depends on nothing else, so the processor overlaps it with
     * the groups without being asked, and folding it into a six-wide pass
     * only forces that pass to exist.  A pass for the mask alone costs sixty
     * AES instructions to use one lane, which is why the wide pass below
     * runs only when there are blocks for it.
     *
     * The spare lane carries the mask only when two things hold.  The sample
     * has to lie entirely in output the groups above have already written:
     * this pass reads it while it runs, and the blocks it is itself
     * computing are stored after it, so a sample reaching into them would be
     * read before it exists.  And the two key schedules have to have the
     * same number of rounds, because the lanes share the loop that counts
     * them and a shorter schedule would be read past its end.  TLS and QUIC
     * satisfy both; anything else gets the mask on a chain of its own, which
     * is what it would have had anyway. */
    {
        __m128i t0, t1, t2, t3, t4, t5;
        __m128i tv[6];
        size_t toff[6];
        int ntail = 0, j;

        if (done >= inlen) goto no_tail;

        for (i = done; i < inlen; i += 16) {
            toff[ntail] = i;
            ctr = _mm_add_epi32(ctr, one32);
            tv[ntail] = _mm_shuffle_epi8(ctr, BSWAP);
            ntail++;
        }

        lane_mask = ntail > 0 && ntail <= 5 && hpkey != 0 && mask != 0
                 && hprounds == rounds
                 && sampleoff + 16 <= done;

        if (ntail > 0) {
            t0 = tv[0];
            t1 = ntail > 1 ? tv[1] : ctrbase;
            t2 = ntail > 2 ? tv[2] : ctrbase;
            t3 = ntail > 3 ? tv[3] : ctrbase;
            t4 = lane_ek0 ? ctrbase : (ntail > 4 ? tv[4] : ctrbase);
            t5 = lane_mask
               ? _mm_loadu_si128((const __m128i *) (out + sampleoff))
               : (ntail > 5 ? tv[5] : ctrbase);
            WIDE6(lane_mask ? hprk : rk);
            tv[0] = t0; tv[1] = t1; tv[2] = t2; tv[3] = t3;
            if (lane_ek0)
                ek0 = t4;
            else
                tv[4] = t4;
            if (lane_mask)
                _mm_storeu_si128((__m128i *) mask, t5);
            else if (ntail > 5)
                tv[5] = t5;
        }
no_tail:
        while (gn > 0) GSTEP();

        for (j = 0; j < ntail; j++) {
            size_t off = toff[j];
            size_t n = inlen - off < 16 ? inlen - off : 16;
            __m128i c = _mm_xor_si128(tv[j], n == 16
                ? _mm_loadu_si128((const __m128i *) (in + off))
                : loadn(in + off, n));
            if (n == 16) {
                _mm_storeu_si128((__m128i *) (out + off), c);
            } else {
                /* The tag goes in at out + inlen, so the bytes above the
                 * last short block are about to be written over anyway:
                 * where there are sixteen of them to spare, one store does
                 * what a store to the stack and a copy back did. */
                if (n + taglen >= 16)
                    _mm_storeu_si128((__m128i *) (out + off), c);
                else
                    storen(out + off, c, n);
                c = clampn(c, n);
            }
            GHASH_ONE(_mm_shuffle_epi8(c, BSWAP), gp);
            gp--;
        }
    }

    {
        uint8_t lenb[16];
        uint64_t la = (uint64_t) aadlen * 8, lc = (uint64_t) inlen * 8;
        int j;
        for (j = 0; j < 8; j++) lenb[j] = (uint8_t) (la >> (56 - 8 * j));
        for (j = 0; j < 8; j++) lenb[8 + j] = (uint8_t) (lc >> (56 - 8 * j));
        GHASH_ONE(_mm_shuffle_epi8(_mm_loadu_si128((const __m128i *) lenb),
                                       BSWAP), gp);
    }

    tag = _mm_shuffle_epi8(gtag, BSWAP);
    tag = _mm_xor_si128(tag, ek0);
    if (taglen == 16)
        _mm_storeu_si128((__m128i *) (out + inlen), tag);
    else
        storen(out + inlen, tag, taglen);

    /* A sample the pass above could not reach -- because it covered blocks
     * that pass was still computing, or the tag, which is written just now
     * -- is taken here instead, where everything it can cover exists. */
    if (!lane_mask && hpkey != 0 && mask != 0)
        _mm_storeu_si128((__m128i *) mask,
                         aes_one_block(hprk, hprounds, _mm_loadu_si128(
                             (const __m128i *) (out + sampleoff))));
}

#endif /* WITH_GCM_FUSED */
