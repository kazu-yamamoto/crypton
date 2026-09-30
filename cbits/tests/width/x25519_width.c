/* The same X25519 asked of the 32-bit donna and the 64-bit donna.  Both files
   define crypton_curve25519_donna, so they cannot share a binary: build twice
   and compare. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

void crypton_curve25519_donna(uint8_t *mypublic, const uint8_t *secret,
                              const uint8_t *basepoint);

static uint64_t s0 = 0x243f6a8885a308d3ULL, s1 = 0x13198a2e03707344ULL;
static uint64_t rnd(void) {
    uint64_t x = s0, y = s1;
    s0 = y; x ^= x << 23;
    s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
    return s1 + y;
}
static void show(const char *t, const uint8_t *b) {
    printf("%s ", t);
    for (int i = 0; i < 32; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    uint8_t sec[32], base[32], out[32];
    /* the named points: the generator, zero, one, the low-order points and
       the all-ones field element that reduces to nothing */
    static const uint8_t corners[][32] = {
        {9},
        {0},
        {1},
        {0xe0,0xeb,0x7a,0x7c,0x3b,0x41,0xb8,0xae,0x16,0x56,0xe3,0xfa,0xf1,0x9f,
         0xc4,0x6a,0xda,0x09,0x8d,0xeb,0x9c,0x32,0xb1,0xfd,0x86,0x62,0x05,0x16,
         0x5f,0x49,0xb8,0x00},
        {0x5f,0x9c,0x95,0xbc,0xa3,0x50,0x8c,0x24,0xb1,0xd0,0xb1,0x55,0x9c,0x83,
         0xef,0x5b,0x04,0x44,0x5c,0xc4,0x58,0x1c,0x8e,0x86,0xd8,0x22,0x4e,0xdd,
         0xd0,0x9f,0x11,0x57},
        {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff},
        {0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
    };
    for (unsigned c = 0; c < sizeof corners / sizeof *corners; c++) {
        memset(sec, 0, 32);
        sec[0] = (uint8_t)(0x40 + c); sec[31] = 0x40;
        crypton_curve25519_donna(out, sec, corners[c]);
        show("corner", out);
        /* and the scalars with every clamped bit at an edge */
        memset(sec, 0xff, 32); sec[0] = 0xf8; sec[31] = 0x7f;
        crypton_curve25519_donna(out, sec, corners[c]);
        show("cmax", out);
        memset(sec, 0x00, 32); sec[31] = 0x40;
        crypton_curve25519_donna(out, sec, corners[c]);
        show("cmin", out);
    }
    for (int it = 0; it < 2048; it++) {
        for (int i = 0; i < 32; i++) sec[i] = (uint8_t)(rnd() >> 24);
        for (int i = 0; i < 32; i++) base[i] = (uint8_t)(rnd() >> 24);
        crypton_curve25519_donna(out, sec, base);
        show("r", out);
        /* and a round trip: the shared secret both sides should agree on */
        uint8_t pa[32], pb[32], sa[32], sb[32], g[32] = {9};
        uint8_t s2[32];
        for (int i = 0; i < 32; i++) s2[i] = (uint8_t)(rnd() >> 24);
        crypton_curve25519_donna(pa, sec, g);
        crypton_curve25519_donna(pb, s2, g);
        crypton_curve25519_donna(sa, sec, pb);
        crypton_curve25519_donna(sb, s2, pa);
        printf("agree=%d\n", memcmp(sa, sb, 32) == 0);
        show("sa", sa);
    }
    return 0;
}
