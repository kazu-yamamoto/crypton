/* Marking secrets for valgrind.
 *
 * memcheck already follows undefined bytes through arithmetic and complains
 * the moment one decides a branch or an address.  That is the same question
 * as "does this run in time independent of the secret", so a secret declared
 * undefined turns memcheck into a checker for it.  The technique is Adam
 * Langley's ctgrind.
 *
 * Without CRYPTON_CT_VALGRIND the macros vanish and the drivers still build
 * and run, which is how they are kept honest on a machine with no valgrind.
 */
#ifndef CRYPTON_TESTS_CT_H
#define CRYPTON_TESTS_CT_H

#ifdef CRYPTON_CT_VALGRIND
#include <valgrind/memcheck.h>
/* this memory is a secret: report any branch or index that depends on it */
#define CT_SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
/* and this is the answer, which the caller is allowed to look at */
#define CT_PUBLIC(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#define CT_SECRET(p, n) ((void)(p), (void)(n))
#define CT_PUBLIC(p, n) ((void)(p), (void)(n))
#endif

#include <stdint.h>
#include <stdio.h>

/* A deterministic filler, so that a report names the same operation on every
 * run.  It is not random and does not need to be. */
static uint64_t ct_s0 = 0x243f6a8885a308d3ULL, ct_s1 = 0x13198a2e03707344ULL;
static uint64_t ct_rnd(void) {
    uint64_t x = ct_s0, y = ct_s1;
    ct_s0 = y;
    x ^= x << 23;
    ct_s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
    return ct_s1 + y;
}
static void ct_fill(void *p, size_t n) {
    uint8_t *q = (uint8_t *)p;
    size_t i;
    for (i = 0; i < n; i++) q[i] = (uint8_t)(ct_rnd() >> 24);
}
/* Look at the answer, so that nothing above is optimized away.  Whatever is
 * handed here has been declared public first. */
static void ct_sink(const void *p, size_t n) {
    const uint8_t *q = (const uint8_t *)p;
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) acc ^= q[i];
    if (acc == 0xa5 && n == (size_t)-1) printf("unreachable\n");
}
#endif
