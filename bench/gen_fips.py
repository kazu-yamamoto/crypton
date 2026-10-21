#!/usr/bin/env python3
"""Generate fully unrolled product-scanning (FIPS) Montgomery multiplication
and squaring for a fixed limb count, AArch64 inline asm for the
multiply-accumulate.  Prototype only."""
import sys

def gen(n):
    out = []
    w = out.append
    # multiply-accumulate into the three-word accumulator (t0,t1,t2)
    # mul, umulh, then the chain
    # mul
    for name, sq in (("mul", False), ("sqr", True)):
        if sq:
            w(f"static void fips_sqr{n}(uint64_t *r, const uint64_t *a, const uint64_t *m, uint64_t n0)")
        else:
            w(f"static void fips_mul{n}(uint64_t *r, const uint64_t *a, const uint64_t *b, const uint64_t *m, uint64_t n0)")
        w("{")
        w(f"\tuint64_t u[{n}], t0 = 0, t1 = 0, t2 = 0, s0, s1, s2, borrow, take;")
        w(f"\tuint64_t z[{n}];")
        for i in range(2 * n - 1):
            if sq:
                # cross products a[j]*a[i-j] with j < i-j, accumulated apart and doubled
                pairs = [(j, i - j) for j in range(max(0, i - n + 1), n) if j < i - j]
                if pairs:
                    w("\ts0 = 0; s1 = 0; s2 = 0;")
                    for (j, k) in pairs:
                        w(f"\tMAC(s0, s1, s2, a[{j}], a[{k}]);")
                    w("\tDBL(s0, s1, s2);")
                    w("\tADD3(t0, t1, t2, s0, s1, s2);")
                if i % 2 == 0 and i // 2 < n:
                    w(f"\tMAC(t0, t1, t2, a[{i//2}], a[{i//2}]);")
            else:
                for j in range(max(0, i - n + 1), min(i, n - 1) + 1):
                    w(f"\tMAC(t0, t1, t2, a[{j}], b[{i - j}]);")
            # the reduction's products for this column: u[j]*m[i-j], j < i (and j < n)
            for j in range(max(0, i - n + 1), min(i, n)):
                if j < i:
                    w(f"\tMAC(t0, t1, t2, u[{j}], m[{i - j}]);")
            if i < n:
                w(f"\tu[{i}] = t0 * n0;")
                w(f"\tMAC(t0, t1, t2, u[{i}], m[0]);")
            else:
                w(f"\tz[{i - n}] = t0;")
            w("\tt0 = t1; t1 = t2; t2 = 0;")
        w(f"\tz[{n - 1}] = t0;")
        # t1 holds the carry above n limbs
        w(f"\tborrow = sub_n(r, z, m, {n});")
        w("\ttake = t1 | (borrow ^ 1);")
        w(f"\tselect_n(r, r, z, take & 1, {n});")
        w("}")
        w("")
    return "\n".join(out)

hdr = r'''
#if defined(__aarch64__)
#define MAC(t0, t1, t2, x, y) do { uint64_t lo_, hi_; \
	__asm__("mul %0, %5, %6\n\tumulh %1, %5, %6\n\tadds %2, %2, %0\n\tadcs %3, %3, %1\n\tadc %4, %4, xzr" \
	: "=&r"(lo_), "=&r"(hi_), "+r"(t0), "+r"(t1), "+r"(t2) : "r"(x), "r"(y) : "cc"); } while (0)
#define ADD3(t0, t1, t2, s0, s1, s2) __asm__("adds %0, %0, %3\n\tadcs %1, %1, %4\n\tadc %2, %2, %5" \
	: "+r"(t0), "+r"(t1), "+r"(t2) : "r"(s0), "r"(s1), "r"(s2) : "cc")
#else
#define MAC(t0, t1, t2, x, y) do { unsigned __int128 p_ = (unsigned __int128)(x) * (y); \
	unsigned __int128 s_ = (unsigned __int128)(t0) + (uint64_t)p_; t0 = (uint64_t)s_; \
	s_ = (unsigned __int128)(t1) + (uint64_t)(p_ >> 64) + (uint64_t)(s_ >> 64); t1 = (uint64_t)s_; \
	t2 += (uint64_t)(s_ >> 64); } while (0)
#define ADD3(t0, t1, t2, s0, s1, s2) do { unsigned __int128 s_ = (unsigned __int128)(t0) + (s0); t0 = (uint64_t)s_; \
	s_ = (unsigned __int128)(t1) + (s1) + (uint64_t)(s_ >> 64); t1 = (uint64_t)s_; t2 += (s2) + (uint64_t)(s_ >> 64); } while (0)
#endif
#define DBL(s0, s1, s2) do { s2 = (s2 << 1) | (s1 >> 63); s1 = (s1 << 1) | (s0 >> 63); s0 <<= 1; } while (0)
'''

if __name__ == "__main__":
    print(hdr)
    for n in map(int, sys.argv[1:]):
        print(gen(n))
