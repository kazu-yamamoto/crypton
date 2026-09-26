/*
 * Choosing between s2n-bignum's two forms of each routine.  The reasoning
 * is in cbits/s2n/README.md; in short, on ARM the choice is a
 * microarchitecture one that no feature bit answers, and on x86-64 it is
 * exactly a feature bit.
 */
#include "p256/p256_s2n.h"
#include "crypton_cpu.h"

extern void p256_scalarmul(uint64_t res[8], const uint64_t scalar[4],
                           const uint64_t point[8]);
extern void p256_scalarmul_alt(uint64_t res[8], const uint64_t scalar[4],
                               const uint64_t point[8]);
extern void p256_scalarmulbase(uint64_t res[8], const uint64_t scalar[4],
                               uint64_t blocksize, const uint64_t *table);
extern void p256_scalarmulbase_alt(uint64_t res[8], const uint64_t scalar[4],
                                   uint64_t blocksize, const uint64_t *table);

extern const uint64_t crypton_p256_s2n_base_blocksize;
extern const uint64_t crypton_p256_s2n_base_table[];

void crypton_s2n_p256_scalarmul(uint64_t res[8], const uint64_t scalar[4],
                                const uint64_t point[8])
{
#if defined(__aarch64__) || defined(__arm64__)
#ifdef __APPLE__
	/* the _alt form is the one written for high multiplier throughput,
	 * and it is 30-40% faster on Apple silicon */
	p256_scalarmul_alt(res, scalar, point);
#else
	p256_scalarmul(res, scalar, point);
#endif
#else
	if (crypton_x86_simd_features() & CRYPTON_X86_ADX)
		p256_scalarmul(res, scalar, point);
	else
		p256_scalarmul_alt(res, scalar, point);
#endif
}

void crypton_s2n_p256_scalarmulbase(uint64_t res[8], const uint64_t scalar[4])
{
#if defined(__aarch64__) || defined(__arm64__)
#ifdef __APPLE__
	p256_scalarmulbase_alt(res, scalar, crypton_p256_s2n_base_blocksize,
	                       crypton_p256_s2n_base_table);
#else
	p256_scalarmulbase(res, scalar, crypton_p256_s2n_base_blocksize,
	                   crypton_p256_s2n_base_table);
#endif
#else
	if (crypton_x86_simd_features() & CRYPTON_X86_ADX)
		p256_scalarmulbase(res, scalar,
		                   crypton_p256_s2n_base_blocksize,
		                   crypton_p256_s2n_base_table);
	else
		p256_scalarmulbase_alt(res, scalar,
		                       crypton_p256_s2n_base_blocksize,
		                       crypton_p256_s2n_base_table);
#endif
}
