/*
 * ChaCha with SSE, four blocks at a time, and the choice of which x86
 * version to run.
 *
 * Word i of four blocks goes in lane i of one register, so every quarter
 * round is one operation on whole registers and no lane moves between the
 * column and the diagonal rounds.  Only the counter differs between the
 * four blocks.
 *
 * SSE2 is part of the x86-64 baseline and needs no check.  SSSE3 takes the
 * rotates by sixteen and eight in one instruction each, and AVX2 -- in
 * chacha_avx2.c -- carries eight blocks instead of four; both are reached
 * only after crypton_x86_simd_features() says so.  Both also need function
 * attributes to sit in a translation unit that is otherwise baseline, so
 * with use_target_attributes turned off only the SSE2 version is built.
 */

#include <stdint.h>
#include <emmintrin.h>
#ifdef WITH_TARGET_ATTRIBUTES
#include <tmmintrin.h>
#endif
#include "crypton_chacha.h"
#include "crypton_cpu.h"

#define SIZED(n) n##_sse2
#define TARGET
#define ROL(x, n) _mm_or_si128(_mm_slli_epi32((x), (n)), _mm_srli_epi32((x), 32 - (n)))
#include <chacha_sse_impl.c>
#undef SIZED
#undef TARGET
#undef ROL

#ifdef WITH_TARGET_ATTRIBUTES

static const int8_t rot16_tbl[16] = { 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13 };
static const int8_t rot8_tbl[16]  = { 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14 };

#define SIZED(n) n##_ssse3
#define TARGET __attribute__((target("ssse3")))
#define ROL(x, n)                                                              \
	((n) == 16 ? _mm_shuffle_epi8((x), _mm_loadu_si128((const __m128i *) rot16_tbl)) \
	 : (n) == 8 ? _mm_shuffle_epi8((x), _mm_loadu_si128((const __m128i *) rot8_tbl)) \
	 : _mm_or_si128(_mm_slli_epi32((x), (n)), _mm_srli_epi32((x), 32 - (n))))
#include <chacha_sse_impl.c>
#undef SIZED
#undef TARGET
#undef ROL

void crypton_chacha_avx2_combine(int rounds, uint8_t *dst, const uint8_t *src,
                                 const crypton_chacha_state *in);
void crypton_chacha_avx2_generate(int rounds, uint8_t *dst, const crypton_chacha_state *in);

#endif

/* how many blocks a call covers, and which version does it */
enum { IMPL_UNRESOLVED = 0, IMPL_SSE2, IMPL_SSSE3, IMPL_AVX2 };

static int impl = IMPL_UNRESOLVED;

/* Two threads racing to answer this both write the same value. */
static int resolve(void)
{
#ifdef WITH_TARGET_ATTRIBUTES
	uint32_t f = crypton_x86_simd_features();

	if (f & CRYPTON_X86_AVX2)
		impl = IMPL_AVX2;
	else if (f & CRYPTON_X86_SSSE3)
		impl = IMPL_SSSE3;
	else
#endif
		impl = IMPL_SSE2;
	return impl;
}

int crypton_chacha_simd_width(void)
{
	int i = impl ? impl : resolve();

	return i == IMPL_AVX2 ? 8 : 4;
}

void crypton_chacha_simd_combine(int rounds, uint8_t *dst, const uint8_t *src,
                                 const crypton_chacha_state *in)
{
	switch (impl ? impl : resolve()) {
#ifdef WITH_TARGET_ATTRIBUTES
	case IMPL_AVX2:  crypton_chacha_avx2_combine(rounds, dst, src, in); return;
	case IMPL_SSSE3: combine_ssse3(rounds, dst, src, in); return;
#endif
	default:         combine_sse2(rounds, dst, src, in); return;
	}
}

void crypton_chacha_simd_generate(int rounds, uint8_t *dst, const crypton_chacha_state *in)
{
	switch (impl ? impl : resolve()) {
#ifdef WITH_TARGET_ATTRIBUTES
	case IMPL_AVX2:  crypton_chacha_avx2_generate(rounds, dst, in); return;
	case IMPL_SSSE3: generate_ssse3(rounds, dst, in); return;
#endif
	default:         generate_sse2(rounds, dst, in); return;
	}
}
