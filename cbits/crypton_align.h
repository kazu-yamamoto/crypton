#ifndef CRYPTON_ALIGN_H
#define CRYPTON_ALIGN_H

#include "crypton_bitfn.h"

#include <string.h>

#if (defined(__i386__))
# define UNALIGNED_ACCESS_OK
#elif defined(__x86_64__)
# define UNALIGNED_ACCESS_OK
#else
# define UNALIGNED_ACCESS_FAULT
#endif

/* n need to be power of 2.
 * IS_ALIGNED(p,8) */
#define IS_ALIGNED(p,alignment) (((uintptr_t) (p)) & ((alignment)-1))

#ifdef WITH_ASSERT_ALIGNMENT
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
# define ASSERT_ALIGNMENT(up, alignment) \
	do { if (IS_ALIGNED(up, alignment)) \
	{ printf("ALIGNMENT-ASSERT-FAILURE: %s:%d: ptr=%p alignment=%d\n", __FILE__, __LINE__, (void *) up, (alignment)); \
	  exit(99); \
	}; } while (0)
#else
# define ASSERT_ALIGNMENT(p, n) do {} while (0)
#endif

#ifdef UNALIGNED_ACCESS_OK
#define need_alignment(p,n) (0)
#else
#define need_alignment(p,n) IS_ALIGNED(p,n)
#endif

/*
 * Reading and writing a 32- or 64-bit word at a byte pointer.
 *
 * Through memcpy, not a cast to uint32_t * or uint64_t *.  A cast is two
 * things the standard does not allow -- a read of the value through the
 * wrong type, and a read at an address that type is not aligned for -- and
 * this file used to do both wherever UNALIGNED_ACCESS_OK is defined, which
 * is i386 and x86-64.  UndefinedBehaviorSanitizer reported seventy-eight
 * lines of it.
 *
 * Every compiler crypton is built with turns a memcpy of four or eight bytes
 * into the one load or store the cast used to be, so this is the same code
 * with none of the licence.  Where the target cannot do an unaligned load,
 * the compiler is the one that knows, and it emits what the target needs --
 * which is what the byte-at-a-time versions this replaces were for.
 *
 * The _aligned names stay because nineteen files use them.  They no longer
 * ask anything of the pointer.
 */

static inline uint32_t load_le32(const uint8_t *p)
{
	uint32_t v;

	memcpy(&v, p, sizeof(v));
	return le32_to_cpu(v);
}

static inline uint64_t load_le64(const uint8_t *p)
{
	uint64_t v;

	memcpy(&v, p, sizeof(v));
	return le64_to_cpu(v);
}

static inline uint32_t load_be32(const uint8_t *p)
{
	uint32_t v;

	memcpy(&v, p, sizeof(v));
	return be32_to_cpu(v);
}

static inline uint64_t load_be64(const uint8_t *p)
{
	uint64_t v;

	memcpy(&v, p, sizeof(v));
	return be64_to_cpu(v);
}

static inline void store_le32(uint8_t *dst, const uint32_t v)
{
	uint32_t w = cpu_to_le32(v);

	memcpy(dst, &w, sizeof(w));
}

static inline void xor_le32(uint8_t *dst, const uint32_t v)
{
	store_le32(dst, le32_to_cpu(load_le32(dst)) ^ v);
}

static inline void store_be32(uint8_t *dst, const uint32_t v)
{
	uint32_t w = cpu_to_be32(v);

	memcpy(dst, &w, sizeof(w));
}

static inline void xor_be32(uint8_t *dst, const uint32_t v)
{
	uint32_t w;

	memcpy(&w, dst, sizeof(w));
	w ^= cpu_to_be32(v);
	memcpy(dst, &w, sizeof(w));
}

static inline void store_le64(uint8_t *dst, const uint64_t v)
{
	uint64_t w = cpu_to_le64(v);

	memcpy(dst, &w, sizeof(w));
}

static inline void store_be64(uint8_t *dst, const uint64_t v)
{
	uint64_t w = cpu_to_be64(v);

	memcpy(dst, &w, sizeof(w));
}

static inline void xor_be64(uint8_t *dst, const uint64_t v)
{
	uint64_t w;

	memcpy(&w, dst, sizeof(w));
	w ^= cpu_to_be64(v);
	memcpy(dst, &w, sizeof(w));
}

#define load_le32_aligned(p)     load_le32(p)
#define load_le64_aligned(p)     load_le64(p)
#define load_be32_aligned(p)     load_be32(p)
#define load_be64_aligned(p)     load_be64(p)
#define store_le32_aligned(d, v) store_le32(d, v)
#define xor_le32_aligned(d, v)   xor_le32(d, v)
#define store_be32_aligned(d, v) store_be32(d, v)
#define xor_be32_aligned(d, v)   xor_be32(d, v)
#define store_le64_aligned(d, v) store_le64(d, v)
#define store_be64_aligned(d, v) store_be64(d, v)
#define xor_be64_aligned(d, v)   xor_be64(d, v)

#endif
