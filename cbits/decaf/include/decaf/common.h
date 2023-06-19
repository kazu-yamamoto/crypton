/**
 * @file decaf/common.h
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Common utility headers for Decaf library.
 */

#ifndef __CRYPTON_DECAF_COMMON_H__
#define __CRYPTON_DECAF_COMMON_H__ 1

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Goldilocks' build flags default to hidden and stripping executables. */
/** @cond internal */
#if defined(DOXYGEN) && !defined(__attribute__)
#define __attribute__((x))
#endif
#define CRYPTON_DECAF_API_VIS __attribute__((visibility("default")))
#define CRYPTON_DECAF_NOINLINE  __attribute__((noinline))
#define CRYPTON_DECAF_WARN_UNUSED __attribute__((warn_unused_result))
#define CRYPTON_DECAF_NONNULL __attribute__((nonnull))
#define CRYPTON_DECAF_INLINE inline __attribute__((always_inline,unused))
// Cribbed from libnotmuch
#if defined (__clang_major__) && __clang_major__ >= 3 \
    || defined (__GNUC__) && __GNUC__ >= 5 \
    || defined (__GNUC__) && __GNUC__ == 4 && __GNUC_MINOR__ >= 5
#define CRYPTON_DECAF_DEPRECATED(msg) __attribute__ ((deprecated(msg)))
#else
#define CRYPTON_DECAF_DEPRECATED(msg) __attribute__ ((deprecated))
#endif
/** @endcond */

/* Internal word types.
 *
 * Somewhat tricky.  This could be decided separately per platform.  However,
 * the structs do need to be all the same size and alignment on a given
 * platform to support dynamic linking, since even if you header was built
 * with eg arch_neon, you might end up linking a library built with arch_arm32.
 */
#ifndef CRYPTON_DECAF_WORD_BITS
    #if (defined(__ILP64__) || defined(__amd64__) || defined(__x86_64__) || (((__UINT_FAST32_MAX__)>>30)>>30))
        #define CRYPTON_DECAF_WORD_BITS 64 /**< The number of bits in a word */
    #else
        #define CRYPTON_DECAF_WORD_BITS 32 /**< The number of bits in a word */
    #endif
#endif
    
#if CRYPTON_DECAF_WORD_BITS == 64
typedef uint64_t crypton_decaf_word_t;      /**< Word size for internal computations */
typedef int64_t crypton_decaf_sword_t;      /**< Signed word size for internal computations */
typedef uint64_t crypton_decaf_bool_t;      /**< "Boolean" type, will be set to all-zero or all-one (i.e. -1u) */
typedef __uint128_t crypton_decaf_dword_t;  /**< Double-word size for internal computations */
typedef __int128_t crypton_decaf_dsword_t;  /**< Signed double-word size for internal computations */
#elif CRYPTON_DECAF_WORD_BITS == 32         /**< The number of bits in a word */
typedef uint32_t crypton_decaf_word_t;      /**< Word size for internal computations */
typedef int32_t crypton_decaf_sword_t;      /**< Signed word size for internal computations */
typedef uint32_t crypton_decaf_bool_t;      /**< "Boolean" type, will be set to all-zero or all-one (i.e. -1u) */
typedef uint64_t crypton_decaf_dword_t;     /**< Double-word size for internal computations */
typedef int64_t crypton_decaf_dsword_t;     /**< Signed double-word size for internal computations */
#else
#error "Only supporting CRYPTON_DECAF_WORD_BITS = 32 or 64 for now"
#endif
    
/** CRYPTON_DECAF_TRUE = -1 so that CRYPTON_DECAF_TRUE & x = x */
static const crypton_decaf_bool_t CRYPTON_DECAF_TRUE = -(crypton_decaf_bool_t)1;

/** CRYPTON_DECAF_FALSE = 0 so that CRYPTON_DECAF_FALSE & x = 0 */
static const crypton_decaf_bool_t CRYPTON_DECAF_FALSE = 0;

/** Another boolean type used to indicate success or failure. */
typedef enum {
    CRYPTON_DECAF_SUCCESS = -1, /**< The operation succeeded. */
    CRYPTON_DECAF_FAILURE = 0   /**< The operation failed. */
} crypton_decaf_error_t;


/** Return success if x is true */
static CRYPTON_DECAF_INLINE crypton_decaf_error_t
crypton_decaf_succeed_if(crypton_decaf_bool_t x) {
    return (crypton_decaf_error_t)x;
}

/** Return CRYPTON_DECAF_TRUE iff x == CRYPTON_DECAF_SUCCESS */
static CRYPTON_DECAF_INLINE crypton_decaf_bool_t
crypton_decaf_successful(crypton_decaf_error_t e) {
    crypton_decaf_dword_t w = ((crypton_decaf_word_t)e) ^  ((crypton_decaf_word_t)CRYPTON_DECAF_SUCCESS);
    return (w-1)>>CRYPTON_DECAF_WORD_BITS;
}
    
/** Overwrite data with zeros.  Uses memset_s if available. */
void crypton_decaf_bzero (
    void *data,
    size_t size
) CRYPTON_DECAF_NONNULL CRYPTON_DECAF_API_VIS;

/** Compare two buffers, returning CRYPTON_DECAF_TRUE if they are equal. */
crypton_decaf_bool_t crypton_decaf_memeq (
    const void *data1,
    const void *data2,
    size_t size
) CRYPTON_DECAF_NONNULL CRYPTON_DECAF_WARN_UNUSED CRYPTON_DECAF_API_VIS;
    
#ifdef __cplusplus
} /* extern "C" */
#endif
    
#endif /* __CRYPTON_DECAF_COMMON_H__ */
