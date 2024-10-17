/**
 * @file decaf/ed448.h
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief A group of prime order p, based on Ed448-Goldilocks.
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */

#ifndef __CRYPTON_DECAF_ED448_H__
#define __CRYPTON_DECAF_ED448_H__ 1

#include <decaf/point_448.h>
#include <decaf/shake.h>
#include <decaf/sha512.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Number of bytes in an EdDSA public key. */
#define CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES 57

/** Number of bytes in an EdDSA private key. */
#define CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES

/** Number of bytes in an EdDSA private key. */
#define CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES (CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES + CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES)

/** Does EdDSA support non-contextual signatures? */
#if defined _MSC_VER  /* Different syntax for exposing API */
#define CRYPTON_DECAF_EDDSA_448_SUPPORTS_CONTEXTLESS_SIGS 0

#else
#define CRYPTON_DECAF_EDDSA_448_SUPPORTS_CONTEXTLESS_SIGS 0

#endif

/** Prehash context (raw), because each EdDSA instance has a different prehash. */
#define crypton_decaf_ed448_prehash_ctx_s   crypton_decaf_shake256_ctx_s

/** Prehash context, array[1] form. */
#define crypton_decaf_ed448_prehash_ctx_t   crypton_decaf_shake256_ctx_t
    
/** Prehash update. */
#define crypton_decaf_ed448_prehash_update  crypton_decaf_shake256_update
    
/** Prehash destroy. */
#define crypton_decaf_ed448_prehash_destroy crypton_decaf_shake256_destroy

/** EdDSA encoding ratio. */
#define CRYPTON_DECAF_448_EDDSA_ENCODE_RATIO 4

/** EdDSA decoding ratio. */
#define CRYPTON_DECAF_448_EDDSA_DECODE_RATIO (4 / 4)
    
#ifndef CRYPTON_DECAF_EDDSA_NON_KEYPAIR_API_IS_DEPRECATED
/** If 1, add deprecation attribute to non-keypair API functions. Now deprecated. */
#define CRYPTON_DECAF_EDDSA_NON_KEYPAIR_API_IS_DEPRECATED 1
#endif

/** @cond internal */
/** @brief Scheduled EdDSA keypair */
typedef struct crypton_decaf_eddsa_448_keypair_s {
    uint8_t privkey[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES];
    uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES];
}  crypton_decaf_eddsa_448_keypair_s, crypton_decaf_eddsa_448_keypair_t[1];
/** @endcond */

/**
 * @brief EdDSA key generation.  This function uses a different (non-Decaf)
 * encoding.
 *
 * @param [out] pubkey The public key.
 * @param [in] privkey The private key.
 */    
void CRYPTON_DECAF_API_VIS crypton_decaf_ed448_derive_public_key (
    uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t privkey[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES]
) CRYPTON_DECAF_NONNULL CRYPTON_DECAF_NOINLINE;

/**
 * @brief EdDSA keypair scheduling.  This is to add a safer version of the signing algorithm,
 * where it is harder to use the wrong pubkey for your private key..
 *
 * @param [out] keypair The scheduled keypair.
 * @param [in] privkey The private key.
 */    
void CRYPTON_DECAF_API_VIS crypton_decaf_ed448_derive_keypair (
    crypton_decaf_eddsa_448_keypair_t keypair,
    const uint8_t privkey[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES]
) CRYPTON_DECAF_NONNULL CRYPTON_DECAF_NOINLINE;

/**
 * @brief Extract the public key from an EdDSA keypair.
 *
 * @param [out] pubkey The public key.
 * @param [in] keypair The keypair.
 */    
void CRYPTON_DECAF_API_VIS crypton_decaf_ed448_keypair_extract_public_key (
    uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const crypton_decaf_eddsa_448_keypair_t keypair
) CRYPTON_DECAF_NONNULL CRYPTON_DECAF_NOINLINE;

/**
 * @brief Extract the private key from an EdDSA keypair.
 *
 * @param [out] privkey The private key.
 * @param [in] keypair The keypair.
 */    
void CRYPTON_DECAF_API_VIS crypton_decaf_ed448_keypair_extract_private_key (
    uint8_t privkey[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES],
    const crypton_decaf_eddsa_448_keypair_t keypair
) CRYPTON_DECAF_NONNULL CRYPTON_DECAF_NOINLINE;

/**
 * @brief EdDSA keypair destructor.
 * @param [in] pubkey The keypair.
 */    
void CRYPTON_DECAF_API_VIS crypton_decaf_ed448_keypair_destroy (
    crypton_decaf_eddsa_448_keypair_t keypair
) CRYPTON_DECAF_NONNULL CRYPTON_DECAF_NOINLINE;

/**
 * @brief EdDSA signing.  However, this API is deprecated because it isn't safe: if the wrong
 * public key is passed, it would reveal the private key.  Instead, this function checks that
 * the public key is correct, and otherwise aborts.
 *
 * @deprecated Use CRYPTON_DECAF_API_VIS crypton_decaf_ed448_keypair_sign instead.
 *
 * @param [out] signature The signature.
 * @param [in] privkey The private key.
 * @param [in] pubkey The public key.
 * @param [in] message The message to sign.
 * @param [in] message_len The length of the message.
 * @param [in] prehashed Nonzero if the message is actually the hash of something you want to sign.
 * @param [in] context A "context" for this signature of up to 255 bytes.
 * @param [in] context_len Length of the context.
 *
 * @warning For Ed25519, it is unsafe to use the same key for both prehashed and non-prehashed
 * messages, at least without some very careful protocol-level disambiguation.  For Ed448 it is
 * safe.  The C++ wrapper is designed to make it harder to screw this up, but this C code gives
 * you no seat belt.
 */  
void CRYPTON_DECAF_API_VIS crypton_decaf_ed448_sign (
    uint8_t signature[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t privkey[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES],
    const uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed,
    const uint8_t *context,
    uint8_t context_len
) __attribute__((nonnull(1,2,3))) CRYPTON_DECAF_NOINLINE
#if CRYPTON_DECAF_EDDSA_NON_KEYPAIR_API_IS_DEPRECATED
  CRYPTON_DECAF_DEPRECATED("Passing the pubkey and privkey separately is unsafe, use crypton_decaf_ed448_keypair_sign")
#endif
;

/**
 * @brief EdDSA signing with prehash.  However, this API is deprecated because it isn't safe: if the wrong
 * public key is passed, it would reveal the private key.  Instead, this function checks that
 * the public key is correct, and otherwise aborts.
 *
 * @deprecated Use CRYPTON_DECAF_API_VIS crypton_decaf_ed448_keypair_sign_prehash instead.
 *
 * @param [out] signature The signature.
 * @param [in] privkey The private key.
 * @param [in] pubkey The public key.
 * @param [in] hash The hash of the message.  This object will not be modified by the call.
 * @param [in] context A "context" for this signature of up to 255 bytes.  Must be the same as what was used for the prehash.
 * @param [in] context_len Length of the context.
 */  
void CRYPTON_DECAF_API_VIS crypton_decaf_ed448_sign_prehash (
    uint8_t signature[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t privkey[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES],
    const uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const crypton_decaf_ed448_prehash_ctx_t hash,
    const uint8_t *context,
    uint8_t context_len
) __attribute__((nonnull(1,2,3,4))) CRYPTON_DECAF_NOINLINE
#if CRYPTON_DECAF_EDDSA_NON_KEYPAIR_API_IS_DEPRECATED
  CRYPTON_DECAF_DEPRECATED("Passing the pubkey and privkey separately is unsafe, use crypton_decaf_ed448_keypair_sign_prehash")
#endif
;

/**
 * @brief EdDSA signing.
 *
 * @param [out] signature The signature.
 * @param [in] keypair The private and public key.
 * @param [in] message The message to sign.
 * @param [in] message_len The length of the message.
 * @param [in] prehashed Nonzero if the message is actually the hash of something you want to sign.
 * @param [in] context A "context" for this signature of up to 255 bytes.
 * @param [in] context_len Length of the context.
 */  
void CRYPTON_DECAF_API_VIS crypton_decaf_ed448_keypair_sign (
    uint8_t signature[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES],
    const crypton_decaf_eddsa_448_keypair_t keypair,
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed,
    const uint8_t *context,
    uint8_t context_len
) __attribute__((nonnull(1,2,3))) CRYPTON_DECAF_NOINLINE;

/**
 * @brief EdDSA signing with prehash.
 *
 * @param [out] signature The signature.
 * @param [in] keypair The private and public key.
 * @param [in] hash The hash of the message.  This object will not be modified by the call.
 * @param [in] context A "context" for this signature of up to 255 bytes.  Must be the same as what was used for the prehash.
 * @param [in] context_len Length of the context.
 */  
void CRYPTON_DECAF_API_VIS crypton_decaf_ed448_keypair_sign_prehash (
    uint8_t signature[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES],
    const crypton_decaf_eddsa_448_keypair_t keypair,
    const crypton_decaf_ed448_prehash_ctx_t hash,
    const uint8_t *context,
    uint8_t context_len
) __attribute__((nonnull(1,2,3,4))) CRYPTON_DECAF_NOINLINE;
    
/**
 * @brief Prehash initialization, with contexts if supported.
 *
 * @param [out] hash The hash object to be initialized.
 */
void CRYPTON_DECAF_API_VIS crypton_decaf_ed448_prehash_init (
    crypton_decaf_ed448_prehash_ctx_t hash
) __attribute__((nonnull(1))) CRYPTON_DECAF_NOINLINE;

/**
 * @brief EdDSA signature verification.
 *
 * Uses the standard (i.e. less-strict) verification formula.
 *
 * @param [in] signature The signature.
 * @param [in] pubkey The public key.
 * @param [in] message The message to verify.
 * @param [in] message_len The length of the message.
 * @param [in] prehashed Nonzero if the message is actually the hash of something you want to verify.
 * @param [in] context A "context" for this signature of up to 255 bytes.
 * @param [in] context_len Length of the context.
 *
 * @warning For Ed25519, it is unsafe to use the same key for both prehashed and non-prehashed
 * messages, at least without some very careful protocol-level disambiguation.  For Ed448 it is
 * safe.  The C++ wrapper is designed to make it harder to screw this up, but this C code gives
 * you no seat belt.
 */
crypton_decaf_error_t CRYPTON_DECAF_API_VIS crypton_decaf_ed448_verify (
    const uint8_t signature[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed,
    const uint8_t *context,
    uint8_t context_len
) __attribute__((nonnull(1,2))) CRYPTON_DECAF_NOINLINE;

/**
 * @brief EdDSA signature verification.
 *
 * Uses the standard (i.e. less-strict) verification formula.
 *
 * @param [in] signature The signature.
 * @param [in] pubkey The public key.
 * @param [in] hash The hash of the message.  This object will not be modified by the call.
 * @param [in] context A "context" for this signature of up to 255 bytes.  Must be the same as what was used for the prehash.
 * @param [in] context_len Length of the context.
 *
 * @warning For Ed25519, it is unsafe to use the same key for both prehashed and non-prehashed
 * messages, at least without some very careful protocol-level disambiguation.  For Ed448 it is
 * safe.  The C++ wrapper is designed to make it harder to screw this up, but this C code gives
 * you no seat belt.
 */
crypton_decaf_error_t CRYPTON_DECAF_API_VIS crypton_decaf_ed448_verify_prehash (
    const uint8_t signature[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const crypton_decaf_ed448_prehash_ctx_t hash,
    const uint8_t *context,
    uint8_t context_len
) __attribute__((nonnull(1,2))) CRYPTON_DECAF_NOINLINE;

/**
 * @brief EdDSA point encoding.  Used internally, exposed externally.
 * Multiplies by CRYPTON_DECAF_448_EDDSA_ENCODE_RATIO first.
 *
 * The multiplication is required because the EdDSA encoding represents
 * the cofactor information, but the Decaf encoding ignores it (which
 * is the whole point).  So if you decode from EdDSA and re-encode to
 * EdDSA, the cofactor info must get cleared, because the intermediate
 * representation doesn't track it.
 *
 * The way libdecaf handles this is to multiply by
 * CRYPTON_DECAF_448_EDDSA_DECODE_RATIO when decoding, and by
 * CRYPTON_DECAF_448_EDDSA_ENCODE_RATIO when encoding.  The product of these
 * ratios is always exactly the cofactor 4, so the cofactor
 * ends up cleared one way or another.  But exactly how that shakes
 * out depends on the base points specified in RFC 8032.
 *
 * The upshot is that if you pass the Decaf/Ristretto base point to
 * this function, you will get CRYPTON_DECAF_448_EDDSA_ENCODE_RATIO times the
 * EdDSA base point.
 *
 * @param [out] enc The encoded point.
 * @param [in] p The point.
 */       
void CRYPTON_DECAF_API_VIS crypton_decaf_448_point_mul_by_ratio_and_encode_like_eddsa (
    uint8_t enc[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const crypton_decaf_448_point_t p
) CRYPTON_DECAF_NONNULL CRYPTON_DECAF_NOINLINE;

/**
 * @brief EdDSA point decoding.  Multiplies by CRYPTON_DECAF_448_EDDSA_DECODE_RATIO,
 * and ignores cofactor information.
 *
 * See notes on crypton_decaf_448_point_mul_by_ratio_and_encode_like_eddsa
 *
 * @param [out] enc The encoded point.
 * @param [in] p The point.
 */       
crypton_decaf_error_t CRYPTON_DECAF_API_VIS crypton_decaf_448_point_decode_like_eddsa_and_mul_by_ratio (
    crypton_decaf_448_point_t p,
    const uint8_t enc[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES]
) CRYPTON_DECAF_NONNULL CRYPTON_DECAF_NOINLINE;

/**
 * @brief EdDSA to ECDH public key conversion
 * Deserialize the point to get y on Edwards curve,
 * Convert it to u coordinate on Montgomery curve.
 *
 * @warning This function does not check that the public key being converted
 * is a valid EdDSA public key (FUTURE?)
 *
 * @param[out] x The ECDH public key as in RFC7748(point on Montgomery curve)
 * @param[in] ed The EdDSA public key(point on Edwards curve)
 */
void CRYPTON_DECAF_API_VIS crypton_decaf_ed448_convert_public_key_to_x448 (
    uint8_t x[CRYPTON_DECAF_X448_PUBLIC_BYTES],
    const uint8_t ed[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES]
) CRYPTON_DECAF_NONNULL CRYPTON_DECAF_NOINLINE;

/**
 * @brief EdDSA to ECDH private key conversion
 * Using the appropriate hash function, hash the EdDSA private key
 * and keep only the lower bytes to get the ECDH private key
 *
 * @param[out] x The ECDH private key as in RFC7748
 * @param[in] ed The EdDSA private key
 */
void CRYPTON_DECAF_API_VIS crypton_decaf_ed448_convert_private_key_to_x448 (
    uint8_t x[CRYPTON_DECAF_X448_PRIVATE_BYTES],
    const uint8_t ed[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES]
) CRYPTON_DECAF_NONNULL CRYPTON_DECAF_NOINLINE;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __CRYPTON_DECAF_ED448_H__ */
