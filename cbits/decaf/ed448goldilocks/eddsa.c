/**
 * @file ed448goldilocks/eddsa.c
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @cond internal
 * @brief EdDSA routines.
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */
#include "word.h"
#include <decaf/ed448.h>
#include <decaf/shake.h>
#include <decaf/sha512.h>
#include <string.h>

#define API_NAME "crypton_decaf_448"
#define API_NS(_id) crypton_decaf_448_##_id

#define hash_ctx_t   crypton_decaf_shake256_ctx_t
#define hash_init    crypton_decaf_shake256_init
#define hash_update  crypton_decaf_shake256_update
#define hash_final   crypton_decaf_shake256_final
#define hash_destroy crypton_decaf_shake256_destroy
#define hash_hash    crypton_decaf_shake256_hash

#define NO_CONTEXT CRYPTON_DECAF_EDDSA_448_SUPPORTS_CONTEXTLESS_SIGS
#define EDDSA_USE_SIGMA_ISOGENY 0
#define COFACTOR 4
#define EDDSA_PREHASH_BYTES 64

#if NO_CONTEXT
const uint8_t CRYPTON_NO_CONTEXT_POINTS_HERE = 0;
const uint8_t * const CRYPTON_DECAF_ED448_NO_CONTEXT = &CRYPTON_NO_CONTEXT_POINTS_HERE;
#endif

static void clamp (
    uint8_t secret_scalar_ser[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES]
) {
    /* Blarg */
    secret_scalar_ser[0] &= -COFACTOR;
    uint8_t hibit = (1<<0)>>1;
    if (hibit == 0) {
        secret_scalar_ser[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES - 1] = 0;
        secret_scalar_ser[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES - 2] |= 0x80;
    } else {
        secret_scalar_ser[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES - 1] &= hibit-1;
        secret_scalar_ser[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES - 1] |= hibit;
    }
}

static void hash_init_with_dom(
    hash_ctx_t hash,
    uint8_t prehashed,
    uint8_t for_prehash,
    const uint8_t *context,
    uint8_t context_len
) {
    hash_init(hash);

#if NO_CONTEXT
    if (context_len == 0 && context == CRYPTON_DECAF_ED448_NO_CONTEXT) {
        (void)prehashed;
        (void)for_prehash;
        (void)context;
        (void)context_len;
        return;
    }
#endif
    const char *dom_s = "SigEd448";
    const uint8_t dom[2] = {2+word_is_zero(prehashed)+word_is_zero(for_prehash), context_len};
    hash_update(hash,(const unsigned char *)dom_s, strlen(dom_s));
    hash_update(hash,dom,2);
    hash_update(hash,context,context_len);
}

void crypton_decaf_ed448_prehash_init (
    hash_ctx_t hash
) {
    hash_init(hash);
}

/* In this file because it uses the hash */
void crypton_decaf_ed448_convert_private_key_to_x448 (
    uint8_t x[CRYPTON_DECAF_X448_PRIVATE_BYTES],
    const uint8_t ed[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES]
) {
    /* pass the private key through hash_hash function */
    /* and keep the first CRYPTON_DECAF_X448_PRIVATE_BYTES bytes */
    hash_hash(
        x,
        CRYPTON_DECAF_X448_PRIVATE_BYTES,
        ed,
        CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES
    );
}
    
void crypton_decaf_ed448_derive_public_key (
    uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t privkey[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES]
) {
    /* only this much used for keygen */
    uint8_t secret_scalar_ser[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES];
    
    hash_hash(
        secret_scalar_ser,
        sizeof(secret_scalar_ser),
        privkey,
        CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES
    );
    clamp(secret_scalar_ser);
        
    API_NS(scalar_t) secret_scalar;
    API_NS(scalar_decode_long)(secret_scalar, secret_scalar_ser, sizeof(secret_scalar_ser));
    
    /* Since we are going to mul_by_cofactor during encoding, divide by it here.
     * However, the EdDSA base point is not the same as the decaf base point if
     * the sigma isogeny is in use: the EdDSA base point is on Etwist_d/(1-d) and
     * the decaf base point is on Etwist_d, and when converted it effectively
     * picks up a factor of 2 from the isogenies.  So we might start at 2 instead of 1. 
     */
    for (unsigned int c=1; c<CRYPTON_DECAF_448_EDDSA_ENCODE_RATIO; c <<= 1) {
        API_NS(scalar_halve)(secret_scalar,secret_scalar);
    }
    
    API_NS(point_t) p;
    API_NS(precomputed_scalarmul)(p,API_NS(precomputed_base),secret_scalar);
    
    API_NS(point_mul_by_ratio_and_encode_like_eddsa)(pubkey, p);
        
    /* Cleanup */
    API_NS(scalar_destroy)(secret_scalar);
    API_NS(point_destroy)(p);
    crypton_decaf_bzero(secret_scalar_ser, sizeof(secret_scalar_ser));
}
        
static void crypton_decaf_ed448_sign_internal (
    uint8_t signature[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t privkey[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES],
    const uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed,
    const uint8_t *context,
    uint8_t context_len
) {
    API_NS(scalar_t) secret_scalar;
    hash_ctx_t hash;
    {
        /* Schedule the secret key */
        struct {
            uint8_t secret_scalar_ser[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES];
            uint8_t seed[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES];
        } __attribute__((packed)) expanded;
        hash_hash(
            (uint8_t *)&expanded,
            sizeof(expanded),
            privkey,
            CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES
        );
        clamp(expanded.secret_scalar_ser);   
        API_NS(scalar_decode_long)(secret_scalar, expanded.secret_scalar_ser, sizeof(expanded.secret_scalar_ser));
    
        /* Hash to create the nonce */
        hash_init_with_dom(hash,prehashed,0,context,context_len);
        hash_update(hash,expanded.seed,sizeof(expanded.seed));
        hash_update(hash,message,message_len);
        crypton_decaf_bzero(&expanded, sizeof(expanded));
    }
    
    /* Decode the nonce */
    API_NS(scalar_t) nonce_scalar;
    {
        uint8_t nonce[2*CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES];
        hash_final(hash,nonce,sizeof(nonce));
        API_NS(scalar_decode_long)(nonce_scalar, nonce, sizeof(nonce));
        crypton_decaf_bzero(nonce, sizeof(nonce));
    }
    
    uint8_t nonce_point[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES] = {0};
    {
        /* Scalarmul to create the nonce-point */
        API_NS(scalar_t) nonce_scalar_2;
        API_NS(scalar_halve)(nonce_scalar_2,nonce_scalar);
        for (unsigned int c = 2; c < CRYPTON_DECAF_448_EDDSA_ENCODE_RATIO; c <<= 1) {
            API_NS(scalar_halve)(nonce_scalar_2,nonce_scalar_2);
        }
        
        API_NS(point_t) p;
        API_NS(precomputed_scalarmul)(p,API_NS(precomputed_base),nonce_scalar_2);
        API_NS(point_mul_by_ratio_and_encode_like_eddsa)(nonce_point, p);
        API_NS(point_destroy)(p);
        API_NS(scalar_destroy)(nonce_scalar_2);
    }
    
    API_NS(scalar_t) challenge_scalar;
    {
        /* Compute the challenge */
        hash_init_with_dom(hash,prehashed,0,context,context_len);
        hash_update(hash,nonce_point,sizeof(nonce_point));
        hash_update(hash,pubkey,CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES);
        hash_update(hash,message,message_len);
        uint8_t challenge[2*CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES];
        hash_final(hash,challenge,sizeof(challenge));
        hash_destroy(hash);
        API_NS(scalar_decode_long)(challenge_scalar,challenge,sizeof(challenge));
        crypton_decaf_bzero(challenge,sizeof(challenge));
    }
    
    API_NS(scalar_mul)(challenge_scalar,challenge_scalar,secret_scalar);
    API_NS(scalar_add)(challenge_scalar,challenge_scalar,nonce_scalar);
    
    crypton_decaf_bzero(signature,CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES);
    memcpy(signature,nonce_point,sizeof(nonce_point));
    API_NS(scalar_encode)(&signature[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],challenge_scalar);
    
    API_NS(scalar_destroy)(secret_scalar);
    API_NS(scalar_destroy)(nonce_scalar);
    API_NS(scalar_destroy)(challenge_scalar);
}

void crypton_decaf_ed448_sign (
    uint8_t signature[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t privkey[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES],
    const uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed,
    const uint8_t *context,
    uint8_t context_len
) {
    uint8_t rederived_pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES];
    crypton_decaf_ed448_derive_public_key(rederived_pubkey, privkey);
    if (CRYPTON_DECAF_TRUE != crypton_decaf_memeq(rederived_pubkey, pubkey, sizeof(rederived_pubkey))) {
        abort();
    }
    crypton_decaf_ed448_sign_internal(signature,privkey,rederived_pubkey,message,
        message_len,prehashed,context,context_len);
}

void crypton_decaf_ed448_sign_prehash (
    uint8_t signature[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t privkey[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES],
    const uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const crypton_decaf_ed448_prehash_ctx_t hash,
    const uint8_t *context,
    uint8_t context_len
) {
    uint8_t hash_output[EDDSA_PREHASH_BYTES];
    {
        crypton_decaf_ed448_prehash_ctx_t hash_too;
        memcpy(hash_too,hash,sizeof(hash_too));
        hash_final(hash_too,hash_output,sizeof(hash_output));
        hash_destroy(hash_too);
    }

    uint8_t rederived_pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES];
    crypton_decaf_ed448_derive_public_key(rederived_pubkey, privkey);
    if (CRYPTON_DECAF_TRUE != crypton_decaf_memeq(rederived_pubkey, pubkey, sizeof(rederived_pubkey))) {
        abort();
    }

    crypton_decaf_ed448_sign_internal(signature,privkey,rederived_pubkey,hash_output,
        sizeof(hash_output),1,context,context_len);
    crypton_decaf_bzero(hash_output,sizeof(hash_output));
}

void crypton_decaf_ed448_derive_keypair (
    crypton_decaf_eddsa_448_keypair_t keypair,
    const uint8_t privkey[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES]
) {
    memcpy(keypair->privkey, privkey, CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES);
    crypton_decaf_ed448_derive_public_key(keypair->pubkey, keypair->privkey);
}

void crypton_decaf_ed448_keypair_extract_public_key (
    uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const crypton_decaf_eddsa_448_keypair_t keypair
) {
    memcpy(pubkey,keypair->pubkey,CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES);
}

void crypton_decaf_ed448_keypair_extract_private_key (
    uint8_t privkey[CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES],
    const crypton_decaf_eddsa_448_keypair_t keypair
) {
    memcpy(privkey,keypair->privkey,CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES);
}

void crypton_decaf_ed448_keypair_destroy (
    crypton_decaf_eddsa_448_keypair_t keypair
) {
    crypton_decaf_bzero(keypair, sizeof(crypton_decaf_eddsa_448_keypair_t));
}

void crypton_decaf_ed448_keypair_sign (
    uint8_t signature[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES],
    const crypton_decaf_eddsa_448_keypair_t keypair,
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed,
    const uint8_t *context,
    uint8_t context_len
) {
    crypton_decaf_ed448_sign_internal(signature,keypair->privkey,keypair->pubkey,message,
        message_len,prehashed,context,context_len);
}

void crypton_decaf_ed448_keypair_sign_prehash (
    uint8_t signature[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES],
    const crypton_decaf_eddsa_448_keypair_t keypair,
    const crypton_decaf_ed448_prehash_ctx_t hash,
    const uint8_t *context,
    uint8_t context_len
) {
    uint8_t hash_output[EDDSA_PREHASH_BYTES];
    {
        crypton_decaf_ed448_prehash_ctx_t hash_too;
        memcpy(hash_too,hash,sizeof(hash_too));
        hash_final(hash_too,hash_output,sizeof(hash_output));
        hash_destroy(hash_too);
    }

    crypton_decaf_ed448_sign_internal(signature,keypair->privkey,keypair->pubkey,hash_output,
        sizeof(hash_output),1,context,context_len);
    crypton_decaf_bzero(hash_output,sizeof(hash_output));
}

crypton_decaf_error_t crypton_decaf_ed448_verify (
    const uint8_t signature[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed,
    const uint8_t *context,
    uint8_t context_len
) { 
    API_NS(point_t) pk_point, r_point;
    crypton_decaf_error_t error = API_NS(point_decode_like_eddsa_and_mul_by_ratio)(pk_point,pubkey);
    if (CRYPTON_DECAF_SUCCESS != error) { return error; }
    
    error = API_NS(point_decode_like_eddsa_and_mul_by_ratio)(r_point,signature);
    if (CRYPTON_DECAF_SUCCESS != error) { return error; }
    
    API_NS(scalar_t) challenge_scalar;
    {
        /* Compute the challenge */
        hash_ctx_t hash;
        hash_init_with_dom(hash,prehashed,0,context,context_len);
        hash_update(hash,signature,CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES);
        hash_update(hash,pubkey,CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES);
        hash_update(hash,message,message_len);
        uint8_t challenge[2*CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES];
        hash_final(hash,challenge,sizeof(challenge));
        hash_destroy(hash);
        API_NS(scalar_decode_long)(challenge_scalar,challenge,sizeof(challenge));
        crypton_decaf_bzero(challenge,sizeof(challenge));
    }
    API_NS(scalar_sub)(challenge_scalar, API_NS(scalar_zero), challenge_scalar);
    
    API_NS(scalar_t) response_scalar;
    error = API_NS(scalar_decode)(
        response_scalar,
        &signature[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES]
    );
    if (CRYPTON_DECAF_SUCCESS != error) { return error; }

#if CRYPTON_DECAF_448_SCALAR_BYTES < CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES
    for (unsigned i = CRYPTON_DECAF_448_SCALAR_BYTES;
         i < CRYPTON_DECAF_EDDSA_448_PRIVATE_BYTES;
         i++) {
        if (signature[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES+i] != 0x00) {
            return CRYPTON_DECAF_FAILURE;
        }
    }
#endif
    
    for (unsigned c=1; c<CRYPTON_DECAF_448_EDDSA_DECODE_RATIO; c<<=1) {
        API_NS(scalar_add)(response_scalar,response_scalar,response_scalar);
    }
    
    
    /* pk_point = -c(x(P)) + (cx + k)G = kG */
    API_NS(base_double_scalarmul_non_secret)(
        pk_point,
        response_scalar,
        pk_point,
        challenge_scalar
    );
    return crypton_decaf_succeed_if(API_NS(point_eq(pk_point,r_point)));
}


crypton_decaf_error_t crypton_decaf_ed448_verify_prehash (
    const uint8_t signature[CRYPTON_DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t pubkey[CRYPTON_DECAF_EDDSA_448_PUBLIC_BYTES],
    const crypton_decaf_ed448_prehash_ctx_t hash,
    const uint8_t *context,
    uint8_t context_len
) {
    crypton_decaf_error_t ret;
    
    uint8_t hash_output[EDDSA_PREHASH_BYTES];
    {
        crypton_decaf_ed448_prehash_ctx_t hash_too;
        memcpy(hash_too,hash,sizeof(hash_too));
        hash_final(hash_too,hash_output,sizeof(hash_output));
        hash_destroy(hash_too);
    }
    
    ret = crypton_decaf_ed448_verify(signature,pubkey,hash_output,sizeof(hash_output),1,context,context_len);
    
    return ret;
}
