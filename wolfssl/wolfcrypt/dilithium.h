/* dilithium.h
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://pq-crystals.org/dilithium/
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */

/*!
    \file wolfssl/wolfcrypt/dilithium.h
*/

#ifndef WOLF_CRYPT_DILITHIUM_H
#define WOLF_CRYPT_DILITHIUM_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_DILITHIUM

#ifdef __cplusplus
    extern "C" {
#endif

#define DILITH_SEEDBYTES 32
#define DILITH_CRHBYTES 48
#define DILITH_N 256
#define DILITH_Q 8380417
#define DILITH_D 13
#define ROOT_OF_UNITY 1753

#if DILITHIUM_MODE == 2
    #define DILITH_K 4
    #define DILITH_L 4
    #define DILITH_ETA 2
    #define TAU 39
    #define BETA 78
    #define GAMMA1 (1 << 17)
    #define GAMMA2 ((DILITH_Q-1)/88)
    #define OMEGA 80
    #define DILITHIUM_CRYPTO_PUBLICKEYBYTES 1312
    #define DILITHIUM_CRYPTO_SECRETKEYBYTES 2544
    #define DILITHIUM_CRYPTO_BYTES 2420

#elif DILITHIUM_MODE == 3
    #define DILITH_K 6
    #define DILITH_L 5
    #define DILITH_ETA 4
    #define TAU 49
    #define BETA 196
    #define GAMMA1 (1 << 19)
    #define GAMMA2 ((DILITH_Q-1)/32)
    #define OMEGA 55
    #define DILITHIUM_CRYPTO_PUBLICKEYBYTES 1952
    #define DILITHIUM_CRYPTO_SECRETKEYBYTES 4016
    #define DILITHIUM_CRYPTO_BYTES 3293

#elif DILITHIUM_MODE == 5
    #define DILITH_K 8
    #define DILITH_L 7
    #define DILITH_ETA 2
    #define TAU 60
    #define BETA 120
    #define GAMMA1 (1 << 19)
    #define GAMMA2 ((DILITH_Q-1)/32)
    #define OMEGA 75
    #define DILITHIUM_CRYPTO_PUBLICKEYBYTES 2592
    #define DILITHIUM_CRYPTO_SECRETKEYBYTES 4880
    #define DILITHIUM_CRYPTO_BYTES 4595
#endif

#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416
#define POLYVECH_PACKEDBYTES (OMEGA + DILITH_K)

#if GAMMA1 == (1 << 17)
    #define POLYZ_PACKEDBYTES   576
    #elif GAMMA1 == (1 << 19)
    #define POLYZ_PACKEDBYTES   640
#endif

#if GAMMA2 == (DILITH_Q-1)/88
    #define POLYW1_PACKEDBYTES  192
    #elif GAMMA2 == (DILITH_Q-1)/32
    #define POLYW1_PACKEDBYTES  128
#endif

#if DILITH_ETA == 2
    #define POLYETA_PACKEDBYTES  96
#elif DILITH_ETA == 4
#define POLYETA_PACKEDBYTES 128
#endif

#define DILITHIUM_KEY_SIZE          DILITHIUM_CRYPTO_PUBLICKEYBYTES
#define DILITHIUM_PUB_KEY_SIZE      DILITHIUM_CRYPTO_PUBLICKEYBYTES
#define DILITHIUM_PRIV_KEY_SIZE     DILITHIUM_CRYPTO_SECRETKEYBYTES
#define DILITHIUM_SIG_SIZE          DILITHIUM_CRYPTO_BYTES

/*
    Code to generate Dilithium parameters:

    #define DILITHIUM_CRYPTO_PUBLICKEYBYTES (DILITH_SEEDBYTES + DILITH_K*POLYT1_PACKEDBYTES)
    #define DILITHIUM_CRYPTO_SECRETKEYBYTES (2*DILITH_SEEDBYTES + DILITH_CRHBYTES \
                                + DILITH_L*POLYETA_PACKEDBYTES \
                                + DILITH_K*POLYETA_PACKEDBYTES \
                                + DILITH_K*POLYT0_PACKEDBYTES)
    #define DILITHIUM_CRYPTO_BYTES (DILITH_SEEDBYTES + DILITH_L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)
*/

#include <stddef.h>
#include <stdint.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/dilithium_polynoms.h>

/* Dilithium key struct*/

#ifndef WC_DILITHIUMKEY_TYPE_DEFINED
    typedef struct DilithiumKey DilithiumKey;
    #define WC_DILITHIUMKEY_TYPE_DEFINED
#endif

typedef struct DilithiumKey {
    uint8_t pk[DILITHIUM_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[DILITHIUM_CRYPTO_SECRETKEYBYTES];
} DilithiumKey;

/* Dilithium API */
WOLFSSL_API int wc_InitDilithiumKey(DilithiumKey* key);
WOLFSSL_API void wc_FreeDilithiumKey(DilithiumKey* key);

WOLFSSL_API int wc_ExportDilithiumPublic(DilithiumKey* key,
                                         byte* out,
                                         word32* outLen);

WOLFSSL_API int wc_ImportDilithiumPublic(const byte* in,
                                         word32 inLen,
                                         DilithiumKey* key);

WOLFSSL_API int wc_ExportDilithiumPrivate(DilithiumKey* key,
                                          byte* out,
                                          word32* outLen);

WOLFSSL_API int wc_ImportDilithiumPrivate(const byte* priv,
                                          word32 privSz,
                                          DilithiumKey* key);

WOLFSSL_API int wc_ExportDilithiumKeys(DilithiumKey* key,
                                       byte* priv,
                                       word32 *privSz,
                                       byte* pub,
                                       word32 *pubSz);

WOLFSSL_API int wc_ImportDilithiumKeys(const byte* priv,
                                       word32 privSz,
                                       const byte* pub,
                                       word32 pubSz,
                                       DilithiumKey* key);

WOLFSSL_API int wc_DilithiumKeyGen(DilithiumKey* key,
                                    WC_RNG* rng);

WOLFSSL_API int wc_DilithiumSign (uint8_t *out,
                      size_t *outlen,
                      const uint8_t *in,
                      size_t inlen,
                      DilithiumKey* key,
                      WC_RNG* rng);

WOLFSSL_API int wc_DilithiumVerify(uint8_t *out,
                     size_t *outlen,
                     const uint8_t *in,
                     size_t inlen,
                     DilithiumKey *key);

/* Dilithium reference implementation prototypes */

void challenge(d_poly *c, const uint8_t seed[DILITH_SEEDBYTES]);

int dilithium_crypto_sign_keypair(uint8_t *pk, uint8_t *sk, WC_RNG *rng);

int dilithium_crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk, WC_RNG *rng);

int dilithium_crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk, WC_RNG *rng);

int dilithium_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *pk);

int dilithium_crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_DILITHIUM */
#endif /* WOLF_CRYPT_DILITHIUM_H */
