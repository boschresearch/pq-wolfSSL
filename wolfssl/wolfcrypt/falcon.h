/* falcon.h
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from Falcon Project
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */

/*!
    \file wolfssl/wolfcrypt/falcon.h
*/

#ifndef WOLF_CRYPT_FALCON_H
#define WOLF_CRYPT_FALCON_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_FALCON

#ifdef __cplusplus
    extern "C" {
#endif

#if FALCON_MODE == 1
    #define FALCON_BITMODE                 512
    #define FALCON_CRYPTO_SECRETKEYBYTES   1281
    #define FALCON_CRYPTO_PUBLICKEYBYTES   897
    #define FALCON_CRYPTO_BYTES            690
    #define FALCON_CRYPTO_ALGNAME          "Falcon-512"
    #define FALCON_KEYGEN_BUF              14336 /* FALCON_KEYGEN_TEMP_9 */
    #define FALCON_I                       9
#elif FALCON_MODE == 5
    #define FALCON_BITMODE                 1024
    #define FALCON_CRYPTO_SECRETKEYBYTES   2305
    #define FALCON_CRYPTO_PUBLICKEYBYTES   1793
    #define FALCON_CRYPTO_BYTES            1330
    #define FALCON_CRYPTO_ALGNAME          "Falcon-1024"
    #define FALCON_KEYGEN_BUF              28672 /* FALCON_KEYGEN_TEMP_10 */
    #define FALCON_I                       10
#endif

#define FALCON_KEY_SIZE          FALCON_CRYPTO_PUBLICKEYBYTES
#define FALCON_PUB_KEY_SIZE      FALCON_CRYPTO_PUBLICKEYBYTES
#define FALCON_PRIV_KEY_SIZE     FALCON_CRYPTO_SECRETKEYBYTES
#define FALCON_SIG_SIZE          FALCON_CRYPTO_BYTES

#include <stddef.h>
#include <stdint.h>
#include <wolfssl/wolfcrypt/integer.h>

/* Falcon key struct*/

#ifndef WC_FALCONKEY_TYPE_DEFINED
    typedef struct FalconKey FalconKey;
    #define WC_FALCONKEY_TYPE_DEFINED
#endif

typedef struct FalconKey {
    uint8_t pk[FALCON_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[FALCON_CRYPTO_SECRETKEYBYTES];
} FalconKey;

/* Falcon API */

WOLFSSL_API int wc_InitFalconKey(FalconKey* key);
WOLFSSL_API void wc_FreeFalconKey(FalconKey* key);

WOLFSSL_API int wc_ExportFalconPublic(FalconKey* key,
                                         byte* out,
                                         word32* outLen);

WOLFSSL_API int wc_ImportFalconPublic(const byte* in,
                                         word32 inLen,
                                         FalconKey* key);

WOLFSSL_API int wc_ExportFalconPrivate(FalconKey* key,
                                          byte* out,
                                          word32* outLen);

WOLFSSL_API int wc_ImportFalconPrivate(const byte* priv,
                                          word32 privSz,
                                          FalconKey* key);

WOLFSSL_API int wc_ExportFalconKeys(FalconKey* key,
                                       byte* priv,
                                       word32 *privSz,
                                       byte* pub,
                                       word32 *pubSz);

WOLFSSL_API int wc_ImportFalconKeys(const byte* priv,
                                       word32 privSz,
                                       const byte* pub,
                                       word32 pubSz,
                                       FalconKey* key);

WOLFSSL_API int wc_FalconKeyGen(FalconKey* key,
                                    WC_RNG* rng);

WOLFSSL_API int wc_FalconSign (uint8_t *out,
                      size_t *outlen,
                      const uint8_t *in,
                      size_t inlen,
                      FalconKey* key,
                      WC_RNG* rng);

WOLFSSL_API int wc_FalconVerify(uint8_t *out,
                     size_t *outlen,
                     const uint8_t *in,
                     size_t inlen,
                     FalconKey *key);

/* Falcon reference implementation prototypes */

int falcon_crypto_sign_keypair(uint8_t *pk, uint8_t *sk, WC_RNG *rng);

int falcon_crypto_sign(uint8_t *sm, size_t *smlen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *sk, WC_RNG *rng);

int falcon_crypto_sign_open(uint8_t *m, size_t *mlen,
                            const uint8_t *sm, size_t smlen,
                            const uint8_t *pk);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_FALCON */
#endif /* WOLF_CRYPT_FALCON_H */
