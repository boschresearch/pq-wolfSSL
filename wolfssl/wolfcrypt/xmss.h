/* xmss.h
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://github.com/XMSS/
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */

/*!
    \file wolfssl/wolfcrypt/xmss.h
*/

#ifndef WOLF_CRYPT_XMSS_H
#define WOLF_CRYPT_XMSS_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_XMSS

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdint.h>
#include <wolfssl/wolfcrypt/random.h>

/* Supported hash functions */
#define XMSS_SHA2_10_256 0
#define XMSS_SHA2_10_512 1

/* This is a result of the OID definitions in the draft; needed for parsing. */
#define XMSS_OID_LEN 4

/* XMSS parameter set */
#if XMSS_MODE == 1
    #define XMSS_SIG_TYPE            XMSS_SHA2_10_256
    #define XMSS_OID                0x00000001
    #define XMSS_N                  32
    #define XMSS_PADDING_LEN        32
    #define XMSS_WOTS_W             16
    #define XMSS_WOTS_LOG_W         4
    #define XMSS_WOTS_LEN2          3
    #define XMSS_FULL_HEIGHT        10
    #define XMSS_TREE_HEIGHT        10
    #define XMSS_D                  1
    #define XMSS_INDEX_BYTES        4
    #define XMSS_BDS_K              0
#elif XMSS_MODE == 5
    #define XMSS_SIG_TYPE           XMSS_SHA2_10_512
    #define XMSS_OID                0x00000004
    #define XMSS_N                  64
    #define XMSS_PADDING_LEN        64
    #define XMSS_WOTS_W             16
    #define XMSS_WOTS_LOG_W         4
    #define XMSS_WOTS_LEN2          3
    #define XMSS_FULL_HEIGHT        10
    #define XMSS_TREE_HEIGHT        10
    #define XMSS_D                  1
    #define XMSS_INDEX_BYTES        4
    #define XMSS_BDS_K              0
#endif

    #define XMSS_WOTS_LEN1          (8 * XMSS_N / XMSS_WOTS_LOG_W)
    #define XMSS_WOTS_LEN           (XMSS_WOTS_LEN1 + XMSS_WOTS_LEN2)
    #define XMSS_WOTS_SIG_BYTES     (XMSS_WOTS_LEN * XMSS_N)
    #define XMSS_SIG_BYTES          (XMSS_INDEX_BYTES + XMSS_N + XMSS_D * \
                                    XMSS_WOTS_SIG_BYTES + XMSS_FULL_HEIGHT * XMSS_N)
    #define XMSS_PK_BYTES           (2 * XMSS_N)
    /* When compiling xmss_core_fast.c */
    #define XMSS_SK_BYTES           (XMSS_INDEX_BYTES + 4 * XMSS_N + (2 * XMSS_D - 1) * \
                                    ((XMSS_TREE_HEIGHT + 1) * XMSS_N + 4 + XMSS_TREE_HEIGHT + \
                                    1 + XMSS_TREE_HEIGHT * XMSS_N  + (XMSS_TREE_HEIGHT >> 1) * \
                                    XMSS_N + (XMSS_TREE_HEIGHT - XMSS_BDS_K) * (7 + XMSS_N) + \
                                    ((1 << XMSS_BDS_K) - XMSS_BDS_K - 1) * XMSS_N + 4 ) + \
                                    (XMSS_D - 1) * XMSS_WOTS_SIG_BYTES)
    /* When compiling xmss_core.c, use
    #define XMSS_SK_BYTES           (XMSS_INDEX_BYTES + 4 * XMSS_N)
    */

#define XMSS_KEY_SIZE          XMSS_PK_BYTES + XMSS_OID_LEN
#define XMSS_PUB_KEY_SIZE      XMSS_PK_BYTES + XMSS_OID_LEN
#define XMSS_PRIV_KEY_SIZE     XMSS_SK_BYTES + XMSS_OID_LEN
#define XMSS_MAX_SIG_SIZE      XMSS_SIG_BYTES + 64
#define XMSS_SIG_SIZE          XMSS_SIG_BYTES

/**
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [OID || (32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [OID || root || PUB_SEED]
 */
int xmss_keypair(unsigned char *pk, unsigned char *sk,
                 WC_RNG *rng);

/**
 * Signs a message using an XMSS secret key.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 */
int xmss_crypto_sign(unsigned char *sk,
              unsigned char *sm, unsigned long long *smlen,
              const unsigned char *m, unsigned long long mlen);

/**
 * Verifies a given message signature pair using a given public key.
 *
 * Note: m and mlen are pure outputs which carry the message in case
 * verification succeeds. The (input) message is assumed to be contained in sm
 * which has the form [signature || message].
 */
int xmss_sign_open(unsigned char *m, unsigned long long *mlen,
                   const unsigned char *sm, unsigned long long smlen,
                   const unsigned char *pk);

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [OID || (ceil(h/8) bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [OID || root || PUB_SEED]
 */
int xmssmt_keypair(unsigned char *pk, unsigned char *sk,
                   WC_RNG *rng);

/**
 * Signs a message using an XMSSMT secret key.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 */
int xmssmt_sign(unsigned char *sk,
                unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen);

/**
 * Verifies a given message signature pair using a given public key.
 *
 * Note: m and mlen are pure outputs which carry the message in case
 * verification succeeds. The (input) message is assumed to be contained in sm
 * which has the form [signature || message].
 */
int xmssmt_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

/* XMSS key struct */

#ifndef WC_XMSSKEY_TYPE_DEFINED
    typedef struct XmssKey XmssKey;
    #define WC_XMSSKEY_TYPE_DEFINED
#endif

typedef struct XmssKey {
    uint8_t pk[XMSS_PUB_KEY_SIZE];
    uint8_t sk[XMSS_PRIV_KEY_SIZE];
} XmssKey;

/* XMSS API */
WOLFSSL_API int wc_InitXmssKey(XmssKey* key);
WOLFSSL_API void wc_FreeXmssKey(XmssKey* key);

WOLFSSL_API int wc_ExportXmssPublic(XmssKey* key,
                                    byte* out,
                                    word32* outLen);

WOLFSSL_API int wc_ImportXmssPublic(const byte* in,
                                    word32 inLen,
                                    XmssKey* key);

WOLFSSL_API int wc_ExportXmssPrivate(XmssKey* key,
                                     byte* out,
                                     word32* outLen);

WOLFSSL_API int wc_ImportXmssPrivate(const byte* priv,
                                     word32 privSz,
                                     XmssKey* key);

WOLFSSL_API int wc_ExportXmssKeys(XmssKey* key,
                                  byte* priv,
                                  word32 *privSz,
                                  byte* pub,
                                  word32 *pubSz);

WOLFSSL_API int wc_ImportXmssKeys(const byte* priv,
                                  word32 privSz,
                                  const byte* pub,
                                  word32 pubSz,
                                  XmssKey* key);

WOLFSSL_API int wc_XmssKeyGen(XmssKey* key,
                              WC_RNG* rng);

WOLFSSL_API int wc_XmssSign (uint8_t *out,
                      long long unsigned int *outlen,
                      const uint8_t *in,
                      size_t inlen,
                      XmssKey* key);

WOLFSSL_API int wc_XmssVerify(uint8_t *out,
                     long long unsigned int *outlen,
                     const uint8_t *in,
                     size_t inlen,
                     XmssKey *key);

#endif /* HAVE_XMSS */
#endif /* WOLF_CRYPT_XMSS_H */
