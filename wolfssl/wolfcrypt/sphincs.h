/* sphincs.h
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://sphincs.org/
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */


/*!
    \file wolfssl/wolfcrypt/sphincs.h
*/

#ifndef WOLF_CRYPT_SPHINCS_H
#define WOLF_CRYPT_SPHINCS_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_SPHINCS

#ifdef __cplusplus
    extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <wolfssl/wolfcrypt/integer.h>

#define SHA256_128F_SIMPLE 0    // OK, but TLS does not work ("Encrypted data too long error", -328)
#define SHA256_128S_SIMPLE 1    // OK, TLS OK as well
#define SHA256_128S_ROBUST 2    // OK, TLS OK as well
#define SHA256_192F_SIMPLE 3    // FAILS (CORE DUMPED)
#define SHA256_192S_SIMPLE 4    // OK, TLS OK as well
#define SHA256_192S_ROBUST 5    // OK, TLS OK as well

/* Sphincs+ parameter set */
#if SPX_MODE == 1
    #if SPX_TYPE == SHA256_128F_SIMPLE
        /* Hash output length in bytes. */
        #define SPX_N 16
        /* FORS tree dimensions. */
        #define SPX_FORS_HEIGHT 6
        #define SPX_FORS_TREES 33
        /* Height of the hypertree. */
        #define SPX_FULL_HEIGHT 66
        /* Number of subtree layer. */
        #define SPX_D 22
        /* Winternitz parameter, */
        #define SPX_WOTS_W 16
        #define SPX_THASH_SIMPLE
    #elif SPX_TYPE == SHA256_128S_SIMPLE
        /* Hash output length in bytes. */
        #define SPX_N 16
        /* FORS tree dimensions. */
        #define SPX_FORS_HEIGHT 12
        #define SPX_FORS_TREES 14
        /* Height of the hypertree. */
        #define SPX_FULL_HEIGHT 63
        /* Number of subtree layer. */
        #define SPX_D 7
        /* Winternitz parameter, */
        #define SPX_WOTS_W 16
        #define SPX_THASH_SIMPLE
    #elif SPX_TYPE == SHA256_128S_ROBUST
        /* Hash output length in bytes. */
        #define SPX_N 16
        /* FORS tree dimensions. */
        #define SPX_FORS_HEIGHT 12
        #define SPX_FORS_TREES 14
        /* Height of the hypertree. */
        #define SPX_FULL_HEIGHT 63
        /* Number of subtree layer. */
        #define SPX_D 7
        /* Winternitz parameter, */
        #define SPX_WOTS_W 16
        #define SPX_THASH_ROBUST
    #endif
#elif SPX_MODE == 3
    #if SPX_TYPE == SHA256_192F_SIMPLE
        /* Hash output length in bytes. */
        #define SPX_N 24
        /* FORS tree dimensions. */
        #define SPX_FORS_HEIGHT 8
        /* FORS tree dimensions. */
        #define SPX_FORS_TREES 33
        /* Height of the hypertree. */
        #define SPX_FULL_HEIGHT 66
        /* Number of subtree layer. */
        #define SPX_D 22
        /* Winternitz parameter, */
        #define SPX_WOTS_W 16
        #define SPX_THASH_SIMPLE
    #elif SPX_TYPE == SHA256_192S_SIMPLE
        /* Hash output length in bytes. */
        #define SPX_N 24
        /* FORS tree dimensions. */
        #define SPX_FORS_HEIGHT 14
        /* FORS tree dimensions. */
        #define SPX_FORS_TREES 17
        /* Height of the hypertree. */
        #define SPX_FULL_HEIGHT 63
        /* Number of subtree layer. */
        #define SPX_D 7
        /* Winternitz parameter, */
        #define SPX_WOTS_W 16
        #define SPX_THASH_SIMPLE
    #elif SPX_TYPE == SHA256_192S_ROBUST
        /* Hash output length in bytes. */
        #define SPX_N 24
        /* FORS tree dimensions. */
        #define SPX_FORS_HEIGHT 14
        /* FORS tree dimensions. */
        #define SPX_FORS_TREES 17
        /* Height of the hypertree. */
        #define SPX_FULL_HEIGHT 63
        /* Number of subtree layer. */
        #define SPX_D 7
        /* Winternitz parameter, */
        #define SPX_WOTS_W 16
        #define SPX_THASH_ROBUST
    #endif
#endif
/* The hash function is defined by linking a different hash.c file, as opposed
   to setting a #define constant. */

/* For clarity */
#define SPX_ADDR_BYTES 32

/* WOTS parameters. */
#if SPX_WOTS_W == 256
    #define SPX_WOTS_LOGW 8
#elif SPX_WOTS_W == 16
    #define SPX_WOTS_LOGW 4
#else
    #error SPX_WOTS_W assumed 16 or 256
#endif

#define SPX_WOTS_LEN1 (8 * SPX_N / SPX_WOTS_LOGW)

/* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
#if SPX_WOTS_W == 256
    #if SPX_N <= 1
        #define SPX_WOTS_LEN2 1
    #elif SPX_N <= 256
        #define SPX_WOTS_LEN2 2
    #else
        #error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
    #endif
#elif SPX_WOTS_W == 16
    #if SPX_N <= 8
        #define SPX_WOTS_LEN2 2
    #elif SPX_N <= 136
        #define SPX_WOTS_LEN2 3
    #elif SPX_N <= 256
        #define SPX_WOTS_LEN2 4
    #else
        #error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
    #endif
#endif

#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* Subtree size. */
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

#if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT
    #error SPX_D should always divide SPX_FULL_HEIGHT
#endif

/* FORS parameters. */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

/* Resulting SPX sizes. */
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES +\
                   SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

/* Optionally, signing can be made non-deterministic using optrand.
   This can help counter side-channel attacks that would benefit from
   getting a large number of traces when the signer uses the same nodes. */
#define SPX_OPTRAND_BYTES 32

#include <wolfssl/wolfcrypt/sphincs_sha256_offsets.h>

/* Sphincs+ API */

#define SPHINCS_CRYPTO_SECRETKEYBYTES SPX_SK_BYTES
#define SPHINCS_CRYPTO_PUBLICKEYBYTES SPX_PK_BYTES
#define SPHINCS_CRYPTO_BYTES SPX_BYTES
#define SPHINCS_CRYPTO_SEEDBYTES 3*SPX_N

#define SPHINCS_KEY_SIZE          SPHINCS_CRYPTO_PUBLICKEYBYTES
#define SPHINCS_PUB_KEY_SIZE      SPHINCS_CRYPTO_PUBLICKEYBYTES
#define SPHINCS_PRIV_KEY_SIZE     SPHINCS_CRYPTO_SECRETKEYBYTES
#define SPHINCS_SIG_SIZE          SPHINCS_CRYPTO_BYTES

int sphincs_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed);

int sphincs_crypto_sign_keypair(unsigned char *pk, unsigned char *sk, WC_RNG *rng);

int sphincs_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                          size_t mlen, const uint8_t *sk, WC_RNG *rng);

int sphincs_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk);

int sphincs_crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk, WC_RNG *rng);

int sphincs_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

/* Sphincs key struct*/

#ifndef WC_SPHINCSKEY_TYPE_DEFINED
    typedef struct SphincsKey SphincsKey;
    #define WC_SPHINCSKEY_TYPE_DEFINED
#endif

typedef struct SphincsKey {
    uint8_t pk[SPHINCS_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[SPHINCS_CRYPTO_SECRETKEYBYTES];
} SphincsKey;

/* Sphincs API */

WOLFSSL_API int wc_InitSphincsKey(SphincsKey* key);
WOLFSSL_API void wc_FreeSphincsKey(SphincsKey* key);

WOLFSSL_API int wc_ExportSphincsPublic(SphincsKey* key,
                                         byte* out,
                                         word32* outLen);

WOLFSSL_API int wc_ImportSphincsPublic(const byte* in,
                                         word32 inLen,
                                         SphincsKey* key);

WOLFSSL_API int wc_ExportSphincsPrivate(SphincsKey* key,
                                          byte* out,
                                          word32* outLen);

WOLFSSL_API int wc_ImportSphincsPrivate(const byte* priv,
                                          word32 privSz,
                                          SphincsKey* key);

WOLFSSL_API int wc_ExportSphincsKeys(SphincsKey* key,
                                       byte* priv,
                                       word32 *privSz,
                                       byte* pub,
                                       word32 *pubSz);

WOLFSSL_API int wc_ImportSphincsKeys(const byte* priv,
                                       word32 privSz,
                                       const byte* pub,
                                       word32 pubSz,
                                       SphincsKey* key);

WOLFSSL_API int wc_SphincsKeyGen(SphincsKey* key,
                                    WC_RNG* rng);

WOLFSSL_API int wc_SphincsSign (uint8_t *out,
                      long long unsigned int *outlen,
                      const uint8_t *in,
                      size_t inlen,
                      SphincsKey* key,
                      WC_RNG* rng);

WOLFSSL_API int wc_SphincsVerify(uint8_t *out,
                     long long unsigned int *outlen,
                     const uint8_t *in,
                     size_t inlen,
                     SphincsKey *key);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_SPHINCS */
#endif /* WOLF_CRYPT_SPHINCS_H */
