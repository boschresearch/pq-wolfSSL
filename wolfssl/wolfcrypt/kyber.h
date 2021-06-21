/* kyber.h
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://pq-crystals.org/kyber/
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */

/*!
    \file wolfssl/wolfcrypt/kyber.h
*/


#ifndef WOLF_CRYPT_KYBER_H
#define WOLF_CRYPT_KYBER_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_KYBER

#ifdef __cplusplus
    extern "C" {
#endif

#include <wolfssl/wolfcrypt/integer.h>
#include <stdint.h>

/* Kyber Types */

typedef enum kyber_id {
    KYBER_512,
    KYBER_768,
    KYBER_1024,
} kyber_id;

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES              384
#define KYBER_POLYVECBYTES           (KYBER_K * KYBER_POLYBYTES)

#if KYBER_MODE == 1
    #define HAVE_KYBER_512
    #define KYBER_K                      2
    #define KYBER_ETA1                   3
    #define KYBER_POLYCOMPRESSEDBYTES    128
    #define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_MODE == 2
    #define HAVE_KYBER_768
    #define KYBER_K                      3
    #define KYBER_ETA1                   2
    #define KYBER_POLYCOMPRESSEDBYTES    128
    #define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_MODE == 3
    #define HAVE_KYBER_1024
    #define KYBER_K                      4
    #define KYBER_ETA1                   2
    #define KYBER_POLYCOMPRESSEDBYTES    160
    #define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif

#define KYBER_ETA2 2

#define KYBER_INDCPA_MSGBYTES       KYBER_SYMBYTES
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES +  KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES) /* 32 bytes of additional space to save H(pk) */
#define KYBER_CIPHERTEXTBYTES  KYBER_INDCPA_BYTES
#define XOF_BLOCKBYTES 168

typedef struct KyberParams {
        word32 n;
        word32 k;
        word32 q;
        word32 eta;
        word32 d_u;
        word32 d_v;
        mp_int delta;
} KyberParams;

/* Kyber Key */
typedef struct KyberKey {
    byte pub[KYBER_PUBLICKEYBYTES];
    byte priv[KYBER_SECRETKEYBYTES];
    byte ss[KYBER_SSBYTES];
    byte ct[KYBER_CIPHERTEXTBYTES];
} KyberKey;

WOLFSSL_API int wc_GenerateKyberKeyPair(KyberKey* key, WC_RNG* rng);
WOLFSSL_API int wc_KyberEncrypt(KyberKey* key, WC_RNG* rng);
WOLFSSL_API int wc_KyberDecrypt(KyberKey* key);
WOLFSSL_API int wc_InitKyberKey(KyberKey* key);
WOLFSSL_API void wc_FreeKyberKey(KyberKey* key);

void indcpa_keypair(byte *pk, byte *sk, WC_RNG* rng);
void indcpa_enc(byte *c, const byte *m, const byte *pk, const byte *coins);
void indcpa_dec(byte *m, const byte *c, const byte *sk);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_KYBER */
#endif /* WOLF_CRYPT_KYBER_H */

