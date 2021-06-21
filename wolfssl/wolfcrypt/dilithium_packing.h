/* dilithium_packing.h
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
    \file wolfssl/wolfcrypt/dilithium_packing.h
*/


#ifndef WOLF_CRYPT_DILITHIUM_PACKING_H
#define WOLF_CRYPT_DILITHIUM_PACKING_H

#ifdef HAVE_DILITHIUM

#include <stdint.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/dilithium_polynoms.h>

#ifdef __cplusplus
    extern "C" {
#endif

void pack_pk(uint8_t pk[DILITHIUM_CRYPTO_PUBLICKEYBYTES],
             const uint8_t rho[DILITH_SEEDBYTES], const polyveck *t1);

void pack_sk(uint8_t sk[DILITHIUM_CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[DILITH_SEEDBYTES],
             const uint8_t tr[DILITH_CRHBYTES],
             const uint8_t key[DILITH_SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2);

void pack_sig(uint8_t sig[DILITHIUM_CRYPTO_BYTES],
              const uint8_t c[DILITH_SEEDBYTES], const polyvecl *z, const polyveck *h);

void unpack_pk(uint8_t rho[DILITH_SEEDBYTES], polyveck *t1,
               const uint8_t pk[DILITHIUM_CRYPTO_PUBLICKEYBYTES]);

void unpack_sk(uint8_t rho[DILITH_SEEDBYTES],
               uint8_t tr[DILITH_CRHBYTES],
               uint8_t key[DILITH_SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[DILITHIUM_CRYPTO_SECRETKEYBYTES]);

int unpack_sig(uint8_t c[DILITH_SEEDBYTES], polyvecl *z, polyveck *h,
               const uint8_t sig[DILITHIUM_CRYPTO_BYTES]);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_DILITHIUM */
#endif /* WOLF_CRYPT_DILITHIUM_PACKING_H */
