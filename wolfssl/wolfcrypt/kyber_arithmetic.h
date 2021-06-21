/* kyber_arithmetic.h
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
    \file wolfssl/wolfcrypt/kyber_arithmetic.h
*/


#ifndef WOLF_CRYPT_KYBER_ARITHMETIC_H
#define WOLF_CRYPT_KYBER_ARITHMETIC_H

#ifdef HAVE_KYBER

#include <stdint.h>
#include <wolfssl/wolfcrypt/kyber.h>

#ifdef __cplusplus
    extern "C" {
#endif

#define MONT_KYBER 2285 // 2^16 mod Q
#define QINV_KYBER 62209 // q^(-1) mod 2^16

int16_t montgomery_reduce32(int32_t a);
int16_t barrett_reduce(int16_t a);
int16_t csubq(int16_t a);
void init_ntt();
void kyber_ntt(int16_t r[256]);
void kyber_invntt_tomont(int16_t r[256]);
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

extern const int16_t kyber_zetas[128];
extern const int16_t kyber_zetas_inv[128];

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_KYBER */
#endif /* WOLF_CRYPT_KYBER_ARITHMETIC_H */