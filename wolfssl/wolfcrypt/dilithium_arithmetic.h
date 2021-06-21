/* dilithium_arithmetic.h
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
    \file wolfssl/wolfcrypt/dilithium_arithmetic.h
*/

#ifndef WOLF_CRYPT_DILITHIUM_ARITHMETIC_H
#define WOLF_CRYPT_DILITHIUM_ARITHMETIC_H

#ifdef HAVE_DILITHIUM

#include <stdint.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#ifdef __cplusplus
    extern "C" {
#endif

#define MONT_DILITHIUM -4186625 // 2^32 % Q
#define DILITH_QINV 58728449 // q^(-1) mod 2^32

int32_t montgomery_reduce64(int64_t a);

int32_t reduce32(int32_t a);

int32_t caddq(int32_t a);

int32_t freeze(int32_t a);

void dilithium_ntt(int32_t a[DILITH_N]);

void dilithium_invntt_tomont(int32_t a[DILITH_N]);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_DILITHIUM */
#endif /* WOLF_CRYPT_DILITHIUM_ARITHMETIC_H */
