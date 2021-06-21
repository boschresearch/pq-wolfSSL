/* kyber_memory.h
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
    \file wolfssl/wolfcrypt/kyber_memory.h
*/


#ifndef WOLF_CRYPT_KYBER_MEMORY_H
#define WOLF_CRYPT_KYBER_MEMORY_H

#include <stdint.h>

#ifdef HAVE_KYBER

#ifdef __cplusplus
    extern "C" {
#endif

    uint32_t load24_littleendian(const uint8_t x[3]);
    uint32_t load32_littleendian(const uint8_t *x);
    uint64_t load64(const uint8_t *x);
    void store64(uint8_t *x, uint64_t u);
    int verify(const uint8_t *a, const uint8_t *b, size_t len);
    void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

#endif /* HAVE_KYBER */
#endif /* WOLF_CRYPT_KYBER_MEMORY_H */
