/* kyber_symmetric.h
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
    \file wolfssl/wolfcrypt/kyber_symmetric.h
*/


#ifndef WOLF_CRYPT_KYBER_SYMMETRIC_H
#define WOLF_CRYPT_KYBER_SYMMETRIC_H

#ifdef HAVE_KYBER

    #include <stdint.h>
    #include <wolfssl/wolfcrypt/kyber.h>

    #ifdef __cplusplus
        extern "C" {
    #endif

    typedef struct {
        uint64_t s[25];
    } keccak_state;

    #define SHAKE128_RATE 168
    #define SHAKE256_RATE 136
    #define SHA3_256_RATE 136
    #define SHA3_512_RATE  72

    void kyber_shake128_absorb(keccak_state *s, const uint8_t *input, uint8_t x, uint8_t y);
    void kyber_shake128_squeezeblocks(uint8_t *output, size_t nblocks, keccak_state *s);

    #define XOF_BLOCKBYTES 168

    #ifdef __cplusplus
        } /* extern "C" */
    #endif

#endif /* HAVE_KYBER */
#endif /* WOLF_CRYPT_KYBER_SYMMETRIC_H */