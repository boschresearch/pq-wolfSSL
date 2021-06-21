/* sphincs_sha256.h
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
    \file wolfssl/wolfcrypt/sphincs_sha256.h
*/


#ifndef WOLF_CRYPT_SPHINCS_SHA256_H
#define WOLF_CRYPT_SPHINCS_SHA256_H

#ifdef HAVE_SPHINCS

#ifdef __cplusplus
    extern "C" {
#endif

#define SPX_SHA256_BLOCK_BYTES 64
#define SPX_SHA256_OUTPUT_BYTES 32  /* This does not necessarily equal SPX_N */

//#if SPX_SHA256_OUTPUT_BYTES < SPX_N
//    #error Linking against SHA-256 with N larger than 32 bytes is not supported
//#endif

#define SPX_SHA256_ADDR_BYTES 22

#include <stddef.h>
#include <stdint.h>

void sha256_inc_init(uint8_t *state);
void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
void sha256_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen);
void sha256(uint8_t *out, const uint8_t *in, size_t inlen);

void mgf1(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);

uint8_t state_seeded[40];

void seed_state(const unsigned char *pub_seed);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_SPHINCS */
#endif /* WOLF_CRYPT_SPHINCS_SHA256_H */
