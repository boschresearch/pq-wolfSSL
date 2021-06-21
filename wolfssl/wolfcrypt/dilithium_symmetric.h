/* dilithium_symmetric.h
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
    \file wolfssl/wolfcrypt/dilithium_symmetric.h
*/

#ifndef WOLF_CRYPT_DILITHIUM_SYMMETRIC_H
#define WOLF_CRYPT_DILITHIUM_SYMMETRIC_H

#ifdef HAVE_DILITHIUM

#include <stddef.h>
#include <stdint.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#ifdef __cplusplus
    extern "C" {
#endif

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

void shake128_init(keccak_state *state);
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake128_finalize(keccak_state *state);
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);
void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state);

void shake256_init(keccak_state *state);
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake256_finalize(keccak_state *state);
void shake256_squeezeblocks(uint8_t *out, size_t nblocks,  keccak_state *state);
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);

void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);

typedef keccak_state stream128_state;
typedef keccak_state stream256_state;

void dilithium_shake128_stream_init(keccak_state *state, const uint8_t seed[DILITH_SEEDBYTES], uint16_t nonce);
void dilithium_shake256_stream_init(keccak_state *state, const uint8_t seed[DILITH_CRHBYTES], uint16_t nonce);

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_DILITHIUM */
#endif /* WOLF_CRYPT_DILITHIUM_SYMMETRIC_H */
