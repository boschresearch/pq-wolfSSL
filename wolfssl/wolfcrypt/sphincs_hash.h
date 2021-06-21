/* sphincs_hash.h
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
    \file wolfssl/wolfcrypt/sphincs_hash.h
*/


#ifndef WOLF_CRYPT_SPHINCS_HASH_H
#define WOLF_CRYPT_SPHINCS_HASH_H

#ifdef HAVE_SPHINCS

#include <stdint.h>

#ifdef __cplusplus
    extern "C" {
#endif

void initialize_hash_function(const unsigned char *pub_seed,
                              const unsigned char *sk_seed);

void prf_addr(unsigned char *out, const unsigned char *key,
              const uint32_t addr[8]);

void gen_message_random(unsigned char *R, const unsigned char *sk_seed,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen);

void sphincs_hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_SPHINCS */
#endif /* WOLF_CRYPT_SPHINCS_HASH_H */
