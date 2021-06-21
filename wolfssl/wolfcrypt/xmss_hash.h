/* xmss_hash.h
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://github.com/XMSS/
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */


/*!
    \file wolfssl/wolfcrypt/xmss_hash.h
*/


#ifndef WOLF_CRYPT_XMSS_HASH_H
#define WOLF_CRYPT_XMSS_HASH_H

#ifdef HAVE_XMSS

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdint.h>

void addr_to_bytes(unsigned char *bytes, const uint32_t addr[8]);

int prf(unsigned char *out, const unsigned char in[32],
        const unsigned char *key);

int prf_keygen(unsigned char *out, const unsigned char *in,
        const unsigned char *key);

int h_msg(unsigned char *out,
          const unsigned char *in, unsigned long long inlen,
          const unsigned char *key, const unsigned int keylen);

int thash_h(unsigned char *out, const unsigned char *in,
            const unsigned char *pub_seed, uint32_t addr[8]);

int thash_f(unsigned char *out, const unsigned char *in,
            const unsigned char *pub_seed, uint32_t addr[8]);

int xmss_hash_message(unsigned char *out, const unsigned char *R,
                 const unsigned char *root, unsigned long long idx,
                 unsigned char *m_with_prefix, unsigned long long mlen);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_XMSS */
#endif /* WOLF_CRYPT_XMSS_HASH_H */
