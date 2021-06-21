/* sphincs_thash.h
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
    \file wolfssl/wolfcrypt/sphincs_thash.h
*/


#ifndef WOLF_CRYPT_SPHINCS_THASH_H
#define WOLF_CRYPT_SPHINCS_THASH_H

#ifdef HAVE_SPHINCS

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdint.h>

void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const unsigned char *pub_seed, uint32_t addr[8]);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_SPHINCS */
#endif /* SPHINCS_THASH_H */
