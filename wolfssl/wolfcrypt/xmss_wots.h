/* xmss_wots.h
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
    \file wolfssl/wolfcrypt/xmss_wots.h
*/


#ifndef WOLF_CRYPT_XMSS_WOTS_H
#define WOLF_CRYPT_XMSS_WOTS_H

#ifdef HAVE_XMSS

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdint.h>

/**
 * WOTS key generation. Takes a 32 byte seed for the private key, expands it to
 * a full WOTS private key and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this WOTS key pair.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pkgen(unsigned char *pk, const unsigned char *seed,
                const unsigned char *pub_seed, uint32_t addr[8]);

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
void xmss_wots_sign(unsigned char *sig, const unsigned char *msg,
               const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[8]);

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void xmss_wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[8]);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_XMSS */
#endif /* WOLF_CRYPT_XMSS_WOTS_H */
