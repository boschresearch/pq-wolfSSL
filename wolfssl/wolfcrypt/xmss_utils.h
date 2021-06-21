/* xmss_utils.h
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
    \file wolfssl/wolfcrypt/xmss_utils.h
*/


#ifndef WOLF_CRYPT_XMSS_UTILS_H
#define WOLF_CRYPT_XMSS_UTILS_H

#ifdef HAVE_XMSS

#ifdef __cplusplus
    extern "C" {
#endif

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void xmss_ull_to_bytes(unsigned char *out, unsigned int outlen,
                  unsigned long long in);

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long xmss_bytes_to_ull(const unsigned char *in, unsigned int inlen);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_XMSS */
#endif /* WOLF_CRYPT_XMSS_UTILS_H */
