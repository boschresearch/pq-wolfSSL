/* kyber_polynoms.h
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
    \file wolfssl/wolfcrypt/kyber_polynoms.h
*/


#ifndef WOLF_CRYPT_KYBER_POLYNOMS_H
#define WOLF_CRYPT_KYBER_POLYNOMS_H

#ifdef HAVE_KYBER

#include <wolfssl/wolfcrypt/kyber.h>

#ifdef __cplusplus
    extern "C" {
#endif

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[KYBER_N];
} poly;

typedef struct{
  poly vec[KYBER_K];
} polyvec;

void cbd_eta1(poly *r, const uint8_t *buf);
void cbd_eta2(poly *r, const uint8_t *buf);

void poly_compress(uint8_t *r, poly *a);
void poly_decompress(poly *r, const uint8_t *a);

void poly_tobytes(uint8_t *r, poly *a);
void poly_frombytes(poly *r, const uint8_t *a);

void poly_frommsg(poly *r, const uint8_t msg[KYBER_SYMBYTES]);
void poly_tomsg(uint8_t msg[KYBER_SYMBYTES], poly *r);

void poly_getnoise_eta1(poly *r,const uint8_t *seed, uint8_t nonce);
void poly_getnoise_eta2(poly *r,const uint8_t *seed, uint8_t nonce);

void kyber_poly_ntt(poly *r);
void kyber_poly_invntt_tomont(poly *r);
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
void poly_tomont(poly *r);

void kyber_poly_reduce(poly *r);
void poly_csubq(poly *r);

void kyber_poly_add(poly *r, const poly *a, const poly *b);
void kyber_poly_sub(poly *r, const poly *a, const poly *b);

void polyvec_compress(uint8_t *r, polyvec *a);
void polyvec_decompress(polyvec *r, const uint8_t *a);

void polyvec_tobytes(uint8_t *r, polyvec *a);
void polyvec_frombytes(polyvec *r, const uint8_t *a);

void polyvec_ntt(polyvec *r);
void polyvec_invntt_tomont(polyvec *r);

void polyvec_pointwise_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);

void polyvec_reduce(polyvec *r);
void polyvec_csubq(polyvec *r);

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_KYBER */
#endif /* WOLF_CRYPT_KYBER_POLYNOMS_H */