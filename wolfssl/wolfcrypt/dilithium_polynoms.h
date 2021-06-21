/* dilithium_polynoms.h
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
    \file wolfssl/wolfcrypt/dilithium_polynoms.h
*/


#ifndef WOLF_CRYPT_DILITHIUM_POLYNOMS_H
#define WOLF_CRYPT_DILITHIUM_POLYNOMS_H

#ifdef HAVE_DILITHIUM

#include <stdint.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#ifdef __cplusplus
    extern "C" {
#endif

typedef struct {
  int32_t coeffs[DILITH_N];
} d_poly;

int32_t power2round(int32_t *a0, int32_t a);
int32_t decompose(int32_t *a0, int32_t a);
unsigned int make_hint(int32_t a0, int32_t a1);
int32_t use_hint(int32_t a, unsigned int hint);

void dilithium_poly_reduce(d_poly *a);
void poly_caddq(d_poly *a);
void poly_freeze(d_poly *a);

void dilithium_poly_add(d_poly *c, const d_poly *a, const d_poly *b);
void dilithium_poly_sub(d_poly *c, const d_poly *a, const d_poly *b);
void poly_shiftl(d_poly *a);

void dilithium_poly_ntt(d_poly *a);
void dilithium_poly_invntt_tomont(d_poly *a);
void poly_pointwise_montgomery(d_poly *c, const d_poly *a, const d_poly *b);

void poly_power2round(d_poly *a1, d_poly *a0, const d_poly *a);
void poly_decompose(d_poly *a1, d_poly *a0, const d_poly *a);
unsigned int poly_make_hint(d_poly *h, const d_poly *a0, const d_poly *a1);
void poly_use_hint(d_poly *b, const d_poly *a, const d_poly *h);

int poly_chknorm(const d_poly *a, int32_t B);
void poly_uniform(d_poly *a, const uint8_t seed[DILITH_SEEDBYTES], uint16_t nonce);
void poly_uniform_eta(d_poly *a, const uint8_t seed[DILITH_SEEDBYTES], uint16_t nonce);
void poly_uniform_gamma1(d_poly *a, const uint8_t seed[DILITH_CRHBYTES], uint16_t nonce);
void poly_challenge(d_poly *c, const uint8_t seed[DILITH_SEEDBYTES]);

void polyeta_pack(uint8_t *r, const d_poly *a);
void polyeta_unpack(d_poly *r, const uint8_t *a);
void polyt1_pack(uint8_t *r, const d_poly *a);
void polyt1_unpack(d_poly *r, const uint8_t *a);
void polyt0_pack(uint8_t *r, const d_poly *a);
void polyt0_unpack(d_poly *r, const uint8_t *a);
void polyz_pack(uint8_t *r, const d_poly *a);
void polyz_unpack(d_poly *r, const uint8_t *a);
void polyw1_pack(uint8_t *r, const d_poly *a);

/* Vectors of polynomials of length DILITH_L */
typedef struct {
  d_poly vec[DILITH_L];
} polyvecl;

void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[DILITH_SEEDBYTES], uint16_t nonce);
void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[DILITH_SEEDBYTES], uint16_t nonce);

void polyvecl_reduce(polyvecl *v);
void polyvecl_freeze(polyvecl *v);
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);
void polyvecl_ntt(polyvecl *v);
void polyvecl_invntt_tomont(polyvecl *v);
void polyvecl_pointwise_poly_montgomery(polyvecl *r, const d_poly *a, const polyvecl *v);
void polyvecl_pointwise_acc_montgomery(d_poly *w,
                                       const polyvecl *u,
                                       const polyvecl *v);

int polyvecl_chknorm(const polyvecl *v, int32_t B);

/* Vectors of polynomials of length DILITH_K */
typedef struct {
  d_poly vec[DILITH_K];
} polyveck;

void polyveck_uniform_eta(polyveck *v, const uint8_t seed[DILITH_SEEDBYTES], uint16_t nonce);

void polyveck_reduce(polyveck *v);
void polyveck_caddq(polyveck *v);
void polyveck_freeze(polyveck *v);

void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_shiftl(polyveck *v);

void polyveck_ntt(polyveck *v);
void polyveck_invntt_tomont(polyveck *v);
void polyveck_pointwise_poly_montgomery(polyveck *r, const d_poly *a, const polyveck *v);

int polyveck_chknorm(const polyveck *v, int32_t B);

void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
unsigned int polyveck_make_hint(polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1);
void polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);

void polyveck_pack_w1(uint8_t r[DILITH_K*POLYW1_PACKEDBYTES], const polyveck *w1);

void polyvec_matrix_expand(polyvecl mat[DILITH_K], const uint8_t rho[DILITH_SEEDBYTES]);
void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[DILITH_K], const polyvecl *v);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_DILITHIUM */
#endif /* WOLF_CRYPT_DILITHIUM_POLYNOMS_H */
