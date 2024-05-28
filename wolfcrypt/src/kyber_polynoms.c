/* kyber_polynoms.c
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://pq-crystals.org/kyber/
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_KYBER

#include <wolfssl/wolfcrypt/kyber_arithmetic.h>
#include <wolfssl/wolfcrypt/kyber_polynoms.h>
#include <wolfssl/wolfcrypt/kyber_memory.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <stdint.h>

/*************************************************
* Name:        cbd2
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=2
*
* Arguments:   - poly *r:            pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
static void cbd2(poly *r, const uint8_t *buf)
{
    unsigned int i,j;
    uint32_t t,d;
    int16_t a,b;

    for(i=0; i < KYBER_N/8; i++) {
        t  = load32_littleendian(buf+4*i);
        d  = t & 0x55555555;
        d += (t>>1) & 0x55555555;

        for(j=0;j<8;j++) {
            a = (d >> (4*j+0)) & 0x3;
            b = (d >> (4*j+2)) & 0x3;
            r->coeffs[8*i+j] = a - b;
        }
    }
}

/*************************************************
* Name:        cbd3
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=3
*              This function is only needed for Kyber-512
*
* Arguments:   - poly *r:            pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
#if KYBER_ETA1 == 3
static void cbd3(poly *r, const uint8_t *buf)
{
    unsigned int i,j;
    uint32_t t,d;
    int16_t a,b;

    for(i=0; i < KYBER_N/4; i++) {
        t  = load24_littleendian(buf+3*i);
        d  = t & 0x00249249;
        d += (t>>1) & 0x00249249;
        d += (t>>2) & 0x00249249;

        for(j=0; j < 4; j++) {
            a = (d >> (6*j+0)) & 0x7;
            b = (d >> (6*j+3)) & 0x7;
            r->coeffs[4*i+j] = a - b;
        }
    }
}
#endif

void cbd_eta1(poly *r, const uint8_t *buf)
{
#if KYBER_ETA1 == 2
  cbd2(r, buf);
#elif KYBER_ETA1 == 3
  cbd3(r, buf);
#else
#error "This implementation requires eta1 in {2,3}"
#endif
}

void cbd_eta2(poly *r, const uint8_t *buf)
{
#if KYBER_ETA2 != 2
#error "This implementation requires eta2 = 2"
#else
  cbd2(r, buf);
#endif
}

/*************************************************
* Name:        poly_compress
*
* Description: Compression and subsequent serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array (needs space for KYBER_POLYCOMPRESSEDBYTES bytes)
*              - poly *a:    pointer to input polynomial
**************************************************/
void poly_compress(uint8_t *r, poly *a)
{
    uint8_t t[8];
    unsigned int i, j;

    poly_csubq(a);

    #if (KYBER_POLYCOMPRESSEDBYTES == 128)
        for(i=0; i < KYBER_N/8; i++) {
            for(j=0; j < 8; j++) {
                t[j] = ((((uint16_t)a->coeffs[8*i+j] << 4) + KYBER_Q/2)/KYBER_Q) & 15;
            }
            r[0] = t[0] | (t[1] << 4);
            r[1] = t[2] | (t[3] << 4);
            r[2] = t[4] | (t[5] << 4);
            r[3] = t[6] | (t[7] << 4);
            r += 4;
        }
    #elif (KYBER_POLYCOMPRESSEDBYTES == 160)
      for(i=0; i < KYBER_N/8; i++) {
          for(j=0; j < 8; j++) {
              t[j] = ((((uint32_t)a->coeffs[8*i+j] << 5) + KYBER_Q/2)/KYBER_Q) & 31;
          }
          r[0] = (t[0] >> 0) | (t[1] << 5);
          r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
          r[2] = (t[3] >> 1) | (t[4] << 4);
          r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
          r[4] = (t[6] >> 2) | (t[7] << 3);
          r += 5;
      }
    #else
    #error "KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
    #endif
}

/*************************************************
* Name:        poly_decompress
*
* Description: De-serialization and subsequent decompression of a polynomial;
*              approximate inverse of poly_compress
*
* Arguments:   - poly *r:                pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array (of length KYBER_POLYCOMPRESSEDBYTES bytes)
**************************************************/
void poly_decompress(poly *r, const uint8_t *a)
{
    unsigned int i;
    #if (KYBER_POLYCOMPRESSEDBYTES == 128)
        for(i=0; i < KYBER_N/2; i++) {
            r->coeffs[2*i+0] = (((uint16_t)(a[0] & 15)*KYBER_Q) + 8) >> 4;
            r->coeffs[2*i+1] = (((uint16_t)(a[0] >> 4)*KYBER_Q) + 8) >> 4;
            a += 1;
        }
    #elif (KYBER_POLYCOMPRESSEDBYTES == 160)
        uint8_t t[8];
        for(i=0; i < KYBER_N/8; i++) {
            t[0] = (a[0] >> 0);
            t[1] = (a[0] >> 5) | (a[1] << 3);
            t[2] = (a[1] >> 2);
            t[3] = (a[1] >> 7) | (a[2] << 1);
            t[4] = (a[2] >> 4) | (a[3] << 4);
            t[5] = (a[3] >> 1);
            t[6] = (a[3] >> 6) | (a[4] << 2);
            t[7] = (a[4] >> 3);
            a += 5;

            for(unsigned int j=0; j < 8; j++) {
                r->coeffs[8*i+j] = ((uint32_t)(t[j] & 31)*KYBER_Q + 16) >> 5;
            }
        }
    #else
    #error "KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
    #endif
}

/*************************************************
* Name:        poly_tobytes
*
* Description: Serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array (needs space for KYBER_POLYBYTES bytes)
*              - poly *a:    pointer to input polynomial
**************************************************/
void poly_tobytes(uint8_t *r, poly *a)
{
    uint16_t t0, t1;

    poly_csubq(a);

    for(unsigned int i=0; i < KYBER_N/2; i++) {
        t0 = a->coeffs[2*i];
        t1 = a->coeffs[2*i+1];
        r[3*i+0] = (t0 >> 0);
        r[3*i+1] = (t0 >> 8) | (t1 << 4);
        r[3*i+2] = (t1 >> 4);
    }
}

/*************************************************
* Name:        poly_frombytes
*
* Description: De-serialization of a polynomial;
*              inverse of poly_tobytes
*
* Arguments:   - poly *r:          pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array (of KYBER_POLYBYTES bytes)
**************************************************/
void poly_frombytes(poly *r, const uint8_t *a)
{
    for(unsigned int i=0; i < KYBER_N/2; i++){
        r->coeffs[2*i]   = ((a[3*i+0] >> 0) | ((uint16_t)a[3*i+1] << 8)) & 0xFFF;
        r->coeffs[2*i+1] = ((a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4)) & 0xFFF;
    }
}

/*************************************************
* Name:        poly_getnoise_eta1
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA1
*
* Arguments:   - poly *r:             pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed (pointing to array of length KYBER_SYMBYTES bytes)
*              - uint8_t nonce:       one-byte input nonce
**************************************************/
void poly_getnoise_eta1(poly *r, const uint8_t *seed, uint8_t nonce)
{
    uint8_t buf[KYBER_ETA1*KYBER_N/4];
    uint8_t extkey[KYBER_SYMBYTES+1];
    size_t i;

    for(i=0; i < KYBER_SYMBYTES; i++)
        extkey[i] = seed[i];
    extkey[i] = nonce;

    wc_Shake256Hash(extkey, sizeof(extkey), buf, sizeof(buf));
    cbd_eta1(r, buf);
}

/*************************************************
* Name:        poly_getnoise_eta2
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA2
*
* Arguments:   - poly *r:             pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed (pointing to array of length KYBER_SYMBYTES bytes)
*              - uint8_t nonce:       one-byte input nonce
**************************************************/
void poly_getnoise_eta2(poly *r, const uint8_t *seed, uint8_t nonce)
{
    uint8_t buf[KYBER_ETA2*KYBER_N/4];
    uint8_t extkey[KYBER_SYMBYTES+1];
    size_t i;

    for(i=0; i < KYBER_SYMBYTES; i++)
        extkey[i] = seed[i];
    extkey[i] = nonce;

    wc_Shake256Hash(extkey, sizeof(extkey), buf, sizeof(buf));
    cbd_eta2(r, buf);
}

/*************************************************
* Name:        kyber_poly_ntt
*
* Description: Computes negacyclic number-theoretic transform (kyber_ntt) of
*              a polynomial in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *r: pointer to in/output polynomial
**************************************************/
void kyber_poly_ntt(poly *r)
{
    kyber_ntt(r->coeffs);
    kyber_poly_reduce(r);
}

/*************************************************
* Name:        kyber_poly_invntt_tomont
*
* Description: Computes inverse of negacyclic number-theoretic transform (kyber_ntt) of
*              a polynomial in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void kyber_poly_invntt_tomont(poly *r)
{
    kyber_invntt_tomont(r->coeffs);
}

/*************************************************
* Name:        poly_basemul_montgomery
*
* Description: Multiplication of two polynomials in kyber_ntt domain
*
* Arguments:   - poly *r:       pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b)
{
    unsigned int i;

    for(i = 0; i < KYBER_N/4; ++i) {
         basemul(&r->coeffs[4*i], &a->coeffs[4*i], &b->coeffs[4*i], kyber_zetas[64+i]);
         basemul(&r->coeffs[4*i+2], &a->coeffs[4*i+2], &b->coeffs[4*i+2], -kyber_zetas[64+i]);
    }
}

/*************************************************
* Name:        poly_tomont
*
* Description: Inplace conversion of all coefficients of a polynomial
*              from normal domain to Montgomery domain
*
* Arguments:   - poly *r:       pointer to input/output polynomial
**************************************************/
void poly_tomont(poly *r)
{
    const int16_t f = (1ULL << 32) % KYBER_Q;

    for(unsigned int i=0; i < KYBER_N; i++) {
        r->coeffs[i] = montgomery_reduce32((int32_t)r->coeffs[i]*f);
    }
}

/*************************************************
* Name:        kyber_poly_reduce
*
* Description: Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r:       pointer to input/output polynomial
**************************************************/
void kyber_poly_reduce(poly *r)
{
    for(unsigned int i=0; i < KYBER_N; i++) {
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
    }
}

/*************************************************
* Name:        poly_csubq
*
* Description: Applies conditional subtraction of q to each coefficient of a polynomial
*              for details of conditional subtraction of q see comments in reduce.c
*
* Arguments:   - poly *r:       pointer to input/output polynomial
**************************************************/
void poly_csubq(poly *r)
{
    for(unsigned int i=0; i < KYBER_N; i++) {
        r->coeffs[i] = csubq(r->coeffs[i]);
    }
}

/*************************************************
* Name:        kyber_poly_add
*
* Description: Add two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void kyber_poly_add(poly *r, const poly *a, const poly *b)
{
    for(unsigned int i=0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

/*************************************************
* Name:        kyber_poly_sub
*
* Description: Subtract two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void kyber_poly_sub(poly *r, const poly *a, const poly *b)
{
    for(unsigned int i=0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

/*************************************************
* Name:        poly_frommsg
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly *r:            pointer to output polynomial
*              - const uint8_t *msg: pointer to input message
**************************************************/
void poly_frommsg(poly *r, const uint8_t msg[KYBER_SYMBYTES])
{
    unsigned int i,j;
    int16_t mask;

#if (KYBER_INDCPA_MSGBYTES != KYBER_N/8)
#error "KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!"
#endif

    for(i=0; i < KYBER_N/8; i++) {
        for(j=0; j < 8; j++) {
            mask = -(int16_t)((msg[i] >> j)&1);
            r->coeffs[8*i+j] = mask & ((KYBER_Q+1)/2);
        }
    }
}

/*************************************************
* Name:        poly_tomsg
*
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - uint8_t *msg: pointer to output message
*              - const poly *a:      pointer to input polynomial
**************************************************/
void poly_tomsg(uint8_t msg[KYBER_SYMBYTES], poly *a)
{
    uint32_t t;
    unsigned int i,j;

    poly_csubq(a);

    for(i=0; i < KYBER_N/8; i++) {
        msg[i] = 0;
        for(j=0; j < 8; j++) {
            t  = a->coeffs[8*i+j];
            //t = ((((uint16_t)a->coeffs[8*i+j] << 1) + KYBER_Q/2)/KYBER_Q) & 1;
            t <<= 1;
            t += 1665;
            t *= 80635;
            t >>= 28;
            t &= 1;
            msg[i] |= t << j;
        }
    }
}

/*************************************************
* Name:        polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - uint8_t *r:  pointer to output byte array (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
*              - polyvec *a:  pointer to input vector of polynomials
**************************************************/
void polyvec_compress(uint8_t *r, polyvec *a)
{
    unsigned int i,j,k;

    polyvec_csubq(a);

    #if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
      uint16_t t[8];
      for(i=0; i < KYBER_K; i++) {
          for(j=0; j < KYBER_N/8; j++) {
              for(k=0; k < 8; k++) {
                  t[k] = ((((uint32_t)a->vec[i].coeffs[8*j+k] << 11) + KYBER_Q/2) / KYBER_Q) & 0x7ff;
              }
              r[ 0] = (t[0] >>  0);
              r[ 1] = (t[0] >>  8) | (t[1] << 3);
              r[ 2] = (t[1] >>  5) | (t[2] << 6);
              r[ 3] = (t[2] >>  2);
              r[ 4] = (t[2] >> 10) | (t[3] << 1);
              r[ 5] = (t[3] >>  7) | (t[4] << 4);
              r[ 6] = (t[4] >>  4) | (t[5] << 7);
              r[ 7] = (t[5] >>  1);
              r[ 8] = (t[5] >>  9) | (t[6] << 2);
              r[ 9] = (t[6] >>  6) | (t[7] << 5);
              r[10] = (t[7] >>  3);
              r += 11;
          }
      }
    #elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
      uint16_t t[4];
      for(i=0; i < KYBER_K; i++) {
          for(j=0; j < KYBER_N/4; j++) {
              for(k=0; k < 4; k++) {
                  t[k] = ((((uint32_t)a->vec[i].coeffs[4*j+k] << 10) + KYBER_Q/2) / KYBER_Q) & 0x3ff;
              }
              r[0] = (t[0] >> 0);
              r[1] = (t[0] >> 8) | (t[1] << 2);
              r[2] = (t[1] >> 6) | (t[2] << 4);
              r[3] = (t[2] >> 4) | (t[3] << 6);
              r[4] = (t[3] >> 2);
              r += 5;
          }
      }
    #else
    #error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
    #endif
}

/*************************************************
* Name:        polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of polyvec_compress
*
* Arguments:   - polyvec *r:       pointer to output vector of polynomials
*              - const uint8_t *a: pointer to input byte array (of length KYBER_POLYVECCOMPRESSEDBYTES)
**************************************************/
void polyvec_decompress(polyvec *r, const uint8_t *a)
{
    unsigned int i, j, k;
    #if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
        uint16_t t[8];
        for(i=0; i < KYBER_K; i++) {
            for(j=0; j < KYBER_N/8; j++) {
                t[0] = (a[0] >> 0) | ((uint16_t)a[ 1] << 8);
                t[1] = (a[1] >> 3) | ((uint16_t)a[ 2] << 5);
                t[2] = (a[2] >> 6) | ((uint16_t)a[ 3] << 2) | ((uint16_t)a[4] << 10);
                t[3] = (a[4] >> 1) | ((uint16_t)a[ 5] << 7);
                t[4] = (a[5] >> 4) | ((uint16_t)a[ 6] << 4);
                t[5] = (a[6] >> 7) | ((uint16_t)a[ 7] << 1) | ((uint16_t)a[8] << 9);
                t[6] = (a[8] >> 2) | ((uint16_t)a[ 9] << 6);
                t[7] = (a[9] >> 5) | ((uint16_t)a[10] << 3);
                a += 11;

                for(k=0;k<8;k++)
                    r->vec[i].coeffs[8*j+k] = ((uint32_t)(t[k] & 0x7FF)*KYBER_Q + 1024) >> 11;
            }
        }
    #elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
        uint16_t t[8];
        for(i=0; i < KYBER_K; i++) {
            for(j=0; j < KYBER_N/4; j++) {
                t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
                t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
                t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
                t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
                a += 5;

                for(k=0; k < 4; k++)
                    r->vec[i].coeffs[4*j+k] = ((uint32_t)(t[k] & 0x3FF)*KYBER_Q + 512) >> 10;
            }
        }
    #else
    #error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
    #endif
}

/*************************************************
* Name:        polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array (needs space for KYBER_POLYVECBYTES)
*              - polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_tobytes(uint8_t *r, polyvec *a)
{
    for (unsigned int i=0; i < KYBER_K; i++) {
        poly_tobytes(r+i*KYBER_POLYBYTES, &a->vec[i]);
    }
}

/*************************************************
* Name:        polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes
*
* Arguments:   - uint8_t *r: pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials (of length KYBER_POLYVECBYTES)
**************************************************/
void polyvec_frombytes(polyvec *r, const uint8_t *a)
{
    for(unsigned int i=0; i < KYBER_K; i++) {
        poly_frombytes(&r->vec[i], a+i*KYBER_POLYBYTES);
    }
}

/*************************************************
* Name:        polyvec_ntt
*
* Description: Apply forward kyber_ntt to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_ntt(polyvec *r)
{
    for(unsigned int i=0; i < KYBER_K; i++) {
        kyber_poly_ntt(&r->vec[i]);
    }
}

/*************************************************
* Name:        polyvec_invntt_tomont
*
* Description: Apply inverse kyber_ntt to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_invntt_tomont(polyvec *r)
{
    for(unsigned int i=0; i < KYBER_K; i++) {
        kyber_poly_invntt_tomont(&r->vec[i]);
    }
}

/*************************************************
* Name:        polyvec_pointwise_acc_montgomery
*
* Description: Pointwise multiply elements of a and b and accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - poly *r:          pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_pointwise_acc_montgomery(poly *r, const polyvec *a, const polyvec *b)
{
    poly t;

    poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for(unsigned int i=1; i < KYBER_K; i++) {
        poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        kyber_poly_add(r, r, &t);
    }

    kyber_poly_reduce(r);
}

/*************************************************
* Name:        polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r:       pointer to input/output polynomial
**************************************************/
void polyvec_reduce(polyvec *r)
{
    for(unsigned int i=0; i < KYBER_K; i++) {
        kyber_poly_reduce(&r->vec[i]);
    }
}

/*************************************************
* Name:        polyvec_csubq
*
* Description: Applies conditional subtraction of q to each coefficient
*              of each element of a vector of polynomials
*              for details of conditional subtraction of q see comments in reduce.c
*
* Arguments:   - poly *r:       pointer to input/output polynomial
**************************************************/
void polyvec_csubq(polyvec *r)
{
    for(unsigned int i=0; i < KYBER_K; i++) {
        poly_csubq(&r->vec[i]);
    }
}

/*************************************************
* Name:        polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r:       pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
    for(unsigned int i=0; i < KYBER_K; i++) {
        kyber_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

#endif /* HAVE_KYBER */