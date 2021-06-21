/* kyber_indcpa.c
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

#include <stdint.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/kyber.h>
#include <wolfssl/wolfcrypt/kyber_polynoms.h>
#include <wolfssl/wolfcrypt/kyber_symmetric.h>

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   byte *r:          pointer to the output serialized public key
*              polyvec *pk:      pointer to the input public-key polyvec
*              const byte *seed: pointer to the input public seed
**************************************************/
static void pack_pk(byte *r, polyvec *pk, const byte *seed)
{
    polyvec_tobytes(r, pk);
    for(size_t i=0; i < KYBER_SYMBYTES; i++) {
        r[i+KYBER_POLYVECBYTES] = seed[i];
    }
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk:          pointer to output public-key vector of polynomials
*              - byte *seed:           pointer to output seed to generate matrix A
*              - const byte *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk, byte *seed, const byte *packedpk)
{
    polyvec_frombytes(pk, packedpk);
    for(size_t i=0; i < KYBER_SYMBYTES; i++) {
        seed[i] = packedpk[i+KYBER_POLYVECBYTES];
    }
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - byte *r:           pointer to output serialized secret key
*              - const polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(byte *r, polyvec *sk)
{
    polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key;
*              inverse of pack_sk
*
* Arguments:   - polyvec *sk:          pointer to output vector of polynomials (secret key)
*              - const byte *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const byte *packedsk)
{
    polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   byte *r:     pointer to the output serialized ciphertext
*              polyvec *b:  pointer to the input vector of polynomials b
*              poly *v:     pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(byte *r, polyvec *b, poly *v)
{
    polyvec_compress(r, b);
    poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b:    pointer to the output vector of polynomials b
*              - poly *v:       pointer to the output polynomial v
*              - const byte *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const byte *c)
{
    polyvec_decompress(b, c);
    poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r:               pointer to output buffer
*              - unsigned int len:         requested number of 16-bit integers (uniform mod q)
*              - const byte *buf:          pointer to input buffer (assumed to be uniform random bytes)
*              - unsigned int buflen:      length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r, unsigned int len, const byte *buf, unsigned int buflen)
{
    unsigned int ctr, pos;
    uint16_t val0, val1;

    ctr = pos = 0;
    while(ctr < len && pos + 3 <= buflen) {
        val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
        val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
        pos += 3;

        if(val0 < KYBER_Q)
            r[ctr++] = val0;
        if(ctr < len && val1 < KYBER_Q)
            r[ctr++] = val1;
    }

    return ctr;
}

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a:                pointer to ouptput matrix A
*              - const byte *seed:          pointer to input seed
*              - int transposed:            boolean deciding whether A or A^T is generated
**************************************************/
#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q \
                             + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)

static void gen_matrix(polyvec *a, const byte *seed, int transposed) // Not static for benchmarking
{
    unsigned int ctr, i, j, k;
    unsigned int buflen, off;
    uint8_t buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2];
    keccak_state state;

    for(i=0; i < KYBER_K; i++) {
        for(j=0; j < KYBER_K; j++) {
            if(transposed) {
                kyber_shake128_absorb(&state, seed, i, j);
            } else {
                kyber_shake128_absorb(&state, seed, j, i);
            }

            kyber_shake128_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
            buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
            ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

            while(ctr < KYBER_N) {
                off = buflen % 3;
                for(k = 0; k < off; k++) {
                    buf[k] = buf[buflen - off + k];
                }
                kyber_shake128_squeezeblocks(buf + off, 1, &state);
                buflen = off + XOF_BLOCKBYTES;
                ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
            }
        }
    }
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - byte *pk: pointer to output public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - byte *sk: pointer to output private key (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
void indcpa_keypair(byte* pk, byte* sk, WC_RNG* rng)
{
    polyvec a[KYBER_K], e, pkpv, skpv;
    byte buf[2*KYBER_SYMBYTES];
    byte *publicseed = buf;
    byte *noiseseed = buf+KYBER_SYMBYTES;
    byte nonce = 0;
    unsigned int i;

    wc_RNG_GenerateBlock(rng,buf, KYBER_SYMBYTES);
    wc_Sha3_512Hash(buf, KYBER_SYMBYTES, buf);

    gen_a(a, publicseed);

    for(i=0; i < KYBER_K; i++) {
        poly_getnoise_eta1(skpv.vec+i, noiseseed, nonce++);
    }

    for(i=0; i < KYBER_K; i++) {
        poly_getnoise_eta1(e.vec+i, noiseseed, nonce++);
    }

    polyvec_ntt(&skpv);
    polyvec_ntt(&e);

    /* matrix-vector multiplication */
    for(i=0; i < KYBER_K; i++) {
        polyvec_pointwise_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&pkpv.vec[i]);
    }

    polyvec_add(&pkpv, &pkpv, &e);
    polyvec_reduce(&pkpv);

    pack_sk(sk, &skpv);
    pack_pk(pk, &pkpv, publicseed);
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - byte *c:           pointer to output ciphertext (of length KYBER_INDCPA_BYTES bytes)
*              - const byte *m:     pointer to input message (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const byte *pk:    pointer to input public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - const byte *coins: pointer to input random coins used as seed (of length KYBER_SYMBYTES bytes)
*                                           to deterministically generate all randomness
**************************************************/
void indcpa_enc(byte *c,
                const byte *m,
                const byte *pk,
                const byte *coins)
{
    polyvec sp, pkpv, ep, at[KYBER_K], bp;
    poly v, k, epp;
    byte seed[KYBER_SYMBYTES];
    byte nonce = 0;
    unsigned int i;

    unpack_pk(&pkpv, seed, pk);
    poly_frommsg(&k, m);
    gen_at(at, seed);

    for(i=0; i < KYBER_K; i++) {
        poly_getnoise_eta1(sp.vec+i, coins, nonce++);
    }
    for(i=0; i < KYBER_K; i++) {
        poly_getnoise_eta2(ep.vec+i, coins, nonce++);
    }
    poly_getnoise_eta2(&epp, coins, nonce++);

    polyvec_ntt(&sp);

    /* matrix-vector multiplication */
    for(i=0; i < KYBER_K; i++) {
        polyvec_pointwise_acc_montgomery(&bp.vec[i], &at[i], &sp);
    }
    polyvec_pointwise_acc_montgomery(&v, &pkpv, &sp);

    polyvec_invntt_tomont(&bp);
    kyber_poly_invntt_tomont(&v);

    polyvec_add(&bp, &bp, &ep);
    kyber_poly_add(&v, &v, &epp);
    kyber_poly_add(&v, &v, &k);
    polyvec_reduce(&bp);
    kyber_poly_reduce(&v);

    pack_ciphertext(c, &bp, &v);
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - byte *m:        pointer to output decrypted message (of length KYBER_INDCPA_MSGBYTES)
*              - const byte *c:  pointer to input ciphertext (of length KYBER_INDCPA_BYTES)
*              - const byte *sk: pointer to input secret key (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void indcpa_dec(byte *m,
                const byte *c,
                const byte *sk)
{
    polyvec bp, skpv;
    poly v, mp;

    unpack_ciphertext(&bp, &v, c);
    unpack_sk(&skpv, sk);

    polyvec_ntt(&bp);
    polyvec_pointwise_acc_montgomery(&mp, &skpv, &bp);
    kyber_poly_invntt_tomont(&mp);

    kyber_poly_sub(&mp, &v, &mp);
    kyber_poly_reduce(&mp);

    poly_tomsg(m, &mp);
}

#endif /* HAVE_KYBER */