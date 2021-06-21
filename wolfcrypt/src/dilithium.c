/* dilithium.c
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://pq-crystals.org/dilithium/
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_DILITHIUM

#include <stdint.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/dilithium_packing.h>
#include <wolfssl/wolfcrypt/dilithium_polynoms.h>
#include <wolfssl/wolfcrypt/dilithium_symmetric.h>

/**
 * Name:        dilithium_crypto_sign_keypair
 *
 * Description: Generates public and private key.
 *
 * Arguments:    uint8_t *pk: pointer to output public key (allocated
 *                            array of DILITHIUM_CRYPTO_PUBLICKEYBYTES bytes)
 *               uint8_t *sk: pointer to output private key (allocated
 *                            array of DILITHIUM_CRYPTO_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success)
 */
int dilithium_crypto_sign_keypair(uint8_t *pk, uint8_t *sk, WC_RNG* rng)
{
  uint8_t seedbuf[3*DILITH_SEEDBYTES];
  uint8_t tr[DILITH_CRHBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl mat[DILITH_K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  /* Get randomness for rho, rhoprime and key */
  wc_RNG_GenerateBlock(rng, seedbuf, DILITH_SEEDBYTES);
  wc_Shake256Hash(seedbuf, DILITH_SEEDBYTES, seedbuf, 3*DILITH_SEEDBYTES);
  rho = seedbuf;
  rhoprime = seedbuf + DILITH_SEEDBYTES;
  key = seedbuf + 2*DILITH_SEEDBYTES;

  /* Expand matrix */
  polyvec_matrix_expand(mat, rho);

  /* Sample short vectors s1 and s2 */
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, DILITH_L);

  /* Matrix-vector multiplication */
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);

  /* Add error vector s2 */
  polyveck_add(&t1, &t1, &s2);

  /* Extract t1 and write public key */
  polyveck_caddq(&t1);
  polyveck_power2round(&t1, &t0, &t1);
  pack_pk(pk, rho, &t1);

  /* Compute CRH(rho, t1) and write secret key */
  wc_Shake256Hash(pk, DILITHIUM_CRYPTO_PUBLICKEYBYTES, tr, DILITH_CRHBYTES);
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

  return 0;
}

/**
 * Name:        dilithium_crypto_sign_signature
 *
 * Description: Computes signature.
 *
 * Arguments:    uint8_t *sig:      pointer to output signature (of length DILITHIUM_CRYPTO_BYTES)
 *               size_t *siglen:    pointer to output length of signature
 *               uint8_t *m:        pointer to message to be signed
 *               size_t mlen:       length of message
 *               uint8_t *sk:       pointer to bit-packed secret key
 *
 * Returns 0 (success)
 */
int dilithium_crypto_sign_signature(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk,
                          WC_RNG *rng)
{
  (void)rng;

  unsigned int n;
  uint8_t seedbuf[2*DILITH_SEEDBYTES + 3*DILITH_CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  polyvecl mat[DILITH_K], s1, y, z;
  polyveck t0, s2, w1, w0, h;
  d_poly cp;
  keccak_state state;

  rho = seedbuf;
  tr = rho + DILITH_SEEDBYTES;
  key = tr + DILITH_CRHBYTES;
  mu = key + DILITH_SEEDBYTES;
  rhoprime = mu + DILITH_CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute CRH(tr, msg) */
  shake256_init(&state);
  shake256_absorb(&state, tr, DILITH_CRHBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, DILITH_CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  wc_RNG_GenerateBlock(rng, rhoprime, DILITH_CRHBYTES);
#else
  wc_Shake256Hash(key, DILITH_SEEDBYTES + DILITH_CRHBYTES, rhoprime, DILITH_CRHBYTES);
#endif

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  /* Sample intermediate vector y */
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);
  z = y;
  polyvecl_ntt(&z);

  /* Matrix-vector multiplication */
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);
  polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, DILITH_CRHBYTES);
  shake256_absorb(&state, sig, DILITH_K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, DILITH_SEEDBYTES, &state);
  poly_challenge(&cp, sig);
  dilithium_poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&w0, &w0, &h);
  polyveck_reduce(&w0);
  if(polyveck_chknorm(&w0, GAMMA2 - BETA))
    goto rej;

  /* Compute hints for w1 */
  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h);
  polyveck_reduce(&h);
  if(polyveck_chknorm(&h, GAMMA2))
    goto rej;

  polyveck_add(&w0, &w0, &h);
  polyveck_caddq(&w0);
  n = polyveck_make_hint(&h, &w0, &w1);
  if(n > OMEGA)
    goto rej;

  /* Write signature */
  pack_sig(sig, sig, &z, &h);
  *siglen = DILITHIUM_CRYPTO_BYTES;
  return 0;
}

/**
 * Name:        dilithium_crypto_sign
 *
 * Description: Compute signed message.
 *
 * Arguments:    uint8_t *sm:       pointer to output signed message (allocated
 *                                  array with DILITHIUM_CRYPTO_BYTES + mlen bytes),
 *                                  can be equal to m
 *               size_t *smlen:     pointer to output length of signed message
 *               const uint8_t *m:  pointer to message to be signed
 *               size_t mlen:       length of message
 *               const uint8_t *sk: pointer to bit-packed secret key
 *
 * Returns 0 (success)
 */
int dilithium_crypto_sign(uint8_t *sm,
                size_t *smlen,
                const uint8_t *m,
                size_t mlen,
                const uint8_t *sk,
                WC_RNG *rng)
{
  size_t i;

  for(i = 0; i < mlen; ++i)
    sm[DILITHIUM_CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  dilithium_crypto_sign_signature(sm, smlen, sm + DILITHIUM_CRYPTO_BYTES, mlen, sk, rng);
  *smlen += mlen;
  return 0;
}

/**
 * Name:        dilithium_crypto_sign_verify
 *
 * Description: Verifies signature.
 *
 * Arguments:    uint8_t *sig:      pointer to input signature
 *               size_t siglen:     length of signature
 *               const uint8_t *m:  pointer to message
 *               size_t mlen:       length of message
 *               const uint8_t *pk: pointer to bit-packed public key
 *
 * Returns 0 if signature could be verified correctly and -1 otherwise
 */
int dilithium_crypto_sign_verify(const uint8_t *sig,
                                 size_t siglen,
                                 const uint8_t *m,
                                 size_t mlen,
                                 const uint8_t *pk)
{
  unsigned int i;
  uint8_t buf[DILITH_K*POLYW1_PACKEDBYTES];
  uint8_t rho[DILITH_SEEDBYTES];
  uint8_t mu[DILITH_CRHBYTES];
  uint8_t c[DILITH_SEEDBYTES];
  uint8_t c2[DILITH_SEEDBYTES];
  d_poly cp;
  polyvecl mat[DILITH_K], z;
  polyveck t1, w1, h;
  keccak_state state;

  if(siglen != DILITHIUM_CRYPTO_BYTES)
    return -1;

  unpack_pk(rho, &t1, pk);
  if(unpack_sig(c, &z, &h, sig))
    return -1;
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

  /* Compute CRH(CRH(rho, t1), msg) */
  wc_Shake256Hash(pk, DILITHIUM_CRYPTO_PUBLICKEYBYTES, mu, DILITH_CRHBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, DILITH_CRHBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, DILITH_CRHBYTES, &state);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  dilithium_poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);
  polyveck_pack_w1(buf, &w1);

  /* Call random oracle and verify challenge */
  shake256_init(&state);
  shake256_absorb(&state, mu, DILITH_CRHBYTES);
  shake256_absorb(&state, buf, DILITH_K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, DILITH_SEEDBYTES, &state);
  for(i = 0; i < DILITH_SEEDBYTES; ++i)
    if(c[i] != c2[i])
      return -1;

  return 0;
}

/**
 * Name:        dilithium_crypto_sign_open
 *
 * Description: Verify signed message.
 *
 * Arguments:    uint8_t *m:        pointer to output message (allocated
 *                                  array with smlen bytes), can be equal to sm
 *               size_t *mlen:      pointer to output length of message
 *               const uint8_t *sm: pointer to signed message
 *               size_t smlen:      length of signed message
 *               const uint8_t *pk: pointer to bit-packed public key
 *
 * Returns 0 if signed message could be verified correctly and -1 otherwise
 */
int dilithium_crypto_sign_open(uint8_t *m,
                     size_t *mlen,
                     const uint8_t *sm,
                     size_t smlen,
                     const uint8_t *pk)
{
  size_t i;

  if(smlen < DILITHIUM_CRYPTO_BYTES)
    goto badsig;

  *mlen = smlen - DILITHIUM_CRYPTO_BYTES;
  if(dilithium_crypto_sign_verify(sm, DILITHIUM_CRYPTO_BYTES, sm + DILITHIUM_CRYPTO_BYTES, *mlen, pk))
    goto badsig;
  else {
    /* All good, copy msg, return 0 */
    for(i = 0; i < *mlen; ++i)
      m[i] = sm[DILITHIUM_CRYPTO_BYTES + i];
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = -1;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
}

/**
 * Initializes DilithiumKey struct where the keys are stored.
 * Zeroes out the memory contents.
 *
 * Arguments: DilithiumKey* key: pointer to struct where the keys are stored
 */
int wc_InitDilithiumKey(DilithiumKey* key)
{
  int ret = 0;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ret == 0) {
        XMEMSET(key, 0, sizeof(*key));
    }

    return ret;
}

/**
 * Wrapper function for generating the (pk, sk) pair.
 * Randomness is provided by built-in RNG.
 *
 * Arguments:   DilithiumKey* key:  pointer to struct where the keys are stored
 *              WC_RNG* rng:        pointer to built-in RNG
 *
 * Returns 0 if success.
 */
int wc_DilithiumKeyGen(DilithiumKey* key,
                        WC_RNG* rng)
{
    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }
    return dilithium_crypto_sign_keypair(key->pk, key->sk, rng);
}

/**
 * Wrapper function for signing the message.
 *
 * Arguments:    uint8_t *out:      pointer to output signed message (allocated
 *                                  array with DILITHIUM_CRYPTO_BYTES + mlen bytes),
 *                                  can be equal to m
 *               size_t *outlen:    pointer to output length of signed message
 *               const uint8_t *in: pointer to message to be signed
 *               size_t inlen:      length of message
 *               DilithiumKey* key: pointer to struct where the sk is stored
 *               WC_RNG* rng:       pointer to built-in RNG
 *
 * Returns 0 if success.
 */
int wc_DilithiumSign (uint8_t *out,
                      size_t *outlen,
                      const uint8_t *in,
                      size_t inlen,
                      DilithiumKey* key,
                      WC_RNG* rng)
{
    if (out == NULL || outlen == NULL || in == NULL ||
             inlen == 0 || key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }

    return dilithium_crypto_sign(out, outlen, in, inlen, key->sk, rng);
}

/**
 * Wrapper function for verifying the signature.
 *
 * Arguments:    uint8_t *out:      pointer to output message (allocated
 *                                  array with outlen bytes), can be equal to in
 *               size_t *outlen:    pointer to output length of message
 *               const uint8_t *in: pointer to signed message
 *               size_t inlen:      length of signed message
 *               DilithiumKey* key: pointer to struct where the pk is stored
 *
 * Returns 0 if success, -1 otherwise.
 */
int wc_DilithiumVerify(uint8_t *out,
                     size_t *outlen,
                     const uint8_t *in,
                     size_t inlen,
                     DilithiumKey *key)
{

    if (out == NULL || outlen == NULL || in == NULL ||
                           inlen == 0 || key == NULL ) {
        return BAD_FUNC_ARG;
    }

    return dilithium_crypto_sign_open(out, outlen, in, inlen, key->pk);
}

/**
 * Clears the DilithiumKey data.
 *
 * Arguments: DilithiumKey* key: Dilithium key object
 */
void wc_FreeDilithiumKey(DilithiumKey* key)
{
    if (key != NULL) {
       XMEMSET(key->pk, 0, DILITHIUM_CRYPTO_PUBLICKEYBYTES);
       XMEMSET(key->sk, 0, DILITHIUM_CRYPTO_SECRETKEYBYTES);
   }
}

/**
 * Exports the Dilithium public key.
 *
 * Arguments: DilithiumKey* key: Dilithium public key.
 *            byte out:          Array to hold public key.
 *            word32 outLen:     On input, the number of bytes in array.
 *                               On output, the number bytes put into array.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than DILITHIUM_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ExportDilithiumPublic(DilithiumKey* key, byte* out, word32* outLen)
{
    /* sanity check on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (*outLen < DILITHIUM_KEY_SIZE) {
        *outLen = DILITHIUM_KEY_SIZE;
        return BUFFER_E;
    }

    *outLen = DILITHIUM_KEY_SIZE;
    XMEMCPY(out, key->pk, DILITHIUM_KEY_SIZE);

    return 0;
}

/**
 * Imports a compressed Dilithium public key from a byte array.
 * Public key encoded in big-endian.
 *
 * Arguments: const byte* in:    Array holding public key.
 *            word32 inLen:      Number of bytes of data in array.
 *            DilithiumKey* key: Dilithium public key.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL or key format is not supported,
 *         0 otherwise.
 */
int wc_ImportDilithiumPublic(const byte* in, word32 inLen, DilithiumKey* key)
{
    int ret = 0;

    /* sanity check on arguments */
    if ((in == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if  (inLen < DILITHIUM_KEY_SIZE) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* compressed prefix according to draft
         * https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-06 */
        if (in[0] == 0x40 && inLen > DILITHIUM_KEY_SIZE) {
            /* key is stored in compressed format so just copy in */
            XMEMCPY(key->pk, (in + 1), DILITHIUM_KEY_SIZE);
        }
        else if (inLen == DILITHIUM_KEY_SIZE) {
            /* if key size is equal to compressed key size copy in key */
            XMEMCPY(key->pk, in, DILITHIUM_KEY_SIZE);
        }
        else {
            /* bad public key format */
            ret = BAD_FUNC_ARG;
        }
    }

    return ret;
}

/**
 * Imports a Dilithium private key from a byte array.
 *
 * Arguments: const byte* priv:  Array holding private key.
 *            word32 privSz:     Number of bytes of data in array.
 *            DilithiumKey* key: Dilithium private key.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL or privSz is less than
 *         DILITHIUM_PRIV_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ImportDilithiumPrivate(const byte* priv, word32 privSz,
                                 DilithiumKey* key)
{
    /* sanity check on arguments */
    if ((priv == NULL) || (key == NULL) || (privSz < DILITHIUM_PRIV_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(key->sk, priv, DILITHIUM_PRIV_KEY_SIZE);

    return 0;
}

/**
 * Exports the Dilithium private key.
 *
 * Arguments: DilithiumKey* key: Dilithium private key.
 *            byte* out:         Array to hold private key.
 *            word32* outLen:    On input, the number of bytes in array.
 *                               On output, the number bytes put into array.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than DILITHIUM_PRIV_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ExportDilithiumPrivate(DilithiumKey* key, byte* out, word32* outLen)
{
    /* sanity checks on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (*outLen < DILITHIUM_PRIV_KEY_SIZE) {
        *outLen = DILITHIUM_PRIV_KEY_SIZE;
        return BUFFER_E;
    }
    *outLen = DILITHIUM_PRIV_KEY_SIZE;
    XMEMCPY(out, key->sk, DILITHIUM_PRIV_KEY_SIZE);

    return 0;
}

/**
 * Exports the Dilithium private and public key.
 *
 * Arguments: DilithiumKey* key: Dilithium private/public key.
 *            byte* priv:        Array to hold private key.
 *            word32* privSz:    On input, the number of bytes in private key array.
 *            byte* pub:         Array to hold  public key.
 *            word32* pubSz:     On input, the number of bytes in public key array.
 *                               On output, the number bytes put into array.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when privSz is less than DILITHIUM_PRIV_KEY_SIZE or pubSz is less
 *         than DILITHIUM_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ExportDilithiumKeys(DilithiumKey* key, byte* priv, word32 *privSz,
                        byte* pub, word32 *pubSz)
{
    int ret = 0;

    /* export 'full' private part */
    ret = wc_ExportDilithiumPrivate(key, priv, privSz);
    if (ret == 0) {
        /* export public part */
        ret = wc_ExportDilithiumPublic(key, pub, pubSz);
    }

    return ret;
}

/**
 * Imports Dilithium private and public keys from byte arrays.
 *
 * Arguments: const byte* priv:  Array holding private key.
 *            word32 privSz:     Number of bytes of data in private key array.
 *            const byte* pub:   Array holding public key.
 *            word32 pubSz:      Number of bytes of data in public key array.
 *            DilithiumKey* key: Dilithium private/public key.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL or privSz is less than
 *         DILITHIUM_PRIV_KEY_SIZE or pubSz is less than DILITHIUM_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ImportDilithiumKeys(const byte* priv, word32 privSz,
                           const byte* pub, word32 pubSz, DilithiumKey* key)
{
    int ret = 0;

    /* sanity check on arguments */
    if ((priv == NULL) || (pub == NULL) || (key == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* key size check */
    if ((privSz < DILITHIUM_PRIV_KEY_SIZE) || (pubSz < DILITHIUM_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }

    /* import public key */
    ret = wc_ImportDilithiumPublic(pub, pubSz, key);
    if (ret == 0) {
        /* import private key */
        ret = wc_ImportDilithiumPrivate(priv, privSz, key);
    }

    return ret;
}

#endif /* HAVE_DILITHIUM */