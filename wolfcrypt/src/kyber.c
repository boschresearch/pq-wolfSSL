/* kyber.c
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://pq-crystals.org/kyber/
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_KYBER

#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/kyber.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/kyber_memory.h>

/**
 * Generates public and private key for CCA-secure Kyber key encapsulation mechanism
 *
 * Arguments:   byte *pk: pointer to output public key (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              byte *sk: pointer to output private key (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *
 * Returns 0 if success
 */
static int crypto_kem_keypair(byte *pk, byte *sk, WC_RNG* rng)
{
    indcpa_keypair(pk, sk, rng);

    for(size_t i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; i++) {
        sk[i+KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
    }
    wc_Sha3_256Hash(pk, KYBER_PUBLICKEYBYTES, sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES);

    return wc_RNG_GenerateBlock(rng, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);
}

/**
 * Generates cipher text and shared secret for given public key
 *
 * Arguments:   byte *ct:       pointer to output cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes
 *              byte *ss:       pointer to output shared secret (an already allocated array of KYBER_SSBYTES bytes)
 *              const byte *pk: pointer to input public key (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              WC_RNG* rng:             pointer to built-in RNG
 *
 * Returns 0 if success
 */
static int crypto_kem_enc(byte* ct, byte* ss, byte* pk, WC_RNG* rng)
{
    /* Buffers will contain key, coins */
    byte kr[2*KYBER_SYMBYTES];
    byte buf[2*KYBER_SYMBYTES];

    wc_RNG_GenerateBlock(rng, buf, KYBER_SYMBYTES);
    wc_Sha3_256Hash(buf, KYBER_SYMBYTES, buf);                          /* Don't release system RNG output */
    wc_Sha3_256Hash(pk, KYBER_PUBLICKEYBYTES, buf+KYBER_SYMBYTES);      /* Multitarget countermeasure for coins + contributory KEM */
    wc_Sha3_512Hash(buf, 2*KYBER_SYMBYTES, kr);
    indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);                         /* coins are in kr+KYBER_SYMBYTES */
    wc_Sha3_256Hash(ct, KYBER_CIPHERTEXTBYTES, kr+KYBER_SYMBYTES);      /* overwrite coins in kr with H(c) */
    wc_Shake256Hash(kr, 2*KYBER_SYMBYTES, ss, KYBER_SSBYTES);           /* hash concatenation of pre-k and H(c) to k */

    return 0;
}

/**
 * Generates shared secret for given cipher text and private key
 *
 * Arguments:   byte *ss:       pointer to output shared secret (an already allocated array of KYBER_SSBYTES bytes)
 *              const byte *ct: pointer to input cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
 *              const byte *sk: pointer to input private key (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *
 * Returns 0 if success
 *
 * On failure, &key->ss parameter will contain a pseudo-random value.
 */
static int crypto_kem_dec(byte* ss, byte* ct, byte* sk)
{
    byte cmp[KYBER_CIPHERTEXTBYTES];
    byte buf[2*KYBER_SYMBYTES];
    byte kr[2*KYBER_SYMBYTES];                                      /* Will contain key, coins */
    const byte *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

    indcpa_dec(buf, ct, sk);

    for(size_t i=0; i < KYBER_SYMBYTES; i++) {                               /* Multitarget countermeasure for coins + contributory KEM */
        buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES+i]; /* Save hash by storing H(pk) in sk */
    }
    wc_Sha3_512Hash(buf, 2*KYBER_SYMBYTES, kr);

    indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);                             /* coins are in kr+KYBER_SYMBYTES */
    int fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);
    wc_Sha3_256Hash(ct, KYBER_CIPHERTEXTBYTES, kr+KYBER_SYMBYTES);             /* overwrite coins in kr with H(c)  */
    cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);  /* Overwrite pre-k with z on re-encryption failure */
    wc_Shake256Hash(kr, 2*KYBER_SYMBYTES, ss, KYBER_SSBYTES);                  /* hash concatenation of pre-k and H(c) to k */

    return 0;
}

/**
 * Wrapper function for generating the (pk, sk) pair.
 * Randomness is provided by built-in RNG.
 *
 * Arguments:   KyberKey* key:  pointer to struct where the keys are stored
 *              WC_RNG* rng:    pointer to built-in RNG
 *
 * Returns 0 if success.
 */
int wc_GenerateKyberKeyPair(KyberKey* key, WC_RNG* rng)
{
    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }
    return crypto_kem_keypair(key->pub, key->priv, rng);
}

/**
 * Wrapper function for encrypting the shared secret by responder.
 * The resulting value is stored in the KyberKey struct.
 *
 * Arguments:   KyberKey* key:  pointer to struct where the keys are stored
 *              WC_RNG* rng:    pointer to built-in RNG
 *
 * Returns 0 if success.
 */
int wc_KyberEncrypt(KyberKey* key, WC_RNG* rng)
{
    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }
    return crypto_kem_enc(key->ct, key->ss, key->pub, rng);
}

/**
 * Wrapper function for decrypting the shared secret by initiator.
 * The resulting value is stored in the KyberKey struct.
 *
 * Arguments:   KyberKey* key: pointer to struct where the keys are stored
 *
 * Returns 0 if success.
 */
int wc_KyberDecrypt(KyberKey* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    return crypto_kem_dec(key->ss, key->ct, key->priv);
}

/**
 * Initializes KyberKey struct where the keys are stored.
 * Zeroes out the memory contents.
 *
 * Arguments: KyberKey* key: pointer to struct where the keys are stored
 */
int wc_InitKyberKey(KyberKey* key)
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
 * Clears the KyberKey data.
 *
 * Arguments: KyberKey* key: Kyber key object
 */
void wc_FreeKyberKey(KyberKey* key)
{
   if (key != NULL) {
       XMEMSET(key->pub, 0, KYBER_PUBLICKEYBYTES);
       XMEMSET(key->priv, 0, KYBER_SECRETKEYBYTES);
       XMEMSET(key->ss, 0, KYBER_SSBYTES);
       XMEMSET(key->ct, 0, KYBER_CIPHERTEXTBYTES);
   }
}

#endif /* HAVE_KYBER */