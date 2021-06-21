/* xmss.c
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://github.com/XMSS.
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_XMSS

#include <stdint.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/xmss.h>
#include <wolfssl/wolfcrypt/xmss_core.h>

/* This file provides wrapper functions that take keys that include OIDs to
identify the parameter set to be used. After setting the parameters accordingly
it falls back to the regular XMSS core functions. */

int xmss_keypair(unsigned char *pk, unsigned char *sk, WC_RNG *rng)
{
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        pk[XMSS_OID_LEN - i - 1] = (XMSS_OID >> (8 * i)) & 0xFF;
        /* For an implementation that uses runtime parameters, it is crucial
        that the OID is part of the secret key as well;
        i.e. not just for interoperability, but also for internal use. */
        sk[XMSS_OID_LEN - i - 1] = (XMSS_OID >> (8 * i)) & 0xFF;
    }
    return xmss_core_keypair(pk + XMSS_OID_LEN, sk + XMSS_OID_LEN, rng);
}

int xmss_crypto_sign(unsigned char *sk, unsigned char *sm, unsigned long long *smlen,
              const unsigned char *m, unsigned long long mlen)
{
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    return xmss_core_sign(sk + XMSS_OID_LEN, sm, smlen, m, mlen);
}

int xmss_sign_open(unsigned char *m, unsigned long long *mlen,
                   const unsigned char *sm, unsigned long long smlen,
                   const unsigned char *pk)
{
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= pk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    return xmss_core_sign_open(m, mlen, sm, smlen, pk + XMSS_OID_LEN);
}

int xmssmt_keypair(unsigned char *pk, unsigned char *sk,
                   WC_RNG *rng)
{
    unsigned int i;


    for (i = 0; i < XMSS_OID_LEN; i++) {
        pk[XMSS_OID_LEN - i - 1] = (XMSS_OID >> (8 * i)) & 0xFF;
        sk[XMSS_OID_LEN - i - 1] = (XMSS_OID >> (8 * i)) & 0xFF;
    }
    return xmssmt_core_keypair(pk + XMSS_OID_LEN, sk + XMSS_OID_LEN, rng);
}

int xmssmt_sign(unsigned char *sk,
                unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen)
{
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }

    return xmssmt_core_sign(sk + XMSS_OID_LEN, sm, smlen, m, mlen);
}

int xmssmt_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= pk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    return xmssmt_core_sign_open(m, mlen, sm, smlen, pk + XMSS_OID_LEN);
}

/**
 * Initializes XmssKey struct where the keys are stored.
 * Zeroes out the memory contents.
 *
 * Arguments: XmssKey* key: pointer to struct where the keys are stored
 */
int wc_InitXmssKey(XmssKey* key)
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
 * Arguments:   XmssKey* key:  pointer to struct where the keys are stored
 *              WC_RNG* rng:        pointer to built-in RNG
 *
 * Returns 0 if success.
 */
int wc_XmssKeyGen(XmssKey* key, WC_RNG* rng)
{
    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }
    return xmss_keypair(key->pk, key->sk, rng);
}

/**
 * Wrapper function for signing the message.
 *
 * Arguments:    uint8_t *out:      pointer to output signed message (allocated
 *                                  array with XMSS_CRYPTO_BYTES + mlen bytes),
 *                                  can be equal to m
 *               size_t *outlen:    pointer to output length of signed message
 *               const uint8_t *in: pointer to message to be signed
 *               size_t inlen:      length of message
 *               XmssKey* key: pointer to struct where the sk is stored
 *               WC_RNG* rng:       pointer to built-in RNG
 *
 * Returns 0 if success.
 */
int wc_XmssSign (uint8_t *out,
                      long long unsigned int *outlen,
                      const uint8_t *in,
                      size_t inlen,
                      XmssKey* key)
{
    if (out == NULL || outlen == NULL || in == NULL ||
             inlen == 0 || key == NULL) {
        return BAD_FUNC_ARG;
    }

    return xmss_crypto_sign(key->sk, out, outlen, in, inlen);
}

/**
 * Wrapper function for verifying the signature.
 *
 * Arguments:    uint8_t *out:      pointer to output message (allocated
 *                                  array with outlen bytes), can be equal to in
 *               size_t *outlen:    pointer to output length of message
 *               const uint8_t *in: pointer to signed message
 *               size_t inlen:      length of signed message
 *               XmssKey* key: pointer to struct where the pk is stored
 *
 * Returns 0 if success, -1 otherwise.
 */
int wc_XmssVerify(uint8_t *out,
                     long long unsigned int *outlen,
                     const uint8_t *in,
                     size_t inlen,
                     XmssKey *key)
{

    if (out == NULL || outlen == NULL || in == NULL ||
                           inlen == 0 || key == NULL ) {
        return BAD_FUNC_ARG;
    }

    return xmss_sign_open(out, outlen, in, inlen, key->pk);
}

/**
 * Clears the XmssKey data.
 *
 * Arguments: XmssKey* key: Xmss key object
 */
void wc_FreeXmssKey(XmssKey* key)
{
    if (key != NULL) {
       XMEMSET(key->pk, 0, XMSS_PUB_KEY_SIZE);
       XMEMSET(key->sk, 0, XMSS_PRIV_KEY_SIZE);
   }
}

/**
 * Exports the Xmss public key.
 *
 * Arguments: XmssKey* key: Xmss public key.
 *            byte out:          Array to hold public key.
 *            word32 outLen:     On input, the number of bytes in array.
 *                               On output, the number bytes put into array.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than XMSS_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ExportXmssPublic(XmssKey* key, byte* out, word32* outLen)
{
    /* sanity check on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (*outLen < XMSS_KEY_SIZE) {
        *outLen = XMSS_KEY_SIZE;
        return BUFFER_E;
    }

    *outLen = XMSS_KEY_SIZE;
    XMEMCPY(out, key->pk, XMSS_KEY_SIZE);

    return 0;
}

/**
 * Imports a compressed Xmss public key from a byte array.
 * Public key encoded in big-endian.
 *
 * Arguments: const byte* in:    Array holding public key.
 *            word32 inLen:      Number of bytes of data in array.
 *            XmssKey* key: Xmss public key.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL or key format is not supported,
 *         0 otherwise.
 */
int wc_ImportXmssPublic(const byte* in, word32 inLen, XmssKey* key)
{
    int ret = 0;

    /* sanity check on arguments */
    if ((in == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if  (inLen < XMSS_KEY_SIZE) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* compressed prefix according to draft
         * https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-06 */
        if (in[0] == 0x40 && inLen > XMSS_KEY_SIZE) {
            /* key is stored in compressed format so just copy in */
            XMEMCPY(key->pk, (in + 1), XMSS_KEY_SIZE);
        }
        else if (inLen == XMSS_KEY_SIZE) {
            /* if key size is equal to compressed key size copy in key */
            XMEMCPY(key->pk, in, XMSS_KEY_SIZE);
        }
        else {
            /* bad public key format */
            ret = BAD_FUNC_ARG;
        }
    }

    return ret;
}

/**
 * Imports a Xmss private key from a byte array.
 *
 * Arguments: const byte* priv:  Array holding private key.
 *            word32 privSz:     Number of bytes of data in array.
 *            XmssKey* key: Xmss private key.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL or privSz is less than
 *         XMSS_PRIV_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ImportXmssPrivate(const byte* priv, word32 privSz,
                                 XmssKey* key)
{
    /* sanity check on arguments */
    if ((priv == NULL) || (key == NULL) || (privSz < XMSS_PRIV_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(key->sk, priv, XMSS_PRIV_KEY_SIZE);

    return 0;
}

/**
 * Exports the Xmss private key.
 *
 * Arguments: XmssKey* key: Xmss private key.
 *            byte* out:         Array to hold private key.
 *            word32* outLen:    On input, the number of bytes in array.
 *                               On output, the number bytes put into array.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than XMSS_PRIV_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ExportXmssPrivate(XmssKey* key, byte* out, word32* outLen)
{
    /* sanity checks on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (*outLen < XMSS_PRIV_KEY_SIZE) {
        *outLen = XMSS_PRIV_KEY_SIZE;
        return BUFFER_E;
    }
    *outLen = XMSS_PRIV_KEY_SIZE;
    XMEMCPY(out, key->sk, XMSS_PRIV_KEY_SIZE);

    return 0;
}

/**
 * Exports the Xmss private and public key.
 *
 * Arguments: XmssKey* key: Xmss private/public key.
 *            byte* priv:        Array to hold private key.
 *            word32* privSz:    On input, the number of bytes in private key array.
 *            byte* pub:         Array to hold  public key.
 *            word32* pubSz:     On input, the number of bytes in public key array.
 *                               On output, the number bytes put into array.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when privSz is less than XMSS_PRIV_KEY_SIZE or pubSz is less
 *         than XMSS_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ExportXmssKeys(XmssKey* key, byte* priv, word32 *privSz,
                        byte* pub, word32 *pubSz)
{
    int ret = 0;

    /* export 'full' private part */
    ret = wc_ExportXmssPrivate(key, priv, privSz);
    if (ret == 0) {
        /* export public part */
        ret = wc_ExportXmssPublic(key, pub, pubSz);
    }

    return ret;
}

/**
 * Imports Xmss private and public keys from byte arrays.
 *
 * Arguments: const byte* priv:  Array holding private key.
 *            word32 privSz:     Number of bytes of data in private key array.
 *            const byte* pub:   Array holding public key.
 *            word32 pubSz:      Number of bytes of data in public key array.
 *            XmssKey* key: Xmss private/public key.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL or privSz is less than
 *         XMSS_PRIV_KEY_SIZE or pubSz is less than XMSS_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ImportXmssKeys(const byte* priv, word32 privSz,
                           const byte* pub, word32 pubSz, XmssKey* key)
{
    int ret = 0;

    /* sanity check on arguments */
    if ((priv == NULL) || (pub == NULL) || (key == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* key size check */
    if ((privSz < XMSS_PRIV_KEY_SIZE) || (pubSz < XMSS_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }

    /* import public key */
    ret = wc_ImportXmssPublic(pub, pubSz, key);
    if (ret == 0) {
        /* import private key */
        ret = wc_ImportXmssPrivate(priv, privSz, key);
    }

    return ret;
}

#endif
