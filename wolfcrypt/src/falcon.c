/* falcon.c
 *
 * Falcon signature verification.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2017-2019  Falcon Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@nccgroup.com>
 */

/*
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library.
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_FALCON

#include <stddef.h>
#include <string.h>

#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/falcon_inner.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define NONCELEN   40

/*
 * If stack usage is an issue, define TEMPALLOC to static in order to
 * allocate temporaries in the data section instead of the stack. This
 * would make the falcon_crypto_sign_keypair(), falcon_crypto_sign(), and
 * falcon_crypto_sign_open() functions not reentrant and not thread-safe, so
 * this should be done only for testing purposes.
 */
#define TEMPALLOC

int falcon_crypto_sign_keypair(unsigned char *pk,
                               unsigned char *sk,
							   WC_RNG *wolfssl_rng)
{
	TEMPALLOC union {
		uint8_t b[FALCON_KEYGEN_BUF];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC int8_t f[FALCON_BITMODE], g[FALCON_BITMODE], F[FALCON_BITMODE];
	TEMPALLOC uint16_t h[FALCON_BITMODE];
	TEMPALLOC unsigned char seed[48];
	TEMPALLOC inner_shake256_context rng;
	size_t u, v;

	/*
	 * Generate key pair.
	 */
	wc_RNG_GenerateBlock(wolfssl_rng, seed, sizeof seed);
	inner_shake256_init(&rng);
	inner_shake256_inject(&rng, seed, sizeof seed);
	inner_shake256_flip(&rng);
	Zf(keygen)(&rng, f, g, F, NULL, h, FALCON_I, tmp.b);

	/*
	 * Encode private key.
	 */
	sk[0] = 0x50 + FALCON_I;
	u = 1;
	v = Zf(trim_i8_encode)(sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u,
		f, FALCON_I, Zf(max_fg_bits)[FALCON_I]);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u,
		g, FALCON_I, Zf(max_fg_bits)[FALCON_I]);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u,
		F, FALCON_I, Zf(max_FG_bits)[FALCON_I]);
	if (v == 0) {
		return -1;
	}
	u += v;
	if (u != FALCON_CRYPTO_SECRETKEYBYTES) {
		return -1;
	}

	/*
	 * Encode public key.
	 */
	pk[0] = 0x00 + FALCON_I;
	v = Zf(modq_encode)(pk + 1, FALCON_CRYPTO_PUBLICKEYBYTES - 1, h, FALCON_I);
	if (v != FALCON_CRYPTO_PUBLICKEYBYTES - 1) {
		return -1;
	}

	return 0;
}

int falcon_crypto_sign(uint8_t *sm, size_t *smlen,
                       const uint8_t *m, size_t mlen,
					   const uint8_t *sk, WC_RNG *rng)
{
	TEMPALLOC union {
		uint8_t b[72 * FALCON_BITMODE];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC int8_t f[FALCON_BITMODE], g[FALCON_BITMODE], F[FALCON_BITMODE], G[FALCON_BITMODE];
	TEMPALLOC union {
		int16_t sig[FALCON_BITMODE];
		uint16_t hm[FALCON_BITMODE];
	} r;
	TEMPALLOC unsigned char seed[48], nonce[NONCELEN];
	TEMPALLOC unsigned char esig[FALCON_CRYPTO_BYTES - 2 - sizeof nonce];
	TEMPALLOC inner_shake256_context sc;
	size_t u, v, sig_len;

	/*
	 * Decode the private key.
	 */
	if (sk[0] != 0x50 + FALCON_I) {
		return -1;
	}
	u = 1;
	v = Zf(trim_i8_decode)(f, FALCON_I, Zf(max_fg_bits)[FALCON_I],
		sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_decode)(g, FALCON_I, Zf(max_fg_bits)[FALCON_I],
		sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_decode)(F, FALCON_I, Zf(max_FG_bits)[FALCON_I],
		sk + u, FALCON_CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	if (u != FALCON_CRYPTO_SECRETKEYBYTES) {
		return -1;
	}
	if (!Zf(complete_private)(G, f, g, F, FALCON_I, tmp.b)) {
		return -1;
	}

	/*
	 * Create a random nonce (40 bytes).
	 */
	wc_RNG_GenerateBlock(rng, nonce, sizeof nonce);

	/*
	 * Hash message nonce + message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, nonce, sizeof nonce);
	inner_shake256_inject(&sc, m, mlen);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, r.hm, FALCON_I);

	/*
	 * Initialize a RNG.
	 */
	wc_RNG_GenerateBlock(rng, seed, sizeof seed);
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, seed, sizeof seed);
	inner_shake256_flip(&sc);

	/*
	 * Compute the signature.
	 */
	Zf(sign_dyn)(r.sig, &sc, f, g, F, G, r.hm, FALCON_I, tmp.b);

	/*
	 * Encode the signature and bundle it with the message. Format is:
	 *   signature length     2 bytes, big-endian
	 *   nonce                40 bytes
	 *   message              mlen bytes
	 *   signature            slen bytes
	 */
	esig[0] = 0x20 + FALCON_I;
	sig_len = Zf(comp_encode)(esig + 1, (sizeof esig) - 1, r.sig, FALCON_I);
	if (sig_len == 0) {
		return -1;
	}
	sig_len ++;
	memmove(sm + 2 + sizeof nonce, m, mlen);
	sm[0] = (unsigned char)(sig_len >> 8);
	sm[1] = (unsigned char)sig_len;
	memcpy(sm + 2, nonce, sizeof nonce);
	memcpy(sm + 2 + (sizeof nonce) + mlen, esig, sig_len);
	*smlen = 2 + (sizeof nonce) + mlen + sig_len;
	return 0;
}

int falcon_crypto_sign_open(uint8_t *m, size_t *mlen,
                     		const uint8_t *sm, size_t smlen,
                     		const uint8_t *pk)
{
	TEMPALLOC union {
		uint8_t b[2 * FALCON_BITMODE];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	const unsigned char *esig;
	TEMPALLOC uint16_t h[FALCON_BITMODE], hm[FALCON_BITMODE];
	TEMPALLOC int16_t sig[FALCON_BITMODE];
	TEMPALLOC inner_shake256_context sc;
	size_t sig_len, msg_len;

	/*
	 * Decode public key.
	 */
	if (pk[0] != 0x00 + FALCON_I) {
		return -1;
	}
	if (Zf(modq_decode)(h, FALCON_I, pk + 1, FALCON_CRYPTO_PUBLICKEYBYTES - 1)
		!= FALCON_CRYPTO_PUBLICKEYBYTES - 1)
	{
		return -1;
	}
	Zf(to_ntt_monty)(h, FALCON_I);

	/*
	 * Find nonce, signature, message length.
	 */
	if (smlen < 2 + NONCELEN) {
		return -1;
	}
	sig_len = ((size_t)sm[0] << 8) | (size_t)sm[1];
	if (sig_len > (smlen - 2 - NONCELEN)) {
		return -1;
	}
	msg_len = smlen - 2 - NONCELEN - sig_len;

	/*
	 * Decode signature.
	 */
	esig = sm + 2 + NONCELEN + msg_len;
	if (sig_len < 1 || esig[0] != 0x20 + FALCON_I) {
		return -1;
	}
	if (Zf(comp_decode)(sig, FALCON_I,
		esig + 1, sig_len - 1) != sig_len - 1)
	{
		return -1;
	}

	/*
	 * Hash nonce + message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, sm + 2, NONCELEN + msg_len);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, hm, FALCON_I);

	/*
	 * Verify signature.
	 */
	if (!Zf(verify_raw)(hm, sig, h, FALCON_I, tmp.b)) {
		return -1;
	}

	/*
	 * Return plaintext.
	 */
	memmove(m, sm + 2 + NONCELEN, msg_len);
	*mlen = msg_len;
	return 0;
}

/**
 * Initializes FalconKey struct where the keys are stored.
 * Zeroes out the memory contents.
 *
 * Arguments: FalconKey* key: pointer to struct where the keys are stored
 */
int wc_InitFalconKey(FalconKey* key)
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
 * Arguments:   FalconKey* key:  pointer to struct where the keys are stored
 *              WC_RNG* rng:        pointer to built-in RNG
 *
 * Returns 0 if success.
 */
int wc_FalconKeyGen(FalconKey* key,
                    WC_RNG* rng)
{
    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }
    return falcon_crypto_sign_keypair(key->pk, key->sk, rng);
}

/**
 * Wrapper function for signing the message.
 *
 * Arguments:    uint8_t *out:      pointer to output signed message (allocated
 *                                  array with FALCON_CRYPTO_BYTES + mlen bytes),
 *                                  can be equal to m
 *               size_t *outlen:    pointer to output length of signed message
 *               const uint8_t *in: pointer to message to be signed
 *               size_t inlen:      length of message
 *               FalconKey* key: pointer to struct where the sk is stored
 *               WC_RNG* rng:       pointer to built-in RNG
 *
 * Returns 0 if success.
 */
int wc_FalconSign (uint8_t *out,
                   size_t *outlen,
                   const uint8_t *in,
                   size_t inlen,
                   FalconKey* key,
                   WC_RNG* rng)
{
    if (out == NULL || outlen == NULL || in == NULL ||
             inlen == 0 || key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }

    return falcon_crypto_sign(out, outlen, in, inlen, key->sk, rng);
}

/**
 * Wrapper function for verifying the signature.
 *
 * Arguments:    uint8_t *out:      pointer to output message (allocated
 *                                  array with outlen bytes), can be equal to in
 *               size_t *outlen:    pointer to output length of message
 *               const uint8_t *in: pointer to signed message
 *               size_t inlen:      length of signed message
 *               FalconKey* key: pointer to struct where the pk is stored
 *
 * Returns 0 if success, -1 otherwise.
 */
int wc_FalconVerify(uint8_t *out,
                     size_t *outlen,
                     const uint8_t *in,
                     size_t inlen,
                     FalconKey *key)
{

    if (out == NULL || outlen == NULL || in == NULL ||
                           inlen == 0 || key == NULL ) {
        return BAD_FUNC_ARG;
    }

    return falcon_crypto_sign_open(out, outlen, in, inlen, key->pk);
}

/**
 * Clears the FalconKey data.
 *
 * Arguments: FalconKey* key: Falcon key object
 */
void wc_FreeFalconKey(FalconKey* key)
{
    if (key != NULL) {
       XMEMSET(key->pk, 0, FALCON_CRYPTO_PUBLICKEYBYTES);
       XMEMSET(key->sk, 0, FALCON_CRYPTO_SECRETKEYBYTES);
   }
}

/**
 * Exports the Falcon public key.
 *
 * Arguments: FalconKey* key: Falcon public key.
 *            byte out:          Array to hold public key.
 *            word32 outLen:     On input, the number of bytes in array.
 *                               On output, the number bytes put into array.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than FALCON_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ExportFalconPublic(FalconKey* key, byte* out, word32* outLen)
{
    /* sanity check on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (*outLen < FALCON_KEY_SIZE) {
        *outLen = FALCON_KEY_SIZE;
        return BUFFER_E;
    }

    *outLen = FALCON_KEY_SIZE;
    XMEMCPY(out, key->pk, FALCON_KEY_SIZE);

    return 0;
}

/**
 * Imports a compressed Falcon public key from a byte array.
 * Public key encoded in big-endian.
 *
 * Arguments: const byte* in:    Array holding public key.
 *            word32 inLen:      Number of bytes of data in array.
 *            FalconKey* key: Falcon public key.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL or key format is not supported,
 *         0 otherwise.
 */
int wc_ImportFalconPublic(const byte* in, word32 inLen, FalconKey* key)
{
    int ret = 0;

    /* sanity check on arguments */
    if ((in == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if  (inLen < FALCON_KEY_SIZE) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* compressed prefix according to draft
         * https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-06 */
        if (in[0] == 0x40 && inLen > FALCON_KEY_SIZE) {
            /* key is stored in compressed format so just copy in */
            XMEMCPY(key->pk, (in + 1), FALCON_KEY_SIZE);
        }
        else if (inLen == FALCON_KEY_SIZE) {
            /* if key size is equal to compressed key size copy in key */
            XMEMCPY(key->pk, in, FALCON_KEY_SIZE);
        }
        else {
            /* bad public key format */
            ret = BAD_FUNC_ARG;
        }
    }

    return ret;
}

/**
 * Imports a Falcon private key from a byte array.
 *
 * Arguments: const byte* priv:  Array holding private key.
 *            word32 privSz:     Number of bytes of data in array.
 *            FalconKey* key: Falcon private key.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL or privSz is less than
 *         FALCON_PRIV_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ImportFalconPrivate(const byte* priv, word32 privSz,
                                 FalconKey* key)
{
    /* sanity check on arguments */
    if ((priv == NULL) || (key == NULL) || (privSz < FALCON_PRIV_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(key->sk, priv, FALCON_PRIV_KEY_SIZE);

    return 0;
}

/**
 * Exports the Falcon private key.
 *
 * Arguments: FalconKey* key: Falcon private key.
 *            byte* out:         Array to hold private key.
 *            word32* outLen:    On input, the number of bytes in array.
 *                               On output, the number bytes put into array.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than FALCON_PRIV_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ExportFalconPrivate(FalconKey* key, byte* out, word32* outLen)
{
    /* sanity checks on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (*outLen < FALCON_PRIV_KEY_SIZE) {
        *outLen = FALCON_PRIV_KEY_SIZE;
        return BUFFER_E;
    }
    *outLen = FALCON_PRIV_KEY_SIZE;
    XMEMCPY(out, key->sk, FALCON_PRIV_KEY_SIZE);

    return 0;
}

/**
 * Exports the Falcon private and public key.
 *
 * Arguments: FalconKey* key: Falcon private/public key.
 *            byte* priv:        Array to hold private key.
 *            word32* privSz:    On input, the number of bytes in private key array.
 *            byte* pub:         Array to hold  public key.
 *            word32* pubSz:     On input, the number of bytes in public key array.
 *                               On output, the number bytes put into array.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when privSz is less than FALCON_PRIV_KEY_SIZE or pubSz is less
 *         than FALCON_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ExportFalconKeys(FalconKey* key, byte* priv, word32 *privSz,
                        byte* pub, word32 *pubSz)
{
    int ret = 0;

    /* export 'full' private part */
    ret = wc_ExportFalconPrivate(key, priv, privSz);
    if (ret == 0) {
        /* export public part */
        ret = wc_ExportFalconPublic(key, pub, pubSz);
    }

    return ret;
}

/**
 * Imports Falcon private and public keys from byte arrays.
 *
 * Arguments: const byte* priv:  Array holding private key.
 *            word32 privSz:     Number of bytes of data in private key array.
 *            const byte* pub:   Array holding public key.
 *            word32 pubSz:      Number of bytes of data in public key array.
 *            FalconKey* key: Falcon private/public key.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL or privSz is less than
 *         FALCON_PRIV_KEY_SIZE or pubSz is less than FALCON_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ImportFalconKeys(const byte* priv, word32 privSz,
                           const byte* pub, word32 pubSz, FalconKey* key)
{
    int ret = 0;

    /* sanity check on arguments */
    if ((priv == NULL) || (pub == NULL) || (key == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* key size check */
    if ((privSz < FALCON_PRIV_KEY_SIZE) || (pubSz < FALCON_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }

    /* import public key */
    ret = wc_ImportFalconPublic(pub, pubSz, key);
    if (ret == 0) {
        /* import private key */
        ret = wc_ImportFalconPrivate(priv, privSz, key);
    }

    return ret;
}

#endif /* HAVE_FALCON */