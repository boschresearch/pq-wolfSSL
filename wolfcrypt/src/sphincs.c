/* sphincs.c
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://sphincs.org/
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_SPHINCS

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sphincs.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sphincs_wots.h>
#include <wolfssl/wolfcrypt/sphincs_fors.h>
#include <wolfssl/wolfcrypt/sphincs_hash.h>
#include <wolfssl/wolfcrypt/sphincs_thash.h>
#include <wolfssl/wolfcrypt/sphincs_utils.h>
#include <wolfssl/wolfcrypt/sphincs_address.h>

/**
 * Computes the leaf at a given address. First generates the WOTS key pair,
 * then computes leaf by hashing horizontally.
 */
static void wots_gen_leaf(unsigned char *leaf, const unsigned char *sk_seed,
                          const unsigned char *pub_seed,
                          uint32_t addr_idx, const uint32_t tree_addr[8])
{
    unsigned char pk[SPX_WOTS_BYTES];
    uint32_t wots_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    sphincs_set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    sphincs_set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    sphincs_copy_subtree_addr(wots_addr, tree_addr);
    set_keypair_addr(wots_addr, addr_idx);
    wots_gen_pk(pk, sk_seed, pub_seed, wots_addr);

    copy_keypair_addr(wots_pk_addr, wots_addr);
    thash(leaf, pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);
}

/*
 * Generates an SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int sphincs_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed)
{
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[SPX_TREE_HEIGHT * SPX_N];
    uint32_t top_tree_addr[8] = {0};

    sphincs_set_layer_addr(top_tree_addr, SPX_D - 1);
    sphincs_set_type(top_tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, SPHINCS_CRYPTO_SEEDBYTES);

    memcpy(pk, sk + 2*SPX_N, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(pk, sk);

    /* Compute root node of the top-most subtree. */
    treehash(sk + 3*SPX_N, auth_path, sk, sk + 2*SPX_N, 0, 0, SPX_TREE_HEIGHT,
             wots_gen_leaf, top_tree_addr);

    memcpy(pk + SPX_N, sk + 3*SPX_N, SPX_N);

    return 0;
}

/*
 * Generates an SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int sphincs_crypto_sign_keypair(unsigned char *pk, unsigned char *sk, WC_RNG *rng)
{
  unsigned char seed[SPHINCS_CRYPTO_SEEDBYTES];
  wc_RNG_GenerateBlock(rng, seed, SPHINCS_CRYPTO_SEEDBYTES);
  sphincs_crypto_sign_seed_keypair(pk, sk, seed);

  return 0;
}

/**
 * Returns an array containing a detached signature.
 */
int sphincs_crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk, WC_RNG *rng)
{
    const unsigned char *sk_seed = sk;
    const unsigned char *sk_prf = sk + SPX_N;
    const unsigned char *pk = sk + 2*SPX_N;
    const unsigned char *pub_seed = pk;

    unsigned char optrand[SPX_N];
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char root[SPX_N];
    unsigned long long i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(pub_seed, sk_seed);

    sphincs_set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    sphincs_set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    wc_RNG_GenerateBlock(rng, optrand, SPX_N);
    /* Compute the digest randomization value. */
    gen_message_random(sig, sk_prf, optrand, m, mlen);

    /* Derive the message digest and leaf index from R, PK and M. */
    sphincs_hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen);
    sig += SPX_N;

    sphincs_set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign(sig, root, mhash, sk_seed, pub_seed, wots_addr);
    sig += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; i++) {
        sphincs_set_layer_addr(tree_addr, i);
        sphincs_set_tree_addr(tree_addr, tree);

        sphincs_copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        /* Compute a WOTS signature. */
        sphincs_wots_sign(sig, root, sk_seed, pub_seed, wots_addr);
        sig += SPX_WOTS_BYTES;

        /* Compute the authentication path for the used WOTS leaf. */
        treehash(root, sig, sk_seed, pub_seed, idx_leaf, 0,
                 SPX_TREE_HEIGHT, wots_gen_leaf, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    *siglen = SPX_BYTES;

    return 0;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
int sphincs_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    const unsigned char *pub_seed = pk;
    const unsigned char *pub_root = pk + SPX_N;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    if (siglen != SPX_BYTES) {
        return -1;
    }

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(pub_seed, NULL);

    sphincs_set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    sphincs_set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    sphincs_set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    sphincs_hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen);
    sig += SPX_N;

    /* Layer correctly defaults to 0, so no need to sphincs_set_layer_addr */
    sphincs_set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig(root, sig, mhash, pub_seed, wots_addr);
    sig += SPX_FORS_BYTES;

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++) {
        sphincs_set_layer_addr(tree_addr, i);
        sphincs_set_tree_addr(tree_addr, tree);

        sphincs_copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        sphincs_wots_pk_from_sig(wots_pk, sig, root, pub_seed, wots_addr);
        sig += SPX_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     pub_seed, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N)) {
        return -1;
    }

    return 0;
}


/**
 * Returns an array containing the signature followed by the message.
 */
int sphincs_crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk, WC_RNG *rng)
{
    size_t siglen;

    sphincs_crypto_sign_signature(sm, &siglen, m, (size_t)mlen, sk, rng);

    memmove(sm + SPX_BYTES, m, mlen);
    *smlen = siglen + mlen;

    return 0;
}

/**
 * Verifies a given signature-message pair under a given public key.
 */
int sphincs_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly SPX_BYTES. */
    if (smlen < SPX_BYTES) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    *mlen = smlen - SPX_BYTES;

    if (sphincs_crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, (size_t)*mlen, pk)) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    /* If verification was successful, move the message to the right place. */
    memmove(m, sm + SPX_BYTES, *mlen);

    return 0;
}

/**
 * Initializes SphincsKey struct where the keys are stored.
 * Zeroes out the memory contents.
 *
 * Arguments: SphincsKey* key: pointer to struct where the keys are stored
 */
int wc_InitSphincsKey(SphincsKey* key)
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
 * Arguments:   SphincsKey* key:  pointer to struct where the keys are stored
 *              WC_RNG* rng:        pointer to built-in RNG
 *
 * Returns 0 if success.
 */
int wc_SphincsKeyGen(SphincsKey* key,
                        WC_RNG* rng)
{
    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }
    return sphincs_crypto_sign_keypair(key->pk, key->sk, rng);
}

/**
 * Wrapper function for signing the message.
 *
 * Arguments:    uint8_t *out:      pointer to output signed message (allocated
 *                                  array with SPHINCS_CRYPTO_BYTES + mlen bytes),
 *                                  can be equal to m
 *               size_t *outlen:    pointer to output length of signed message
 *               const uint8_t *in: pointer to message to be signed
 *               size_t inlen:      length of message
 *               SphincsKey* key: pointer to struct where the sk is stored
 *               WC_RNG* rng:       pointer to built-in RNG
 *
 * Returns 0 if success.
 */
int wc_SphincsSign (uint8_t *out,
                      long long unsigned int *outlen,
                      const uint8_t *in,
                      size_t inlen,
                      SphincsKey* key,
                      WC_RNG* rng)
{
    if (out == NULL || outlen == NULL || in == NULL ||
             inlen == 0 || key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }

    return sphincs_crypto_sign(out, outlen, in, inlen, key->sk, rng);
}

/**
 * Wrapper function for verifying the signature.
 *
 * Arguments:    uint8_t *out:      pointer to output message (allocated
 *                                  array with outlen bytes), can be equal to in
 *               size_t *outlen:    pointer to output length of message
 *               const uint8_t *in: pointer to signed message
 *               size_t inlen:      length of signed message
 *               SphincsKey* key: pointer to struct where the pk is stored
 *
 * Returns 0 if success, -1 otherwise.
 */
int wc_SphincsVerify(uint8_t *out,
                     long long unsigned int *outlen,
                     const uint8_t *in,
                     size_t inlen,
                     SphincsKey *key)
{

    if (out == NULL || outlen == NULL || in == NULL ||
                           inlen == 0 || key == NULL ) {
        return BAD_FUNC_ARG;
    }

    return sphincs_crypto_sign_open(out, outlen, in, inlen, key->pk);
}

/**
 * Clears the SphincsKey data.
 *
 * Arguments: SphincsKey* key: Sphincs key object
 */
void wc_FreeSphincsKey(SphincsKey* key)
{
    if (key != NULL) {
       XMEMSET(key->pk, 0, SPHINCS_CRYPTO_PUBLICKEYBYTES);
       XMEMSET(key->sk, 0, SPHINCS_CRYPTO_SECRETKEYBYTES);
   }
}

/**
 * Exports the Sphincs public key.
 *
 * Arguments: SphincsKey* key: Sphincs public key.
 *            byte out:          Array to hold public key.
 *            word32 outLen:     On input, the number of bytes in array.
 *                               On output, the number bytes put into array.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than SPHINCS_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ExportSphincsPublic(SphincsKey* key, byte* out, word32* outLen)
{
    /* sanity check on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (*outLen < SPHINCS_KEY_SIZE) {
        *outLen = SPHINCS_KEY_SIZE;
        return BUFFER_E;
    }

    *outLen = SPHINCS_KEY_SIZE;
    XMEMCPY(out, key->pk, SPHINCS_KEY_SIZE);

    return 0;
}

/**
 * Imports a compressed Sphincs public key from a byte array.
 * Public key encoded in big-endian.
 *
 * Arguments: const byte* in:    Array holding public key.
 *            word32 inLen:      Number of bytes of data in array.
 *            SphincsKey* key: Sphincs public key.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL or key format is not supported,
 *         0 otherwise.
 */
int wc_ImportSphincsPublic(const byte* in, word32 inLen, SphincsKey* key)
{
    int ret = 0;

    /* sanity check on arguments */
    if ((in == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if  (inLen < SPHINCS_KEY_SIZE) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* compressed prefix according to draft
         * https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-06 */
        if (in[0] == 0x40 && inLen > SPHINCS_KEY_SIZE) {
            /* key is stored in compressed format so just copy in */
            XMEMCPY(key->pk, (in + 1), SPHINCS_KEY_SIZE);
        }
        else if (inLen == SPHINCS_KEY_SIZE) {
            /* if key size is equal to compressed key size copy in key */
            XMEMCPY(key->pk, in, SPHINCS_KEY_SIZE);
        }
        else {
            /* bad public key format */
            ret = BAD_FUNC_ARG;
        }
    }

    return ret;
}

/**
 * Imports a Sphincs private key from a byte array.
 *
 * Arguments: const byte* priv:  Array holding private key.
 *            word32 privSz:     Number of bytes of data in array.
 *            SphincsKey* key: Sphincs private key.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL or privSz is less than
 *         SPHINCS_PRIV_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ImportSphincsPrivate(const byte* priv, word32 privSz,
                                 SphincsKey* key)
{
    /* sanity check on arguments */
    if ((priv == NULL) || (key == NULL) || (privSz < SPHINCS_PRIV_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(key->sk, priv, SPHINCS_PRIV_KEY_SIZE);

    return 0;
}

/**
 * Exports the Sphincs private key.
 *
 * Arguments: SphincsKey* key: Sphincs private key.
 *            byte* out:         Array to hold private key.
 *            word32* outLen:    On input, the number of bytes in array.
 *                               On output, the number bytes put into array.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than SPHINCS_PRIV_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ExportSphincsPrivate(SphincsKey* key, byte* out, word32* outLen)
{
    /* sanity checks on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (*outLen < SPHINCS_PRIV_KEY_SIZE) {
        *outLen = SPHINCS_PRIV_KEY_SIZE;
        return BUFFER_E;
    }
    *outLen = SPHINCS_PRIV_KEY_SIZE;
    XMEMCPY(out, key->sk, SPHINCS_PRIV_KEY_SIZE);

    return 0;
}

/**
 * Exports the Sphincs private and public key.
 *
 * Arguments: SphincsKey* key: Sphincs private/public key.
 *            byte* priv:        Array to hold private key.
 *            word32* privSz:    On input, the number of bytes in private key array.
 *            byte* pub:         Array to hold  public key.
 *            word32* pubSz:     On input, the number of bytes in public key array.
 *                               On output, the number bytes put into array.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when privSz is less than SPHINCS_PRIV_KEY_SIZE or pubSz is less
 *         than SPHINCS_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ExportSphincsKeys(SphincsKey* key, byte* priv, word32 *privSz,
                        byte* pub, word32 *pubSz)
{
    int ret = 0;

    /* export 'full' private part */
    ret = wc_ExportSphincsPrivate(key, priv, privSz);
    if (ret == 0) {
        /* export public part */
        ret = wc_ExportSphincsPublic(key, pub, pubSz);
    }

    return ret;
}

/**
 * Imports Sphincs private and public keys from byte arrays.
 *
 * Arguments: const byte* priv:  Array holding private key.
 *            word32 privSz:     Number of bytes of data in private key array.
 *            const byte* pub:   Array holding public key.
 *            word32 pubSz:      Number of bytes of data in public key array.
 *            SphincsKey* key: Sphincs private/public key.
 *
 * Returns BAD_FUNC_ARG when a parameter is NULL or privSz is less than
 *         SPHINCS_PRIV_KEY_SIZE or pubSz is less than SPHINCS_KEY_SIZE,
 *         0 otherwise.
 */
int wc_ImportSphincsKeys(const byte* priv, word32 privSz,
                           const byte* pub, word32 pubSz, SphincsKey* key)
{
    int ret = 0;

    /* sanity check on arguments */
    if ((priv == NULL) || (pub == NULL) || (key == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* key size check */
    if ((privSz < SPHINCS_PRIV_KEY_SIZE) || (pubSz < SPHINCS_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }

    /* import public key */
    ret = wc_ImportSphincsPublic(pub, pubSz, key);
    if (ret == 0) {
        /* import private key */
        ret = wc_ImportSphincsPrivate(priv, privSz, key);
    }

    return ret;
}
#endif
