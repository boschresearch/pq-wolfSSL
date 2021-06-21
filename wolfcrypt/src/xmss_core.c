/* xmss_core.c
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://github.com/XMSS.
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_XMSS

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wolfssl/wolfcrypt/xmss_hash.h>
#include <wolfssl/wolfcrypt/xmss_hash_address.h>
#include <wolfssl/wolfcrypt/xmss.h>
#include <wolfssl/wolfcrypt/xmss_wots.h>
#include <wolfssl/wolfcrypt/xmss_utils.h>
#include <wolfssl/wolfcrypt/xmss_core.h>

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of subtree_addr to be set.
 */
static void treehash(unsigned char *root, unsigned char *auth_path,
                     const unsigned char *sk_seed,
                     const unsigned char *pub_seed,
                     uint32_t leaf_idx, const uint32_t subtree_addr[8])
{
    unsigned char stack[(XMSS_TREE_HEIGHT+1)*XMSS_N];
    unsigned int heights[XMSS_TREE_HEIGHT+1];
    unsigned int offset = 0;

    /* The subtree has at most 2^20 leafs, so uint32_t suffices. */
    uint32_t idx;
    uint32_t tree_idx;

    /* We need all three types of addresses in parallel. */
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    /* Select the required subtree. */
    xmss_copy_subtree_addr(ots_addr, subtree_addr);
    xmss_copy_subtree_addr(ltree_addr, subtree_addr);
    xmss_copy_subtree_addr(node_addr, subtree_addr);

    xmss_set_type(ots_addr, XMSS_ADDR_TYPE_OTS);
    xmss_set_type(ltree_addr, XMSS_ADDR_TYPE_LTREE);
    xmss_set_type(node_addr, XMSS_ADDR_TYPE_HASHTREE);

    for (idx = 0; idx < (uint32_t)(1 << XMSS_TREE_HEIGHT); idx++) {
        /* Add the next leaf node to the stack. */
        set_ltree_addr(ltree_addr, idx);
        set_ots_addr(ots_addr, idx);
        gen_leaf_wots(stack + offset*XMSS_N,
                      sk_seed, pub_seed, ltree_addr, ots_addr);
        offset++;
        heights[offset - 1] = 0;

        /* If this is a node we need for the auth path.. */
        if ((leaf_idx ^ 0x1) == idx) {
            memcpy(auth_path, stack + (offset - 1)*XMSS_N, XMSS_N);
        }

        /* While the top-most nodes are of equal height.. */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* Compute index of the new node, in the next layer. */
            tree_idx = (idx >> (heights[offset - 1] + 1));

            /* Hash the top-most nodes from the stack together. */
            /* Note that tree height is the 'lower' layer, even though we use
               the index of the new node on the 'higher' layer. This follows
               from the fact that we address the hash function calls. */
            xmss_set_tree_height(node_addr, heights[offset - 1]);
            xmss_set_tree_index(node_addr, tree_idx);
            thash_h(stack + (offset-2)*XMSS_N,
                           stack + (offset-2)*XMSS_N, pub_seed, node_addr);
            offset--;
            /* Note that the top-most node is now one layer higher. */
            heights[offset - 1]++;

            /* If this is a node we need for the auth path.. */
            if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
                memcpy(auth_path + heights[offset - 1]*XMSS_N,
                       stack + (offset - 1)*XMSS_N, XMSS_N);
            }
        }
    }
    memcpy(root, stack, XMSS_N);
}

/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED], omitting algorithm OID.
 */
int xmss_core_keypair(unsigned char *pk, unsigned char *sk,
                      WC_RNG *rng)
{
    /* The key generation procedure of XMSS and XMSSMT is exactly the same.
       The only important detail is that the right subtree must be selected;
       this requires us to correctly set the d=1 parameter for XMSS. */
    return xmssmt_core_keypair(pk, sk, rng);
}

/**
 * Signs a message. Returns an array containing the signature followed by the
 * message and an updated secret key.
 */
int xmss_core_sign(unsigned char *sk,
                   unsigned char *sm, unsigned long long *smlen,
                   const unsigned char *m, unsigned long long mlen)
{
    /* XMSS signatures are fundamentally an instance of XMSSMT signatures.
       For d=1, as is the case with XMSS, some of the calls in the XMSSMT
       routine become vacuous (i.e. the loop only iterates once, and address
       management can be simplified a bit).*/
    return xmssmt_core_sign(sk, sm, smlen, m, mlen);
}

/*
 * Derives a XMSSMT key pair for a given parameter set.
 * Seed must be 3*n long.
 * Format sk: [(ceil(h/8) bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algorithm OID.
 */
int xmssmt_core_seed_keypair(unsigned char *pk, unsigned char *sk,
                             unsigned char *seed)
{
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[XMSS_TREE_HEIGHT * XMSS_N];
    uint32_t top_tree_addr[8] = {0};
    xmss_set_layer_addr(top_tree_addr, XMSS_D - 1);

    /* Initialize index to 0. */
    memset(sk, 0, XMSS_INDEX_BYTES);
    sk += XMSS_INDEX_BYTES;

    /* Initialize SK_SEED and SK_PRF. */
    memcpy(sk, seed, 2 * XMSS_N);

    /* Initialize PUB_SEED. */
    memcpy(sk + 3 * XMSS_N, seed + 2 * XMSS_N,  XMSS_N);
    memcpy(pk + XMSS_N, sk + 3*XMSS_N, XMSS_N);

    /* Compute root node of the top-most subtree. */
    treehash(pk, auth_path, sk, pk + XMSS_N, 0, top_tree_addr);
    memcpy(sk + 2*XMSS_N, pk, XMSS_N);

    return 0;
}

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algorithm OID.
 */
int xmssmt_core_keypair(unsigned char *pk, unsigned char *sk,
                        WC_RNG *rng)
{
    unsigned char seed[3 * XMSS_N];

    wc_RNG_GenerateBlock(rng, seed, 3 * XMSS_N);
    xmssmt_core_seed_keypair(pk, sk, seed);

    return 0;
}

/**
 * Signs a message. Returns an array containing the signature followed by the
 * message and an updated secret key.
 */
int xmssmt_core_sign(unsigned char *sk,
                     unsigned char *sm, unsigned long long *smlen,
                     const unsigned char *m, unsigned long long mlen)
{
    const unsigned char *sk_seed = sk + XMSS_INDEX_BYTES;
    const unsigned char *sk_prf = sk + XMSS_INDEX_BYTES + XMSS_N;
    const unsigned char *pub_root = sk + XMSS_INDEX_BYTES + 2*XMSS_N;
    const unsigned char *pub_seed = sk + XMSS_INDEX_BYTES + 3*XMSS_N;

    unsigned char root[XMSS_N];
    unsigned char *mhash = root;
    unsigned long long idx;
    unsigned char idx_bytes_32[32];
    unsigned int i;
    uint32_t idx_leaf;

    uint32_t ots_addr[8] = {0};
    xmss_set_type(ots_addr, XMSS_ADDR_TYPE_OTS);

    /* Already put the message in the right place, to make it easier to prepend
     * things when computing the hash over the message. */
    memcpy(sm + XMSS_SIG_BYTES, m, mlen);
    *smlen = XMSS_SIG_BYTES + mlen;

    /* Read and use the current index from the secret key. */
    idx = (unsigned long)xmss_bytes_to_ull(sk, XMSS_INDEX_BYTES);
    memcpy(sm, sk, XMSS_INDEX_BYTES);

    /*************************************************************************
     * THIS IS WHERE PRODUCTION IMPLEMENTATIONS WOULD UPDATE THE SECRET KEY. *
     *************************************************************************/
    /* Increment the index in the secret key. */
    xmss_ull_to_bytes(sk, XMSS_INDEX_BYTES, idx + 1);

    /* Compute the digest randomization value. */
    xmss_ull_to_bytes(idx_bytes_32, 32, idx);
    prf(sm + XMSS_INDEX_BYTES, idx_bytes_32, sk_prf);

    /* Compute the message hash. */
    xmss_hash_message(mhash, sm + XMSS_INDEX_BYTES, pub_root, idx,
                 sm + XMSS_SIG_BYTES - XMSS_PADDING_LEN - 3*XMSS_N,
                 mlen);
    sm += XMSS_INDEX_BYTES + XMSS_N;

    xmss_set_type(ots_addr, XMSS_ADDR_TYPE_OTS);

    for (i = 0; i < XMSS_D; i++) {
        idx_leaf = (idx & ((1 << XMSS_TREE_HEIGHT)-1));
        idx = idx >> XMSS_TREE_HEIGHT;

        xmss_set_layer_addr(ots_addr, i);
        xmss_set_tree_addr(ots_addr, idx);
        set_ots_addr(ots_addr, idx_leaf);

        /* Compute a WOTS signature. */
        /* Initially, root = mhash, but on subsequent iterations it is the root
           of the subtree below the currently processed subtree. */
        xmss_wots_sign(sm, root, sk_seed, pub_seed, ots_addr);
        sm += XMSS_WOTS_SIG_BYTES;

        /* Compute the authentication path for the used WOTS leaf. */
        treehash(root, sm, sk_seed, pub_seed, idx_leaf, ots_addr);
        sm += XMSS_TREE_HEIGHT*XMSS_N;
    }

    return 0;
}

#endif /* HAVE_XMSS */
