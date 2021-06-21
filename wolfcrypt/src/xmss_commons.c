/* xmss_commons.c
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
 * Computes a leaf node from a WOTS public key using an L-tree.
 * Note that this destroys the used WOTS public key.
 */
static void l_tree(unsigned char *leaf, unsigned char *wots_pk,
                   const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned int l = XMSS_WOTS_LEN;
    unsigned int parent_nodes;
    uint32_t i;
    uint32_t height = 0;

    xmss_set_tree_height(addr, height);

    while (l > 1) {
        parent_nodes = l >> 1;
        for (i = 0; i < parent_nodes; i++) {
            xmss_set_tree_index(addr, i);
            /* Hashes the nodes at (i*2)*XMSS_N and (i*2)*XMSS_N + 1 */
            thash_h(wots_pk + i*XMSS_N,
                    wots_pk + (i*2)*XMSS_N, pub_seed, addr);
        }
        /* If the row contained an odd number of nodes, the last node was not
           hashed. Instead, we pull it up to the next layer. */
        if (l & 1) {
            memcpy(wots_pk + (l >> 1)*XMSS_N,
                   wots_pk + (l - 1)*XMSS_N, XMSS_N);
            l = (l >> 1) + 1;
        }
        else {
            l = l >> 1;
        }
        height++;
        xmss_set_tree_height(addr, height);
    }
    memcpy(leaf, wots_pk, XMSS_N);
}

/**
 * Computes a root node given a leaf and an auth path
 */
static void compute_root(unsigned char *root, const unsigned char *leaf,
                         unsigned long leafidx, const unsigned char *auth_path,
                         const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;
    unsigned char buffer[2*XMSS_N];

    /* If leafidx is odd (last bit = 1), current path element is a right child
       and auth_path has to go left. Otherwise it is the other way around. */
    if (leafidx & 1) {
        memcpy(buffer + XMSS_N, leaf, XMSS_N);
        memcpy(buffer, auth_path, XMSS_N);
    }
    else {
        memcpy(buffer, leaf, XMSS_N);
        memcpy(buffer + XMSS_N, auth_path, XMSS_N);
    }
    auth_path += XMSS_N;

    for (i = 0; i < XMSS_TREE_HEIGHT - 1; i++) {
        xmss_set_tree_height(addr, i);
        leafidx >>= 1;
        xmss_set_tree_index(addr, leafidx);

        /* Pick the right or left neighbor, depending on parity of the node. */
        if (leafidx & 1) {
            thash_h(buffer + XMSS_N, buffer, pub_seed, addr);
            memcpy(buffer, auth_path, XMSS_N);
        }
        else {
            thash_h(buffer, buffer, pub_seed, addr);
            memcpy(buffer + XMSS_N, auth_path, XMSS_N);
        }
        auth_path += XMSS_N;
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    xmss_set_tree_height(addr, XMSS_TREE_HEIGHT - 1);
    leafidx >>= 1;
    xmss_set_tree_index(addr, leafidx);
    thash_h(root, buffer, pub_seed, addr);
}


/**
 * Computes the leaf at a given address. First generates the WOTS key pair,
 * then computes leaf using l_tree. As this happens position independent, we
 * only require that addr encodes the right ltree-address.
 */
void gen_leaf_wots(unsigned char *leaf,
                   const unsigned char *sk_seed, const unsigned char *pub_seed,
                   uint32_t ltree_addr[8], uint32_t ots_addr[8])
{
    unsigned char pk[XMSS_WOTS_SIG_BYTES];

    wots_pkgen(pk, sk_seed, pub_seed, ots_addr);

    l_tree(leaf, pk, pub_seed, ltree_addr);
}


/**
 * Verifies a given message signature pair under a given public key.
 * Note that this assumes a pk without an OID, i.e. [root || PUB_SEED]
 */
int xmss_core_sign_open(unsigned char *m, unsigned long long *mlen,
                        const unsigned char *sm, unsigned long long smlen,
                        const unsigned char *pk)
{
    /* XMSS signatures are fundamentally an instance of XMSSMT signatures.
       For d=1, as is the case with XMSS, some of the calls in the XMSSMT
       routine become vacuous (i.e. the loop only iterates once, and address
       management can be simplified a bit).*/
    return xmssmt_core_sign_open(m, mlen, sm, smlen, pk);
}

/**
 * Verifies a given message signature pair under a given public key.
 * Note that this assumes a pk without an OID, i.e. [root || PUB_SEED]
 */
int xmssmt_core_sign_open(unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *pk)
{
    const unsigned char *pub_root = pk;
    const unsigned char *pub_seed = pk + XMSS_N;
    unsigned char wots_pk[XMSS_WOTS_SIG_BYTES];
    unsigned char leaf[XMSS_N];
    unsigned char root[XMSS_N];
    unsigned char *mhash = root;
    unsigned long long idx = 0;
    unsigned int i;
    uint32_t idx_leaf;
    unsigned char m_tmp[smlen+XMSS_SIG_BYTES];

    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    xmss_set_type(ots_addr, XMSS_ADDR_TYPE_OTS);
    xmss_set_type(ltree_addr, XMSS_ADDR_TYPE_LTREE);
    xmss_set_type(node_addr, XMSS_ADDR_TYPE_HASHTREE);

    *mlen = smlen - XMSS_SIG_BYTES;

    /* Convert the index bytes from the signature to an integer. */
    idx = xmss_bytes_to_ull(sm, XMSS_INDEX_BYTES);

    /* Put the message all the way at the end of the m buffer, so that we can
     * prepend the required other inputs for the hash function. */
    memcpy(m_tmp + XMSS_SIG_BYTES, sm + XMSS_SIG_BYTES, *mlen);

    /* Compute the message hash. */
    xmss_hash_message(mhash, sm + XMSS_INDEX_BYTES, pk, idx,
                 m_tmp + XMSS_SIG_BYTES - XMSS_PADDING_LEN - 3*XMSS_N,
                 *mlen);
    sm += XMSS_INDEX_BYTES + XMSS_N;

    /* For each subtree.. */
    for (i = 0; i < XMSS_D; i++) {
        idx_leaf = (idx & ((1 << XMSS_TREE_HEIGHT)-1));
        idx = idx >> XMSS_TREE_HEIGHT;

        xmss_set_layer_addr(ots_addr, i);
        xmss_set_layer_addr(ltree_addr, i);
        xmss_set_layer_addr(node_addr, i);

        xmss_set_tree_addr(ltree_addr, idx);
        xmss_set_tree_addr(ots_addr, idx);
        xmss_set_tree_addr(node_addr, idx);

        /* The WOTS public key is only correct if the signature was correct. */
        set_ots_addr(ots_addr, idx_leaf);
        /* Initially, root = mhash, but on subsequent iterations it is the root
           of the subtree below the currently processed subtree. */
        xmss_wots_pk_from_sig(wots_pk, sm, root, pub_seed, ots_addr);
        sm += XMSS_WOTS_SIG_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        set_ltree_addr(ltree_addr, idx_leaf);
        l_tree(leaf, wots_pk, pub_seed, ltree_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, sm, pub_seed, node_addr);
        sm += XMSS_TREE_HEIGHT*XMSS_N;
    }

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, XMSS_N)) {
        /* If not, zero the message */
        memset(m, 0, *mlen);
        *mlen = 0;
        return -1;
    }

    /* If verification was successful, copy the message from the signature. */
    memcpy(m, sm, *mlen);

    return 0;
}

#endif /* HAVE_XMSS */
