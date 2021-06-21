/* xmss_core_fast.c
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

typedef struct{
    unsigned char h;
    unsigned long next_idx;
    unsigned char stackusage;
    unsigned char completed;
    unsigned char *node;
} treehash_inst;

typedef struct {
    unsigned char *stack;
    unsigned int stackoffset;
    unsigned char *stacklevels;
    unsigned char *auth;
    unsigned char *keep;
    treehash_inst *treehash;
    unsigned char *retain;
    unsigned int next_leaf;
} bds_state;

/* These serialization functions provide a transition between the current
   way of storing the state in an exposed struct, and storing it as part of the
   byte array that is the secret key.
   They will probably be refactored in a non-backwards-compatible way, soon. */

static void xmssmt_serialize_state(unsigned char *sk, bds_state *states)
{
    unsigned int i, j;

    /* Skip past the 'regular' sk */
    sk += XMSS_INDEX_BYTES + 4*XMSS_N;

    for (i = 0; i < 2*XMSS_D - 1; i++) {
        sk += (XMSS_TREE_HEIGHT + 1) * XMSS_N; /* stack */

        xmss_ull_to_bytes(sk, 4, states[i].stackoffset);
        sk += 4;

        sk += XMSS_TREE_HEIGHT + 1; /* stacklevels */
        sk += XMSS_TREE_HEIGHT * XMSS_N; /* auth */
        sk += (XMSS_TREE_HEIGHT >> 1) * XMSS_N; /* keep */

        for (j = 0; j < XMSS_TREE_HEIGHT - XMSS_BDS_K; j++) {
            xmss_ull_to_bytes(sk, 1, states[i].treehash[j].h);
            sk += 1;

            xmss_ull_to_bytes(sk, 4, states[i].treehash[j].next_idx);
            sk += 4;

            xmss_ull_to_bytes(sk, 1, states[i].treehash[j].stackusage);
            sk += 1;

            xmss_ull_to_bytes(sk, 1, states[i].treehash[j].completed);
            sk += 1;

            sk += XMSS_N; /* node */
        }

        /* retain */
        sk += ((1 << XMSS_BDS_K) - XMSS_BDS_K - 1) * XMSS_N;

        xmss_ull_to_bytes(sk, 4, states[i].next_leaf);
        sk += 4;
    }
}

static void xmssmt_deserialize_state(bds_state *states,
                                     unsigned char **wots_sigs,
                                     unsigned char *sk)
{
    unsigned int i, j;

    /* Skip past the 'regular' sk */
    sk += XMSS_INDEX_BYTES + 4*XMSS_N;

    // TODO These data sizes follow from the (former) test xmss_core_fast.c
    // TODO They should be reconsidered / motivated more explicitly

    for (i = 0; i < 2*XMSS_D - 1; i++) {
        states[i].stack = sk;
        sk += (XMSS_TREE_HEIGHT + 1) * XMSS_N;

        states[i].stackoffset = xmss_bytes_to_ull(sk, 4);
        sk += 4;

        states[i].stacklevels = sk;
        sk += XMSS_TREE_HEIGHT + 1;

        states[i].auth = sk;
        sk += XMSS_TREE_HEIGHT * XMSS_N;

        states[i].keep = sk;
        sk += (XMSS_TREE_HEIGHT >> 1) * XMSS_N;

        for (j = 0; j < XMSS_TREE_HEIGHT - XMSS_BDS_K; j++) {
            states[i].treehash[j].h = xmss_bytes_to_ull(sk, 1);
            sk += 1;

            states[i].treehash[j].next_idx = xmss_bytes_to_ull(sk, 4);
            sk += 4;

            states[i].treehash[j].stackusage = xmss_bytes_to_ull(sk, 1);
            sk += 1;

            states[i].treehash[j].completed = xmss_bytes_to_ull(sk, 1);
            sk += 1;

            states[i].treehash[j].node = sk;
            sk += XMSS_N;
        }

        states[i].retain = sk;
        sk += ((1 << XMSS_BDS_K) - XMSS_BDS_K - 1) * XMSS_N;

        states[i].next_leaf = xmss_bytes_to_ull(sk, 4);
        sk += 4;
    }

    if (XMSS_D > 1) {
        *wots_sigs = sk;
    }
}

static void xmss_serialize_state(unsigned char *sk, bds_state *state)
{
    xmssmt_serialize_state(sk, state);
}

static void xmss_deserialize_state(bds_state *state, unsigned char *sk)
{
    xmssmt_deserialize_state(state, NULL, sk);
}

static void memswap(void *a, void *b, void *t, unsigned long long len)
{
    memcpy(t, a, len);
    memcpy(a, b, len);
    memcpy(b, t, len);
}

/**
 * Swaps the content of two bds_state objects, swapping actual memory rather
 * than pointers.
 * As we're mapping memory chunks in the secret key to bds state objects,
 * it is now necessary to make swaps 'real swaps'. This could be done in the
 * serialization function as well, but that causes more overhead
 */
// TODO this should not be necessary if we keep better track of the states
static void deep_state_swap(bds_state *a, bds_state *b)
{
    // TODO this is extremely ugly and should be refactored
    // TODO right now, this ensures that both 'stack' and 'retain' fit
    unsigned char t[
        ((XMSS_TREE_HEIGHT + 1) > ((1 << XMSS_BDS_K) - XMSS_BDS_K - 1)
         ? (XMSS_TREE_HEIGHT + 1)
         : ((1 << XMSS_BDS_K) - XMSS_BDS_K - 1))
        * XMSS_N];
    unsigned int i;

    memswap(a->stack, b->stack, t, (XMSS_TREE_HEIGHT + 1) * XMSS_N);
    memswap(&a->stackoffset, &b->stackoffset, t, sizeof(a->stackoffset));
    memswap(a->stacklevels, b->stacklevels, t, XMSS_TREE_HEIGHT + 1);
    memswap(a->auth, b->auth, t, XMSS_TREE_HEIGHT * XMSS_N);
    memswap(a->keep, b->keep, t, (XMSS_TREE_HEIGHT >> 1) * XMSS_N);

    for (i = 0; i < XMSS_TREE_HEIGHT - XMSS_BDS_K; i++) {
        memswap(&a->treehash[i].h, &b->treehash[i].h, t, sizeof(a->treehash[i].h));
        memswap(&a->treehash[i].next_idx, &b->treehash[i].next_idx, t, sizeof(a->treehash[i].next_idx));
        memswap(&a->treehash[i].stackusage, &b->treehash[i].stackusage, t, sizeof(a->treehash[i].stackusage));
        memswap(&a->treehash[i].completed, &b->treehash[i].completed, t, sizeof(a->treehash[i].completed));
        memswap(a->treehash[i].node, b->treehash[i].node, t, XMSS_N);
    }

    memswap(a->retain, b->retain, t, ((1 << XMSS_BDS_K) - XMSS_BDS_K - 1) * XMSS_N);
    memswap(&a->next_leaf, &b->next_leaf, t, sizeof(a->next_leaf));
}

static int treehash_minheight_on_stack(bds_state *state,
                                       const treehash_inst *treehash)
{
    unsigned int r = XMSS_TREE_HEIGHT, i;

    for (i = 0; i < treehash->stackusage; i++) {
        if (state->stacklevels[state->stackoffset - i - 1] < r) {
            r = state->stacklevels[state->stackoffset - i - 1];
        }
    }
    return r;
}

/**
 * Merkle's TreeHash algorithm. The address only needs to initialize the first 78 bits of addr. Everything else will be set by treehash.
 * Currently only used for key generation.
 *
 */
static void treehash_init(unsigned char *node, int height, int index,
                          bds_state *state, const unsigned char *sk_seed,
                          const unsigned char *pub_seed, const uint32_t addr[8])
{
    unsigned int idx = index;
    // use three different addresses because at this point we use all three formats in parallel
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};
    // only copy layer and tree address parts
    xmss_copy_subtree_addr(ots_addr, addr);
    // type = ots
    xmss_set_type(ots_addr, 0);
    xmss_copy_subtree_addr(ltree_addr, addr);
    xmss_set_type(ltree_addr, 1);
    xmss_copy_subtree_addr(node_addr, addr);
    xmss_set_type(node_addr, 2);

    uint32_t lastnode, i;
    unsigned char stack[(height+1)*XMSS_N];
    unsigned int stacklevels[height+1];
    unsigned int stackoffset=0;
    unsigned int nodeh;

    lastnode = idx+(1<<height);

    for (i = 0; i < XMSS_TREE_HEIGHT-XMSS_BDS_K; i++) {
        state->treehash[i].h = i;
        state->treehash[i].completed = 1;
        state->treehash[i].stackusage = 0;
    }

    i = 0;
    for (; idx < lastnode; idx++) {
        set_ltree_addr(ltree_addr, idx);
        set_ots_addr(ots_addr, idx);
        gen_leaf_wots(stack+stackoffset*XMSS_N, sk_seed, pub_seed, ltree_addr, ots_addr);
        stacklevels[stackoffset] = 0;
        stackoffset++;
        if (XMSS_TREE_HEIGHT - XMSS_BDS_K > 0 && i == 3) {
            memcpy(state->treehash[0].node, stack+stackoffset*XMSS_N, XMSS_N);
        }
        while (stackoffset>1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2]) {
            nodeh = stacklevels[stackoffset-1];
            if (i >> nodeh == 1) {
                memcpy(state->auth + nodeh*XMSS_N, stack+(stackoffset-1)*XMSS_N, XMSS_N);
            }
            else {
                if (nodeh < XMSS_TREE_HEIGHT - XMSS_BDS_K && i >> nodeh == 3) {
                    memcpy(state->treehash[nodeh].node, stack+(stackoffset-1)*XMSS_N, XMSS_N);
                }
                else if (nodeh >= XMSS_TREE_HEIGHT - XMSS_BDS_K) {
                    memcpy(state->retain + ((1 << (XMSS_TREE_HEIGHT - 1 - nodeh)) + nodeh - XMSS_TREE_HEIGHT + (((i >> nodeh) - 3) >> 1)) * XMSS_N, stack+(stackoffset-1)*XMSS_N, XMSS_N);
                }
            }
            xmss_set_tree_height(node_addr, stacklevels[stackoffset-1]);
            xmss_set_tree_index(node_addr, (idx >> (stacklevels[stackoffset-1]+1)));
            thash_h(stack+(stackoffset-2)*XMSS_N, stack+(stackoffset-2)*XMSS_N, pub_seed, node_addr);
            stacklevels[stackoffset-2]++;
            stackoffset--;
        }
        i++;
    }

    for (i = 0; i < XMSS_N; i++) {
        node[i] = stack[i];
    }
}

static void treehash_update(treehash_inst *treehash, bds_state *state,
                            const unsigned char *sk_seed,
                            const unsigned char *pub_seed,
                            const uint32_t addr[8])
{
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};
    // only copy layer and tree address parts
    xmss_copy_subtree_addr(ots_addr, addr);
    // type = ots
    xmss_set_type(ots_addr, 0);
    xmss_copy_subtree_addr(ltree_addr, addr);
    xmss_set_type(ltree_addr, 1);
    xmss_copy_subtree_addr(node_addr, addr);
    xmss_set_type(node_addr, 2);

    set_ltree_addr(ltree_addr, treehash->next_idx);
    set_ots_addr(ots_addr, treehash->next_idx);

    unsigned char nodebuffer[2 * XMSS_N];
    unsigned int nodeheight = 0;
    gen_leaf_wots(nodebuffer, sk_seed, pub_seed, ltree_addr, ots_addr);
    while (treehash->stackusage > 0 && state->stacklevels[state->stackoffset-1] == nodeheight) {
        memcpy(nodebuffer + XMSS_N, nodebuffer, XMSS_N);
        memcpy(nodebuffer, state->stack + (state->stackoffset-1)*XMSS_N, XMSS_N);
        xmss_set_tree_height(node_addr, nodeheight);
        xmss_set_tree_index(node_addr, (treehash->next_idx >> (nodeheight+1)));
        thash_h(nodebuffer, nodebuffer, pub_seed, node_addr);
        nodeheight++;
        treehash->stackusage--;
        state->stackoffset--;
    }
    if (nodeheight == treehash->h) { // this also implies stackusage == 0
        memcpy(treehash->node, nodebuffer, XMSS_N);
        treehash->completed = 1;
    }
    else {
        memcpy(state->stack + state->stackoffset*XMSS_N, nodebuffer, XMSS_N);
        treehash->stackusage++;
        state->stacklevels[state->stackoffset] = nodeheight;
        state->stackoffset++;
        treehash->next_idx++;
    }
}

/**
 * Performs treehash updates on the instance that needs it the most.
 * Returns the updated number of available updates.
 **/
static char bds_treehash_update(bds_state *state, unsigned int updates,
                                const unsigned char *sk_seed,
                                unsigned char *pub_seed,
                                const uint32_t addr[8])
{
    uint32_t i, j;
    unsigned int level, l_min, low;
    unsigned int used = 0;

    for (j = 0; j < updates; j++) {
        l_min = XMSS_TREE_HEIGHT;
        level = XMSS_TREE_HEIGHT - XMSS_BDS_K;
        for (i = 0; i < XMSS_TREE_HEIGHT - XMSS_BDS_K; i++) {
            if (state->treehash[i].completed) {
                low = XMSS_TREE_HEIGHT;
            }
            else if (state->treehash[i].stackusage == 0) {
                low = i;
            }
            else {
                low = treehash_minheight_on_stack(state, &(state->treehash[i]));
            }
            if (low < l_min) {
                level = i;
                l_min = low;
            }
        }
        if (level == XMSS_TREE_HEIGHT - XMSS_BDS_K) {
            break;
        }
        treehash_update(&(state->treehash[level]), state, sk_seed, pub_seed, addr);
        used++;
    }
    return updates - used;
}

/**
 * Updates the state (typically NEXT_i) by adding a leaf and updating the stack
 * Returns -1 if all leaf nodes have already been processed
 **/
static char bds_state_update(bds_state *state, const unsigned char *sk_seed,
                             const unsigned char *pub_seed,
                             const uint32_t addr[8])
{
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};
    uint32_t ots_addr[8] = {0};

    unsigned int nodeh;
    int idx = state->next_leaf;
    if (idx == 1 << XMSS_TREE_HEIGHT) {
        return -1;
    }

    // only copy layer and tree address parts
    xmss_copy_subtree_addr(ots_addr, addr);
    // type = ots
    xmss_set_type(ots_addr, 0);
    xmss_copy_subtree_addr(ltree_addr, addr);
    xmss_set_type(ltree_addr, 1);
    xmss_copy_subtree_addr(node_addr, addr);
    xmss_set_type(node_addr, 2);

    set_ots_addr(ots_addr, idx);
    set_ltree_addr(ltree_addr, idx);

    gen_leaf_wots(state->stack+state->stackoffset*XMSS_N, sk_seed, pub_seed, ltree_addr, ots_addr);

    state->stacklevels[state->stackoffset] = 0;
    state->stackoffset++;
    if (XMSS_TREE_HEIGHT - XMSS_BDS_K > 0 && idx == 3) {
        memcpy(state->treehash[0].node, state->stack+state->stackoffset*XMSS_N, XMSS_N);
    }
    while (state->stackoffset>1 && state->stacklevels[state->stackoffset-1] == state->stacklevels[state->stackoffset-2]) {
        nodeh = state->stacklevels[state->stackoffset-1];
        if (idx >> nodeh == 1) {
            memcpy(state->auth + nodeh*XMSS_N, state->stack+(state->stackoffset-1)*XMSS_N, XMSS_N);
        }
        else {
            if (nodeh < XMSS_TREE_HEIGHT - XMSS_BDS_K && idx >> nodeh == 3) {
                memcpy(state->treehash[nodeh].node, state->stack+(state->stackoffset-1)*XMSS_N, XMSS_N);
            }
            else if (nodeh >= XMSS_TREE_HEIGHT - XMSS_BDS_K) {
                memcpy(state->retain + ((1 << (XMSS_TREE_HEIGHT - 1 - nodeh)) + nodeh - XMSS_TREE_HEIGHT + (((idx >> nodeh) - 3) >> 1)) * XMSS_N, state->stack+(state->stackoffset-1)*XMSS_N, XMSS_N);
            }
        }
        xmss_set_tree_height(node_addr, state->stacklevels[state->stackoffset-1]);
        xmss_set_tree_index(node_addr, (idx >> (state->stacklevels[state->stackoffset-1]+1)));
        thash_h(state->stack+(state->stackoffset-2)*XMSS_N, state->stack+(state->stackoffset-2)*XMSS_N, pub_seed, node_addr);

        state->stacklevels[state->stackoffset-2]++;
        state->stackoffset--;
    }
    state->next_leaf++;
    return 0;
}

/**
 * Returns the auth path for node leaf_idx and computes the auth path for the
 * next leaf node, using the algorithm described by Buchmann, Dahmen and Szydlo
 * in "Post Quantum Cryptography", Springer 2009.
 */
static void bds_round(bds_state *state, const unsigned long leaf_idx,
                      const unsigned char *sk_seed,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned int i;
    unsigned int tau = XMSS_TREE_HEIGHT;
    unsigned int startidx;
    unsigned int offset, rowidx;
    unsigned char buf[2 * XMSS_N];

    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    // only copy layer and tree address parts
    xmss_copy_subtree_addr(ots_addr, addr);
    // type = ots
    xmss_set_type(ots_addr, 0);
    xmss_copy_subtree_addr(ltree_addr, addr);
    xmss_set_type(ltree_addr, 1);
    xmss_copy_subtree_addr(node_addr, addr);
    xmss_set_type(node_addr, 2);

    for (i = 0; i < XMSS_TREE_HEIGHT; i++) {
        if (! ((leaf_idx >> i) & 1)) {
            tau = i;
            break;
        }
    }

    if (tau > 0) {
        memcpy(buf, state->auth + (tau-1) * XMSS_N, XMSS_N);
        // we need to do this before refreshing state->keep to prevent overwriting
        memcpy(buf + XMSS_N, state->keep + ((tau-1) >> 1) * XMSS_N, XMSS_N);
    }
    if (!((leaf_idx >> (tau + 1)) & 1) && (tau < XMSS_TREE_HEIGHT - 1)) {
        memcpy(state->keep + (tau >> 1)*XMSS_N, state->auth + tau*XMSS_N, XMSS_N);
    }
    if (tau == 0) {
        set_ltree_addr(ltree_addr, leaf_idx);
        set_ots_addr(ots_addr, leaf_idx);
        gen_leaf_wots(state->auth, sk_seed, pub_seed, ltree_addr, ots_addr);
    }
    else {
        xmss_set_tree_height(node_addr, (tau-1));
        xmss_set_tree_index(node_addr, leaf_idx >> tau);
        thash_h(state->auth + tau * XMSS_N, buf, pub_seed, node_addr);
        for (i = 0; i < tau; i++) {
            if (i < XMSS_TREE_HEIGHT - XMSS_BDS_K) {
                memcpy(state->auth + i * XMSS_N, state->treehash[i].node, XMSS_N);
            }
            else {
                offset = (1 << (XMSS_TREE_HEIGHT - 1 - i)) + i - XMSS_TREE_HEIGHT;
                rowidx = ((leaf_idx >> i) - 1) >> 1;
                memcpy(state->auth + i * XMSS_N, state->retain + (offset + rowidx) * XMSS_N, XMSS_N);
            }
        }

        for (i = 0; i < ((tau < XMSS_TREE_HEIGHT - XMSS_BDS_K) ? tau : (XMSS_TREE_HEIGHT - XMSS_BDS_K)); i++) {
            startidx = leaf_idx + 1 + 3 * (1 << i);
            if (startidx < 1U << XMSS_TREE_HEIGHT) {
                state->treehash[i].h = i;
                state->treehash[i].next_idx = startidx;
                state->treehash[i].completed = 0;
                state->treehash[i].stackusage = 0;
            }
        }
    }
}

/**
 * Given a set of parameters, this function returns the size of the secret key.
 * This is implementation specific, as varying choices in tree traversal will
 * result in varying requirements for state storage.
 *
 * This function handles both XMSS and XMSSMT parameter sets.
 */
/*
unsigned long long xmss_xmssmt_core_sk_bytes(void)
{
    return XMSS_INDEX_BYTES + 4 * XMSS_N
        + (2 * XMSS_D - 1) * (
            (XMSS_TREE_HEIGHT + 1) * XMSS_N
            + 4
            + XMSS_TREE_HEIGHT + 1
            + XMSS_TREE_HEIGHT * XMSS_N
            + (XMSS_TREE_HEIGHT >> 1) * XMSS_N
            + (XMSS_TREE_HEIGHT - XMSS_BDS_K) * (7 + XMSS_N)
            + ((1 << XMSS_BDS_K) - XMSS_BDS_K - 1) * XMSS_N
            + 4
         )
        + (XMSS_D - 1) * XMSS_WOTS_SIG_BYTES;
}
*/
/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) idx || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmss_core_keypair(unsigned char *pk, unsigned char *sk,
                      WC_RNG *rng)
{
    uint32_t addr[8] = {0};

    // TODO refactor BDS state not to need separate treehash instances
    bds_state state;
    treehash_inst treehash[XMSS_TREE_HEIGHT - XMSS_BDS_K];
    state.treehash = treehash;

    xmss_deserialize_state(&state, sk);

    state.stackoffset = 0;
    state.next_leaf = 0;

    // Set idx = 0
    sk[0] = 0;
    sk[1] = 0;
    sk[2] = 0;
    sk[3] = 0;
    // Init SK_SEED (n byte) and SK_PRF (n byte)
     wc_RNG_GenerateBlock(rng, sk + XMSS_INDEX_BYTES, 2*XMSS_N);

    // Init PUB_SEED (n byte)
     wc_RNG_GenerateBlock(rng, sk + XMSS_INDEX_BYTES + 3*XMSS_N, XMSS_N);
    // Copy PUB_SEED to public key
    memcpy(pk + XMSS_N, sk + XMSS_INDEX_BYTES + 3*XMSS_N, XMSS_N);

    // Compute root
    treehash_init(pk, XMSS_TREE_HEIGHT, 0, &state, sk + XMSS_INDEX_BYTES, sk + XMSS_INDEX_BYTES + 3*XMSS_N, addr);
    // copy root to sk
    memcpy(sk + XMSS_INDEX_BYTES + 2*XMSS_N, pk, XMSS_N);

    /* Write the BDS state into sk. */
    xmss_serialize_state(sk, &state);

    return 0;
}

/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmss_core_sign(unsigned char *sk,
                   unsigned char *sm, unsigned long long *smlen,
                   const unsigned char *m, unsigned long long mlen)
{
    const unsigned char *pub_root = sk + XMSS_INDEX_BYTES + 2*XMSS_N;

    uint16_t i = 0;

    // TODO refactor BDS state not to need separate treehash instances
    bds_state state;
    treehash_inst treehash[XMSS_TREE_HEIGHT - XMSS_BDS_K];
    state.treehash = treehash;

    /* Load the BDS state from sk. */
    xmss_deserialize_state(&state, sk);

    // Extract SK
    unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
    unsigned char sk_seed[XMSS_N];
    memcpy(sk_seed, sk + XMSS_INDEX_BYTES, XMSS_N);
    unsigned char sk_prf[XMSS_N];
    memcpy(sk_prf, sk + XMSS_INDEX_BYTES + XMSS_N, XMSS_N);
    unsigned char pub_seed[XMSS_N];
    memcpy(pub_seed, sk + XMSS_INDEX_BYTES + 3*XMSS_N, XMSS_N);

    // index as 32 bytes string
    unsigned char idx_bytes_32[32];
    xmss_ull_to_bytes(idx_bytes_32, 32, idx);

    // Update SK
    sk[0] = ((idx + 1) >> 24) & 255;
    sk[1] = ((idx + 1) >> 16) & 255;
    sk[2] = ((idx + 1) >> 8) & 255;
    sk[3] = (idx + 1) & 255;
    // Secret key for this non-forward-secure version is now updated.
    // A production implementation should consider using a file handle instead,
    //  and write the updated secret key at this point!

    // Init working params
    unsigned char R[XMSS_N];
    unsigned char msg_h[XMSS_N];
    uint32_t ots_addr[8] = {0};

    // ---------------------------------
    // Message Hashing
    // ---------------------------------

    // Message Hash:
    // First compute pseudorandom value
    prf(R, idx_bytes_32, sk_prf);

    /* Already put the message in the right place, to make it easier to prepend
     * things when computing the hash over the message. */
    memcpy(sm + XMSS_SIG_BYTES, m, mlen);

    /* Compute the message hash. */
    xmss_hash_message(msg_h, R, pub_root, idx,
                 sm + XMSS_SIG_BYTES - XMSS_PADDING_LEN - 3*XMSS_N,
                 mlen);

    // Start collecting signature
    *smlen = 0;

    // Copy index to signature
    sm[0] = (idx >> 24) & 255;
    sm[1] = (idx >> 16) & 255;
    sm[2] = (idx >> 8) & 255;
    sm[3] = idx & 255;

    sm += 4;
    *smlen += 4;

    // Copy R to signature
    for (i = 0; i < XMSS_N; i++) {
        sm[i] = R[i];
    }

    sm += XMSS_N;
    *smlen += XMSS_N;

    // ----------------------------------
    // Now we start to "really sign"
    // ----------------------------------

    // Prepare Address
    xmss_set_type(ots_addr, 0);
    set_ots_addr(ots_addr, idx);

    // Compute WOTS signature
    xmss_wots_sign(sm, msg_h, sk_seed, pub_seed, ots_addr);

    sm += XMSS_WOTS_SIG_BYTES;
    *smlen += XMSS_WOTS_SIG_BYTES;

    // the auth path was already computed during the previous round
    memcpy(sm, state.auth, XMSS_TREE_HEIGHT*XMSS_N);

    if (idx < (1U << XMSS_TREE_HEIGHT) - 1) {
        bds_round(&state, idx, sk_seed, pub_seed, ots_addr);
        bds_treehash_update(&state, (XMSS_TREE_HEIGHT - XMSS_BDS_K) >> 1, sk_seed, pub_seed, ots_addr);
    }

    sm += XMSS_TREE_HEIGHT*XMSS_N;
    *smlen += XMSS_TREE_HEIGHT*XMSS_N;

    memcpy(sm, m, mlen);
    *smlen += mlen;

    /* Write the updated BDS state back into sk. */
    xmss_serialize_state(sk, &state);

    return 0;
}

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) idx || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmssmt_core_keypair(unsigned char *pk, unsigned char *sk, WC_RNG *rng)
{
    uint32_t addr[8] = {0};
    unsigned int i;
    unsigned char *wots_sigs;

    // TODO refactor BDS state not to need separate treehash instances
    bds_state states[2*XMSS_D - 1];
    treehash_inst treehash[(2*XMSS_D - 1) * (XMSS_TREE_HEIGHT - XMSS_BDS_K)];
    for (i = 0; i < 2*XMSS_D - 1; i++) {
        states[i].treehash = treehash + i * (XMSS_TREE_HEIGHT - XMSS_BDS_K);
    }

    xmssmt_deserialize_state(states, &wots_sigs, sk);

    for (i = 0; i < 2 * XMSS_D - 1; i++) {
        states[i].stackoffset = 0;
        states[i].next_leaf = 0;
    }

    // Set idx = 0
    for (i = 0; i < XMSS_INDEX_BYTES; i++) {
        sk[i] = 0;
    }
    // Init SK_SEED (XMSS_N byte) and SK_PRF (XMSS_N byte)
     wc_RNG_GenerateBlock(rng, sk+XMSS_INDEX_BYTES, 2*XMSS_N);

    // Init PUB_SEED (XMSS_N byte)
     wc_RNG_GenerateBlock(rng, sk+XMSS_INDEX_BYTES + 3*XMSS_N, XMSS_N);
    // Copy PUB_SEED to public key
    memcpy(pk+XMSS_N, sk+XMSS_INDEX_BYTES+3*XMSS_N, XMSS_N);

    // Start with the bottom-most layer
    xmss_set_layer_addr(addr, 0);
    // Set up state and compute wots signatures for all but topmost tree root
    for (i = 0; i < XMSS_D - 1; i++) {
        // Compute seed for OTS key pair
        treehash_init(pk, XMSS_TREE_HEIGHT, 0, states + i, sk+XMSS_INDEX_BYTES, pk+XMSS_N, addr);
        xmss_set_layer_addr(addr, (i+1));
        xmss_wots_sign(wots_sigs + i*XMSS_WOTS_SIG_BYTES, pk, sk + XMSS_INDEX_BYTES, pk+XMSS_N, addr);
    }
    // Address now points to the single tree on layer d-1
    treehash_init(pk, XMSS_TREE_HEIGHT, 0, states + i, sk+XMSS_INDEX_BYTES, pk+XMSS_N, addr);
    memcpy(sk + XMSS_INDEX_BYTES + 2*XMSS_N, pk, XMSS_N);

    xmssmt_serialize_state(sk, states);

    return 0;
}

/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmssmt_core_sign(unsigned char *sk,
                     unsigned char *sm, unsigned long long *smlen,
                     const unsigned char *m, unsigned long long mlen)
{
    const unsigned char *pub_root = sk + XMSS_INDEX_BYTES + 2*XMSS_N;

    uint64_t idx_tree;
    uint32_t idx_leaf;
    uint64_t i, j;
    int needswap_upto = -1;
    unsigned int updates;

    unsigned char sk_seed[XMSS_N];
    unsigned char sk_prf[XMSS_N];
    unsigned char pub_seed[XMSS_N];
    // Init working params
    unsigned char R[XMSS_N];
    unsigned char msg_h[XMSS_N];
    uint32_t addr[8] = {0};
    uint32_t ots_addr[8] = {0};
    unsigned char idx_bytes_32[32];

    unsigned char *wots_sigs;

    // TODO refactor BDS state not to need separate treehash instances
    bds_state states[2*XMSS_D];
    treehash_inst treehash[(2*XMSS_D - 1) * (XMSS_TREE_HEIGHT - XMSS_BDS_K)];
    for (i = 0; i < 2*XMSS_D - 1; i++) {
        states[i].treehash = treehash + i * (XMSS_TREE_HEIGHT - XMSS_BDS_K);
    }

    xmssmt_deserialize_state(states, &wots_sigs, sk);

    // Extract SK
    unsigned long long idx = 0;
    for (i = 0; i < XMSS_INDEX_BYTES; i++) {
        idx |= ((unsigned long long)sk[i]) << 8*(XMSS_INDEX_BYTES - 1 - i);
    }

    memcpy(sk_seed, sk+XMSS_INDEX_BYTES, XMSS_N);
    memcpy(sk_prf, sk+XMSS_INDEX_BYTES+XMSS_N, XMSS_N);
    memcpy(pub_seed, sk+XMSS_INDEX_BYTES+3*XMSS_N, XMSS_N);

    // Update SK
    for (i = 0; i < XMSS_INDEX_BYTES; i++) {
        sk[i] = ((idx + 1) >> 8*(XMSS_INDEX_BYTES - 1 - i)) & 255;
    }
    // Secret key for this non-forward-secure version is now updated.
    // A production implementation should consider using a file handle instead,
    //  and write the updated secret key at this point!

    // ---------------------------------
    // Message Hashing
    // ---------------------------------

    // Message Hash:
    // First compute pseudorandom value
    xmss_ull_to_bytes(idx_bytes_32, 32, idx);
    prf(R, idx_bytes_32, sk_prf);

    /* Already put the message in the right place, to make it easier to prepend
     * things when computing the hash over the message. */
    memcpy(sm + XMSS_SIG_BYTES, m, mlen);

    /* Compute the message hash. */
    xmss_hash_message(msg_h, R, pub_root, idx,
                 sm + XMSS_SIG_BYTES - XMSS_PADDING_LEN - 3*XMSS_N,
                 mlen);

    // Start collecting signature
    *smlen = 0;

    // Copy index to signature
    for (i = 0; i < XMSS_INDEX_BYTES; i++) {
        sm[i] = (idx >> 8*(XMSS_INDEX_BYTES - 1 - i)) & 255;
    }

    sm += XMSS_INDEX_BYTES;
    *smlen += XMSS_INDEX_BYTES;

    // Copy R to signature
    for (i = 0; i < XMSS_N; i++) {
        sm[i] = R[i];
    }

    sm += XMSS_N;
    *smlen += XMSS_N;

    // ----------------------------------
    // Now we start to "really sign"
    // ----------------------------------

    // Handle lowest layer separately as it is slightly different...

    // Prepare Address
    xmss_set_type(ots_addr, 0);
    idx_tree = idx >> XMSS_TREE_HEIGHT;
    idx_leaf = (idx & ((1 << XMSS_TREE_HEIGHT)-1));
    xmss_set_layer_addr(ots_addr, 0);
    xmss_set_tree_addr(ots_addr, idx_tree);
    set_ots_addr(ots_addr, idx_leaf);

    // Compute WOTS signature
    xmss_wots_sign(sm, msg_h, sk_seed, pub_seed, ots_addr);

    sm += XMSS_WOTS_SIG_BYTES;
    *smlen += XMSS_WOTS_SIG_BYTES;

    memcpy(sm, states[0].auth, XMSS_TREE_HEIGHT*XMSS_N);
    sm += XMSS_TREE_HEIGHT*XMSS_N;
    *smlen += XMSS_TREE_HEIGHT*XMSS_N;

    // prepare signature of remaining layers
    for (i = 1; i < XMSS_D; i++) {
        // put WOTS signature in place
        memcpy(sm, wots_sigs + (i-1)*XMSS_WOTS_SIG_BYTES, XMSS_WOTS_SIG_BYTES);

        sm += XMSS_WOTS_SIG_BYTES;
        *smlen += XMSS_WOTS_SIG_BYTES;

        // put AUTH nodes in place
        memcpy(sm, states[i].auth, XMSS_TREE_HEIGHT*XMSS_N);
        sm += XMSS_TREE_HEIGHT*XMSS_N;
        *smlen += XMSS_TREE_HEIGHT*XMSS_N;
    }

    updates = (XMSS_TREE_HEIGHT - XMSS_BDS_K) >> 1;

    xmss_set_tree_addr(addr, (idx_tree + 1));
    // mandatory update for NEXT_0 (does not count towards h-k/2) if NEXT_0 exists
    if ((1 + idx_tree) * (1 << XMSS_TREE_HEIGHT) + idx_leaf < (1ULL << XMSS_FULL_HEIGHT)) {
        bds_state_update(&states[XMSS_D], sk_seed, pub_seed, addr);
    }

    for (i = 0; i < XMSS_D; i++) {
        // check if we're not at the end of a tree
        if (! (((idx + 1) & ((1ULL << ((i+1)*XMSS_TREE_HEIGHT)) - 1)) == 0)) {
            idx_leaf = (idx >> (XMSS_TREE_HEIGHT * i)) & ((1 << XMSS_TREE_HEIGHT)-1);
            idx_tree = (idx >> (XMSS_TREE_HEIGHT * (i+1)));
            xmss_set_layer_addr(addr, i);
            xmss_set_tree_addr(addr, idx_tree);
            if (i == (unsigned int) (needswap_upto + 1)) {
                bds_round(&states[i], idx_leaf, sk_seed, pub_seed, addr);
            }
            updates = bds_treehash_update(&states[i], updates, sk_seed, pub_seed, addr);
            xmss_set_tree_addr(addr, (idx_tree + 1));
            // if a NEXT-tree exists for this level;
            if ((1 + idx_tree) * (1 << XMSS_TREE_HEIGHT) + idx_leaf < (1ULL << (XMSS_FULL_HEIGHT - XMSS_TREE_HEIGHT * i))) {
                if (i > 0 && updates > 0 && states[XMSS_D + i].next_leaf < (1ULL << XMSS_FULL_HEIGHT)) {
                    bds_state_update(&states[XMSS_D + i], sk_seed, pub_seed, addr);
                    updates--;
                }
            }
        }
        else if (idx < (1ULL << XMSS_FULL_HEIGHT) - 1) {
            deep_state_swap(states+XMSS_D + i, states + i);

            xmss_set_layer_addr(ots_addr, (i+1));
            xmss_set_tree_addr(ots_addr, ((idx + 1) >> ((i+2) * XMSS_TREE_HEIGHT)));
            set_ots_addr(ots_addr, (((idx >> ((i+1) * XMSS_TREE_HEIGHT)) + 1) & ((1 << XMSS_TREE_HEIGHT)-1)));

            xmss_wots_sign(wots_sigs + i*XMSS_WOTS_SIG_BYTES, states[i].stack, sk_seed, pub_seed, ots_addr);

            states[XMSS_D + i].stackoffset = 0;
            states[XMSS_D + i].next_leaf = 0;

            updates--; // WOTS-signing counts as one update
            needswap_upto = i;
            for (j = 0; j < XMSS_TREE_HEIGHT-XMSS_BDS_K; j++) {
                states[i].treehash[j].completed = 1;
            }
        }
    }

    memcpy(sm, m, mlen);
    *smlen += mlen;

    xmssmt_serialize_state(sk, states);

    return 0;
}

#endif /* HAVE_XMSS */
