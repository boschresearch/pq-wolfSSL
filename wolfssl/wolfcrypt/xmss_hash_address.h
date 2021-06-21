/* xmss_hash_address.h
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://github.com/XMSS/
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */


/*!
    \file wolfssl/wolfcrypt/xmss_hash_address.h
*/


#ifndef WOLF_CRYPT_XMSS_HASH_ADDRESS_H
#define WOLF_CRYPT_XMSS_HASH_ADDRESS_H

#ifdef HAVE_XMSS

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdint.h>

#define XMSS_ADDR_TYPE_OTS 0
#define XMSS_ADDR_TYPE_LTREE 1
#define XMSS_ADDR_TYPE_HASHTREE 2

void xmss_set_layer_addr(uint32_t addr[8], uint32_t layer);

void xmss_set_tree_addr(uint32_t addr[8], uint64_t tree);

void xmss_set_type(uint32_t addr[8], uint32_t type);

void set_key_and_mask(uint32_t addr[8], uint32_t key_and_mask);

/* Copies the layer and tree part of one address into the other */
void xmss_copy_subtree_addr(uint32_t out[8], const uint32_t in[8]);

/* These functions are used for OTS addresses. */

void set_ots_addr(uint32_t addr[8], uint32_t ots);

void xmss_set_chain_addr(uint32_t addr[8], uint32_t chain);

void xmss_set_hash_addr(uint32_t addr[8], uint32_t hash);

/* This function is used for L-tree addresses. */

void set_ltree_addr(uint32_t addr[8], uint32_t ltree);

/* These functions are used for hash tree addresses. */

void xmss_set_tree_height(uint32_t addr[8], uint32_t tree_height);

void xmss_set_tree_index(uint32_t addr[8], uint32_t tree_index);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_XMSS */
#endif /* WOLF_CRYPT_XMSS_HASH_ADDRESS_H */
