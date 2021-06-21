/* sphincs_address.h
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://sphincs.org/
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */


/*!
    \file wolfssl/wolfcrypt/sphincs_address.h
*/


#ifndef WOLF_CRYPT_SPHINCS_ADDRESS_H
#define WOLF_CRYPT_SPHINCS_ADDRESS_H

#ifdef HAVE_SPHINCS

#include <stdint.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* The hash types that are passed to sphincs_set_type */
#define SPX_ADDR_TYPE_WOTS 0
#define SPX_ADDR_TYPE_WOTSPK 1
#define SPX_ADDR_TYPE_HASHTREE 2
#define SPX_ADDR_TYPE_FORSTREE 3
#define SPX_ADDR_TYPE_FORSPK 4

void sphincs_set_layer_addr(uint32_t addr[8], uint32_t layer);

void sphincs_set_tree_addr(uint32_t addr[8], uint64_t tree);

void sphincs_set_type(uint32_t addr[8], uint32_t type);

/* Copies the layer and tree part of one address into the other */
void sphincs_copy_subtree_addr(uint32_t out[8], const uint32_t in[8]);

/* These functions are used for WOTS and FORS addresses. */

void set_keypair_addr(uint32_t addr[8], uint32_t keypair);

void sphincs_set_chain_addr(uint32_t addr[8], uint32_t chain);

void sphincs_set_hash_addr(uint32_t addr[8], uint32_t hash);

void copy_keypair_addr(uint32_t out[8], const uint32_t in[8]);

/* These functions are used for all hash tree addresses (including FORS). */

void sphincs_set_tree_height(uint32_t addr[8], uint32_t tree_height);

void sphincs_set_tree_index(uint32_t addr[8], uint32_t tree_index);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_SPHINCS */
#endif /* WOLF_CRYPT_SPHINCS_ADDRESS_H */
