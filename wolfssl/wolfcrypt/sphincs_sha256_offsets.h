/* sphincs_sha256_offsets.h
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
    \file wolfssl/wolfcrypt/sphincs_sha256_offsets.h
*/


#ifndef WOLF_CRYPT_SPHINCS_SHA256_OFFSETS_H
#define WOLF_CRYPT_SPHINCS_SHA256_OFFSETS_H

#ifdef HAVE_SPHINCS

#ifdef __cplusplus
    extern "C" {
#endif

/*
 * Offsets of various fields in the address structure when we use SHA256 as
 * the Sphincs+ hash function
 */

#define SPX_OFFSET_LAYER     0   /* The byte used to specify the Merkle tree layer */
#define SPX_OFFSET_TREE      1   /* The start of the 8 byte field used to specify the tree */
#define SPX_OFFSET_TYPE      9   /* The byte used to specify the hash type (reason) */
#define SPX_OFFSET_KP_ADDR2  12  /* The high byte used to specify the key pair (which one-time signature) */
#define SPX_OFFSET_KP_ADDR1  13  /* The low byte used to specify the key pair */
#define SPX_OFFSET_CHAIN_ADDR 17  /* The byte used to specify the chain address (which Winternitz chain) */
#define SPX_OFFSET_HASH_ADDR 21  /* The byte used to specify the hash address (where in the Winternitz chain) */
#define SPX_OFFSET_TREE_HGT  17  /* The byte used to specify the height of this node in the FORS or Merkle tree */
#define SPX_OFFSET_TREE_INDEX 18 /* The start of the 4 byte field used to specify the node in the FORS or Merkle tree */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_SPHINCS */
#endif /* WOLF_CRYPT_SPHINCS_SHA256_OFFSETS_H */
