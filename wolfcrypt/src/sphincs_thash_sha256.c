/* sphincs_thash_sha256.c
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://sphincs.org/
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_SPHINCS

#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/sphincs_thash.h>
#include <wolfssl/wolfcrypt/sphincs_sha256.h>
#include <wolfssl/wolfcrypt/sphincs.h>
#include <wolfssl/wolfcrypt/sphincs_address.h>

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const unsigned char *pub_seed, uint32_t addr[8])
{
#if defined(SPX_THASH_SIMPLE)
    unsigned char buf[SPX_SHA256_ADDR_BYTES + inblocks*SPX_N];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    uint8_t sha2_state[40];

    (void)pub_seed; /* Suppress an 'unused parameter' warning. */

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, state_seeded, 40 * sizeof(uint8_t));

    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * SPX_N);

    sha256_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    memcpy(out, outbuf, SPX_N);
#elif defined(SPX_THASH_ROBUST)
    unsigned char buf[SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    unsigned char bitmask[inblocks * SPX_N];
    uint8_t sha2_state[40];
    unsigned int i;

    memcpy(buf, pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SHA256_ADDR_BYTES);
    mgf1(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, state_seeded, 40 * sizeof(uint8_t));

    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_N + SPX_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    sha256_inc_finalize(outbuf, sha2_state, buf + SPX_N,
                        SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    memcpy(out, outbuf, SPX_N);
#endif
}

#endif /* HAVE_SPHINCS */
