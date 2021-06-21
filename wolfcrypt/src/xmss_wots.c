/* xmss_wots.c
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

#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/xmss_utils.h>
#include <wolfssl/wolfcrypt/xmss_hash.h>
#include <wolfssl/wolfcrypt/xmss_wots.h>
#include <wolfssl/wolfcrypt/xmss_hash_address.h>
#include <wolfssl/wolfcrypt/xmss.h>

/**
 * Helper method for pseudorandom key generation.
 * Expands an n-byte array into a len*n byte array using the `prf_keygen` function.
 */
static void expand_seed(unsigned char *outseeds, const unsigned char *inseed,
                        const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;
    unsigned char buf[XMSS_N + 32];

    xmss_set_hash_addr(addr, 0);
    set_key_and_mask(addr, 0);
    memcpy(buf, pub_seed, XMSS_N);
    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        xmss_set_chain_addr(addr, i);
        addr_to_bytes(buf + XMSS_N, addr);
        prf_keygen(outseeds + i*XMSS_N, buf, inseed);
    }
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, XMSS_N);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start+steps) && i < XMSS_WOTS_W; i++) {
        xmss_set_hash_addr(addr, i);
        thash_f(out, out, pub_seed, addr);
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(int *output, const int out_len, const unsigned char *input)
{
    int in = 0;
    int out = 0;
    unsigned char total;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= XMSS_WOTS_LOG_W;
        output[out] = (total >> bits) & (XMSS_WOTS_W - 1);
        out++;
    }
}

/* Computes the WOTS+ checksum over a message (in base_w). */
static void wots_checksum(int *csum_base_w, const int *msg_base_w)
{
    int csum = 0;
    unsigned char csum_bytes[(XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W + 7) / 8];
    unsigned int i;

    /* Compute checksum. */
    for (i = 0; i < XMSS_WOTS_LEN1; i++) {
        csum += XMSS_WOTS_W - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << (8 - ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) % 8));
    xmss_ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w(csum_base_w, XMSS_WOTS_LEN2, csum_bytes);
}

/* Takes a message and derives the matching chain lengths. */
static void chain_lengths(int *lengths, const unsigned char *msg)
{
    base_w(lengths, XMSS_WOTS_LEN1, msg);
    wots_checksum(lengths + XMSS_WOTS_LEN1, lengths);
}

/**
 * WOTS key generation. Takes a 32 byte seed for the private key, expands it to
 * a full WOTS private key and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this WOTS key pair.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pkgen(unsigned char *pk, const unsigned char *seed,
                const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(pk, seed, pub_seed, addr);

    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        xmss_set_chain_addr(addr, i);
        gen_chain(pk + i*XMSS_N, pk + i*XMSS_N,
                  0, XMSS_WOTS_W - 1, pub_seed, addr);
    }
}

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
void xmss_wots_sign(unsigned char *sig, const unsigned char *msg,
               const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[8])
{
    int lengths[XMSS_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(sig, seed, pub_seed, addr);

    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        xmss_set_chain_addr(addr, i);
        gen_chain(sig + i*XMSS_N, sig + i*XMSS_N,
                  0, lengths[i], pub_seed, addr);
    }
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void xmss_wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    int lengths[XMSS_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        xmss_set_chain_addr(addr, i);
        gen_chain(pk + i*XMSS_N, sig + i*XMSS_N,
                  lengths[i], XMSS_WOTS_W - 1 - lengths[i], pub_seed, addr);
    }
}

#endif /* HAVE_XMSS */
