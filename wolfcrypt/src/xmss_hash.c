/* xmss_hash.c
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
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/xmss_hash_address.h>
#include <wolfssl/wolfcrypt/xmss_utils.h>
#include <wolfssl/wolfcrypt/xmss.h>
#include <wolfssl/wolfcrypt/xmss_hash.h>

#define XMSS_HASH_PADDING_F 0
#define XMSS_HASH_PADDING_H 1
#define XMSS_HASH_PADDING_HASH 2
#define XMSS_HASH_PADDING_PRF 3
#define XMSS_HASH_PADDING_PRF_KEYGEN 4

void addr_to_bytes(unsigned char *bytes, const uint32_t addr[8])
{
    int i;
    for (i = 0; i < 8; i++) {
        xmss_ull_to_bytes(bytes + i*4, 4, addr[i]);
    }
}

static int core_hash(unsigned char *out,
                     const unsigned char *in, unsigned long long inlen)
{
    if (XMSS_N == 32) {
       wc_Sha256Hash(in, inlen, out);
    }
    else if (XMSS_N == 64) {
        wc_Sha512Hash(in, inlen, out);
    }
    else {
        return -1;
    }
    return 0;
}

/*
 * Computes PRF(key, in), for a key of XMSS_N bytes, and a 32-byte input.
 */
int prf(unsigned char *out, const unsigned char in[32],
        const unsigned char *key)
{
    unsigned char buf[XMSS_PADDING_LEN + XMSS_N + 32];

    xmss_ull_to_bytes(buf, XMSS_PADDING_LEN, XMSS_HASH_PADDING_PRF);
    memcpy(buf + XMSS_PADDING_LEN, key, XMSS_N);
    memcpy(buf + XMSS_PADDING_LEN + XMSS_N, in, 32);

    return core_hash(out, buf, XMSS_PADDING_LEN + XMSS_N + 32);
}

/*
 * Computes PRF_keygen(key, in), for a key of XMSS_N bytes, and an input
 * of 32 + XMSS_N bytes
 */
int prf_keygen(unsigned char *out, const unsigned char *in,
        const unsigned char *key)
{
    unsigned char buf[XMSS_PADDING_LEN + 2*XMSS_N + 32];

    xmss_ull_to_bytes(buf, XMSS_PADDING_LEN, XMSS_HASH_PADDING_PRF_KEYGEN);
    memcpy(buf + XMSS_PADDING_LEN, key, XMSS_N);
    memcpy(buf + XMSS_PADDING_LEN + XMSS_N, in, XMSS_N + 32);

    return core_hash(out, buf, XMSS_PADDING_LEN + 2*XMSS_N + 32);
}

/*
 * Computes the message hash using R, the public root, the index of the leaf
 * node, and the message. Notably, it requires m_with_prefix to have 3*n plus
 * the length of the padding as free space available before the message,
 * to use for the prefix. This is necessary to prevent having to move the
 * message around (and thus allocate memory for it).
 */
int xmss_hash_message(unsigned char *out, const unsigned char *R,
                const unsigned char *root, unsigned long long idx,
                 unsigned char *m_with_prefix, unsigned long long mlen)
{
    /* We're creating a hash using input of the form:
       toByte(X, 32) || R || root || index || M */
    xmss_ull_to_bytes(m_with_prefix, XMSS_PADDING_LEN, XMSS_HASH_PADDING_HASH);
    memcpy(m_with_prefix + XMSS_PADDING_LEN, R, XMSS_N);
    memcpy(m_with_prefix + XMSS_PADDING_LEN + XMSS_N, root, XMSS_N);
    xmss_ull_to_bytes(m_with_prefix + XMSS_PADDING_LEN + 2*XMSS_N, XMSS_N, idx);

    return core_hash(out, m_with_prefix, mlen + XMSS_PADDING_LEN + 3*XMSS_N);
}

/**
 * We assume the left half is in in[0]...in[n-1]
 */
int thash_h(unsigned char *out, const unsigned char *in,
            const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char buf[XMSS_PADDING_LEN + 3 * XMSS_N];
    unsigned char bitmask[2 * XMSS_N];
    unsigned char addr_as_bytes[32];
    unsigned int i;

    /* Set the function padding. */
    xmss_ull_to_bytes(buf, XMSS_PADDING_LEN, XMSS_HASH_PADDING_H);

    /* Generate the n-byte key. */
    set_key_and_mask(addr, 0);
    addr_to_bytes(addr_as_bytes, addr);
    prf(buf + XMSS_PADDING_LEN, addr_as_bytes, pub_seed);

    /* Generate the 2n-byte mask. */
    set_key_and_mask(addr, 1);
    addr_to_bytes(addr_as_bytes, addr);
    prf(bitmask, addr_as_bytes, pub_seed);

    set_key_and_mask(addr, 2);
    addr_to_bytes(addr_as_bytes, addr);
    prf(bitmask + XMSS_N, addr_as_bytes, pub_seed);

    for (i = 0; i < 2 * XMSS_N; i++) {
        buf[XMSS_PADDING_LEN + XMSS_N + i] = in[i] ^ bitmask[i];
    }
    return core_hash(out, buf, XMSS_PADDING_LEN + 3 * XMSS_N);
}

int thash_f(unsigned char *out, const unsigned char *in,
            const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char buf[XMSS_PADDING_LEN + 2 * XMSS_N];
    unsigned char bitmask[XMSS_N];
    unsigned char addr_as_bytes[32];
    unsigned int i;

    /* Set the function padding. */
    xmss_ull_to_bytes(buf, XMSS_PADDING_LEN, XMSS_HASH_PADDING_F);

    /* Generate the n-byte key. */
    set_key_and_mask(addr, 0);
    addr_to_bytes(addr_as_bytes, addr);
    prf(buf + XMSS_PADDING_LEN, addr_as_bytes, pub_seed);

    /* Generate the n-byte mask. */
    set_key_and_mask(addr, 1);
    addr_to_bytes(addr_as_bytes, addr);
    prf(bitmask, addr_as_bytes, pub_seed);

    for (i = 0; i < XMSS_N; i++) {
        buf[XMSS_PADDING_LEN + XMSS_N + i] = in[i] ^ bitmask[i];
    }
    return core_hash(out, buf, XMSS_PADDING_LEN + 2 * XMSS_N);
}

#endif /* HAVE_XMSS */
