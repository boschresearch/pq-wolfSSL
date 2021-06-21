/* kyber_memory.c
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://pq-crystals.org/kyber/
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_KYBER

#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/kyber.h>
#include <wolfssl/wolfcrypt/kyber_memory.h>

/*************************************************
* Name:        load24_littleendian
*
* Description: load 3 bytes into a 32-bit integer
*              in little-endian order
*              This function is only needed for Kyber-512
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x (most significant byte is zero)
**************************************************/
#if KYBER_ETA1 == 3
uint32_t load24_littleendian(const uint8_t x[3])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  return r;
}
#endif

/*************************************************
* Name:        load32_littleendian
*
* Description: load 4 bytes into a 32-bit integer
*              in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x
**************************************************/
uint32_t load32_littleendian(const uint8_t *x)
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  r |= (uint32_t)x[3] << 24;
  return r;
}

/*************************************************
* Name:        load64
*
* Description: Load 8 bytes into uint64_t in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns the loaded 64-bit unsigned integer
**************************************************/
uint64_t load64(const uint8_t *x)
{
  uint64_t r = 0;

  for (unsigned int i = 0; i < 8; ++i) {
    r |= (uint64_t)x[i] << 8 * i;
  }
  return r;
}

/*************************************************
* Name:        store64
*
* Description: Store a 64-bit integer to array of 8 bytes in little-endian order
*
* Arguments:   - uint8_t *x: pointer to the output byte array (allocated)
*              - uint64_t u: input 64-bit unsigned integer
**************************************************/
void store64(uint8_t *x, uint64_t u)
{
  for(unsigned int i=0; i<8; ++i) {
    x[i] = u >> 8*i;
  }
}

/*************************************************
* Name:        verify
*
* Description: Compare two arrays for equality in constant time.
*
* Arguments:   const uint8_t *a: pointer to first byte array
*              const uint8_t *b: pointer to second byte array
*              size_t len:             length of the byte arrays
*
* Returns 0 if the byte arrays are equal, 1 otherwise
**************************************************/
int verify(const uint8_t *a, const uint8_t *b, size_t len)
{
  uint8_t r = 0;
  size_t i;

  for(i=0; i < len; i++)
    r |= a[i] ^ b[i];

  return (-(uint64_t)r) >> 63;
;
}

/*************************************************
* Name:        cmov
*
* Description: Copy len bytes from x to r if b is 1;
*              don't modify x if b is 0. Requires b to be in {0,1};
*              assumes two's complement representation of negative integers.
*              Runs in constant time.
*
* Arguments:   uint8_t *r:       pointer to output byte array
*              const uint8_t *x: pointer to input byte array
*              size_t len:       Amount of bytes to be copied
*              uint8_t b:        Condition bit; has to be in {0,1}
**************************************************/
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
  size_t i;

  b = -b;
  for(i=0;i<len;i++)
    r[i] ^= b & (x[i] ^ r[i]);
}

#endif /* HAVE_KYBER */