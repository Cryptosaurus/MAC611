/************************************************************
 * MAC611 reference implementation
 * (c) 2018-2019 XXXX
 *
 * This code includes:
 * - a generic C version (using 32+32->64 multiplier)
 * - a GNU C version (using 64+64->128 multiplier and 128-bit integers)
 *
 * The correct version is auto-detected with compiler macros
 ************************************************************/

/*** Setup Macros ***/

#define LAMBDA 1024 // Nb of blocks per key.

#include "MAC611.h"
#include <stdio.h>
#include <string.h>

/*
 * Multiplication mod 2^61-1
 */


uint64_t REDUCE_611(uint64_t x) {
  return x%(0x1fffffffffffffffULL);
}

#ifdef __SIZEOF_INT128__

/*** GCC version with 128-bit integer ***/
char MUL_IMPLEM[] = "GCC int128";
uint64_t mul611(uint64_t x, uint64_t y) {
  unsigned __int128 z = (unsigned __int128) x*y;
  return z%MOD611;
}

#else  //__SIZEOF_INT128__

/*** Generic C version ***/
#define MUL32(a,b) ((uint64_t)(a)*(b))

char MUL_IMPLEM[] = "Generic C";
uint64_t mul611(uint64_t x, uint64_t y) {
  // Split input
  uint32_t xl = x;
  uint32_t xh = x>>32;
  uint32_t yl = y;
  uint32_t yh = y>>32;

  // 128-bit intermediate value
  uint32_t m0 = 0;
  uint32_t m1 = 0;
  uint32_t m2 = 0;
  uint32_t m3 = 0;

  uint64_t t;
  uint32_t th, tl;

  t = MUL32(xl, yl);
  tl = t;
  th = t>>32;
  m0 = tl;
  m1 = th;

  t = MUL32(xh, yh);
  tl = t;
  th = t>>32;
  m2 = tl;
  m3 = th;

  t  = MUL32(xh, yl);
  t += MUL32(xl, yh);
  
  tl = t;
  th = t>>32;
  m1 += tl;
  th += (m1 < tl);
  m2 += th;
  m3 += (m2 < th);
  

  // Reduce mod 2^61-1
  uint32_t r0;
  uint32_t r1;
  uint32_t rr;
  
  r1  = m1&(0xffffffff>>3);

  r0 = m0;
  rr = r0 + (m1>>29);
  r1 += (rr < r0); // Carry!
  r0  = rr + (m2<<3);
  r1 += (r0 < rr); // Carry!

  r1 += m2>>29;
  r1 += m3<<3;

  return ((uint64_t)r1<<32) + r0;
}

#endif //__SIZEOF_INT128__

/*
 * MAC611 initialization.
 */
void MAC611_init (struct MAC611_context * ctx, const uint8_t k[16]) {
  memcpy(ctx->noekeon_key, k, 16);
  
  // Compute first hash key
  unsigned char tmp[16] = {0};
  Noekeon_encrypt(ctx->noekeon_key, tmp, tmp);
  ctx->hash_key = REDUCE_611(read64(tmp));
}


/*
 * MAC611 tag evaluation
 * The context should be initialized using MAC611_init.
 * len is the message length in bytes
 */
void MAC611_tag (const struct MAC611_context * context, const uint8_t * M, size_t len, const uint8_t nonce[8], uint8_t tag[8]) {
  /*** Universal hash ***/
  uint64_t state = 0;
  uint64_t hash_key = context->hash_key;
  
  int cnt = LAMBDA; // Key lifetime
  uint64_t k = 0;   // Key index

  // Read blocks of 7 bytes (56 bits), (last block can be partial)
  for (size_t l=0; l<len; l+=7) {
    uint64_t t = 0;
    // Read bytes
    for (int i=0; i<7 && l+i<len; i++)
      t |= (uint64_t)M[l+i] << (8*i);

    state += t;
    state = mul611(state, hash_key);

    if (--cnt == 0) {
      k++;
      unsigned char tmp[16] = { 0, 0, 0, 0, 0, 0, 0, 0, write64(k) };
      Noekeon_encrypt(context->noekeon_key, tmp, tmp);
      hash_key = REDUCE_611(read64(tmp));
      cnt = LAMBDA;
    }
  }

  // Length padding
  uint64_t t = len;
  state += t;
  state = mul611(state, hash_key);

  // Finalization: Encrypt H||N
  state = REDUCE_611(state) + (1ULL<<63);
  uint8_t S[16] = { write64(state) };
  memcpy(S+8, nonce, 8);
  Noekeon_encrypt(context->noekeon_key, S, S);

  memcpy(tag, S, 8);
}
