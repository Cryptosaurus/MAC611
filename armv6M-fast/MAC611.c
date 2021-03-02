/************************************************************
 * MAC611 optimized ARM implementation
 * (c) 2018-2019 XXXX
 *
 * This code includes:
 * - an assembly version for ARMv6-M (tested on cortex-M0+)
 *   using 32+32->32 multiplier
 *
 *
 * Notes:
 * - the code assumes a LITTLE ENDIAN core
 * - inline assembly uses the old syntax for ARMv6-M (for better GCC compatilibility)
 ************************************************************/
char MUL_IMPLEM[] = "ARMv6-M assembly (Cortex-M0)";

/*** Setup Macros ***/

#define LAMBDA 1024 // Nb of blocks per key.

#include "MAC611.h"
#include <stdio.h>
#include <string.h>


static inline uint64_t make64(uint32_t a, uint32_t b) {
  union { uint64_t u64; uint32_t u32[2]; } t;
  t.u32[0] = a;
  t.u32[1] = b;
  return t.u64;
}


/*
 * Operations mod 2^61-1
 */

// Partial reduce to [0 .. 2^61+6]
static inline uint64_t reduce(uint64_t x) {
  uint32_t xl = x;
  uint32_t xh = x>>32;
  uint32_t t; // Scratch register

  asm ("lsr  %[t], %[xh], #29\n\t"
       "lsl  %[xh], #3\n\t"
       "lsr  %[xh], #3\n\t"
       "add  %[xl], %[t]\n\t"
       "adc  %[xh], %[z]"
       : [xl] "+&l" (xl), [xh] "+&l" (xh), [t] "=&l" (t)
       : [z] "l" (0)
       : "cc");

  return make64(xl, xh);
}

// Full reduce to [0 .. 2^61-2]
static inline uint64_t REDUCE_FULL(uint64_t x) {
  x = reduce(x);

  if (x >= MOD611)
    x -= MOD611;
  return x;
}

/*
 * Multiplication mod 2^61-1
 */

// Convert to base 31
static inline uint64_t base31(uint64_t x) {
  uint32_t a = x;
  uint32_t b = x>>32;

  asm ("add    %[a], %[a]\n\t"
       "adc    %[b], %[b]\n\t"
       "lsr    %[a], #1"
       : [a] "+&l" (a), [b] "+&l" (b)
       :: "cc");
  
  return make64(a, b);
}

static inline uint64_t mul3264(uint32_t a, uint32_t b) {
  uint32_t tmp1, tmp2, tmp3;
  // 32-bit input
  // 17 instructions
  
  asm ("lsr     %[t1], %[b], #16\n\t"      /* t1 = b1 */
       "uxth    %[t2], %[a]\n\t"           /* t2 = a0 */
       "mul     %[t2], %[t1]\n\t"          /* t2 = a0*b1 */
       "lsr     %[t3], %[a], #16\n\t"      /* t3 = a1 */
       "mul     %[t1], %[t3]\n\t"          /* t1 = b1*a1 */
       "uxth    %[b] , %[b]\n\t"
       "uxth    %[a] , %[a]\n\t"
       "mul     %[a] , %[b]\n\t"           /* a  = a0*b0 */
       "mul     %[b] , %[t3]\n\t"          /* b  = b0*a1 */
       "lsl     %[t3], %[t2], #16\n\t"
       "lsr     %[t2], #16\n\t"
       "add     %[a] , %[t3]\n\t"
       "adc     %[t1], %[t2]\n\t"
       "lsl     %[t2], %[b], #16\n\t"
       "lsr     %[b] , #16\n\t"
       "add     %[a], %[t2]\n\t"
       "adc     %[b], %[t1]"
       : [a]  "+&l" (a), [b] "+&l" (b),
	 [t1] "=&l" (tmp1), [t2] "=&l" (tmp2), [t3] "=&l" (tmp3)
       :: "cc");
  
  return make64(a, b);
}

uint64_t mul3164(uint32_t a, uint32_t b) {
  uint32_t tmp1, tmp2, tmp3;
  // 31-bit input
  // 14 instructions
  asm ("lsr     %[t1], %[b], #16\n\t"      /* t1 = b1    */
       "uxth    %[t2], %[a]\n\t"           /* t2 = a0    */
       "mul     %[t2], %[t1]\n\t"          /* t2 = a0*b1 */
       "lsr     %[t3], %[a], #16\n\t"      /* t3 = a1    */
       "mul     %[t1], %[t3]\n\t"          /* t1 = b1*a1 */
       "uxth    %[b] , %[b]\n\t"           /* b  = b0    */
       "uxth    %[a] , %[a]\n\t"           /* a  = a0    */
       "mul     %[a] , %[b]\n\t"           /* a  = a0*b0 */
       "mul     %[b] , %[t3]\n\t"          /* b  = b0*a1 */
       "add     %[b], %[t2]\n\t"           /* no carry with 31-bit input */
       "lsl     %[t3], %[b], #16\n\t"
       "lsr     %[b] , #16\n\t"
       "add     %[a] , %[t3]\n\t"
       "adc     %[b] , %[t1]"
       : [a]  "+&l" (a), [b] "+&l" (b),
	 [t1] "=&l" (tmp1), [t2] "=&l" (tmp2), [t3] "=&l" (tmp3)
       :: "cc");

    return make64(a, b);
}

static inline uint64_t mul611(uint64_t x, uint64_t y) {
  // Convert to base 2^31 to make Karatsuba multiplication easier
  x = base31(x);
  y = base31(y);

  
  uint32_t xl = x;
  uint32_t xh = x>>32;
  uint32_t yl = y;
  uint32_t yh = y>>32;

  uint64_t M0;
  uint64_t M1;
  uint64_t k;

  // Karatsuba multiplication
  M0 = mul3164(xl,yl);
  M1 = mul3164(xh,yh);
  k  = mul3264(xl+xh, yl+yh);
  k -= M0;
  k -= M1;
  
  // Convert back to base 2^32 and reduce
  uint32_t m0 = M0;
  uint32_t m1 = M0>>32;
  uint32_t m2 = M1;
  uint32_t m3 = M1>>32;
  uint32_t k0 = k;
  uint32_t k1 = k>>32;
  uint32_t t0;

  asm ("lsl  %[t0], %[k0], #31\n\t"
       "lsr  %[k0], %[k0], #1\n\t"
       "add  %[m0], %[t0]\n\t"
       "adc  %[m1], %[k0]\n\t"
       "mov  %[k0], #0\n\t"
       "lsl  %[t0], %[k1], #2\n\t" /* MSBs are null */
       "add  %[m0], %[t0]\n\t"
       "adc  %[m1], %[k0]\n\t"
       "add  %[m2], %[m2]\n\t"
       "adc  %[m1], %[k0]\n\t"        /* Carry is m2[31] */
       "lsl  %[m3], %[m3], #1\n\t"    /* MSB is null     */
       "add  %[m0], %[m2]\n\t"
       "adc  %[m1], %[m3]\n\t"
       "lsr  %[t0], %[m1], #29\n\t" /* final reduce */
       "lsl  %[m1], #3\n\t"
       "lsr  %[m1], #3\n\t"
       "add  %[m0], %[t0]\n\t"
       "adc  %[m1], %[k0]"
       : [m0] "+&l" (m0), [m1] "+&l" (m1), [m2] "+&l" (m2), [m3] "+&l" (m3),
         [k0] "+&l" (k0), [k1] "+&l" (k1), [t0] "=&l" (t0)
       :: "cc");

  
  return make64(m0, m1);
}

/*
 * MAC611 initialization.
 */
void MAC611_init (struct MAC611_context * ctx, const uint8_t k[16]) {
  ((uint64_t*)ctx->noekeon_key)[0] = ((uint64_t*)k)[0];
  ((uint64_t*)ctx->noekeon_key)[1] = ((uint64_t*)k)[1];
  
  // Compute first hash key
  uint64_t tmp[2];
  tmp[0] = 0; // Set to zero manually to avoid memset... 
  tmp[1] = 0;
  Noekeon_encrypt(ctx->noekeon_key, (uint8_t*)tmp, (uint8_t*)tmp);
  ctx->hash_key = REDUCE_FULL(tmp[0]);
}


/*
 * MAC611 tag evaluation
 * The context should be initialized using MAC611_init.
 * len is the message length in bytes
 *
 * NOTE: !!! ARMv6-M does not allow unaligned reads !!!
 */

void MAC611_tag (const struct MAC611_context * context, const uint8_t * M, size_t len, const uint8_t nonce[8], uint8_t tag[8]) {
  /*** Universal hash ***/
  uint64_t state = 0;
  uint64_t hash_key = context->hash_key;
  int k = 0; // Key index
  
  const uint8_t * p = M;
#define P32 ((uint32_t*)p)
  size_t l = len;

  /*** Process chunks of LAMBDA*7 bytes ***/
  while (l >= 7*LAMBDA) {
    const uint8_t* pmax = p+7*LAMBDA;
    do {
      /*** Unroll to optimize unaligned reads ***/
      uint64_t t = make64(P32[0], P32[1]&0x00ffffff);
      state += t;
      state = mul611(state, hash_key);
      t = make64((P32[1]>>24)+(P32[2]<<8), ((P32[2]>>24)+(P32[3]<<8))&0x00ffffff);
      state += t;
      state = mul611(state, hash_key);
      t = make64((P32[3]>>16)+(P32[4]<<16), ((P32[4]>>16)+(P32[5]<<16))&0x00ffffff);
      state += t;
      state = mul611(state, hash_key);
      t = make64((P32[5]>>8)+(P32[6]<<24), P32[6]>>8);
      state += t;
      state = mul611(state, hash_key);
      p += 7*4;
    } while (p < pmax);
    /*** Update key ***/
    uint64_t tmp[2] = {0, ++k};
    Noekeon_encrypt(context->noekeon_key, (uint8_t*)tmp, (uint8_t*)tmp);
    hash_key = REDUCE_FULL(tmp[0]);

    l -= 7*LAMBDA;
  }

  /*** Process final chunk ***/
  while (p <= M+len-7) {
    uint64_t t = make64(P32[0], P32[1]&0x00ffffff);
    state += t;
    state = mul611(state, hash_key);
    if (p+7 > M+len-7) {
      p += 7;
      break;
    }
    t = make64((P32[1]>>24)+(P32[2]<<8), ((P32[2]>>24)+(P32[3]<<8))&0x00ffffff);
    state += t;
    state = mul611(state, hash_key);
    if (p+14 > M+len-7) {
      p += 14;
      break;
    }
    t = make64((P32[3]>>16)+(P32[4]<<16), ((P32[4]>>16)+(P32[5]<<16))&0x00ffffff);
    state += t;
    state = mul611(state, hash_key);
    if (p+21 > M+len-7) {
      p += 21;
      break;
    }
    t = make64((P32[5]>>8)+(P32[6]<<24), P32[6]>>8);
    state += t;
    state = mul611(state, hash_key);
    p += 28;
  }

  /*** Partial last block ***/
  if (p < M+len) {
    // Read bytes
    union { uint64_t u64; uint8_t u8[8]; } t;
    t.u64 = 0;
    for (int i=0; p<M+len; p++, i++) {
      t.u8[i] = *p;
    }
    state += t.u64;
    state = mul611(state, hash_key);
  }
  

  /*** If needed, update key ***/
  if (l > 7*(LAMBDA-1)) {
    uint64_t tmp[2] = {0, ++k};
    Noekeon_encrypt(context->noekeon_key, (uint8_t*)tmp, (uint8_t*)tmp);
    hash_key = REDUCE_FULL(tmp[0]);
  }

  // Length padding
  state += len;
  state  = mul611(state, hash_key);

  /*** Finalization: Encrypt H||N ***/
  state = REDUCE_FULL(state) + (1ULL<<63);
  uint64_t S[2] = { state, *(uint64_t*)nonce };
  Noekeon_encrypt(context->noekeon_key, (uint8_t*)S, (uint8_t*)S);

  ((uint64_t*)tag)[0] = S[0];
}
