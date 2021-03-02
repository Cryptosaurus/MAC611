/************************************************************
 * MAC611 optimized ARM implementation
 * (c) 2018-2019 XXXX
 *
 * This code includes:
 * - an assembly version for ARMv7-M (tested on cortex-M4)
 *   using 32+32->64 multiplier
 *
 *
 * Notes:
 * - the code assumes a LITTLE ENDIAN core
 * - inline assembly uses the old syntax for ARMv6-M (for better GCC compatilibility)
 ************************************************************/
char MUL_IMPLEM[] = "ARMv7-M assembly (Cortex-M3 Cortex-M4)";

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

  asm ("adds  %[xl], %[xl], %[xh], lsr #29\n\t"
       "bic  %[xh], %[xh], #0xe0000000\n\t"
       "adc  %[xh], #0"
       : [xl] "+&l" (xl), [xh] "+&l" (xh)
       :: "cc");

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

static inline uint64_t mul611(uint64_t x, uint64_t y) {
  uint32_t xl = x;
  uint32_t xh = x>>32;
  uint32_t yl = y;
  uint32_t yh = y>>32;

  uint32_t m0;
  uint32_t m1;
  uint32_t m2;
  uint32_t m3;

  // Input           : [xh xl] [yh yl]
  // 128-bit product : [m3 m2 m1 m0]
  // Output (mod red): [xh xl]

  asm ("umull %[m0], %[m1], %[xl], %[yl]\n\t"
       "umull %[m2], %[m3], %[xh], %[yh]\n\t"
       "umull %[xh], %[yl], %[xh], %[yl]\n\t"
       "umull %[xl], %[yh], %[xl], %[yh]\n\t"
       "adds  %[xh], %[xl]\n\t"
       "adc   %[yh], %[yl]\n\t"
       "adds  %[m1], %[xh]\n\t"
       "adcs  %[m2], %[yh]\n\t"
       "adc   %[m3], #0\n\t"
       "bic  %[xh], %[m1], #0xe0000000\n\t"
       "adds %[xl], %[m0], %[m1], lsr #29\n\t"
       "adc  %[xh], %[xh], %[m2], lsr #29\n\t"
       "adds %[xl], %[xl], %[m2], lsl #3\n\t"
       "adc  %[xh], %[xh], %[m3], lsl #3"
       : [m0] "=&r" (m0), [m1] "=&r" (m1), [m2] "=&r" (m2), [m3] "=&r" (m3),
         [xl] "+&r" (xl), [xh] "+&r" (xh), [yl] "+&r" (yl), [yh] "+&r" (yh)
       :: "cc");
  
  return make64(xl, xh);
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
 */

void MAC611_tag (const struct MAC611_context * context, const uint8_t * M, size_t len, const uint8_t nonce[8], uint8_t tag[8]) {
  /*** Universal hash ***/
  
  // State
  // Force registers to avoid copy inside loop
  register uint32_t xl asm("r6") = 0, xh asm("r7") = 0;
  // Hash key
  uint64_t hash_key = context->hash_key;
  register uint32_t yl asm("r8") = hash_key;
  register uint32_t yh asm("r9") = hash_key>>32;
  int k = 0; // Key index
  
  const uint8_t * p = M;
  size_t l = len;

  /*** Process chunks of LAMBDA*7 bytes ***/
  while (l >= 7*LAMBDA) {
    const uint8_t* pmax = p+7*LAMBDA;
    do {
      /*** Unroll chunks of 14 bytes ***/
      // (Too much unrolling seems to create a bottleneck to read the code)
      uint32_t m0;
      uint32_t m1;
      uint32_t m2;
      uint32_t m3;
    
      uint32_t t0, t1;
    
      asm (/*** Computes state = (state+*p)*key, and increases p ***/
	   "ldr   %[t1], [%[p], #3]\n\t"
	   "ldr   %[t0], [%[p]], #7\n\t"
	   "adds  %[xl], %[xl], %[t0]\n\t"
	   "adcs  %[xh], %[xh], %[t1], lsr #8\n\t"
	   "umull %[m0], %[m1], %[xl], %[yl]\n\t"
	   "umull %[m2], %[m3], %[xh], %[yh]\n\t"
	   "umull %[xh], %[t0], %[xh], %[yl]\n\t"
	   "umull %[xl], %[t1], %[xl], %[yh]\n\t"
	   "adds  %[xh], %[xl]\n\t"
	   "adcs  %[t1], %[t0]\n\t"
	   "adds  %[m1], %[xh]\n\t"
	   "adcs  %[m2], %[t1]\n\t"
	   "adcs   %[m3], #0\n\t"
	   "bic  %[xh], %[m1], #0xe0000000\n\t"
	   "adds %[xl], %[m0], %[m1], lsr #29\n\t"
	   "adcs %[xh], %[xh], %[m2], lsr #29\n\t"
	   "adds %[xl], %[xl], %[m2], lsl #3\n\t"
	   "adcs  %[xh], %[xh], %[m3], lsl #3\n\t"
	   /*** Computes state = (state+*p)*key, and increases p ***/
	   "ldr   %[t1], [%[p], #3]\n\t"
	   "ldr   %[t0], [%[p]], #7\n\t"
	   "adds  %[xl], %[xl], %[t0]\n\t"
	   "adcs  %[xh], %[xh], %[t1], lsr #8\n\t"
	   "umull %[m0], %[m1], %[xl], %[yl]\n\t"
	   "umull %[m2], %[m3], %[xh], %[yh]\n\t"
	   "umull %[xh], %[t0], %[xh], %[yl]\n\t"
	   "umull %[xl], %[t1], %[xl], %[yh]\n\t"
	   "adds  %[xh], %[xl]\n\t"
	   "adcs  %[t1], %[t0]\n\t"
	   "adds  %[m1], %[xh]\n\t"
	   "adcs  %[m2], %[t1]\n\t"
	   "adcs   %[m3], #0\n\t"
	   "bic  %[xh], %[m1], #0xe0000000\n\t"
	   "adds %[xl], %[m0], %[m1], lsr #29\n\t"
	   "adcs %[xh], %[xh], %[m2], lsr #29\n\t"
	   "adds %[xl], %[xl], %[m2], lsl #3\n\t"
	   "adcs  %[xh], %[xh], %[m3], lsl #3\n\t"
	   /*** Extra reduce ***/
	   "adds  %[xl], %[xl], %[xh], lsr #29\n\t"
	   "bic  %[xh], %[xh], #0xe0000000\n\t"
	   "adc  %[xh], #0"
	   : [m0] "=&r" (m0), [m1] "=&l" (m1), [m2] "=&l" (m2), [m3] "=&r" (m3),
	     [xl] "+&l" (xl), [xh] "+&l" (xh), [t0] "=&l" (t0), [t1] "=&l" (t1),
	     [p]  "+&r" (p)
	   : [yl]  "r" (yl), [yh]  "r" (yh)
	   : "cc");
    } while (p < pmax);
    /*** Update key ***/
    uint64_t tmp[2] = {0, ++k};
    Noekeon_encrypt(context->noekeon_key, (uint8_t*)tmp, (uint8_t*)tmp);
    hash_key = REDUCE_FULL(tmp[0]);
    yl = hash_key;
    yh = hash_key>>32;

    l -= 7*LAMBDA;
  }

  /*** Process final chunk ***/
  // Unroll chunks of 14 bytes
  if (l >= 14) {
    register const uint8_t* pmax asm("sl") = M+len-14;
    do {
      uint32_t m0;
      uint32_t m1;
      uint32_t m2;
      uint32_t m3;

      uint32_t t0, t1;

      asm (/*** Computes state = (state+*p)*key, and increases p ***/
	   "ldr   %[t1], [%[p], #3]\n\t"
	   "ldr   %[t0], [%[p]], #7\n\t"
	   "adds  %[xl], %[xl], %[t0]\n\t"
	   "adcs  %[xh], %[xh], %[t1], lsr #8\n\t"
	   "umull %[m0], %[m1], %[xl], %[yl]\n\t"
	   "umull %[m2], %[m3], %[xh], %[yh]\n\t"
	   "umull %[xh], %[t0], %[xh], %[yl]\n\t"
	   "umull %[xl], %[t1], %[xl], %[yh]\n\t"
	   "adds  %[xh], %[xl]\n\t"
	   "adcs  %[t1], %[t0]\n\t"
	   "adds  %[m1], %[xh]\n\t"
	   "adcs  %[m2], %[t1]\n\t"
	   "adcs   %[m3], #0\n\t"
	   "bic  %[xh], %[m1], #0xe0000000\n\t"
	   "adds %[xl], %[m0], %[m1], lsr #29\n\t"
	   "adcs %[xh], %[xh], %[m2], lsr #29\n\t"
	   "adds %[xl], %[xl], %[m2], lsl #3\n\t"
	   "adcs  %[xh], %[xh], %[m3], lsl #3\n\t"
	   /*** Computes state = (state+*p)*key, and increases p ***/
	   "ldr   %[t1], [%[p], #3]\n\t"
	   "ldr   %[t0], [%[p]], #7\n\t"
	   "adds  %[xl], %[xl], %[t0]\n\t"
	   "adcs  %[xh], %[xh], %[t1], lsr #8\n\t"
	   "umull %[m0], %[m1], %[xl], %[yl]\n\t"
	   "umull %[m2], %[m3], %[xh], %[yh]\n\t"
	   "umull %[xh], %[t0], %[xh], %[yl]\n\t"
	   "umull %[xl], %[t1], %[xl], %[yh]\n\t"
	   "adds  %[xh], %[xl]\n\t"
	   "adcs  %[t1], %[t0]\n\t"
	   "adds  %[m1], %[xh]\n\t"
	   "adcs  %[m2], %[t1]\n\t"
	   "adcs   %[m3], #0\n\t"
	   "bic  %[xh], %[m1], #0xe0000000\n\t"
	   "adds %[xl], %[m0], %[m1], lsr #29\n\t"
	   "adcs %[xh], %[xh], %[m2], lsr #29\n\t"
	   "adds %[xl], %[xl], %[m2], lsl #3\n\t"
	   "adcs  %[xh], %[xh], %[m3], lsl #3\n\t"
	   /*** Extra reduce ***/
	   "adds  %[xl], %[xl], %[xh], lsr #29\n\t"
	   "bic  %[xh], %[xh], #0xe0000000\n\t"
	   "adc  %[xh], #0"
	   : [m0] "=&r" (m0), [m1] "=&l" (m1), [m2] "=&l" (m2), [m3] "=&r" (m3),
	     [xl] "+&l" (xl), [xh] "+&l" (xh), [t0] "=&l" (t0), [t1] "=&l" (t1),
	     [p]  "+&r" (p)
	   : [yl]  "r" (yl), [yh]  "r" (yh)
	   : "cc");
    } while (p <= pmax);
  }
  // Last chunk of 7 bytes
  if (p <= M+len-7) {
    uint32_t m0;
    uint32_t m1;
    uint32_t m2;
    uint32_t m3;
    
    uint32_t t0, t1;
    
    asm (/*** Computes state = (state+*p)*key, and increases p ***/
	 "ldr   %[t1], [%[p], #3]\n\t"
	 "ldr   %[t0], [%[p]], #7\n\t"
	 "adds  %[xl], %[xl], %[t0]\n\t"
	 "adcs  %[xh], %[xh], %[t1], lsr #8\n\t"
	 "umull %[m0], %[m1], %[xl], %[yl]\n\t"
	 "umull %[m2], %[m3], %[xh], %[yh]\n\t"
	 "umull %[xh], %[t0], %[xh], %[yl]\n\t"
	 "umull %[xl], %[t1], %[xl], %[yh]\n\t"
	 "adds  %[xh], %[xl]\n\t"
	 "adcs  %[t1], %[t0]\n\t"
	 "adds  %[m1], %[xh]\n\t"
	 "adcs  %[m2], %[t1]\n\t"
	 "adcs  %[m3], #0\n\t"
	 "bic  %[xh], %[m1], #0xe0000000\n\t"
	 "adds %[xl], %[m0], %[m1], lsr #29\n\t"
	 "adcs %[xh], %[xh], %[m2], lsr #29\n\t"
	 "adds %[xl], %[xl], %[m2], lsl #3\n\t"
	 "adcs  %[xh], %[xh], %[m3], lsl #3"
	 : [m0] "=&r" (m0), [m1] "=&l" (m1), [m2] "=&l" (m2), [m3] "=&r" (m3),
	   [xl] "+&l" (xl), [xh] "+&l" (xh), [t0] "=&l" (t0), [t1] "=&l" (t1),
	   [p]  "+&r" (p)
	 : [yl]  "r" (yl), [yh]  "r" (yh)
	 : "cc");
  }
  uint64_t state = make64(xl, xh);

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
