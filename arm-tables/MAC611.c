/************************************************************
 * MAC611 optimized ARM implementation
 * (c) 2018-2019 XXXX
 *
 * This code includes:
 * - an assembly version for ARMv6-M (tested on cortex-M0+)
 *   using tables (8-bit chunks)
 *
 *
 * Notes:
 * - the code assumes a LITTLE ENDIAN core
 * - inline assembly uses the old syntax for ARMv6-M (for better GCC compatilibility)
 ************************************************************/
char MUL_IMPLEM[] = "ARMv6-M assembly using tables";

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

// Reduce from [0 .. 2^62-2] to [0 .. 2^61-1]
static inline uint64_t reduce_mini(uint64_t x) {
  if (x > MOD611)
    x -= MOD611;
  return x;
}

static inline void init_table(const struct MAC611_context * ctx, int k) {
  uint64_t tmp[2] = {0, k};
  Noekeon_encrypt(ctx->noekeon_key, (uint8_t*)tmp, (uint8_t*)tmp);
  uint64_t x = REDUCE_FULL(tmp[0]);

  // Table elements are just reduced to 0...2^61-1 (versus 0..2^61-2) for full reduce
  for (int i=0; i<8; i++) {
    ctx->mul_table[i][0] = 0;
    if (i == 0)
      ctx->mul_table[i][1] = x;
    else
      ctx->mul_table[i][1] = reduce_mini(2*ctx->mul_table[i-1][128]);

    for (int j=2; j<256; j++) {
      ctx->mul_table[i][j] = reduce_mini(ctx->mul_table[i][j-1]+ctx->mul_table[i][1]);
    }
  }
}


uint64_t mul611_mt(uint64_t x, const uint64_t mt[8][256]) {
  register uint32_t output0 = 0, output1 = 0;

  // Note: registers for ldm are harcoded, because
  // we cannot force GCC to have %[t0] < %[t1] (needed for ldm)
#define str(x) str_(x)
#define str_(x) #x
  // Add from tables
#define STEP(i,dir,n)                                                   \
  "ls" str(dir) " r7, %[x], #" str(n) "\n\t"				\
    "and r7, %[mask], r7\n\t"					\
    "add r7, r7, %[mul]\n\t"					\
    "ldm r7, {r6, r7}\n\t"					\
    "add %[output0], r6\n\t"						\
    "adc %[output1], r7\n\t"						\
    "add %[mul], %[mul], %[delta]\n\t"
  asm (
       STEP(0, l, 3)
       STEP(1, r, 5)
       STEP(2, r, 13)
       STEP(3, r, 21)
       : [output0] "+&l" (output0), [output1] "+&l" (output1), [mul] "+&r" (mt)
       : [x] "l" ((uint32_t) x), [mask] "l" (0xff<<3), [delta] "r" (2048)
       : "r6", "r7", "cc");
  asm (
       STEP(0, l, 3)
       STEP(1, r, 5)
       STEP(2, r, 13)
       STEP(3, r, 21)
       : [output0] "+&l" (output0), [output1] "+&l" (output1), [mul] "+&r" (mt)
       : [x] "l" ((uint32_t) (x>>32)), [mask] "l" (0xff<<3), [delta] "r" (2048)
       : "r6", "r7", "cc");

  return reduce(make64(output0, output1));
}

#if 0
// Muliplication function for debug purpose
uint64_t mul611(uint64_t x, uint64_t y) {
  uint64_t (*mt)[256] = (uint64_t (*)[256])malloc(8*256*sizeof(uint64_t));
  if (!mt) {
    printf("Malloc failed (mul611)!\r\n");
    exit(-1);
  }
  init_table(y, mt);
  uint64_t z = mul611_mt(x, mt);
  free(mt);
  return z;
}
#endif

/*
 * MAC611 initialization.
 */
void MAC611_init (struct MAC611_context * ctx, const uint8_t k[16]) {
  ((uint64_t*)ctx->noekeon_key)[0] = ((uint64_t*)k)[0];
  ((uint64_t*)ctx->noekeon_key)[1] = ((uint64_t*)k)[1];
  ctx->mul_table = (uint64_t (*)[256])malloc(8*256*sizeof(uint64_t));
  if (!ctx->mul_table) {
    printf("Malloc failed (MAC611_init)!\r\n");
    exit(-1);
  }
  // Compute first hash key
  init_table(ctx, 0);
}


/*
 * MAC611 tag evaluation
 * The context should be initialized using MAC611_init.
 * len is the message length in bytes
 *
 * NOTE: !!! ARMv6-M does not allow unaligned reads !!!
 */

void MAC611_tag (const struct MAC611_context * ctx, const uint8_t * M, size_t len, const uint8_t nonce[8], uint8_t tag[8]) {
  /*** Universal hash ***/
  uint64_t state = 0;
  int new_tables = 0;
  
  int cnt = LAMBDA;
  int k = 0;

  /*** Unroll to optimize unaligned reads ***/
  size_t n = len/7;
  const uint32_t * p = (uint32_t*)M;
  while ((uint8_t*)p <= M+len-7) {
    uint64_t t = make64(p[0], p[1]&0x00ffffff);
    state += t;
    state = mul611_mt(state, ctx->mul_table);
    if ((uint8_t*)p+7 > M+len-7)
      break;
    t = make64((p[1]>>24)|(p[2]<<8), ((p[2]>>24)|(p[3]<<8))&0x00ffffff);
    state += t;
    state = mul611_mt(state, ctx->mul_table);
    if ((uint8_t*)p+14 > M+len-7)
      break;
    t = make64((p[3]>>16)|(p[4]<<16), ((p[4]>>16)|(p[5]<<16))&0x00ffffff);
    state += t;
    state = mul611_mt(state, ctx->mul_table);
    if ((uint8_t*)p+21 > M+len-7)
      break;
    t = make64((p[5]>>8)|(p[6]<<24), p[6]>>8);
    state += t;
    state = mul611_mt(state, ctx->mul_table);
    p += 7;

    cnt -= 4;
    if (cnt == 0) {
      // Overwrite table in-place
      init_table(ctx, ++k);
      cnt = LAMBDA;
      new_tables = 1;
    }
  }

  /*** Partial last block ***/
  if (len%7) {
    // Read bytes
    union { uint64_t u64; uint8_t u8[8]; } t;
    t.u64 = 0;
    for (int i=0; i<len%7; i++) {
      t.u8[i] = M[7*n+i];
    }
    state += t.u64;
    state = mul611_mt(state, ctx->mul_table);
  }  

  // Length padding
  state += len;
  state = mul611_mt(state, ctx->mul_table);

  /*** Finalization: Encrypt H||N ***/
  state = REDUCE_FULL(state) + (1ULL<<63);
  uint64_t S[2] = { state, *(uint64_t*)nonce };
  Noekeon_encrypt(ctx->noekeon_key, (uint8_t*)S, (uint8_t*)S);

  ((uint64_t*)tag)[0] = S[0];
  // Restore initial table if needed
  if (new_tables)
    init_table(ctx, 0);
}
