/************************************************************
 * MAC611 benchmarking
 * (c) 2018-2019 XXXX
 ************************************************************/

/*** Standard includes ***/

#ifdef __MBED__

#include "mbed.h"

#else // __MBED__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#endif // __MBED__

#include "MAC611.h"

#ifdef __MBED__

/*** Read timestamp counter on ARM Cortex-M ***/
/* DWT (Data Watchpoint and Trace) registers, only exists on ARM Cortex with a DWT unit */
  #define KIN1_DWT_CONTROL             (*((volatile uint32_t*)0xE0001000))
    /*!< DWT Control register */
  #define KIN1_DWT_CYCCNTENA_BIT       (1UL<<0)
    /*!< CYCCNTENA bit in DWT_CONTROL register */
  #define KIN1_DWT_CYCCNT              (*((volatile uint32_t*)0xE0001004))
    /*!< DWT Cycle Counter register */
  #define KIN1_DEMCR                   (*((volatile uint32_t*)0xE000EDFC))
    /*!< DEMCR: Debug Exception and Monitor Control Register */
  #define KIN1_TRCENA_BIT              (1UL<<24)
    /*!< Trace enable bit in DEMCR register */

/* Functions */
#define KIN1_InitCycleCounter() \
  KIN1_DEMCR |= KIN1_TRCENA_BIT
  /*!< TRCENA: Enable trace and debug block DEMCR (Debug Exception and Monitor Control Register */
 
#define KIN1_ResetCycleCounter() \
  KIN1_DWT_CYCCNT = 0
  /*!< Reset cycle counter */
 
#define KIN1_EnableCycleCounter() \
  KIN1_DWT_CONTROL |= KIN1_DWT_CYCCNTENA_BIT
  /*!< Enable cycle counter */
 
#define KIN1_DisableCycleCounter() \
  KIN1_DWT_CONTROL &= ~KIN1_DWT_CYCCNTENA_BIT
  /*!< Disable cycle counter */
 
#define KIN1_GetCycleCounter() \
  KIN1_DWT_CYCCNT
  /*!< Read cycle counter register */

#ifdef __CORTEX_M4

#define PERF_INIT					\
  KIN1_InitCycleCounter(); /* enable DWT hardware */	\
  KIN1_EnableCycleCounter(); /* start counting */	\
  Timer PERF_timer;					\
  PERF_timer.start();
  
#define PERF_START				\
  int32_t PERF_start_us = PERF_timer.read_us();	\
  KIN1_ResetCycleCounter(); /* reset cycle counter */

#define PERF_STOP				\
  int32_t PERF_stop = KIN1_GetCycleCounter();	\
  int32_t PERF_stop_us = PERF_timer.read_us();

#define PERF_PRINT				\
  printf ("%i cycles\t", (int)PERF_stop);		\
  printf ("%i us", (int)(PERF_stop_us-PERF_start_us));


#else  //__CORTEX_M4

#define PERF_INIT					\
  Timer PERF_timer;					\
  PERF_timer.start();
  
#define PERF_START				\
  int32_t PERF_start_us = PERF_timer.read_us();

#define PERF_STOP				\
  int32_t PERF_stop_us = PERF_timer.read_us(); 

#define PERF_PRINT				\
  printf ("%i us", (int)(PERF_stop_us-PERF_start_us));

#endif //__CORTEX_M4

#else // __MBED__

/*** Read timestamp counter on x86 ***/
#if defined(__x86_64__) || defined(__x86__)
unsigned long long rdtsc (void) {
    unsigned int tickl, tickh;
    __asm__ __volatile__("rdtsc":"=a"(tickl),"=d"(tickh));
    return ((unsigned long long)tickh << 32)|tickl;
}

#define PERF_INIT

#define PERF_START				\
  long long PERF_start = rdtsc();

#define PERF_STOP				\
  long long PERF_stop = rdtsc();

#define PERF_PRINT				\
  printf ("%lli cycles", (long long int)(PERF_stop-PERF_start));

#endif // __x86_64__ || __x86__

#endif // __MBED__

#if 0
void multest(uint64_t a, uint64_t b) {
  PERF_INIT;
  PERF_START;
  
  uint64_t c = mul611(a,b);

  PERF_STOP;
  
  printf ("%16llx * %16llx => %16llx => %16llx\t", a, b, c, c%MOD611);
  PERF_PRINT;
  printf ("\r\n");
}
#endif

void MACtest(const struct MAC611_context *ctx, uint8_t *m, size_t len, const uint8_t N[8]) {
  PERF_INIT;
  PERF_START;

  uint8_t tag[8];
  MAC611_tag(ctx, m, len, N, tag);

  PERF_STOP;

  printf ("M[%4i] = { ", (int)len);
  for (unsigned i=0; i<len && i<10; i++)
    printf ("%02x ", m[i]);
  if (len > 10)
    printf ("... }");
  else 
    printf ("}%*s", (int)(3*(10-len)+4), ""); // Pad for alignment

  printf ("  N = {");
  for (int i=0; i<8; i++)
    printf ("%02x", N[i]);
  
  printf ("} => ");
  for (int i=0; i<8; i++)
    printf ("%02x", tag[i]);
  
  printf ("\t");
  PERF_PRINT;
  printf ("\r\n");
}

int main()
{
  printf ("\r\n########################################\r\n"
	  "MAC611 benchmarks and test vectors\r\n"
	  "########################################\r\n\r\n");
  printf ("Using implementation: %s\r\n\r\n\r\n", MUL_IMPLEM);

#if 0
  printf ("## Noekeon test vectors\r\n");
  /*                 k = 00000000 00000000 00000000 00000000
                     a = 00000000 00000000 00000000 00000000
after NESSIEencrypt, b = b1656851 699e29fa 24b70148 503d2dfc
  */
  {
    uint8_t k[16] = {0};
    uint8_t p[16] = {0};
    uint8_t c[16];
    Noekeon_encrypt(k, p, c);
    for (int i=0; i<16; i+=4)
      printf("%08x ", (p[i]<<24) + (p[i+1]<<16) + (p[i+2]<<8) + (p[i+3]<<0));
    printf ("=>");
    for (int i=0; i<16; i+=4)
      printf(" %08x", (c[i]<<24) + (c[i+1]<<16) + (c[i+2]<<8) + (c[i+3]<<0));
    printf ("\r\n");
  }
  /*                 k = b1656851 699e29fa 24b70148 503d2dfc
                     a = 2a78421b 87c7d092 4f26113f 1d1349b2
after NESSIEencrypt, b = e2f687e0 7b75660f fc372233 bc47532c
  */
  {
    uint8_t k[16] = {0xb1, 0x65, 0x68, 0x51, 0x69, 0x9e, 0x29, 0xfa, 0x24, 0xb7, 0x01, 0x48, 0x50, 0x3d, 0x2d, 0xfc};
    uint8_t p[16] = {0x2a, 0x78, 0x42, 0x1b, 0x87, 0xc7, 0xd0, 0x92, 0x4f, 0x26, 0x11, 0x3f, 0x1d, 0x13, 0x49, 0xb2};
    uint8_t c[16];
    Noekeon_encrypt(k, p, c);
    for (int i=0; i<16; i+=4)
      printf("%08x ", (p[i]<<24) + (p[i+1]<<16) + (p[i+2]<<8) + (p[i+3]<<0));
    printf ("=>");
    for (int i=0; i<16; i+=4)
      printf(" %08x", (c[i]<<24) + (c[i+1]<<16) + (c[i+2]<<8) + (c[i+3]<<0));
    printf ("\r\n");
  }
  printf ("\r\n\r\n");
#endif

#if 0
  // Test multiplication code
  printf("## Multiplication test\r\n");
  uint64_t a = 0xdeadbeefLL, b = 0xbadc0ffeeLL;
  for (int i=0; i<16; i++) {
    a = (a * 3141) % MOD611;
    b = (b * 2718) % MOD611;
    multest(a, b);
  }
#endif

  printf("## MAC test vectors\r\n");
  uint8_t k[16] = {  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
  		     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
  struct MAC611_context ctx;
  MAC611_init(&ctx, k);

#define MLEN 7200 // > 7*LAMBDA
  uint8_t *M = (uint8_t*)malloc(MLEN);
  if (!M) {
    printf("Malloc failed (M)!\r\n");
    exit(-1);
  }

  for (int i=0; i<MLEN; i++)
    M[i] = i;

  // Small messages
  for (int i=0; i<=16; i++) {
    uint8_t N[8] = {(uint8_t) i, (uint8_t) i, (uint8_t) i, (uint8_t) i,
  		    (uint8_t)~i, (uint8_t)~i, (uint8_t)~i, (uint8_t)~i};
    MACtest(&ctx, M, i, N);
  }

  // Medium and long message
  uint64_t N;
  N = 56;
  MACtest(&ctx, M, N, (uint8_t*)&N);

  N = 896;
  MACtest(&ctx, M, N, (uint8_t*)&N);

  N = 7000;
  MACtest(&ctx, M, N, (uint8_t*)&N);

  N = 7168;
  MACtest(&ctx, M, N, (uint8_t*)&N);

  for (int i=7168-8; i<=7168+16; i++) {
    N = i;
    k[0] = N;
    MAC611_init(&ctx, k);
    MACtest(&ctx, M, N, (uint8_t*)&N);
  }

  free(M);
  return 0;
}
