#include <stdint.h>
#include <stddef.h>

/*** Interface with Noekeon source using NESSIE interface ***/

#ifdef __cplusplus
extern "C" {
#endif

#include "Nessie.h"

void Noekeon_encrypt(const unsigned char * const key,
                   const unsigned char * const plaintext,
                   unsigned char * const ciphertext);

void Noekeon_decrypt(const unsigned char * const key,
                   const unsigned char * const ciphertext,
                   unsigned char * const plaintext);

#ifdef __cplusplus
}
#endif


/*** MAC611 interface ***/

#define MOD611 ((1ULL<<61)-1)

struct MAC611_context {
  uint64_t hash_key;
  uint8_t noekeon_key[16];
  uint64_t (*mul_table)[256];
};

#ifdef __cplusplus
extern "C" {
#endif
extern char MUL_IMPLEM[];

void MAC611_init (struct MAC611_context * context, const uint8_t k[16]);
void MAC611_tag (const struct MAC611_context * context, const uint8_t * m, size_t len, const uint8_t nonce[8], uint8_t tag[8]);
/* uint64_t mul611(uint64_t x, uint64_t y); */
/* uint64_t REDUCE_611(uint64_t x); */
#ifdef __cplusplus
}
#endif


/*** Useful macros ***/

#define read64(p)						\
  (((uint64_t)(p)[0] << 0 ) + ((uint64_t)(p)[1] << 8 ) +	\
   ((uint64_t)(p)[2] << 16) + ((uint64_t)(p)[3] << 24) +	\
   ((uint64_t)(p)[4] << 32) + ((uint64_t)(p)[5] << 40) +	\
   ((uint64_t)(p)[6] << 48) + ((uint64_t)(p)[7] << 56))

#define read56(p)						\
  (((uint64_t)(p)[0] << 0 ) + ((uint64_t)(p)[1] << 8 ) +	\
   ((uint64_t)(p)[2] << 16) + ((uint64_t)(p)[3] << 24) +	\
   ((uint64_t)(p)[4] << 32) + ((uint64_t)(p)[5] << 40) +	\
   ((uint64_t)(p)[6] << 48))

#define write64(p)							\
    (uint8_t) (p )    , (uint8_t)((p)>>8) ,				\
    (uint8_t)((p)>>16), (uint8_t)((p)>>24),				\
    (uint8_t)((p)>>32), (uint8_t)((p)>>40),				\
    (uint8_t)((p)>>48), (uint8_t)((p)>>56)
