
#ifndef PARAMS_H
#define PARAMS_H

#define SPX_N               32
#define SPX_FULL_HEIGHT     68
#define SPX_D               17
#define SPX_FORS_HEIGHT     9
#define SPX_FORS_TREES      35
#define SPX_WOTS_W          16
#define SPX_ADDR_BYTES      32
#define SPX_SHA256_BLOCK_BYTES  64
#define SPX_SHA256_OUTPUT_BYTES 32
#define SPX_SHA256_ADDR_BYTES   22

/* WOTS parameters */
#if SPX_WOTS_W == 256
  #define SPX_WOTS_LOGW 8
#elif SPX_WOTS_W == 16
  #define SPX_WOTS_LOGW 4
#else
  #error "SPX_WOTS_W assumed 16 or 256"
#endif

#define SPX_WOTS_LEN1  (8 * SPX_N / SPX_WOTS_LOGW)

#if SPX_WOTS_W == 256
  #if SPX_N <= 1
    #define SPX_WOTS_LEN2 1
  #elif SPX_N <= 256
    #define SPX_WOTS_LEN2 2
  #else
    #error "Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}"
  #endif
#elif SPX_WOTS_W == 16
  #if SPX_N <= 8
    #define SPX_WOTS_LEN2 2
  #elif SPX_N <= 136
    #define SPX_WOTS_LEN2 3
  #elif SPX_N <= 256
    #define SPX_WOTS_LEN2 4
  #else
    #error "Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}"
  #endif
#endif

#define SPX_WOTS_LEN      (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES    (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES  SPX_WOTS_BYTES

/* Subtree size */
#define SPX_TREE_HEIGHT    (SPX_FULL_HEIGHT / SPX_D)
#if (SPX_TREE_HEIGHT * SPX_D) != SPX_FULL_HEIGHT
  #error "SPX_D should always divide SPX_FULL_HEIGHT"
#endif

/* FORS parameters */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES     ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES   SPX_N

/* Resulting SPX sizes */
#define SPX_BYTES          (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES       (2 * SPX_N)
#define SPX_SK_BYTES       (2 * SPX_N + SPX_PK_BYTES)

#define SPX_OPTRAND_BYTES  32

/* Address offsets */
#define SPX_OFFSET_LAYER       0
#define SPX_OFFSET_TREE        1
#define SPX_OFFSET_TYPE        9
#define SPX_OFFSET_KP_ADDR2   12
#define SPX_OFFSET_KP_ADDR1   13
#define SPX_OFFSET_CHAIN_ADDR 17
#define SPX_OFFSET_HASH_ADDR  21
#define SPX_OFFSET_TREE_HGT   17
#define SPX_OFFSET_TREE_INDEX  18

/* API */
#define CRYPTO_SECRETKEYBYTES  SPX_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES  SPX_PK_BYTES
#define CRYPTO_BYTES           SPX_BYTES
#define CRYPTO_SEEDBYTES       (3 * SPX_N)
#define CRYPTO_ALGNAME         "SPHINCS+"

#endif