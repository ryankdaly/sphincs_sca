/* spx_params.h
 *
 * Designed around the sha256 256 bit fast simple version of sphincs+
 */

#ifndef SPX_PARAMS_H
#define SPX_PARAMS_H

/* Core SPHINCS+ dimensions gathered from specification documentaion */
#define SPX_N              32
#define SPX_FULL_HEIGHT    68
#define SPX_D              17

/* FORS configuration */
#define SPX_FORS_HEIGHT     9
#define SPX_FORS_TREES     35

/* WOTS parameter */
#define SPX_WOTS_W         16

/* The address size in bytes */
#define SPX_ADDR_BYTES     32

/* ---- WOTS derived parameters ---- */

#if SPX_WOTS_W == 256
    #define SPX_WOTS_LOGW 8
#elif SPX_WOTS_W == 16
    #define SPX_WOTS_LOGW 4
#else
    #error "SPX_WOTS_W must be either 16 or 256"
#endif

#define SPX_WOTS_LEN1 (8 * SPX_N / SPX_WOTS_LOGW)

/*
 * Precomputed checksum lengths for WOTS
 * W = 16, N = 32, which gives us LEN2 = 3.
 */
#if SPX_WOTS_W == 256
    #if SPX_N <= 1
        #define SPX_WOTS_LEN2 1
    #elif SPX_N <= 256
        #define SPX_WOTS_LEN2 2
    #else
        #error "Unsupported SPX_N for SPX_WOTS_W = 256"
    #endif
#elif SPX_WOTS_W == 16
    #if SPX_N <= 8
        #define SPX_WOTS_LEN2 2
    #elif SPX_N <= 136
        #define SPX_WOTS_LEN2 3
    #elif SPX_N <= 256
        #define SPX_WOTS_LEN2 4
    #else
        #error "Unsupported SPX_N for SPX_WOTS_W = 16"
    #endif
#endif



#define SPX_WOTS_LEN      (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES    (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* Parameters  for the hypertrees */

#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

#if (SPX_TREE_HEIGHT * SPX_D) != SPX_FULL_HEIGHT
    #error "SPX_D must divide SPX_FULL_HEIGHT exactly"
#endif

/*  Parameters used for FORS  */

#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES     ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES  SPX_N

/* Specific defined sizes */

/* Signature = R || FORS_sig || D * (WOTS_sig || auth_path) */
#define SPX_BYTES \
    (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N)

#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

#define SPX_OPTRAND_BYTES 32

/* SHA-256-specific address field placement header */
#include "sha256_offsets.h"

#endif