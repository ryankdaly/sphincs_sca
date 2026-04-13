// thash_sha256.c
#include <string.h>
#include "thash_sha256.h"
#include "params.h"
#include "sha256.h"


void thash(uint8_t *out, const uint8_t *in, unsigned int inblocks,
           const uint8_t *pub_seed, const uint8_t *addr)
{
    uint8_t buf[SPX_SHA256_ADDR_BYTES + inblocks * SPX_N]; /* VLA */
    uint8_t outbuf[SPX_SHA256_OUTPUT_BYTES];
    uint8_t sha2_state[40];
    uint8_t block[SPX_SHA256_BLOCK_BYTES];

    memcpy(block, pub_seed, SPX_N);
    memset(block + SPX_N, 0, SPX_SHA256_BLOCK_BYTES - SPX_N);

    sha256_inc_init(sha2_state);
    sha256_inc_blocks(sha2_state, block, 1);

    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * SPX_N);

    sha256_inc_finalize(outbuf, sha2_state, buf,
                        SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);
    memcpy(out, outbuf, SPX_N);
}