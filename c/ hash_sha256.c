// hash_sha256.c
#include <string.h>
#include "hash_sha256.h"
#include "params.h"
#include "utils.h"
#include "sha256.h"

#define SPX_TREE_BITS  (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS   SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

/* Round up (SPX_N + SPX_PK_BYTES) to next multiple of SPX_SHA256_BLOCK_BYTES */
#define SPX_INBLOCKS (((SPX_N + SPX_PK_BYTES + SPX_SHA256_BLOCK_BYTES - 1) \
                       & ~(SPX_SHA256_BLOCK_BYTES - 1)) / SPX_SHA256_BLOCK_BYTES)

void initialize_hash_function(const uint8_t *pub_seed,
                              const uint8_t *sk_seed)
{
    seed_state(pub_seed);
    (void)sk_seed;
}

void prf_addr(uint8_t *out, const uint8_t *key, const uint8_t *addr)
{
    uint8_t buf[SPX_N + SPX_SHA256_ADDR_BYTES];
    uint8_t outbuf[SPX_SHA256_OUTPUT_BYTES];

    memcpy(buf, key, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SHA256_ADDR_BYTES);

    sha256(outbuf, buf, SPX_N + SPX_SHA256_ADDR_BYTES);
    memcpy(out, outbuf, SPX_N);
}

void gen_message_random(uint8_t *R, const uint8_t *sk_prf,
                        const uint8_t *optrand,
                        const uint8_t *m, size_t mlen)
{
    uint8_t buf[SPX_SHA256_BLOCK_BYTES + SPX_SHA256_OUTPUT_BYTES];
    uint8_t state[40];
    unsigned int i;

#if SPX_N > SPX_SHA256_BLOCK_BYTES
#error "Currently only supports SPX_N of at most SPX_SHA256_BLOCK_BYTES"
#endif

    for (i = 0; i < SPX_N; i++) {
        buf[i] = 0x36 ^ sk_prf[i];
    }
    memset(buf + SPX_N, 0x36, SPX_SHA256_BLOCK_BYTES - SPX_N);

    sha256_inc_init(state);
    sha256_inc_blocks(state, buf, 1);

    memcpy(buf, optrand, SPX_N);

    if (SPX_N + mlen < SPX_SHA256_BLOCK_BYTES) {
        memcpy(buf + SPX_N, m, mlen);
        sha256_inc_finalize(buf + SPX_SHA256_BLOCK_BYTES, state,
                            buf, mlen + SPX_N);
    } else {
        size_t offset = SPX_SHA256_BLOCK_BYTES - SPX_N;
        memcpy(buf + SPX_N, m, offset);
        sha256_inc_blocks(state, buf, 1);

        m += offset;
        mlen -= offset;
        sha256_inc_finalize(buf + SPX_SHA256_BLOCK_BYTES, state, m, mlen);
    }

    for (i = 0; i < SPX_N; i++) {
        buf[i] = 0x5c ^ sk_prf[i];
    }
    memset(buf + SPX_N, 0x5c, SPX_SHA256_BLOCK_BYTES - SPX_N);

    sha256(buf, buf, SPX_SHA256_BLOCK_BYTES + SPX_SHA256_OUTPUT_BYTES);
    memcpy(R, buf, SPX_N);
}

void hash_message(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const uint8_t *R, const uint8_t *pk,
                  const uint8_t *m, size_t mlen)
{
    uint8_t seed[SPX_SHA256_OUTPUT_BYTES];
    uint8_t inbuf[SPX_INBLOCKS * SPX_SHA256_BLOCK_BYTES];
    uint8_t buf[SPX_DGST_BYTES];
    unsigned int bufp = 0;
    uint8_t state[40];

#if (SPX_SHA256_BLOCK_BYTES & (SPX_SHA256_BLOCK_BYTES - 1)) != 0
#error "Assumes that SPX_SHA256_BLOCK_BYTES is a power of 2"
#endif

#if SPX_TREE_BITS > 64
#error "For given height and depth, 64 bits cannot represent all subtrees"
#endif

    sha256_inc_init(state);

    memcpy(inbuf, R, SPX_N);
    memcpy(inbuf + SPX_N, pk, SPX_PK_BYTES);

    if (SPX_N + SPX_PK_BYTES + mlen < SPX_INBLOCKS * SPX_SHA256_BLOCK_BYTES) {
        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m, mlen);
        sha256_inc_finalize(seed, state, inbuf,
                            SPX_N + SPX_PK_BYTES + mlen);
    } else {
        size_t val = SPX_INBLOCKS * SPX_SHA256_BLOCK_BYTES
                     - SPX_N - SPX_PK_BYTES;
        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m, val);
        sha256_inc_blocks(state, inbuf, SPX_INBLOCKS);

        m += val;
        mlen -= val;
        sha256_inc_finalize(seed, state, m, mlen);
    }

    mgf1(buf, SPX_DGST_BYTES, seed, SPX_SHA256_OUTPUT_BYTES);

    memcpy(digest, buf + bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

    *tree = bytes_to_ull(buf + bufp, SPX_TREE_BYTES);
    *tree &= ((uint64_t)1 << SPX_TREE_BITS) - 1;
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(buf + bufp, SPX_LEAF_BYTES);
    *leaf_idx &= ((uint32_t)1 << SPX_LEAF_BITS) - 1;
}