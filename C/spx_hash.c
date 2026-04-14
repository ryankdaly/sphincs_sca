#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sha256_core.h"
#include "spx_bytes.h"
#include "spx_hash.h"
#include "spx_params.h"

void initialize_hash_function(const unsigned char *pub_seed,
                              const unsigned char *sk_seed)
{
    (void)sk_seed;
    seed_state(pub_seed);
}

void prf_addr(unsigned char *out,
              const unsigned char *key,
              const uint32_t addr[8])
{
    unsigned char buf[SPX_N + SPX_SHA256_ADDR_BYTES];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];

    memcpy(buf, key, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SHA256_ADDR_BYTES);
    sha256(outbuf, buf, sizeof(buf));
    memcpy(out, outbuf, SPX_N);
}

void gen_message_random(unsigned char *R,
                        const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m,
                        unsigned long long mlen)
{
    unsigned char buf[SPX_SHA256_BLOCK_BYTES + SPX_SHA256_OUTPUT_BYTES];
    uint8_t state[40];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    unsigned long long i;

    for (i = 0; i < SPX_N; ++i) {
        buf[i] = (unsigned char)(0x36u ^ sk_prf[i]);
    }
    memset(buf + SPX_N, 0x36, SPX_SHA256_BLOCK_BYTES - SPX_N);

    sha256_inc_init(state);
    sha256_inc_blocks(state, buf, 1);

    memcpy(buf, optrand, SPX_N);
    if ((unsigned long long)SPX_N + mlen < SPX_SHA256_BLOCK_BYTES) {
        memcpy(buf + SPX_N, m, (size_t)mlen);
        sha256_inc_finalize(outbuf, state, buf, (size_t)SPX_N + (size_t)mlen);
    } else {
        size_t offset = SPX_SHA256_BLOCK_BYTES - SPX_N;

        memcpy(buf + SPX_N, m, offset);
        sha256_inc_blocks(state, buf, 1);
        m += offset;
        mlen -= offset;
        sha256_inc_finalize(outbuf, state, m, (size_t)mlen);
    }

    memcpy(buf + SPX_SHA256_BLOCK_BYTES, outbuf, SPX_SHA256_OUTPUT_BYTES);
    for (i = 0; i < SPX_N; ++i) {
        buf[i] = (unsigned char)(0x5cu ^ sk_prf[i]);
    }
    memset(buf + SPX_N, 0x5c, SPX_SHA256_BLOCK_BYTES - SPX_N);

    sha256(buf, buf, sizeof(buf));
    memcpy(R, buf, SPX_N);
}

void hash_message(unsigned char *digest,
                  uint64_t *tree,
                  uint32_t *leaf_idx,
                  const unsigned char *R,
                  const unsigned char *pk,
                  const unsigned char *m,
                  unsigned long long mlen)
{
    enum {
        SPX_TREE_BITS = SPX_TREE_HEIGHT * (SPX_D - 1),
        SPX_TREE_BYTES = (SPX_TREE_BITS + 7) / 8,
        SPX_LEAF_BITS = SPX_TREE_HEIGHT,
        SPX_LEAF_BYTES = (SPX_LEAF_BITS + 7) / 8,
        SPX_DGST_BYTES = SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES,
        SPX_INBLOCKS =
            (((SPX_N + SPX_PK_BYTES + SPX_SHA256_BLOCK_BYTES - 1) &
              -SPX_SHA256_BLOCK_BYTES) /
             SPX_SHA256_BLOCK_BYTES)
    };

    unsigned char seed[SPX_SHA256_OUTPUT_BYTES];
    unsigned char inbuf[SPX_INBLOCKS * SPX_SHA256_BLOCK_BYTES];
    unsigned char buf[SPX_DGST_BYTES];
    uint8_t state[40];
    unsigned int bufp = 0;

    sha256_inc_init(state);

    memcpy(inbuf, R, SPX_N);
    memcpy(inbuf + SPX_N, pk, SPX_PK_BYTES);

    if ((unsigned long long)(SPX_N + SPX_PK_BYTES) + mlen <
        (unsigned long long)sizeof(inbuf)) {
        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m, (size_t)mlen);
        sha256_inc_finalize(seed,
                            state,
                            inbuf,
                            SPX_N + SPX_PK_BYTES + (size_t)mlen);
    } else {
        size_t inbuf_remaining = sizeof(inbuf) - SPX_N - SPX_PK_BYTES;

        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m, inbuf_remaining);
        sha256_inc_blocks(state, inbuf, SPX_INBLOCKS);
        m += inbuf_remaining;
        mlen -= inbuf_remaining;
        sha256_inc_finalize(seed, state, m, (size_t)mlen);
    }

    mgf1(buf, SPX_DGST_BYTES, seed, SPX_SHA256_OUTPUT_BYTES);

    memcpy(digest, buf, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

    *tree = bytes_to_ull(buf + bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(buf + bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
