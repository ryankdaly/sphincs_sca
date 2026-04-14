#ifndef SPX_UTILS_H
#define SPX_UTILS_H

#include <stdint.h>

typedef void (*spx_gen_leaf_fn)(
    unsigned char *leaf,
    const unsigned char *sk_seed,
    const unsigned char *pub_seed,
    uint32_t addr_idx,
    const uint32_t tree_addr[8]);

void compute_root(unsigned char *root,
                  const unsigned char *leaf,
                  uint32_t leaf_idx,
                  uint32_t idx_offset,
                  const unsigned char *auth_path,
                  uint32_t tree_height,
                  const unsigned char *pub_seed,
                  uint32_t addr[8]);

void treehash(unsigned char *root,
              unsigned char *auth_path,
              const unsigned char *sk_seed,
              const unsigned char *pub_seed,
              uint32_t leaf_idx,
              uint32_t idx_offset,
              uint32_t tree_height,
              spx_gen_leaf_fn gen_leaf,
              uint32_t tree_addr[8]);

#endif
