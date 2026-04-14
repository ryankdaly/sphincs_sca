#include <stdint.h>
#include <string.h>

#include "spx_address.h"
#include "spx_params.h"
#include "spx_thash.h"
#include "spx_utils.h"

void compute_root(unsigned char *root,
                  const unsigned char *leaf,
                  uint32_t leaf_idx,
                  uint32_t idx_offset,
                  const unsigned char *auth_path,
                  uint32_t tree_height,
                  const unsigned char *pub_seed,
                  uint32_t addr[8])
{
    unsigned char buffer[2 * SPX_N];
    unsigned char leafbuf[SPX_N];
    uint32_t i;

    if (leaf_idx & 1u) {
        memcpy(buffer, auth_path, SPX_N);
        memcpy(buffer + SPX_N, leaf, SPX_N);
    } else {
        memcpy(buffer, leaf, SPX_N);
        memcpy(buffer + SPX_N, auth_path, SPX_N);
    }
    auth_path += SPX_N;

    for (i = 0; i + 1 < tree_height; ++i) {
        leaf_idx >>= 1;
        idx_offset >>= 1;

        set_tree_height(addr, i + 1);
        set_tree_index(addr, leaf_idx + idx_offset);

        thash(leafbuf, buffer, 2, pub_seed, addr);
        if (leaf_idx & 1u) {
            memcpy(buffer, auth_path, SPX_N);
            memcpy(buffer + SPX_N, leafbuf, SPX_N);
        } else {
            memcpy(buffer, leafbuf, SPX_N);
            memcpy(buffer + SPX_N, auth_path, SPX_N);
        }
        auth_path += SPX_N;
    }

    leaf_idx >>= 1;
    idx_offset >>= 1;
    set_tree_height(addr, tree_height);
    set_tree_index(addr, leaf_idx + idx_offset);
    thash(root, buffer, 2, pub_seed, addr);
}

void treehash(unsigned char *root,
              unsigned char *auth_path,
              const unsigned char *sk_seed,
              const unsigned char *pub_seed,
              uint32_t leaf_idx,
              uint32_t idx_offset,
              uint32_t tree_height,
              spx_gen_leaf_fn gen_leaf,
              uint32_t tree_addr[8])
{
    unsigned char stack[(SPX_FORS_HEIGHT + 1) * SPX_N];
    unsigned char heights[SPX_FORS_HEIGHT + 1];
    unsigned char leaf[SPX_N];
    unsigned char node[SPX_N];
    uint32_t idx;
    uint32_t offset = 0;

    for (idx = 0; idx < (1u << tree_height); ++idx) {
        uint32_t node_height;
        uint32_t tree_idx;

        gen_leaf(leaf, sk_seed, pub_seed, idx + idx_offset, tree_addr);
        memcpy(stack + offset * SPX_N, leaf, SPX_N);
        heights[offset] = 0;
        ++offset;

        if ((leaf_idx ^ 1u) == idx) {
            memcpy(auth_path, stack + (offset - 1) * SPX_N, SPX_N);
        }

        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            node_height = heights[offset - 1];
            tree_idx = idx >> (node_height + 1);

            set_tree_height(tree_addr, node_height + 1);
            set_tree_index(tree_addr,
                           tree_idx + (idx_offset >> (node_height + 1)));

            thash(node, stack + (offset - 2) * SPX_N, 2, pub_seed, tree_addr);
            memcpy(stack + (offset - 2) * SPX_N, node, SPX_N);
            --offset;
            heights[offset - 1] = (unsigned char)(node_height + 1);

            if (((leaf_idx >> heights[offset - 1]) ^ 1u) == tree_idx) {
                memcpy(auth_path + heights[offset - 1] * SPX_N,
                       stack + (offset - 1) * SPX_N,
                       SPX_N);
            }
        }
    }

    memcpy(root, stack, SPX_N);
}
