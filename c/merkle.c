

#include <string.h>
#include <stdint.h>
#include "merkle.h"
#include "params.h"
#include "wots.h"
#include "address.h"
#include "thash_sha256.h"
#include "utils.h"


static void merkle_gen_leaf(uint8_t *leaf,
                            const uint8_t *sk_seed,
                            const uint8_t *pub_seed,
                            uint32_t leaf_idx,
                            uint8_t addr[32])
{
    uint8_t wots_pk[SPX_WOTS_BYTES];

    set_keypair_addr(addr, leaf_idx);

    wots_gen_pk(wots_pk, sk_seed, pub_seed, addr);

    thash(leaf, wots_pk, SPX_WOTS_LEN, pub_seed, addr);
}


void merkle_sign(uint8_t *sig,
                 uint8_t *auth,
                 uint8_t *root,
                 const uint8_t *msg,
                 const uint8_t *sk_seed,
                 const uint8_t *pub_seed,
                 uint32_t leaf_idx,
                 uint8_t addr[32])
{

    uint8_t stack[(SPX_TREE_HEIGHT + 1) * SPX_N];
    unsigned int heights[SPX_TREE_HEIGHT + 1];
    unsigned int stack_top = 0;

    uint8_t node[SPX_N];
    uint8_t wots_pk[SPX_WOTS_BYTES];
    uint32_t total_leaves = (1u << SPX_TREE_HEIGHT);
    uint32_t i;
    unsigned int h;
    uint8_t combined[2 * SPX_N];

    set_keypair_addr(addr, leaf_idx);
    wots_sign(sig, msg, sk_seed, pub_seed, addr);

    for (i = 0; i < total_leaves; i++) {
        merkle_gen_leaf(node, sk_seed, pub_seed, i, addr);

        set_tree_height(addr, 0);
        set_tree_index(addr, i);

        memcpy(stack + stack_top * SPX_N, node, SPX_N);
        heights[stack_top] = 0;
        stack_top++;


        while (stack_top >= 2 &&
               heights[stack_top - 1] == heights[stack_top - 2]) {
            h = heights[stack_top - 1];

            uint32_t ancestor = leaf_idx >> h;

            if (h < SPX_TREE_HEIGHT) {
                if (ancestor % 2 == 0) {
                    memcpy(auth + h * SPX_N,
                           stack + (stack_top - 1) * SPX_N, SPX_N);
                } else {
                    memcpy(auth + h * SPX_N,
                           stack + (stack_top - 2) * SPX_N, SPX_N);
                }
            }

            memcpy(combined,
                   stack + (stack_top - 2) * SPX_N, SPX_N);
            memcpy(combined + SPX_N,
                   stack + (stack_top - 1) * SPX_N, SPX_N);

            set_tree_height(addr, h + 1);
            set_tree_index(addr, (i >> (h + 1)));

            thash(stack + (stack_top - 2) * SPX_N,
                  combined, 2, pub_seed, addr);

            heights[stack_top - 2] = h + 1;
            stack_top--;
        }
    }

    memcpy(root, stack, SPX_N);
}


void merkle_gen_root(uint8_t *root,
                     const uint8_t *sk_seed,
                     const uint8_t *pub_seed,
                     uint8_t addr[32])
{
    uint8_t stack[(SPX_TREE_HEIGHT + 1) * SPX_N];
    unsigned int heights[SPX_TREE_HEIGHT + 1];
    unsigned int stack_top = 0;

    uint8_t node[SPX_N];
    uint8_t combined[2 * SPX_N];
    uint32_t total_leaves = (1u << SPX_TREE_HEIGHT);
    uint32_t i;
    unsigned int h;

    for (i = 0; i < total_leaves; i++) {
        merkle_gen_leaf(node, sk_seed, pub_seed, i, addr);

        set_tree_height(addr, 0);
        set_tree_index(addr, i);

        memcpy(stack + stack_top * SPX_N, node, SPX_N);
        heights[stack_top] = 0;
        stack_top++;

        while (stack_top >= 2 &&
               heights[stack_top - 1] == heights[stack_top - 2]) {
            h = heights[stack_top - 1];

            memcpy(combined,
                   stack + (stack_top - 2) * SPX_N, SPX_N);
            memcpy(combined + SPX_N,
                   stack + (stack_top - 1) * SPX_N, SPX_N);

            set_tree_height(addr, h + 1);
            set_tree_index(addr, (i >> (h + 1)));

            thash(stack + (stack_top - 2) * SPX_N,
                  combined, 2, pub_seed, addr);

            heights[stack_top - 2] = h + 1;
            stack_top--;
        }
    }

    memcpy(root, stack, SPX_N);
}


void merkle_compute_root(uint8_t *root,
                         const uint8_t *sig,
                         const uint8_t *auth,
                         const uint8_t *msg,
                         uint32_t leaf_idx,
                         const uint8_t *pub_seed,
                         uint8_t addr[32])
{
    uint8_t wots_pk[SPX_WOTS_BYTES];
    uint8_t leaf[SPX_N];
    uint8_t node[SPX_N];
    uint8_t combined[2 * SPX_N];
    unsigned int h;

    set_keypair_addr(addr, leaf_idx);
    wots_pk_from_sig(wots_pk, sig, msg, pub_seed, addr);

    thash(leaf, wots_pk, SPX_WOTS_LEN, pub_seed, addr);

    memcpy(node, leaf, SPX_N);

    for (h = 0; h < SPX_TREE_HEIGHT; h++) {
        set_tree_height(addr, h + 1);
        set_tree_index(addr, leaf_idx >> (h + 1));


        if ((leaf_idx >> h) & 1) {
            memcpy(combined, auth + h * SPX_N, SPX_N);
            memcpy(combined + SPX_N, node, SPX_N);
        } else {
            memcpy(combined, node, SPX_N);
            memcpy(combined + SPX_N, auth + h * SPX_N, SPX_N);
        }

        thash(node, combined, 2, pub_seed, addr);
    }

    memcpy(root, node, SPX_N);
}


void ht_sign(uint8_t *sig_ht,
             const uint8_t *msg,
             const uint8_t *sk_seed,
             const uint8_t *pub_seed,
             uint64_t tree_idx,
             uint32_t leaf_idx)
{
    uint8_t root[SPX_N];
    uint8_t addr[32];
    unsigned int layer;
    uint8_t *sig_ptr = sig_ht;

    memset(addr, 0, 32);

    set_layer_addr(addr, 0);
    set_tree_addr(addr, tree_idx);

    merkle_sign(sig_ptr,
                sig_ptr + SPX_WOTS_BYTES,
                root,
                msg,
                sk_seed, pub_seed,
                leaf_idx, addr);

    sig_ptr += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

    for (layer = 1; layer < SPX_D; layer++) {
        leaf_idx = (uint32_t)(tree_idx & ((1u << SPX_TREE_HEIGHT) - 1));
        tree_idx >>= SPX_TREE_HEIGHT;

        set_layer_addr(addr, layer);
        set_tree_addr(addr, tree_idx);

        merkle_sign(sig_ptr,
                    sig_ptr + SPX_WOTS_BYTES,
                    root,
                    root,
                    sk_seed, pub_seed,
                    leaf_idx, addr);

        sig_ptr += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;
    }
}


int ht_verify(const uint8_t *sig_ht,
              const uint8_t *msg,
              const uint8_t *pub_seed,
              const uint8_t *pub_root,
              uint64_t tree_idx,
              uint32_t leaf_idx)
{
    uint8_t root[SPX_N];
    uint8_t addr[32];
    unsigned int layer;
    const uint8_t *sig_ptr = sig_ht;

    memset(addr, 0, 32);

    /* Layer 0 */
    set_layer_addr(addr, 0);
    set_tree_addr(addr, tree_idx);

    merkle_compute_root(root,
                        sig_ptr,
                        sig_ptr + SPX_WOTS_BYTES,
                        msg,
                        leaf_idx,
                        pub_seed, addr);

    sig_ptr += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

    for (layer = 1; layer < SPX_D; layer++) {
        leaf_idx = (uint32_t)(tree_idx & ((1u << SPX_TREE_HEIGHT) - 1));
        tree_idx >>= SPX_TREE_HEIGHT;

        set_layer_addr(addr, layer);
        set_tree_addr(addr, tree_idx);

        merkle_compute_root(root,
                            sig_ptr,
                            sig_ptr + SPX_WOTS_BYTES,
                            root,
                            leaf_idx,
                            pub_seed, addr);

        sig_ptr += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;
    }


    return memcmp(root, pub_root, SPX_N);
}