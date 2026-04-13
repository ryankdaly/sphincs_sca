/*
 * merkle.c — SPHINCS+ Merkle tree (XMSS) and hypertree operations

 */

#include <string.h>
#include <stdint.h>
#include "merkle.h"
#include "params.h"
#include "wots.h"
#include "address.h"
#include "thash_sha256.h"
#include "utils.h"

/*
 * Compute a single leaf node of the Merkle tree.
 *
 * A leaf is the compressed WOTS+ public key: generate all SPX_WOTS_LEN
 * chain endpoints, then hash them together with thash.
 */
static void merkle_gen_leaf(uint8_t *leaf,
                            const uint8_t *sk_seed,
                            const uint8_t *pub_seed,
                            uint32_t leaf_idx,
                            uint8_t addr[32])
{
    uint8_t wots_pk[SPX_WOTS_BYTES];

    /* Set the keypair address to the leaf index */
    set_keypair_addr(addr, leaf_idx);

    /* Generate the full WOTS+ public key */
    wots_gen_pk(wots_pk, sk_seed, pub_seed, addr);

    /* Compress the WOTS+ pk into a single n-byte leaf value */
    thash(leaf, wots_pk, SPX_WOTS_LEN, pub_seed, addr);
}

/*
 * Build a full Merkle tree and extract the authentication path for a
 * given leaf index.
 *
 * Uses a simple bottom-up construction: compute all 2^h leaves, then
 * iteratively hash pairs to form parent nodes. This is NOT memory-
 * efficient (allocates the full tree) but is straightforward and correct.
 *
 * For SCA purposes this is fine — the interesting leakage is in the
 * WOTS+ chain computations inside merkle_gen_leaf, not in the tree
 * construction itself.
 */
void merkle_sign(uint8_t *sig,
                 uint8_t *auth,
                 uint8_t *root,
                 const uint8_t *msg,
                 const uint8_t *sk_seed,
                 const uint8_t *pub_seed,
                 uint32_t leaf_idx,
                 uint8_t addr[32])
{
    /*
     * Stack-based Treehash.
     *
     * We compute nodes left-to-right and use a stack to combine them.
     * This avoids storing the entire 2^h leaf array while still being
     * simple to follow.
     *
     * Stack entries: each is SPX_N bytes, with a height tag.
     */
    uint8_t stack[(SPX_TREE_HEIGHT + 1) * SPX_N];
    unsigned int heights[SPX_TREE_HEIGHT + 1];
    unsigned int stack_top = 0;

    uint8_t node[SPX_N];
    uint8_t wots_pk[SPX_WOTS_BYTES];
    uint32_t total_leaves = (1u << SPX_TREE_HEIGHT);
    uint32_t i;
    unsigned int h;
    uint8_t combined[2 * SPX_N];

    /* Sign the message with WOTS+ at the target leaf */
    set_keypair_addr(addr, leaf_idx);
    wots_sign(sig, msg, sk_seed, pub_seed, addr);

    /* Now build the tree and extract the auth path */
    for (i = 0; i < total_leaves; i++) {
        /* Compute leaf i */
        merkle_gen_leaf(node, sk_seed, pub_seed, i, addr);

        /* If this leaf is a sibling on the auth path, save it */
        /* (handled implicitly by the stack — see below) */

        /* Set tree height and index for internal node hashing */
        set_tree_height(addr, 0);
        set_tree_index(addr, i);

        /* Push this leaf onto the stack */
        memcpy(stack + stack_top * SPX_N, node, SPX_N);
        heights[stack_top] = 0;
        stack_top++;

        /*
         * While the top two stack entries are at the same height,
         * combine them into a parent node.
         */
        while (stack_top >= 2 &&
               heights[stack_top - 1] == heights[stack_top - 2]) {
            h = heights[stack_top - 1];

            /*
             * Check if either of the two nodes being combined is on
             * the authentication path for leaf_idx. The auth path
             * node at height h is the sibling of the node on the
             * path from leaf_idx to root.
             *
             * At height h, the node index of leaf_idx's ancestor is
             * (leaf_idx >> h). Its sibling is (leaf_idx >> h) ^ 1.
             * The left child in this pair has index:
             *   (i >> (h + 1)) << 1, right child is that + 1.
             * But with treehash, we know the pair being combined
             * covers a specific range. The left node's index at
             * height h is ((i >> h) - 1) and the right is (i >> h)?
             *
             * Simpler: at height h, leaf_idx's ancestor index is
             * (leaf_idx >> h). If this is even, the auth node is
             * the right sibling (index + 1); if odd, the left
             * sibling (index - 1). In treehash, when we combine
             * at height h, the right node was just pushed (stack_top-1)
             * and the left node is below it (stack_top-2).
             */
            uint32_t ancestor = leaf_idx >> h;

            if (h < SPX_TREE_HEIGHT) {
                if (ancestor % 2 == 0) {
                    /* auth[h] = right sibling = stack_top - 1 */
                    memcpy(auth + h * SPX_N,
                           stack + (stack_top - 1) * SPX_N, SPX_N);
                } else {
                    /* auth[h] = left sibling = stack_top - 2 */
                    memcpy(auth + h * SPX_N,
                           stack + (stack_top - 2) * SPX_N, SPX_N);
                }
            }

            /* Combine: parent = thash(left || right) */
            memcpy(combined,
                   stack + (stack_top - 2) * SPX_N, SPX_N);
            memcpy(combined + SPX_N,
                   stack + (stack_top - 1) * SPX_N, SPX_N);

            set_tree_height(addr, h + 1);
            /* Parent index at height h+1 */
            set_tree_index(addr, (i >> (h + 1)));

            thash(stack + (stack_top - 2) * SPX_N,
                  combined, 2, pub_seed, addr);

            heights[stack_top - 2] = h + 1;
            stack_top--;
        }
    }

    /* The stack should now contain exactly one node: the root */
    memcpy(root, stack, SPX_N);
}

/*
 * Generate only the root of a Merkle tree (no auth path needed).
 */
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

/*
 * Compute the Merkle root from a WOTS+ signature and authentication path.
 *
 * This is the verification counterpart to merkle_sign: given the WOTS+
 * signature, recover the WOTS+ public key, compress to a leaf, then
 * walk the auth path upward to reconstruct the root.
 */
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

    /* Recover the WOTS+ public key from the signature */
    set_keypair_addr(addr, leaf_idx);
    wots_pk_from_sig(wots_pk, sig, msg, pub_seed, addr);

    /* Compress to leaf */
    thash(leaf, wots_pk, SPX_WOTS_LEN, pub_seed, addr);

    memcpy(node, leaf, SPX_N);

    /* Walk up the tree using the authentication path */
    for (h = 0; h < SPX_TREE_HEIGHT; h++) {
        set_tree_height(addr, h + 1);
        set_tree_index(addr, leaf_idx >> (h + 1));

        /*
         * NOTE: non-constant-time branch on leaf_idx bit.
         * This is intentional — it leaks the path through the tree
         * via power analysis, which is relevant for SCA.
         */
        if ((leaf_idx >> h) & 1) {
            /* Current node is a right child */
            memcpy(combined, auth + h * SPX_N, SPX_N);
            memcpy(combined + SPX_N, node, SPX_N);
        } else {
            /* Current node is a left child */
            memcpy(combined, node, SPX_N);
            memcpy(combined + SPX_N, auth + h * SPX_N, SPX_N);
        }

        thash(node, combined, 2, pub_seed, addr);
    }

    memcpy(root, node, SPX_N);
}

/* ------------------------------------------------------------------ */
/* Hypertree: d layers of Merkle (XMSS) trees                         */
/* ------------------------------------------------------------------ */

/*
 * Sign a message using the full hypertree.
 *
 * The hypertree has SPX_D layers. The bottom layer (layer 0) signs the
 * actual message. Each subsequent layer signs the root of the layer below.
 */
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

    /* Layer 0: sign the input message */
    set_layer_addr(addr, 0);
    set_tree_addr(addr, tree_idx);

    merkle_sign(sig_ptr,                       /* WOTS+ sig */
                sig_ptr + SPX_WOTS_BYTES,      /* auth path */
                root,                          /* tree root */
                msg,
                sk_seed, pub_seed,
                leaf_idx, addr);

    sig_ptr += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

    /* Layers 1 .. d-1: each signs the root of the previous layer */
    for (layer = 1; layer < SPX_D; layer++) {
        /* The leaf index in this layer comes from tree_idx */
        leaf_idx = (uint32_t)(tree_idx & ((1u << SPX_TREE_HEIGHT) - 1));
        tree_idx >>= SPX_TREE_HEIGHT;

        set_layer_addr(addr, layer);
        set_tree_addr(addr, tree_idx);

        merkle_sign(sig_ptr,
                    sig_ptr + SPX_WOTS_BYTES,
                    root,
                    root,                       /* sign previous root */
                    sk_seed, pub_seed,
                    leaf_idx, addr);

        sig_ptr += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;
    }
}

/*
 * Verify a hypertree signature.
 *
 * Walks up through all d layers, recomputing each Merkle root from
 * the WOTS+ signature and authentication path. Returns 0 if the
 * final root matches pub_root.
 */
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
                        sig_ptr,                      /* WOTS+ sig */
                        sig_ptr + SPX_WOTS_BYTES,     /* auth path */
                        msg,
                        leaf_idx,
                        pub_seed, addr);

    sig_ptr += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

    /* Layers 1 .. d-1 */
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

    /* Compare computed root against the public root */
    /*
     * NOTE: non-constant-time comparison. Leaks match/mismatch
     * position, but this is verification — not security-critical
     * for our attack scenario.
     */
    return memcmp(root, pub_root, SPX_N);
}