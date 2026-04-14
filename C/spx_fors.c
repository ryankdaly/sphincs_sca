#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "spx_params.h"
#include "spx_address.h"
#include "spx_hash.h"
#include "spx_utils.h"
#include "spx_thash.h"
#include "spx_fors.h"

static void fors_secret(unsigned char *out, const unsigned char *sk_seed, uint32_t leaf_addr[8])
{
    prf_addr(out, sk_seed, leaf_addr);
}








static void fors_leaf_from_secret(unsigned char *leaf, const unsigned char *sk, const unsigned char *pub_seed, uint32_t leaf_addr[8])
{
    thash(leaf, sk, 1, pub_seed, leaf_addr);
}






static void fors_gen_leaf(unsigned char *leaf, const unsigned char *sk_seed, const unsigned char *pub_seed, uint32_t addr_idx, const uint32_t tree_addr[8])
{
    uint32_t leaf_addr[8] = {0};

    copy_keypair_addr(leaf_addr, tree_addr);
    set_type(leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    set_tree_index(leaf_addr, addr_idx);

    fors_secret(leaf, sk_seed, leaf_addr);
    fors_leaf_from_secret(leaf, leaf, pub_seed, leaf_addr);
}








static void message_to_indices(uint32_t *indices, const unsigned char *m)
{
    unsigned int i, j;
    unsigned int bit = 0;


    for (i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;



        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= ((m[bit >> 3] >> (bit & 7)) & 1) << j;
            bit++;
        }
        
    }
}











void fors_sign(unsigned char *sig, unsigned char *pk, const unsigned char *m, const unsigned char *sk_seed, const unsigned char *pub_seed, const uint32_t fors_addr[8])
{
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    uint32_t tree_addr[8] = {0};
    uint32_t pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(tree_addr, fors_addr);
    copy_keypair_addr(pk_addr, fors_addr);


    set_type(tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);




    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);


        set_tree_height(tree_addr, 0);
        set_tree_index(tree_addr, indices[i] + idx_offset);

        fors_secret(sig, sk_seed, tree_addr);
        sig += SPX_N;



        treehash(roots + i * SPX_N,
                 sig,
                 sk_seed,
                 pub_seed,
                 indices[i],
                 idx_offset,
                 SPX_FORS_HEIGHT,
                 fors_gen_leaf,
                 tree_addr);
        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    thash(pk, roots, SPX_FORS_TREES, pub_seed, pk_addr);
}













void fors_pk_from_sig(unsigned char *pk, const unsigned char *sig, const unsigned char *m, const unsigned char *pub_seed, const uint32_t fors_addr[8])
{
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    unsigned char leaf[SPX_N];

    uint32_t tree_addr[8] = {0};
    uint32_t pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(tree_addr, fors_addr);
    copy_keypair_addr(pk_addr, fors_addr);


    set_type(tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);



    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(tree_addr, 0);
        set_tree_index(tree_addr, indices[i] + idx_offset);

        fors_leaf_from_secret(leaf, sig, pub_seed, tree_addr);
        sig += SPX_N;



        compute_root(roots + i * SPX_N,
                     leaf,
                     indices[i],
                     idx_offset,
                     sig,
                     SPX_FORS_HEIGHT,
                     pub_seed,
                     tree_addr);
        sig += SPX_N * SPX_FORS_HEIGHT;



    }



    thash(pk, roots, SPX_FORS_TREES, pub_seed, pk_addr);
}