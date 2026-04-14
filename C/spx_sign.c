#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "spx_address.h"
#include "spx_fors.h"
#include "spx_hash.h"
#include "spx_params.h"
#include "spx_rng.h"
#include "spx_sign.h"
#include "spx_thash.h"
#include "spx_utils.h"
#include "spx_wots.h"

static void wots_gen_leaf(unsigned char *leaf,
                          const unsigned char *sk_seed,
                          const unsigned char *pub_seed,
                          uint32_t addr_idx,
                          const uint32_t tree_addr[8])
{
    unsigned char pk[SPX_WOTS_BYTES];
    uint32_t wots_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    copy_subtree_addr(wots_addr, tree_addr);
    set_keypair_addr(wots_addr, addr_idx);
    wots_gen_pk(pk, sk_seed, pub_seed, wots_addr);

    copy_keypair_addr(wots_pk_addr, wots_addr);
    thash(leaf, pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);
}

static int invalid_message_input(const unsigned char *m, size_t mlen)
{
    return m == NULL && mlen != 0;
}

size_t crypto_sign_secretkeybytes(void)
{
    return CRYPTO_SECRETKEYBYTES;
}

size_t crypto_sign_publickeybytes(void)
{
    return CRYPTO_PUBLICKEYBYTES;
}

size_t crypto_sign_bytes(void)
{
    return CRYPTO_BYTES;
}

size_t crypto_sign_seedbytes(void)
{
    return CRYPTO_SEEDBYTES;
}

int crypto_sign_seed_keypair(unsigned char *pk,
                             unsigned char *sk,
                             const unsigned char *seed)
{
    unsigned char auth_path[SPX_TREE_HEIGHT * SPX_N];
    uint32_t top_tree_addr[8] = {0};

    if (pk == NULL || sk == NULL || seed == NULL) {
        return SPX_ERR_NULL_PTR;
    }

    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_type(top_tree_addr, SPX_ADDR_TYPE_HASHTREE);

    memcpy(sk, seed, CRYPTO_SEEDBYTES);
    memcpy(pk, sk + 2 * SPX_N, SPX_N);

    initialize_hash_function(pk, sk);
    treehash(sk + 3 * SPX_N,
             auth_path,
             sk,
             pk,
             0,
             0,
             SPX_TREE_HEIGHT,
             wots_gen_leaf,
             top_tree_addr);
    memcpy(pk + SPX_N, sk + 3 * SPX_N, SPX_N);
    return SPX_SUCCESS;
}

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    unsigned char seed[CRYPTO_SEEDBYTES];

    if (pk == NULL || sk == NULL) {
        return SPX_ERR_NULL_PTR;
    }
    if (randombytes(seed, sizeof(seed)) != 0) {
        return SPX_ERR_RANDOMBYTES;
    }
    return crypto_sign_seed_keypair(pk, sk, seed);
}

int crypto_sign_signature(unsigned char *sig,
                          size_t *siglen,
                          const unsigned char *m,
                          size_t mlen,
                          const unsigned char *sk)
{
    const unsigned char *sk_seed;
    const unsigned char *sk_prf;
    const unsigned char *pk;
    const unsigned char *pub_seed;
    unsigned char optrand[SPX_N];
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char root[SPX_N];
    uint64_t tree = 0;
    uint32_t idx_leaf = 0;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    unsigned int i;
    unsigned char *sigp;

    if (sig == NULL || siglen == NULL || sk == NULL) {
        return SPX_ERR_NULL_PTR;
    }
    if (invalid_message_input(m, mlen)) {
        return SPX_ERR_NULL_PTR;
    }

    sk_seed = sk;
    sk_prf = sk + SPX_N;
    pk = sk + 2 * SPX_N;
    pub_seed = pk;
    sigp = sig;

    initialize_hash_function(pub_seed, sk_seed);
    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    if (randombytes(optrand, sizeof(optrand)) != 0) {
        return SPX_ERR_RANDOMBYTES;
    }

    gen_message_random(sigp, sk_prf, optrand, m, mlen);
    hash_message(mhash, &tree, &idx_leaf, sigp, pk, m, mlen);
    sigp += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_sign(sigp, root, mhash, sk_seed, pub_seed, wots_addr);
    sigp += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; ++i) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        wots_sign(sigp, root, sk_seed, pub_seed, wots_addr);
        sigp += SPX_WOTS_BYTES;

        treehash(root,
                 sigp,
                 sk_seed,
                 pub_seed,
                 idx_leaf,
                 0,
                 SPX_TREE_HEIGHT,
                 wots_gen_leaf,
                 tree_addr);
        sigp += SPX_TREE_HEIGHT * SPX_N;

        idx_leaf = (uint32_t)(tree & ((1u << SPX_TREE_HEIGHT) - 1u));
        tree >>= SPX_TREE_HEIGHT;
    }

    *siglen = SPX_BYTES;
    return SPX_SUCCESS;
}

int crypto_sign_verify(const unsigned char *sig,
                       size_t siglen,
                       const unsigned char *m,
                       size_t mlen,
                       const unsigned char *pk)
{
    const unsigned char *pub_seed;
    const unsigned char *pub_root;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    uint64_t tree = 0;
    uint32_t idx_leaf = 0;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};
    unsigned int i;
    const unsigned char *sigp;

    if (sig == NULL || pk == NULL) {
        return SPX_ERR_NULL_PTR;
    }
    if (invalid_message_input(m, mlen)) {
        return SPX_ERR_NULL_PTR;
    }
    if (siglen != SPX_BYTES) {
        return SPX_ERR_INVALID_LEN;
    }

    pub_seed = pk;
    pub_root = pk + SPX_N;
    sigp = sig;

    initialize_hash_function(pub_seed, NULL);
    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    hash_message(mhash, &tree, &idx_leaf, sigp, pk, m, mlen);
    sigp += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig(root, sigp, mhash, pub_seed, wots_addr);
    sigp += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; ++i) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);
        copy_keypair_addr(wots_pk_addr, wots_addr);

        wots_pk_from_sig(wots_pk, sigp, root, pub_seed, wots_addr);
        sigp += SPX_WOTS_BYTES;

        thash(leaf, wots_pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);
        compute_root(root,
                     leaf,
                     idx_leaf,
                     0,
                     sigp,
                     SPX_TREE_HEIGHT,
                     pub_seed,
                     tree_addr);
        sigp += SPX_TREE_HEIGHT * SPX_N;

        idx_leaf = (uint32_t)(tree & ((1u << SPX_TREE_HEIGHT) - 1u));
        tree >>= SPX_TREE_HEIGHT;
    }

    return memcmp(root, pub_root, SPX_N) == 0 ? SPX_SUCCESS : SPX_ERR_VERIFY;
}

int crypto_sign(unsigned char *sm,
                size_t *smlen,
                const unsigned char *m,
                size_t mlen,
                const unsigned char *sk)
{
    size_t siglen;
    int ret;

    if (sm == NULL || smlen == NULL || sk == NULL) {
        return SPX_ERR_NULL_PTR;
    }
    if (invalid_message_input(m, mlen)) {
        return SPX_ERR_NULL_PTR;
    }

    ret = crypto_sign_signature(sm, &siglen, m, mlen, sk);

    if (ret != SPX_SUCCESS) {
        return ret;
    }
    if (mlen > 0) {
        memmove(sm + SPX_BYTES, m, mlen);
    }
    *smlen = siglen + mlen;
    return SPX_SUCCESS;
}

int crypto_sign_open(unsigned char *m,
                     size_t *mlen,
                     const unsigned char *sm,
                     size_t smlen,
                     const unsigned char *pk)
{
    if (mlen == NULL) {
        return SPX_ERR_NULL_PTR;
    }
    *mlen = 0;
    if (m == NULL || sm == NULL || pk == NULL) {
        return SPX_ERR_NULL_PTR;
    }
    if (smlen < SPX_BYTES) {
        return SPX_ERR_INVALID_LEN;
    }

    *mlen = smlen - SPX_BYTES;
    if (crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, *mlen, pk) !=
        SPX_SUCCESS) {
        if (*mlen > 0) {
            memset(m, 0, *mlen);
        }
        *mlen = 0;
        return SPX_ERR_VERIFY;
    }

    if (*mlen > 0) {
        memmove(m, sm + SPX_BYTES, *mlen);
    }
    return SPX_SUCCESS;
}
