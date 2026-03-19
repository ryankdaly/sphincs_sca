from params import (
    SPX_WOTS_BYTES,
    CRYPTO_SECRETKEYBYTES,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_BYTES,
    CRYPTO_SEEDBYTES,
    SPX_TREE_HEIGHT,
    SPX_N,
    SPX_D,
    SPX_FORS_MSG_BYTES,
    SPX_BYTES,
    SPX_FORS_BYTES,
    SPX_WOTS_LEN,
)
from address import (
    set_type,
    SPX_ADDR_TYPE_WOTS,
    SPX_ADDR_TYPE_WOTSPK,
    copy_subtree_addr,
    set_keypair_addr,
    copy_keypair_addr,
    SPX_ADDR_TYPE_HASHTREE,
    set_layer_addr,
    set_tree_addr,
)
from utils import treehash, compute_root
from hash_sha256 import initialize_hash_function, gen_message_random, hash_message
from fors import fors_sign, fors_pk_from_sig
from thash_sha256_simple import thash
from wots import wots_gen_pk, wots_sign, wots_pk_from_sig
from rng import randombytes

def wots_gen_leaf(leaf: bytearray,
                  sk_seed: bytes | bytearray,
                  pub_seed: bytes | bytearray,
                  addr_idx: int,
                  tree_addr: bytes | bytearray)->None:
    pk = bytearray(SPX_WOTS_BYTES)
    wots_addr = bytearray(32)
    wots_pk_addr = bytearray(32)

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS)
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK)

    copy_subtree_addr(wots_addr, tree_addr)
    set_keypair_addr(wots_addr, addr_idx)
    wots_gen_pk(pk, sk_seed, pub_seed, wots_addr)

    copy_keypair_addr(wots_pk_addr, wots_addr)
    thash(leaf, pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr)

def crypto_sign_secretkeybytes()-> int:
    return CRYPTO_SECRETKEYBYTES

def crypto_sign_publickeybytes()-> int:
    return CRYPTO_PUBLICKEYBYTES

def crypto_sign_bytes()-> int:
    return CRYPTO_BYTES

def crypto_sign_seedbytes()-> int:
    return CRYPTO_SEEDBYTES

def crypto_sign_seed_keypair(pk: bytearray, sk: bytearray, seed: bytes | bytearray)->int:
    auth_path = bytearray(SPX_TREE_HEIGHT * SPX_N)
    top_tree_addr = bytearray(32)

    set_layer_addr(top_tree_addr, SPX_D - 1)
    set_type(top_tree_addr, SPX_ADDR_TYPE_HASHTREE)

    sk[0:CRYPTO_SEEDBYTES] = seed[0:CRYPTO_SEEDBYTES]

    pk[0:SPX_N] = sk[2*SPX_N:3*SPX_N]

    initialize_hash_function(pk[0:SPX_N], sk[0:SPX_N])
    buffer = bytearray(SPX_N)
    treehash(buffer,
             auth_path, 
             sk[0:SPX_N], 
             pk[0:SPX_N], 
             0, 
             0, 
             SPX_TREE_HEIGHT,
             wots_gen_leaf, 
             top_tree_addr)
    sk[3*SPX_N:4*SPX_N] = buffer

    pk[SPX_N: 2*SPX_N] = sk[3*SPX_N:4*SPX_N]

    return 0

def crypto_sign_keypair(pk: bytearray, sk: bytearray)->int:
    seed = bytearray(CRYPTO_SEEDBYTES)
    randombytes(seed, CRYPTO_SEEDBYTES)
    crypto_sign_seed_keypair(pk, sk, seed)
    return 0

def crypto_sign_signature(sig: bytearray, 
                          siglen: list[int], 
                          m: bytes|bytearray, 
                          mlen:int, 
                          sk: bytes|bytearray)->int:
    sk_seed = sk[0:SPX_N]
    sk_prf = sk[SPX_N:2*SPX_N]
    pk = sk[2*SPX_N:4*SPX_N]
    pub_seed = pk[0:SPX_N]

    optrand = bytearray(SPX_N)
    mhash = bytearray(SPX_FORS_MSG_BYTES)
    root = bytearray(SPX_N)
    tree = [0]
    idx_leaf = [0]
    wots_addr = bytearray(32)
    tree_addr = bytearray(32)
    sig_offset = 0

    initialize_hash_function(pub_seed, sk_seed)

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS)
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE)

    randombytes(optrand, SPX_N)

    r = bytearray(SPX_N)
    gen_message_random(r, sk_prf, optrand, m, mlen)
    sig[sig_offset:sig_offset+SPX_N] = r

    hash_message(mhash, tree, idx_leaf, sig[sig_offset:sig_offset+SPX_N], pk, m, mlen)
    sig_offset += SPX_N

    set_tree_addr(wots_addr, tree[0])
    set_keypair_addr(wots_addr, idx_leaf[0])

    fors_sig = bytearray(SPX_FORS_BYTES)
    fors_sign(fors_sig, root, mhash, sk_seed, pub_seed, wots_addr)
    sig[sig_offset:sig_offset + SPX_FORS_BYTES] = fors_sig
    sig_offset += SPX_FORS_BYTES

    for i in range(SPX_D):
        set_layer_addr(tree_addr, i)
        set_tree_addr(tree_addr, tree[0])

        copy_subtree_addr(wots_addr, tree_addr)
        set_keypair_addr(wots_addr, idx_leaf[0])

        wots_sig = bytearray(SPX_WOTS_BYTES)
        wots_sign(wots_sig, root, sk_seed, pub_seed, wots_addr)
        sig[sig_offset:sig_offset+SPX_WOTS_BYTES] = wots_sig
        sig_offset += SPX_WOTS_BYTES

        auth_path_i = bytearray(SPX_TREE_HEIGHT * SPX_N)
        treehash(root, 
                 auth_path_i, 
                 sk_seed, 
                 pub_seed, 
                 idx_leaf[0], 
                 0,
                 SPX_TREE_HEIGHT, 
                 wots_gen_leaf, 
                 tree_addr)
        sig[sig_offset:sig_offset+SPX_TREE_HEIGHT * SPX_N] = auth_path_i
        sig_offset += SPX_TREE_HEIGHT * SPX_N

        idx_leaf[0] = tree[0] & ((1 << SPX_TREE_HEIGHT)-1)
        tree[0] >>= SPX_TREE_HEIGHT

    siglen[0] = SPX_BYTES

    return 0


def crypto_sign_verify( sig: bytes|bytearray, 
                        siglen: int, 
                        m: bytes|bytearray, 
                        mlen:int, 
                        pk: bytes|bytearray)->int:
    pub_seed = pk[0:SPX_N]
    pub_root = pk[SPX_N:2*SPX_N]
    mhash = bytearray(SPX_FORS_MSG_BYTES)
    wots_pk = bytearray(SPX_WOTS_BYTES)
    root = bytearray(SPX_N)
    leaf = bytearray(SPX_N)
    tree = [0]
    idx_leaf = [0]
    wots_addr = bytearray(32)
    tree_addr = bytearray(32)
    wots_pk_addr = bytearray(32)
    sig_offset = 0
    
    if siglen != SPX_BYTES:
        return -1
    
    initialize_hash_function(pub_seed, b"")

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS)
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE)
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK)

    hash_message(mhash, tree, idx_leaf, sig[sig_offset:sig_offset+SPX_N], pk, m, mlen)
    sig_offset += SPX_N

    set_tree_addr(wots_addr, tree[0])
    set_keypair_addr(wots_addr, idx_leaf[0])

    fors_pk_from_sig(root, sig[sig_offset:sig_offset+SPX_FORS_BYTES], mhash, pub_seed, wots_addr)
    sig_offset += SPX_FORS_BYTES

    for i in range(SPX_D):
        set_layer_addr(tree_addr, i)
        set_tree_addr(tree_addr, tree[0])

        copy_subtree_addr(wots_addr, tree_addr)
        set_keypair_addr(wots_addr, idx_leaf[0])

        copy_keypair_addr(wots_pk_addr, wots_addr)

        wots_pk_from_sig(wots_pk, sig[sig_offset:sig_offset+SPX_WOTS_BYTES], root, pub_seed, wots_addr)
        sig_offset += SPX_WOTS_BYTES

        thash(leaf, wots_pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr)

        compute_root(root, 
                     leaf, 
                     idx_leaf[0], 
                     0, 
                     sig[sig_offset:sig_offset + SPX_TREE_HEIGHT * SPX_N], 
                     SPX_TREE_HEIGHT, 
                     pub_seed, 
                     tree_addr)
        sig_offset += SPX_TREE_HEIGHT * SPX_N

        idx_leaf[0] = tree[0] & ((1 << SPX_TREE_HEIGHT)-1)
        tree[0] >>= SPX_TREE_HEIGHT

    if root != pub_root:
        return -1
    return 0


def crypto_sign(sm: bytearray, 
                smlen: list[int], 
                m: bytes|bytearray, 
                mlen: int, 
                sk: bytes|bytearray)->int:
    siglen = [0]

    crypto_sign_signature(sm, siglen, m, mlen, sk)

    sm[SPX_BYTES:SPX_BYTES + mlen] = m[0:mlen]
    smlen[0] = siglen[0] + mlen

    return 0

def crypto_sign_open( m: bytearray, 
                     mlen: list[int], 
                     sm: bytes|bytearray, 
                     smlen: int, 
                     pk: bytes|bytearray)->int:
    if smlen < SPX_BYTES:
        m[0:len(m)] = b"\x00" * len(m) #len(m) rather than smlen here and below
        mlen[0] = 0
        return -1
    
    mlen[0] = smlen - SPX_BYTES

    if crypto_sign_verify(sm[0:SPX_BYTES], SPX_BYTES, sm[SPX_BYTES: smlen], mlen[0], pk) != 0:
        m[0:len(m)] = b"\x00" * len(m)
        mlen[0] = 0
        return -1
    
    m[0:mlen[0]] = sm[SPX_BYTES:SPX_BYTES + mlen[0]]

    return 0
