from params import SPX_FORS_TREES, SPX_FORS_HEIGHT, SPX_N
from utils import treehash, compute_root
from address import (
    copy_keypair_addr,
    set_type,
    set_tree_index,
    SPX_ADDR_TYPE_FORSTREE,
    SPX_ADDR_TYPE_FORSPK,
    set_tree_height,
)
from hash_sha256 import prf_addr

def fors_gen_sk(sk: bytearray, sk_seed: bytes | bytearray, fors_leaf_addr: bytes | bytearray)->None:
    prf_addr(sk, sk_seed, fors_leaf_addr)

def fors_sk_to_leaf(leaf: bytearray, 
                    sk: bytes|bytearray, 
                    pub_seed: bytes|bytearray, 
                    fors_leaf_addr: bytes|bytearray)->None:
    #insert thash here
    pass #placeholder

def fors_gen_leaf( leaf: bytearray,
                    sk_seed: bytes|bytearray,
                    pub_seed: bytes|bytearray,
                    addr_idx: int,
                    fors_tree_addr: bytes|bytearray)->None:
    fors_leaf_addr = bytearray(32)

    copy_keypair_addr(fors_leaf_addr, fors_tree_addr)
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE)
    set_tree_index(fors_leaf_addr, addr_idx)

    fors_gen_sk(leaf, sk_seed, fors_leaf_addr)
    fors_sk_to_leaf(leaf, leaf, pub_seed, fors_leaf_addr)

def message_to_indices(indices: list[int], m: bytes | bytearray)->None:
    offset = 0

    for i in range(SPX_FORS_TREES):
        indices[i] = 0
        for j in range(SPX_FORS_HEIGHT):
            indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j
            offset+=1

def fors_sign(sig: bytearray,
              pk: bytearray,
              m: bytes | bytearray,
              sk_seed: bytes | bytearray,
              pub_seed: bytes | bytearray,
              fors_addr: bytes | bytearray)->None:
    indices = [0]*SPX_FORS_TREES
    roots = bytearray(SPX_FORS_TREES * SPX_N)
    fors_tree_addr = bytearray(32)
    fors_pk_addr = bytearray(32)
    idx_offset = 0
    sig_offset = 0
    
    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for i in range(SPX_FORS_TREES):
        idx_offset = i * (1 << SPX_FORS_HEIGHT)

        set_tree_height(fors_tree_addr, 0)
        set_tree_index(fors_tree_addr, indices[i] + idx_offset)

        sk_i = bytearray(SPX_N)
        fors_gen_sk(sk_i, sk_seed, fors_tree_addr)
        sig[sig_offset: sig_offset+SPX_N] = sk_i
        sig_offset += SPX_N

        root_i = bytearray(SPX_N)
        auth_path_i = bytearray(SPX_N * SPX_FORS_HEIGHT)

        treehash(root_i, 
                 auth_path_i, 
                 sk_seed, 
                 pub_seed, 
                 indices[i], 
                 idx_offset, 
                 SPX_FORS_HEIGHT, 
                 fors_gen_leaf, 
                 fors_tree_addr)
        roots[i*SPX_N:(i+1)*SPX_N] = root_i
        sig[sig_offset: sig_offset + SPX_N * SPX_FORS_HEIGHT] = auth_path_i
        sig_offset += SPX_N * SPX_FORS_HEIGHT

    #insert thash here


def fors_pk_from_sig(pk: bytearray,
                    sig: bytearray,
                    m: bytes | bytearray,
                    pub_seed: bytes | bytearray,
                    fors_addr: bytes | bytearray)->None:
    indices = [0]*SPX_FORS_TREES
    roots = bytearray(SPX_FORS_TREES * SPX_N)
    leaf = bytearray(SPX_N)
    fors_tree_addr = bytearray(32)
    fors_pk_addr = bytearray(32)
    idx_offset = 0
    sig_offset = 0
    
    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for i in range(SPX_FORS_TREES):
        idx_offset = i * (1 << SPX_FORS_HEIGHT)

        set_tree_height(fors_tree_addr, 0)
        set_tree_index(fors_tree_addr, indices[i] + idx_offset)

        fors_sk_to_leaf(leaf, sig[sig_offset:sig_offset + SPX_N], pub_seed, fors_tree_addr)
        sig_offset += SPX_N

        root_i = bytearray(SPX_N)

        compute_root(root_i, 
                 leaf, 
                 indices[i], 
                 idx_offset, 
                 sig[sig_offset: sig_offset + SPX_N * SPX_FORS_HEIGHT],
                 SPX_FORS_HEIGHT, 
                 pub_seed, 
                 fors_tree_addr)
        roots[i*SPX_N:(i+1)*SPX_N] = root_i
        sig_offset += SPX_N * SPX_FORS_HEIGHT

    #insert thash here
