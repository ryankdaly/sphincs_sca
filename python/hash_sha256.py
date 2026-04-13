#hash_sha256.py

from params import(
    SPX_N,
    SPX_TREE_HEIGHT,
    SPX_D,
    SPX_FORS_MSG_BYTES,
    SPX_PK_BYTES,
)
from utils import bytes_to_ull
from sha256 import (
    SPX_SHA256_BLOCK_BYTES, 
    SPX_SHA256_OUTPUT_BYTES, 
    SPX_SHA256_ADDR_BYTES,
    seed_state,
    sha256,
    sha256_inc_init,
    sha256_inc_blocks,
    sha256_inc_finalize,
    mgf1,
)

def initialize_hash_function(pub_seed: bytes | bytearray, sk_seed: bytes | bytearray)->None:
    seed_state(pub_seed)
    _ = sk_seed

def prf_addr(outval: bytearray, key: bytes | bytearray, addr: bytes | bytearray)->None:
    buf = bytearray(SPX_N+SPX_SHA256_ADDR_BYTES)
    outbuf = bytearray(SPX_SHA256_OUTPUT_BYTES)

    buf[0:SPX_N] = key[0:SPX_N]
    buf[SPX_N:SPX_N+SPX_SHA256_ADDR_BYTES] = addr[0:SPX_SHA256_ADDR_BYTES]

    sha256(outbuf, buf, SPX_N + SPX_SHA256_ADDR_BYTES)
    outval[0:SPX_N] = outbuf[0:SPX_N]

def gen_message_random( R: bytearray, 
                        sk_prf: bytes | bytearray,
                        optrand: bytes | bytearray,
                        m: bytes | bytearray,
                        mlen: int)->None:
    buf = bytearray(SPX_SHA256_BLOCK_BYTES + SPX_SHA256_OUTPUT_BYTES)
    state = bytearray(40)

    if SPX_N > SPX_SHA256_BLOCK_BYTES:
        raise ValueError("Currently only supports SPX_N of at most SPX_SHA256_BLOCK_BYTES")

    for i in range(SPX_N):
        buf[i] = 0x36 ^ sk_prf[i]
    buf[SPX_N:SPX_SHA256_BLOCK_BYTES] = bytes([0x36])*(SPX_SHA256_BLOCK_BYTES - SPX_N)

    sha256_inc_init(state)
    sha256_inc_blocks(state, buf, 1)

    buf[0:SPX_N] = optrand[0:SPX_N]

    if SPX_N + mlen < SPX_SHA256_BLOCK_BYTES:
        buf[SPX_N:SPX_N + mlen] = m[0:mlen]
        outbuf = bytearray(SPX_SHA256_OUTPUT_BYTES)
        sha256_inc_finalize(outbuf, state, buf, mlen + SPX_N)
        buf[SPX_SHA256_BLOCK_BYTES:SPX_SHA256_BLOCK_BYTES+SPX_SHA256_OUTPUT_BYTES] = outbuf
    else:
        offset = SPX_SHA256_BLOCK_BYTES - SPX_N
        buf[SPX_N: SPX_SHA256_BLOCK_BYTES] = m[0:offset]
        sha256_inc_blocks(state, buf, 1)

        m = m[offset:]
        mlen-=offset
        outbuf = bytearray(SPX_SHA256_OUTPUT_BYTES)
        sha256_inc_finalize(outbuf, state,  m, mlen)
        buf[SPX_SHA256_BLOCK_BYTES:SPX_SHA256_BLOCK_BYTES+SPX_SHA256_OUTPUT_BYTES] = outbuf

    for i in range(SPX_N):
        buf[i] = 0x5c ^ sk_prf[i]
    buf[SPX_N: SPX_SHA256_BLOCK_BYTES] = bytes([0x5c])*(SPX_SHA256_BLOCK_BYTES - SPX_N)

    sha256(buf, buf, SPX_SHA256_BLOCK_BYTES + SPX_SHA256_OUTPUT_BYTES)
    R[0:SPX_N] = buf[0:SPX_N]

def hash_message(digest: bytearray,
                 tree: list[int],
                 leaf_idx: list[int],
                 R: bytes | bytearray,
                 pk: bytes | bytearray,
                 m: bytes | bytearray,
                 mlen: int)->None:
    
    SPX_TREE_BITS = SPX_TREE_HEIGHT * (SPX_D - 1)
    SPX_TREE_BYTES = (SPX_TREE_BITS + 7) // 8
    SPX_LEAF_BITS = SPX_TREE_HEIGHT
    SPX_LEAF_BYTES = (SPX_LEAF_BITS + 7) // 8
    SPX_DGST_BYTES = (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    seed = bytearray(SPX_SHA256_OUTPUT_BYTES)

    if (SPX_SHA256_BLOCK_BYTES & (SPX_SHA256_BLOCK_BYTES-1)) != 0:
        raise ValueError("Assumes that SPX_SHA256_BLOCK_BYTES is a power of 2")
    SPX_INBLOCKS = ((SPX_N + SPX_PK_BYTES + SPX_SHA256_BLOCK_BYTES - 1) & -SPX_SHA256_BLOCK_BYTES) // SPX_SHA256_BLOCK_BYTES
    inbuf = bytearray(SPX_INBLOCKS * SPX_SHA256_BLOCK_BYTES)
    buf = bytearray(SPX_DGST_BYTES)
    bufp = 0
    state = bytearray(40)

    sha256_inc_init(state)

    inbuf[0:SPX_N] = R[0:SPX_N]
    inbuf[SPX_N:SPX_N + SPX_PK_BYTES] = pk[0:SPX_PK_BYTES]

    if SPX_N + SPX_PK_BYTES + mlen < SPX_INBLOCKS * SPX_SHA256_BLOCK_BYTES:
        inbuf[SPX_N + SPX_PK_BYTES: SPX_N + SPX_PK_BYTES + mlen]  = m[0:mlen]
        sha256_inc_finalize(seed, state, inbuf, SPX_N + SPX_PK_BYTES + mlen)
    else:
        val = SPX_INBLOCKS * SPX_SHA256_BLOCK_BYTES - SPX_N - SPX_PK_BYTES
        inbuf[SPX_N + SPX_PK_BYTES: SPX_N + SPX_PK_BYTES + val] = m[0:val]
        sha256_inc_blocks(state, inbuf, SPX_INBLOCKS)

        m = m[val:]
        mlen -= val
        sha256_inc_finalize(seed, state, m, mlen)

    mgf1(buf, SPX_DGST_BYTES, seed, SPX_SHA256_OUTPUT_BYTES)

    digest[0:SPX_FORS_MSG_BYTES] = buf[bufp: bufp + SPX_FORS_MSG_BYTES]
    bufp += SPX_FORS_MSG_BYTES

    if SPX_TREE_BITS > 64:
        raise ValueError("For given height and depth, 64 bits cannot represent all subtrees")
    
    treeval = bytes_to_ull(buf[bufp:bufp + SPX_TREE_BYTES], SPX_TREE_BYTES)
    treeval &= (1 << SPX_TREE_BITS) - 1
    bufp += SPX_TREE_BYTES

    leaf_idx_val = bytes_to_ull(buf[bufp:bufp + SPX_LEAF_BYTES], SPX_LEAF_BYTES)
    leaf_idx_val &= (1 << SPX_LEAF_BITS) - 1

    tree[0] = treeval
    leaf_idx[0] = leaf_idx_val
