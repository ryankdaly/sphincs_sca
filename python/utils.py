#utils.py

from collections.abc import Callable

from params import SPX_N
from address import set_tree_height, set_tree_index

def bytes_to_ull(inval: bytes | bytearray, inlen: int) -> int:
    return inval.from_bytes(inlen, byteorder="big")

def compute_root(root:bytearray, 
                leaf:bytes|bytearray,
                leaf_idx:int,
                idx_offset:int,
                auth_path:bytes|bytearray,
                tree_height:int,
                pub_seed:bytes|bytearray,
                addr:bytearray,)->None:
    
    buffer = bytearray(2 * SPX_N)

    if leaf_idx & 1:
        buffer[SPX_N:2 * SPX_N] = leaf[:SPX_N]
        buffer[0:SPX_N] = auth_path[0:SPX_N]
    else:
        buffer[0:SPX_N] = leaf[:SPX_N]
        buffer[SPX_N:2 * SPX_N] = auth_path[0:SPX_N]

    auth_offset = SPX_N

    for i in range(tree_height-1):
        leaf_idx >>= 1
        idx_offset >>= 1

        set_tree_height(addr, i + 1)
        set_tree_index(addr, leaf_idx + idx_offset)

        if leaf_idx & 1:
            #insert thash here
            buffer[0:SPX_N] = auth_path[auth_offset:auth_offset+SPX_N]
        else:
            #insert thash here
            buffer[SPX_N:2 * SPX_N] = auth_path[auth_offset:auth_offset+SPX_N]

        auth_offset += SPX_N

    leaf_idx >>= 1
    idx_offset >>= 1
    set_tree_height(addr, tree_height)
    set_tree_index(addr, leaf_idx + idx_offset)
    #insert thash here



def treehash(root:bytearray, 
            auth_path:bytearray,
            sk_seed:bytes|bytearray,
            pub_seed:bytes|bytearray,
            leaf_idx:int, 
            idx_offset:int, 
            tree_height:int,
            gen_leaf: Callable[[bytes | bytearray, 
                                bytes | bytearray, 
                                bytes | bytearray, 
                                int, 
                                bytearray], None],
            tree_addr:bytearray)->None:
    
    stack = bytearray((tree_height + 1)*SPX_N)
    heights = [0] * (tree_height + 1)
    offset = 0
    for idx in range(1 << tree_height):
        leaf = gen_leaf(sk_seed, pub_seed, idx + idx_offset, tree_addr)
        stack[offset*SPX_N:(offset+1)*SPX_N] = leaf[:SPX_N]
        offset += 1
        heights[offset-1] = 0

        if (leaf_idx ^ 0x1) == idx:
            auth_path[0:SPX_N] = stack[(offset - 1)*SPX_N:offset*SPX_N]
        
        while offset >= 2 and heights[offset-1] == heights[offset-2]:
            tree_idx = idx >> (heights[offset - 1] + 1)

            set_tree_height(tree_addr, heights[offset - 1] + 1)
            set_tree_index(tree_addr, tree_idx + (idx_offset >> (heights[offset-1] + 1)))

            #insert thash here
            offset -= 1
            heights[offset - 1] += 1

            if ((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx:
                auth_path[heights[offset - 1]*SPX_N:(heights[offset - 1]+1)*SPX_N] = stack[(offset - 1)*SPX_N:offset*SPX_N]
        
    root[0:SPX_N] = stack[0:SPX_N]
