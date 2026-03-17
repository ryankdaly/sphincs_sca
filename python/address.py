#address.py

from params import (
    SPX_OFFSET_LAYER,
    SPX_TREE_HEIGHT,
    SPX_D,
    SPX_OFFSET_TREE,
    SPX_OFFSET_TYPE,
    SPX_FULL_HEIGHT,
    SPX_OFFSET_KP_ADDR1,
    SPX_OFFSET_KP_ADDR2,
    SPX_OFFSET_CHAIN_ADDR,
    SPX_OFFSET_HASH_ADDR,
    SPX_OFFSET_TREE_HGT,
    SPX_OFFSET_TREE_INDEX,
)

#helper utils
def ull_to_bytes(outlen:int,inval:int)->bytes:
    return inval.to_bytes(outlen, byteorder="big")

def u32_to_bytes(inval:int)->bytes:
    return inval.to_bytes(4, byteorder="big")

SPX_ADDR_TYPE_WOTS = 0
SPX_ADDR_TYPE_WOTSPK = 1
SPX_ADDR_TYPE_HASHTREE = 2
SPX_ADDR_TYPE_FORSTREE = 3
SPX_ADDR_TYPE_FORSPK = 4

def set_layer_addr(addr:bytearray, layer:int) -> None:
    addr[SPX_OFFSET_LAYER] = layer&0xFF

def set_tree_addr(addr:bytearray, tree:int) -> None:
    if (SPX_TREE_HEIGHT * (SPX_D - 1)) > 64:
        raise ValueError ("Subtree addressing is currently limited to at most 2^64 trees")
    addr[SPX_OFFSET_TREE:SPX_OFFSET_TREE+8] = ull_to_bytes(8, tree)
    
def set_type(addr:bytearray, addrtype:int)->None:
    addr[SPX_OFFSET_TYPE] = addrtype&0xFF

def copy_subtree_addr(outval:bytearray, inval:bytearray)->None:
    outval[:SPX_OFFSET_TREE+8] = inval[:SPX_OFFSET_TREE+8]

def set_keypair_addr(addr:bytearray, keypair:int)->None:
    if (SPX_FULL_HEIGHT//SPX_D) > 8:
        addr[SPX_OFFSET_KP_ADDR2] = (keypair>>8)&0xFF
    addr[SPX_OFFSET_KP_ADDR1] = keypair&0xFF

def copy_keypair_addr(outval:bytearray, inval:bytearray)->None:
    outval[:SPX_OFFSET_TREE+8] = inval[:SPX_OFFSET_TREE+8]
    if (SPX_FULL_HEIGHT//SPX_D) > 8:
        outval[SPX_OFFSET_KP_ADDR2] = inval[SPX_OFFSET_KP_ADDR2]
    outval[SPX_OFFSET_KP_ADDR1] = inval[SPX_OFFSET_KP_ADDR1]

def set_chain_addr(addr:bytearray, chain:int)->None:
    addr[SPX_OFFSET_CHAIN_ADDR] = chain&0xFF

def set_hash_addr(addr:bytearray, hashval:int)->None:
    addr[SPX_OFFSET_HASH_ADDR] = hashval&0xFF

def set_tree_height(addr:bytearray, tree_height:int)->None:
    addr[SPX_OFFSET_TREE_HGT] = tree_height&0xFF

def set_tree_index(addr:bytearray, tree_index:int)->None:
    addr[SPX_OFFSET_TREE_INDEX:SPX_OFFSET_TREE_INDEX+4] = u32_to_bytes(tree_index)
