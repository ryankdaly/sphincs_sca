// address.c
#include "address.h"

void ull_to_bytes(uint8_t *out, unsigned int outlen, uint64_t in) {
    for (int i = (int)outlen - 1; i >= 0; i--) {
        out[i] = in & 0xFF;
        in >>= 8;
    }
}

static void u32_to_bytes(uint8_t *out, uint32_t in) {
    out[0] = (uint8_t)(in >> 24);
    out[1] = (uint8_t)(in >> 16);
    out[2] = (uint8_t)(in >> 8);
    out[3] = (uint8_t)(in);
}

void set_layer_addr(uint8_t *addr, uint32_t layer) {
    addr[SPX_OFFSET_LAYER] = (uint8_t)layer;
}

void set_tree_addr(uint8_t *addr, uint64_t tree) {
    ull_to_bytes(addr + SPX_OFFSET_TREE, 8, tree);
}

void set_type(uint8_t *addr, uint32_t addrtype) {
    addr[SPX_OFFSET_TYPE] = (uint8_t)addrtype;
}

void copy_subtree_addr(uint8_t *out, const uint8_t *in) {
    memcpy(out, in, SPX_OFFSET_TREE + 8);
}

void set_keypair_addr(uint8_t *addr, uint32_t keypair) {
#if (SPX_FULL_HEIGHT / SPX_D) > 8
    addr[SPX_OFFSET_KP_ADDR2] = (uint8_t)(keypair >> 8);
#endif
    addr[SPX_OFFSET_KP_ADDR1] = (uint8_t)keypair;
}

void copy_keypair_addr(uint8_t *out, const uint8_t *in) {
    memcpy(out, in, SPX_OFFSET_TREE + 8);
#if (SPX_FULL_HEIGHT / SPX_D) > 8
    out[SPX_OFFSET_KP_ADDR2] = in[SPX_OFFSET_KP_ADDR2];
#endif
    out[SPX_OFFSET_KP_ADDR1] = in[SPX_OFFSET_KP_ADDR1];
}

void set_chain_addr(uint8_t *addr, uint32_t chain) {
    addr[SPX_OFFSET_CHAIN_ADDR] = (uint8_t)chain;
}

void set_hash_addr(uint8_t *addr, uint32_t hash) {
    addr[SPX_OFFSET_HASH_ADDR] = (uint8_t)hash;
}

void set_tree_height(uint8_t *addr, uint32_t tree_height) {
    addr[SPX_OFFSET_TREE_HGT] = (uint8_t)tree_height;
}

void set_tree_index(uint8_t *addr, uint32_t tree_index) {
    u32_to_bytes(addr + SPX_OFFSET_TREE_INDEX, tree_index);
}