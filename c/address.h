// address.h
#ifndef ADDRESS_H
#define ADDRESS_H

#include <stdint.h>
#include <string.h>
#include "params.h"

#define SPX_ADDR_TYPE_WOTS     0
#define SPX_ADDR_TYPE_WOTSPK   1
#define SPX_ADDR_TYPE_HASHTREE 2
#define SPX_ADDR_TYPE_FORSTREE 3
#define SPX_ADDR_TYPE_FORSPK   4

void set_layer_addr(uint8_t *addr, uint32_t layer);
void set_tree_addr(uint8_t *addr, uint64_t tree);
void set_type(uint8_t *addr, uint32_t addrtype);
void copy_subtree_addr(uint8_t *out, const uint8_t *in);
void set_keypair_addr(uint8_t *addr, uint32_t keypair);
void copy_keypair_addr(uint8_t *out, const uint8_t *in);
void set_chain_addr(uint8_t *addr, uint32_t chain);
void set_hash_addr(uint8_t *addr, uint32_t hash);
void set_tree_height(uint8_t *addr, uint32_t tree_height);
void set_tree_index(uint8_t *addr, uint32_t tree_index);
void ull_to_bytes(uint8_t *out, unsigned int outlen, uint64_t in);


#endif