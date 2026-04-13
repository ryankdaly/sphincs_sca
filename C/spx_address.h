/* spx_address.h
 *
 * Contains address manipulation helpers
 *
 */

#ifndef SPX_ADDRESS_H
#define SPX_ADDRESS_H

#include <stdint.h>

/* Domain-separated address roles */
#define SPX_ADDR_TYPE_WOTS      0
#define SPX_ADDR_TYPE_WOTSPK    1
#define SPX_ADDR_TYPE_HASHTREE  2
#define SPX_ADDR_TYPE_FORSTREE  3
#define SPX_ADDR_TYPE_FORSPK    4


/* Top-level subtree coordinates */
void set_layer_addr(uint32_t addr[8], uint32_t layer);
void set_tree_addr(uint32_t addr[8], uint64_t tree);


/* Domain separation tag */
void set_type(uint32_t addr[8], uint32_t type);



/* Copy helpers */
void copy_subtree_addr(uint32_t out[8], const uint32_t in[8]);
void copy_keypair_addr(uint32_t out[8], const uint32_t in[8]);

/* WOTS / FORS leaf-local fields */
void set_keypair_addr(uint32_t addr[8], uint32_t keypair);
void set_chain_addr(uint32_t addr[8], uint32_t chain);
void set_hash_addr(uint32_t addr[8], uint32_t hash);



/* Tree node fields */
void set_tree_height(uint32_t addr[8], uint32_t tree_height);
void set_tree_index(uint32_t addr[8], uint32_t tree_index);

#endif