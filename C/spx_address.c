/* spx_address.c
 *
 * Contains the implementation for functions regarding address manipulation for SPHINCS+.
 *
 */

#include <stdint.h>
#include <string.h>

#include "spx_params.h"
#include "spx_bytes.h"
#include "spx_address.h"

static unsigned char *addr_bytes(uint32_t addr[8]) {
    return (unsigned char *)addr;
}

static const unsigned char *addr_bytes_const(const uint32_t addr[8]) {
    return (const unsigned char *)addr;

}


void set_layer_addr(uint32_t addr[8], uint32_t layer)
{

    addr_bytes(addr)[SPX_OFFSET_LAYER] = (unsigned char)layer;
}




void set_tree_addr(uint32_t addr[8], uint64_t tree)
{
#if (SPX_TREE_HEIGHT * (SPX_D - 1)) > 64
    #error "This implementation assumes the subtree index fits in 64 bits"
#endif
    ull_to_bytes(&addr_bytes(addr)[SPX_OFFSET_TREE], 8, tree);
}




void set_type(uint32_t addr[8], uint32_t type)
{
    addr_bytes(addr)[SPX_OFFSET_TYPE] = (unsigned char)type;
}



void copy_subtree_addr(uint32_t out[8], const uint32_t in[8])
{

    memcpy(out, in, SPX_OFFSET_TREE + 8);
}






void set_keypair_addr(uint32_t addr[8], uint32_t keypair)
{
#if SPX_FULL_HEIGHT / SPX_D > 8
    addr_bytes(addr)[SPX_OFFSET_KP_ADDR2] = (unsigned char)(keypair >> 8);
#endif
    addr_bytes(addr)[SPX_OFFSET_KP_ADDR1] = (unsigned char)keypair;
}





void copy_keypair_addr(uint32_t out[8], const uint32_t in[8])
{
    memcpy(out, in, SPX_OFFSET_TREE + 8);

#if SPX_FULL_HEIGHT / SPX_D > 8
    addr_bytes(out)[SPX_OFFSET_KP_ADDR2] =
        addr_bytes_const(in)[SPX_OFFSET_KP_ADDR2];
#endif


    addr_bytes(out)[SPX_OFFSET_KP_ADDR1] =
        addr_bytes_const(in)[SPX_OFFSET_KP_ADDR1];
}




void set_chain_addr(uint32_t addr[8], uint32_t chain) {
    addr_bytes(addr)[SPX_OFFSET_CHAIN_ADDR] = (unsigned char)chain;


}



void set_hash_addr(uint32_t addr[8], uint32_t hash)
{

    addr_bytes(addr)[SPX_OFFSET_HASH_ADDR] = (unsigned char)hash;
}


void set_tree_height(uint32_t addr[8], uint32_t tree_height)
{

    addr_bytes(addr)[SPX_OFFSET_TREE_HGT] = (unsigned char)tree_height;
}




void set_tree_index(uint32_t addr[8], uint32_t tree_index)
{
    u32_to_bytes(&addr_bytes(addr)[SPX_OFFSET_TREE_INDEX], tree_index);
}