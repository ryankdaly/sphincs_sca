#ifndef SPX_WOTS_H
#define SPX_WOTS_H

#include <stdint.h>



void wots_gen_pk(unsigned char *pk, const unsigned char *sk_seed, const unsigned char *pub_seed, uint32_t addr[8]);

void wots_sign(unsigned char *sig, const unsigned char *msg, const unsigned char *sk_seed, const unsigned char *pub_seed, uint32_t addr[8]);


void wots_pk_from_sig(unsigned char *pk, const unsigned char *sig, const unsigned char *msg, const unsigned char *pub_seed, uint32_t addr[8]);

#endif