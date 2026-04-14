#ifndef SPX_FORS_H
#define SPX_FORS_H

#include <stdint.h>


void fors_sign(unsigned char *sig, unsigned char *pk, const unsigned char *m, const unsigned char *sk_seed, const unsigned char *pub_seed, const uint32_t fors_addr[8]);

               
void fors_pk_from_sig(unsigned char *pk, const unsigned char *sig, const unsigned char *m, const unsigned char *pub_seed, const uint32_t fors_addr[8]);






#endif