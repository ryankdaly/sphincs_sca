#ifndef THASH_SHA256_H
#define THASH_SHA256_H

#include <stdint.h>

void thash(uint8_t *out, const uint8_t *in, unsigned int inblocks,
           const uint8_t *pub_seed, const uint8_t *addr);

#endif