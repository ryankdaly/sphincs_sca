#ifndef SHA256_CORE_H
#define SHA256_CORE_H

#include <stddef.h>
#include <stdint.h>

#define SPX_SHA256_BLOCK_BYTES 64
#define SPX_SHA256_OUTPUT_BYTES 32

#if SPX_SHA256_OUTPUT_BYTES < SPX_N
#error "SHA256 output size is too small for this parameter set"
#endif

#define SPX_SHA256_ADDR_BYTES 22


void sha256_inc_init(uint8_t *state);
void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
void sha256_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen);
void sha256(uint8_t *out, const uint8_t *in, size_t inlen);



void mgf1(unsigned char *out, unsigned long outlen, const unsigned char *in, unsigned long inlen);



extern uint8_t state_seeded[40];


void seed_state(const unsigned char *pub_seed);

#endif