#ifndef WOTS_H
#define WOTS_H

#include <stdint.h>

void wots_gen_pk(uint8_t *pk, const uint8_t *sk_seed,
                 const uint8_t *pub_seed, uint8_t addr[32]);

void wots_sign(uint8_t *sig, const uint8_t *msg,
               const uint8_t *sk_seed, const uint8_t *pub_seed,
               uint8_t addr[32]);

void wots_pk_from_sig(uint8_t *pk, const uint8_t *sig,
                      const uint8_t *msg, const uint8_t *pub_seed,
                      uint8_t addr[32]);

#endif