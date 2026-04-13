#ifndef HASH_SHA256_H
#define HASH_SHA256_H

#include <stdint.h>
#include <stddef.h>

void initialize_hash_function(const uint8_t *pub_seed, const uint8_t *sk_seed);

void prf_addr(uint8_t *out, const uint8_t *key, const uint8_t *addr);

void gen_message_random(uint8_t *R, const uint8_t *sk_prf,
                        const uint8_t *optrand,
                        const uint8_t *m, size_t mlen);

void hash_message(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const uint8_t *R, const uint8_t *pk,
                  const uint8_t *m, size_t mlen);

#endif