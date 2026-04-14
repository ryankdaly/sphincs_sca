#ifndef SPX_RNG_H
#define SPX_RNG_H

#include <stddef.h>

int randombytes(unsigned char *out, size_t outlen);
void randombytes_init(const unsigned char *entropy_input,
                      const unsigned char *personalization_string,
                      int security_strength);

#endif
