#ifndef SPX_SIGN_H
#define SPX_SIGN_H

#include <stddef.h>
#include <stdint.h>

#include "spx_params.h"

#define CRYPTO_SECRETKEYBYTES SPX_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES SPX_PK_BYTES
#define CRYPTO_BYTES SPX_BYTES
#define CRYPTO_SEEDBYTES (3 * SPX_N)

size_t crypto_sign_secretkeybytes(void);
size_t crypto_sign_publickeybytes(void);
size_t crypto_sign_bytes(void);
size_t crypto_sign_seedbytes(void);

int crypto_sign_seed_keypair(unsigned char *pk,
                             unsigned char *sk,
                             const unsigned char *seed);

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign_signature(unsigned char *sig,
                          size_t *siglen,
                          const unsigned char *m,
                          size_t mlen,
                          const unsigned char *sk);

int crypto_sign_verify(const unsigned char *sig,
                       size_t siglen,
                       const unsigned char *m,
                       size_t mlen,
                       const unsigned char *pk);

int crypto_sign(unsigned char *sm,
                size_t *smlen,
                const unsigned char *m,
                size_t mlen,
                const unsigned char *sk);

int crypto_sign_open(unsigned char *m,
                     size_t *mlen,
                     const unsigned char *sm,
                     size_t smlen,
                     const unsigned char *pk);

#endif
