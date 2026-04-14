#ifndef SPX_SIGN_H
#define SPX_SIGN_H

#include <stddef.h>
#include <stdint.h>

#include "spx_params.h"

/*
 * Public signing API 
 *
 * If another part of the project wants to call into the implementation
 * directly, this is the header it should use.
 */


#define CRYPTO_SECRETKEYBYTES SPX_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES SPX_PK_BYTES
#define CRYPTO_BYTES SPX_BYTES
#define CRYPTO_SEEDBYTES (3 * SPX_N)
#define CRYPTO_ALGNAME "SPHINCS+-SHA256-256f-simple"

/* Named return codes so callers do not have to guess what an int response means. */
#define SPX_SUCCESS 0
#define SPX_ERR_NULL_PTR -1
#define SPX_ERR_INVALID_LEN -2
#define SPX_ERR_RANDOMBYTES -3
#define SPX_ERR_VERIFY -4

size_t crypto_sign_secretkeybytes(void);
size_t crypto_sign_publickeybytes(void);
size_t crypto_sign_bytes(void);
size_t crypto_sign_seedbytes(void);

/* Key generation from a seed provided by the caller. */
int crypto_sign_seed_keypair(unsigned char *pk,
                             unsigned char *sk,
                             const unsigned char *seed);

/* Key generation using the implementation RNG. */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

/* Detached signing. sig must have room for CRYPTO_BYTES bytes. */
int crypto_sign_signature(unsigned char *sig,
                          size_t *siglen,
                          const unsigned char *m,
                          size_t mlen,
                          const unsigned char *sk);

/* Detached signature verification. */
int crypto_sign_verify(const unsigned char *sig,
                       size_t siglen,
                       const unsigned char *m,
                       size_t mlen,
                       const unsigned char *pk);

/* Signed-message helper: writes sm = sig || m. */
int crypto_sign(unsigned char *sm,
                size_t *smlen,
                const unsigned char *m,
                size_t mlen,
                const unsigned char *sk);

/* Verify and recover the message from a signed-message buffer. */
int crypto_sign_open(unsigned char *m,
                     size_t *mlen,
                     const unsigned char *sm,
                     size_t smlen,
                     const unsigned char *pk);

#endif
