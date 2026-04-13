#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "spx_params.h"
#include "sha256_core.h"
#include "spx_thash.h"


//Modified to use malloc and free since VLA was erroring.
// Little worried about amount of computational overhead from excessive malloc calls.
// Maybe we should use a static max fixed size buffer. Will look into
// - John 4/13
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks, const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char *buf;
    unsigned char hash_out[SPX_SHA256_OUTPUT_BYTES];
    uint8_t state[40];
    size_t buflen;

    (void)pub_seed;

    buflen = SPX_SHA256_ADDR_BYTES + (size_t)inblocks * SPX_N;
    buf = (unsigned char *)malloc(buflen);
    if (buf == NULL) {
        return;
    }

    memcpy(state, state_seeded, 40);
    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, (size_t)inblocks * SPX_N);

    sha256_inc_finalize(hash_out, state, buf, buflen);
    memcpy(out, hash_out, SPX_N);

    free(buf);
}