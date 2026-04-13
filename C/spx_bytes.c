/* spx_bytes.c
 *
 * Implementation of big endian encoding and decoding helpers functions
 */

#include <stdint.h>

#include "spx_bytes.h"

void ull_to_bytes(unsigned char *out, unsigned int outlen, unsigned long long in)
{
    int i;

    for (i = (int)outlen - 1; i >= 0; --i) {
        out[i] = (unsigned char)(in & 0xffu);
        in >>= 8;
    }
}

void u32_to_bytes(unsigned char *out, uint32_t in)
{
    out[0] = (unsigned char)(in >> 24);
    out[1] = (unsigned char)(in >> 16);
    out[2] = (unsigned char)(in >> 8);
    out[3] = (unsigned char)in;
}

unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen)
{
    unsigned long long value = 0;
    unsigned int i;

    for (i = 0; i < inlen; ++i) {
        value |= ((unsigned long long)in[i]) << (8 * (inlen - 1 - i));
    }

    return value;
}