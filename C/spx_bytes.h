#ifndef SPX_BYTES_H
#define SPX_BYTES_H

#include <stdint.h>

/* spx_bytes.h
 *
 * This file consists of small byte modifing helper functions.
 */



/* Store an unsigned long long in big-endian form using exactly outlen bytes */
void ull_to_bytes(unsigned char *out, unsigned int outlen, unsigned long long in);

/*   Store a 32-bit integer in big-endian form    */
void u32_to_bytes(unsigned char *out, uint32_t in);

/* Parse an unsigned integer from big-endian bytes  */
unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen);

#endif