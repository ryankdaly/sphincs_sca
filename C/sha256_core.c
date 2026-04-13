#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "spx_params.h"
#include "spx_bytes.h"
#include "sha256_core.h"

static uint32_t load32_be(const uint8_t *x)
{
    return ((uint32_t)x[3]) |
           ((uint32_t)x[2] << 8) |
           ((uint32_t)x[1] << 16) |
           ((uint32_t)x[0] << 24);
}

static uint64_t load64_be(const uint8_t *x)
{

    return ((uint64_t)x[7]) |
           ((uint64_t)x[6] << 8) |
           ((uint64_t)x[5] << 16) |
           ((uint64_t)x[4] << 24) |
           ((uint64_t)x[3] << 32) |
           ((uint64_t)x[2] << 40) |
           ((uint64_t)x[1] << 48) |
           ((uint64_t)x[0] << 56);
}

static void store32_be(uint8_t *x, uint32_t u)
{
    x[3] = (uint8_t)u;
    u >>= 8;
    x[2] = (uint8_t)u;
    u >>= 8;
    x[1] = (uint8_t)u;
    u >>= 8;
    x[0] = (uint8_t)u;
}

static void store64_be(uint8_t *x, uint64_t u)
{
    x[7] = (uint8_t)u;
    u >>= 8;
    x[6] = (uint8_t)u;
    u >>= 8;
    x[5] = (uint8_t)u;
    u >>= 8;
    x[4] = (uint8_t)u;
    u >>= 8;
    x[3] = (uint8_t)u;
    u >>= 8;
    x[2] = (uint8_t)u;
    u >>= 8;
    x[1] = (uint8_t)u;
    u >>= 8;
    x[0] = (uint8_t)u;
}

#define SHR(x, c) ((x) >> (c))
#define ROTR32(x, c) (((x) >> (c)) | ((x) << (32 - (c))))



#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))



#define Sigma0(x) (ROTR32((x), 2) ^ ROTR32((x), 13) ^ ROTR32((x), 22))
#define Sigma1(x) (ROTR32((x), 6) ^ ROTR32((x), 11) ^ ROTR32((x), 25))
#define sigma0(x) (ROTR32((x), 7) ^ ROTR32((x), 18) ^ SHR((x), 3))
#define sigma1(x) (ROTR32((x), 17) ^ ROTR32((x), 19) ^ SHR((x), 10))

#define EXPAND_WORD(w0, w14, w9, w1) \
    w0 = sigma1(w14) + (w9) + sigma0(w1) + (w0);

#define ROUND(w, k)                           \
    T1 = h + Sigma1(e) + Ch(e, f, g) + (k) + (w); \
    T2 = Sigma0(a) + Maj(a, b, c);           \
    h = g;                                   \
    g = f;                                   \
    f = e;                                   \
    e = d + T1;                              \
    d = c;                                   \
    c = b;                                   \
    b = a;                                   \
    a = T1 + T2;

#define EXPAND_16           \
    EXPAND_WORD(w0, w14, w9, w1)   \
    EXPAND_WORD(w1, w15, w10, w2)  \
    EXPAND_WORD(w2, w0, w11, w3)   \
    EXPAND_WORD(w3, w1, w12, w4)   \
    EXPAND_WORD(w4, w2, w13, w5)   \
    EXPAND_WORD(w5, w3, w14, w6)   \
    EXPAND_WORD(w6, w4, w15, w7)   \
    EXPAND_WORD(w7, w5, w0, w8)    \
    EXPAND_WORD(w8, w6, w1, w9)    \
    EXPAND_WORD(w9, w7, w2, w10)   \
    EXPAND_WORD(w10, w8, w3, w11)  \
    EXPAND_WORD(w11, w9, w4, w12)  \
    EXPAND_WORD(w12, w10, w5, w13) \
    EXPAND_WORD(w13, w11, w6, w14) \
    EXPAND_WORD(w14, w12, w7, w15) \
    EXPAND_WORD(w15, w13, w8, w0)




static size_t sha256_compress_blocks(uint8_t *statebytes, const uint8_t *in, size_t inlen)
{
    uint32_t state[8];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;

    a = load32_be(statebytes + 0);  state[0] = a;
    b = load32_be(statebytes + 4);  state[1] = b;
    c = load32_be(statebytes + 8);  state[2] = c;
    d = load32_be(statebytes + 12); state[3] = d;
    e = load32_be(statebytes + 16); state[4] = e;
    f = load32_be(statebytes + 20); state[5] = f;
    g = load32_be(statebytes + 24); state[6] = g;
    h = load32_be(statebytes + 28); state[7] = h;

    while (inlen >= 64) {


        uint32_t w0  = load32_be(in + 0);
        uint32_t w1  = load32_be(in + 4);
        uint32_t w2  = load32_be(in + 8);
        uint32_t w3  = load32_be(in + 12);
        uint32_t w4  = load32_be(in + 16);
        uint32_t w5  = load32_be(in + 20);
        uint32_t w6  = load32_be(in + 24);
        uint32_t w7  = load32_be(in + 28);
        uint32_t w8  = load32_be(in + 32);
        uint32_t w9  = load32_be(in + 36);
        uint32_t w10 = load32_be(in + 40);
        uint32_t w11 = load32_be(in + 44);
        uint32_t w12 = load32_be(in + 48);
        uint32_t w13 = load32_be(in + 52);
        uint32_t w14 = load32_be(in + 56);
        uint32_t w15 = load32_be(in + 60);

        ROUND(w0, 0x428a2f98) ROUND(w1, 0x71374491)
        ROUND(w2, 0xb5c0fbcf) ROUND(w3, 0xe9b5dba5)
        ROUND(w4, 0x3956c25b) ROUND(w5, 0x59f111f1)
        ROUND(w6, 0x923f82a4) ROUND(w7, 0xab1c5ed5)
        ROUND(w8, 0xd807aa98) ROUND(w9, 0x12835b01)
        ROUND(w10, 0x243185be) ROUND(w11, 0x550c7dc3)
        ROUND(w12, 0x72be5d74) ROUND(w13, 0x80deb1fe)
        ROUND(w14, 0x9bdc06a7) ROUND(w15, 0xc19bf174)


        EXPAND_16

        ROUND(w0, 0xe49b69c1) ROUND(w1, 0xefbe4786)
        ROUND(w2, 0x0fc19dc6) ROUND(w3, 0x240ca1cc)
        ROUND(w4, 0x2de92c6f) ROUND(w5, 0x4a7484aa)
        ROUND(w6, 0x5cb0a9dc) ROUND(w7, 0x76f988da)
        ROUND(w8, 0x983e5152) ROUND(w9, 0xa831c66d)
        ROUND(w10, 0xb00327c8) ROUND(w11, 0xbf597fc7)
        ROUND(w12, 0xc6e00bf3) ROUND(w13, 0xd5a79147)
        ROUND(w14, 0x06ca6351) ROUND(w15, 0x14292967)

        EXPAND_16

        ROUND(w0, 0x27b70a85) ROUND(w1, 0x2e1b2138)
        ROUND(w2, 0x4d2c6dfc) ROUND(w3, 0x53380d13)
        ROUND(w4, 0x650a7354) ROUND(w5, 0x766a0abb)
        ROUND(w6, 0x81c2c92e) ROUND(w7, 0x92722c85)
        ROUND(w8, 0xa2bfe8a1) ROUND(w9, 0xa81a664b)
        ROUND(w10, 0xc24b8b70) ROUND(w11, 0xc76c51a3)
        ROUND(w12, 0xd192e819) ROUND(w13, 0xd6990624)
        ROUND(w14, 0xf40e3585) ROUND(w15, 0x106aa070)

        EXPAND_16


        ROUND(w0, 0x19a4c116) ROUND(w1, 0x1e376c08)
        ROUND(w2, 0x2748774c) ROUND(w3, 0x34b0bcb5)
        ROUND(w4, 0x391c0cb3) ROUND(w5, 0x4ed8aa4a)
        ROUND(w6, 0x5b9cca4f) ROUND(w7, 0x682e6ff3)
        ROUND(w8, 0x748f82ee) ROUND(w9, 0x78a5636f)
        ROUND(w10, 0x84c87814) ROUND(w11, 0x8cc70208)
        ROUND(w12, 0x90befffa) ROUND(w13, 0xa4506ceb)
        ROUND(w14, 0xbef9a3f7) ROUND(w15, 0xc67178f2)


        a += state[0];
        b += state[1];
        c += state[2];
        d += state[3];
        e += state[4];
        f += state[5];
        g += state[6];
        h += state[7];



        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
        state[4] = e;
        state[5] = f;
        state[6] = g;
        state[7] = h;

        in += 64;
        inlen -= 64;
    }



    store32_be(statebytes + 0, state[0]);
    store32_be(statebytes + 4, state[1]);
    store32_be(statebytes + 8, state[2]);
    store32_be(statebytes + 12, state[3]);
    store32_be(statebytes + 16, state[4]);
    store32_be(statebytes + 20, state[5]);
    store32_be(statebytes + 24, state[6]);
    store32_be(statebytes + 28, state[7]);

    return inlen;
}

static const uint8_t sha256_iv[32] = {
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19
};

void sha256_inc_init(uint8_t *state)
{
    size_t i;

    for (i = 0; i < 32; i++) {

        state[i] = sha256_iv[i];

    }
    for (i = 32; i < 40; i++) {
        state[i] = 0;

    }
}

void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks)
{
    uint64_t total = load64_be(state + 32);


    sha256_compress_blocks(state, in, 64 * inblocks);

    total += 64 * inblocks;


    store64_be(state + 32, total);
}

void sha256_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen)
{
    uint8_t padded[128];
    uint64_t total = load64_be(state + 32) + inlen;

    size_t i;

    sha256_compress_blocks(state, in, inlen);
    in += inlen;
    inlen &= 63;
    in -= inlen;




    for (i = 0; i < inlen; i++) {
        padded[i] = in[i];
    }
    padded[inlen] = 0x80;



    if (inlen < 56) {
        for (i = inlen + 1; i < 56; i++) {
            padded[i] = 0;
        }
        padded[56] = (uint8_t)(total >> 53);
        padded[57] = (uint8_t)(total >> 45);
        padded[58] = (uint8_t)(total >> 37);
        padded[59] = (uint8_t)(total >> 29);
        padded[60] = (uint8_t)(total >> 21);
        padded[61] = (uint8_t)(total >> 13);
        padded[62] = (uint8_t)(total >> 5);
        padded[63] = (uint8_t)(total << 3);
        sha256_compress_blocks(state, padded, 64);
    } else {
        for (i = inlen + 1; i < 120; i++) {
            padded[i] = 0;
        }
        padded[120] = (uint8_t)(total >> 53);
        padded[121] = (uint8_t)(total >> 45);
        padded[122] = (uint8_t)(total >> 37);
        padded[123] = (uint8_t)(total >> 29);
        padded[124] = (uint8_t)(total >> 21);
        padded[125] = (uint8_t)(total >> 13);
        padded[126] = (uint8_t)(total >> 5);
        padded[127] = (uint8_t)(total << 3);
        sha256_compress_blocks(state, padded, 128);
    }


    for (i = 0; i < 32; i++) {
        out[i] = state[i];
    }
}


void sha256(uint8_t *out, const uint8_t *in, size_t inlen)
{
    uint8_t state[40];

    sha256_inc_init(state);
    sha256_inc_finalize(out, state, in, inlen);
}




//Modified to use malloc and free since VLA was erroring. 
// 4/13 -john
void mgf1(unsigned char *out, unsigned long outlen, const unsigned char *in, unsigned long inlen)
{
    unsigned char *inbuf;
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    unsigned long i;

    inbuf = (unsigned char *)malloc(inlen + 4);
    if (inbuf == NULL) {
        return;
    }

    memcpy(inbuf, in, inlen);

    for (i = 0; (i + 1) * SPX_SHA256_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, (uint32_t)i);
        sha256(out, inbuf, inlen + 4);
        out += SPX_SHA256_OUTPUT_BYTES;
    }

    if (outlen > i * SPX_SHA256_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, (uint32_t)i);
        sha256(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i * SPX_SHA256_OUTPUT_BYTES);
    }

    free(inbuf);
}

uint8_t state_seeded[40];

void seed_state(const unsigned char *pub_seed)
{
    uint8_t block[SPX_SHA256_BLOCK_BYTES];
    size_t i;

    for (i = 0; i < SPX_N; i++) {
        block[i] = pub_seed[i];
    }
    for (i = SPX_N; i < SPX_SHA256_BLOCK_BYTES; i++) {
        block[i] = 0;
    }

    sha256_inc_init(state_seeded);
    sha256_inc_blocks(state_seeded, block, 1);
}