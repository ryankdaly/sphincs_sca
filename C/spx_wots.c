#include <stdint.h>
#include <string.h>

#include "spx_address.h"
#include "spx_bytes.h"
#include "spx_hash.h"
#include "spx_params.h"
#include "spx_thash.h"
#include "spx_wots.h"

static void wots_gen_sk(unsigned char *sk,
                        const unsigned char *sk_seed,
                        uint32_t wots_addr[8])
{
    set_hash_addr(wots_addr, 0);
    prf_addr(sk, sk_seed, wots_addr);
}

static void gen_chain(unsigned char *out,
                      const unsigned char *in,
                      unsigned int start,
                      unsigned int steps,
                      const unsigned char *pub_seed,
                      uint32_t addr[8])
{
    unsigned int i;

    memcpy(out, in, SPX_N);
    for (i = start; i < start + steps && i < SPX_WOTS_W; ++i) {
        set_hash_addr(addr, i);
        thash(out, out, 1, pub_seed, addr);
    }
}

static void base_w(unsigned int *output,
                   int out_len,
                   const unsigned char *input)
{
    int in_idx = 0;
    int out_idx = 0;
    unsigned int total = 0;
    unsigned int bits = 0;

    while (out_idx < out_len) {
        if (bits == 0) {
            total = input[in_idx++];
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out_idx++] = (total >> bits) & (SPX_WOTS_W - 1);
    }
}

static void wots_checksum(unsigned int *csum_base_w,
                          const unsigned int *msg_base_w)
{
    unsigned int csum = 0;
    unsigned int csum_bytes_len =
        (SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    unsigned int i;

    for (i = 0; i < SPX_WOTS_LEN1; ++i) {
        csum += SPX_WOTS_W - 1 - msg_base_w[i];
    }

    csum <<= (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8;
    ull_to_bytes(csum_bytes, csum_bytes_len, csum);
    base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

static void chain_lengths(unsigned int *lengths, const unsigned char *msg)
{
    base_w(lengths, SPX_WOTS_LEN1, msg);
    wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
}

void wots_gen_pk(unsigned char *pk,
                 const unsigned char *sk_seed,
                 const unsigned char *pub_seed,
                 uint32_t addr[8])
{
    unsigned int i;
    unsigned char buf[SPX_N];

    for (i = 0; i < SPX_WOTS_LEN; ++i) {
        set_chain_addr(addr, i);
        wots_gen_sk(buf, sk_seed, addr);
        gen_chain(buf, buf, 0, SPX_WOTS_W - 1, pub_seed, addr);
        memcpy(pk + i * SPX_N, buf, SPX_N);
    }
}

void wots_sign(unsigned char *sig,
               const unsigned char *msg,
               const unsigned char *sk_seed,
               const unsigned char *pub_seed,
               uint32_t addr[8])
{
    unsigned int lengths[SPX_WOTS_LEN];
    unsigned int i;
    unsigned char buf[SPX_N];

    chain_lengths(lengths, msg);
    for (i = 0; i < SPX_WOTS_LEN; ++i) {
        set_chain_addr(addr, i);
        wots_gen_sk(buf, sk_seed, addr);
        gen_chain(buf, buf, 0, lengths[i], pub_seed, addr);
        memcpy(sig + i * SPX_N, buf, SPX_N);
    }
}

void wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig,
                      const unsigned char *msg,
                      const unsigned char *pub_seed,
                      uint32_t addr[8])
{
    unsigned int lengths[SPX_WOTS_LEN];
    unsigned int i;
    unsigned char buf[SPX_N];

    chain_lengths(lengths, msg);
    for (i = 0; i < SPX_WOTS_LEN; ++i) {
        set_chain_addr(addr, i);
        memcpy(buf, sig + i * SPX_N, SPX_N);
        gen_chain(buf,
                  buf,
                  lengths[i],
                  SPX_WOTS_W - 1 - lengths[i],
                  pub_seed,
                  addr);
        memcpy(pk + i * SPX_N, buf, SPX_N);
    }
}
