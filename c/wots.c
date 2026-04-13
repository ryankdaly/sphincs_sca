// wots.c
#include <string.h>
#include "wots.h"
#include "params.h"
#include "address.h"
#include "hash_sha256.h"
#include "thash_sha256.h"

static void wots_gen_sk(uint8_t *sk, const uint8_t *sk_seed,
                        uint8_t addr[32])
{
    set_hash_addr(addr, 0);
    prf_addr(sk, sk_seed, addr);
}

static void gen_chain(uint8_t *out, const uint8_t *in,
                      unsigned int start, unsigned int steps,
                      const uint8_t *pub_seed, uint8_t addr[32])
{
    unsigned int i;

    memcpy(out, in, SPX_N);

    for (i = start; i < start + steps && i < SPX_WOTS_W; i++) {
        set_hash_addr(addr, i);
        thash(out, out, 1, pub_seed, addr);
    }
}

static void base_w(unsigned int *output, int out_len,
                   const uint8_t *input)
{
    int in_idx = 0;
    int out_idx = 0;
    uint8_t total;
    int bits = 0;
    int i;

    for (i = 0; i < out_len; i++) {
        if (bits == 0) {
            total = input[in_idx];
            in_idx++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out_idx] = (total >> bits) & (SPX_WOTS_W - 1);
        out_idx++;
    }
}

static void wots_checksum(unsigned int *csum_base_w,
                           const unsigned int *msg_base_w)
{
    unsigned int csum = 0;
    unsigned int i;
    int csum_len = (SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8;
    uint8_t csum_bytes[((SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8)];
    int shift;

    for (i = 0; i < SPX_WOTS_LEN1; i++) {
        csum += SPX_WOTS_W - 1 - msg_base_w[i];
    }

    shift = ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    csum <<= shift;

    ull_to_bytes(csum_bytes, csum_len, csum);
    base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

static void chain_lengths(unsigned int *lengths, const uint8_t *msg)
{
    base_w(lengths, SPX_WOTS_LEN1, msg);
    wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
}

void wots_gen_pk(uint8_t *pk, const uint8_t *sk_seed,
                 const uint8_t *pub_seed, uint8_t addr[32])
{
    unsigned int i;

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        wots_gen_sk(pk + i * SPX_N, sk_seed, addr);
        gen_chain(pk + i * SPX_N, pk + i * SPX_N, 0,
                  SPX_WOTS_W - 1, pub_seed, addr);
    }
}

void wots_sign(uint8_t *sig, const uint8_t *msg,
               const uint8_t *sk_seed, const uint8_t *pub_seed,
               uint8_t addr[32])
{
    unsigned int lengths[SPX_WOTS_LEN];
    unsigned int i;

    chain_lengths(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        wots_gen_sk(sig + i * SPX_N, sk_seed, addr);
        gen_chain(sig + i * SPX_N, sig + i * SPX_N, 0,
                  lengths[i], pub_seed, addr);
    }
}

void wots_pk_from_sig(uint8_t *pk, const uint8_t *sig,
                      const uint8_t *msg, const uint8_t *pub_seed,
                      uint8_t addr[32])
{
    unsigned int lengths[SPX_WOTS_LEN];
    unsigned int i;

    chain_lengths(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        memcpy(pk + i * SPX_N, sig + i * SPX_N, SPX_N);
        gen_chain(pk + i * SPX_N, pk + i * SPX_N,
                  lengths[i], SPX_WOTS_W - 1 - lengths[i],
                  pub_seed, addr);
    }
}