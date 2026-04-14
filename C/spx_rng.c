#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "spx_rng.h"

typedef struct {
    unsigned char key[32];
    unsigned char v[16];
    int reseed_counter;
    int initialized;
} aes256_ctr_drbg_state;

static aes256_ctr_drbg_state drbg_state;

/* Here I have a small AES-256 implementation so the C KAT path can build and run from
 * just the repo sources and a normal C compiler. I figured that was the least
 * annoying option for now compared to wiring in OpenSSL or another external
 * crypto dependency.
 *
 * If we later move this code onto the microcontroller path, we should probably
 * revisit this and decide whether this helper still belongs here or if the
 * platform should provide the AES part.
 */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rcon[15] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
};

static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b));
}

static void sub_bytes(uint8_t state[16])
{
    size_t i;
    for (i = 0; i < 16; ++i) {
        state[i] = sbox[state[i]];
    }
}

static void shift_rows(uint8_t state[16])
{
    uint8_t tmp;

    tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    tmp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = tmp;
}

static void mix_columns(uint8_t state[16])
{
    size_t i;

    for (i = 0; i < 4; ++i) {
        uint8_t *col = state + 4 * i;
        uint8_t t = (uint8_t)(col[0] ^ col[1] ^ col[2] ^ col[3]);
        uint8_t u = col[0];

        col[0] ^= t ^ xtime((uint8_t)(col[0] ^ col[1]));
        col[1] ^= t ^ xtime((uint8_t)(col[1] ^ col[2]));
        col[2] ^= t ^ xtime((uint8_t)(col[2] ^ col[3]));
        col[3] ^= t ^ xtime((uint8_t)(col[3] ^ u));
    }
}

static void add_round_key(uint8_t state[16], const uint8_t *round_key)
{
    size_t i;
    for (i = 0; i < 16; ++i) {
        state[i] ^= round_key[i];
    }
}

static void key_expansion_256(uint8_t round_keys[240], const uint8_t key[32])
{
    unsigned int i;
    uint8_t temp[4];

    memcpy(round_keys, key, 32);
    for (i = 8; i < 60; ++i) {
        temp[0] = round_keys[4 * (i - 1) + 0];
        temp[1] = round_keys[4 * (i - 1) + 1];
        temp[2] = round_keys[4 * (i - 1) + 2];
        temp[3] = round_keys[4 * (i - 1) + 3];

        if (i % 8 == 0) {
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
            temp[0] ^= rcon[(i / 8) - 1];
        } else if (i % 8 == 4) {
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }

        round_keys[4 * i + 0] = round_keys[4 * (i - 8) + 0] ^ temp[0];
        round_keys[4 * i + 1] = round_keys[4 * (i - 8) + 1] ^ temp[1];
        round_keys[4 * i + 2] = round_keys[4 * (i - 8) + 2] ^ temp[2];
        round_keys[4 * i + 3] = round_keys[4 * (i - 8) + 3] ^ temp[3];
    }
}

static void aes256_ecb_encrypt(const uint8_t key[32],
                               const uint8_t input[16],
                               uint8_t output[16])
{
    uint8_t state[16];
    uint8_t round_keys[240];
    unsigned int round;

    memcpy(state, input, 16);
    key_expansion_256(round_keys, key);

    add_round_key(state, round_keys);
    for (round = 1; round < 14; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + 16 * round);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys + 16 * 14);

    memcpy(output, state, 16);
}

static void increment_v(unsigned char v[16])
{
    int j;
    for (j = 15; j >= 0; --j) {
        if (v[j] == 0xff) {
            v[j] = 0x00;
        } else {
            ++v[j];
            break;
        }
    }
}

static void aes256_ctr_drbg_update(const unsigned char *provided_data,
                                   unsigned char key[32],
                                   unsigned char v[16])
{
    unsigned char temp[48];
    unsigned int i;

    for (i = 0; i < 3; ++i) {
        increment_v(v);
        aes256_ecb_encrypt(key, v, temp + 16 * i);
    }

    if (provided_data != NULL) {
        for (i = 0; i < 48; ++i) {
            temp[i] ^= provided_data[i];
        }
    }

    memcpy(key, temp, 32);
    memcpy(v, temp + 32, 16);
}

void randombytes_init(const unsigned char *entropy_input,
                      const unsigned char *personalization_string,
                      int security_strength)
{
    unsigned char seed_material[48];
    size_t i;

    (void)security_strength;

    memcpy(seed_material, entropy_input, 48);
    if (personalization_string != NULL) {
        for (i = 0; i < 48; ++i) {
            seed_material[i] ^= personalization_string[i];
        }
    }

    memset(drbg_state.key, 0, sizeof(drbg_state.key));
    memset(drbg_state.v, 0, sizeof(drbg_state.v));
    aes256_ctr_drbg_update(seed_material, drbg_state.key, drbg_state.v);
    drbg_state.reseed_counter = 1;
    drbg_state.initialized = 1;
}

static int randombytes_system(unsigned char *out, size_t outlen)
{
    FILE *fp;
    size_t got;

    fp = fopen("/dev/urandom", "rb");
    if (fp == NULL) {
        return -1;
    }
    got = fread(out, 1, outlen, fp);
    fclose(fp);
    return got == outlen ? 0 : -1;
}

int randombytes(unsigned char *out, size_t outlen)
{
    unsigned char block[16];
    size_t offset = 0;

    if (!drbg_state.initialized) {
        return randombytes_system(out, outlen);
    }

    while (outlen > 0) {
        size_t take;

        increment_v(drbg_state.v);
        aes256_ecb_encrypt(drbg_state.key, drbg_state.v, block);

        take = outlen > 16 ? 16 : outlen;
        memcpy(out + offset, block, take);
        offset += take;
        outlen -= take;
    }

    aes256_ctr_drbg_update(NULL, drbg_state.key, drbg_state.v);
    ++drbg_state.reseed_counter;
    return 0;
}
