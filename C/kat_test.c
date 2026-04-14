#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256_core.h"
#include "spx_rng.h"
#include "spx_sign.h"

typedef struct {
    int count;
    unsigned char seed[48];
    size_t mlen;
    unsigned char *msg;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    size_t smlen;
    unsigned char *sm;
} kat_case;

typedef struct {
    int verbose;
    const char *rsp_path;
} kat_options;

static int parse_hex(const char *hex, unsigned char *out, size_t outlen)
{
    size_t i;
    size_t len = strlen(hex);

    if (len == 0 && outlen == 0) {
        return 0;
    }
    if (len != 2 * outlen) {
        return -1;
    }

    for (i = 0; i < outlen; ++i) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return -1;
        }
        out[i] = (unsigned char)byte;
    }
    return 0;
}

static char *trim(char *s)
{
    char *end;

    while (*s != '\0' && isspace((unsigned char)*s)) {
        ++s;
    }
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        --end;
    }
    *end = '\0';
    return s;
}

static void free_case(kat_case *kat)
{
    free(kat->msg);
    free(kat->sm);
    kat->msg = NULL;
    kat->sm = NULL;
}

static int load_case_from_rsp(FILE *fp, kat_case *kat)
{
    char line[200000];
    int have_count = 0;

    memset(kat, 0, sizeof(*kat));

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *eq;
        char *key;
        char *val;

        key = trim(line);
        if (*key == '\0' || *key == '#') {
            continue;
        }
        eq = strchr(key, '=');
        if (eq == NULL) {
            continue;
        }
        *eq = '\0';
        val = trim(eq + 1);
        key = trim(key);

        if (strcmp(key, "count") == 0) {
            kat->count = atoi(val);
            have_count = 1;
        } else if (strcmp(key, "seed") == 0) {
            if (parse_hex(val, kat->seed, sizeof(kat->seed)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "mlen") == 0) {
            kat->mlen = (size_t)strtoull(val, NULL, 10);
            kat->msg = (unsigned char *)malloc(kat->mlen == 0 ? 1 : kat->mlen);
            if (kat->msg == NULL) {
                return -1;
            }
        } else if (strcmp(key, "msg") == 0) {
            if (parse_hex(val, kat->msg, kat->mlen) != 0) {
                return -1;
            }
        } else if (strcmp(key, "pk") == 0) {
            if (parse_hex(val, kat->pk, sizeof(kat->pk)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "sk") == 0) {
            if (parse_hex(val, kat->sk, sizeof(kat->sk)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "smlen") == 0) {
            kat->smlen = (size_t)strtoull(val, NULL, 10);
            kat->sm = (unsigned char *)malloc(kat->smlen == 0 ? 1 : kat->smlen);
            if (kat->sm == NULL) {
                return -1;
            }
        } else if (strcmp(key, "sm") == 0) {
            if (parse_hex(val, kat->sm, kat->smlen) != 0) {
                return -1;
            }
            return have_count ? 1 : 0;
        }
    }

    return 0;
}

static void hash_case_stable(unsigned char out[32], const kat_case *kat)
{
    unsigned char *buf;
    size_t total_len = 4 + 48 + 8 + kat->mlen + CRYPTO_PUBLICKEYBYTES +
                       CRYPTO_SECRETKEYBYTES + 8 + kat->smlen;
    size_t off = 0;
    size_t i;

    buf = (unsigned char *)malloc(total_len == 0 ? 1 : total_len);
    if (buf == NULL) {
        memset(out, 0, 32);
        return;
    }

    for (i = 0; i < 4; ++i) {
        buf[off + 3 - i] =
            (unsigned char)(((unsigned int)kat->count >> (8 * i)) & 0xffu);
    }
    off += 4;
    memcpy(buf + off, kat->seed, 48);
    off += 48;
    for (i = 0; i < 8; ++i) {
        buf[off + 7 - i] =
            (unsigned char)(((unsigned long long)kat->mlen >> (8 * i)) & 0xffu);
    }
    off += 8;
    memcpy(buf + off, kat->msg, kat->mlen);
    off += kat->mlen;
    memcpy(buf + off, kat->pk, CRYPTO_PUBLICKEYBYTES);
    off += CRYPTO_PUBLICKEYBYTES;
    memcpy(buf + off, kat->sk, CRYPTO_SECRETKEYBYTES);
    off += CRYPTO_SECRETKEYBYTES;
    for (i = 0; i < 8; ++i) {
        buf[off + 7 - i] =
            (unsigned char)(((unsigned long long)kat->smlen >> (8 * i)) & 0xffu);
    }
    off += 8;
    memcpy(buf + off, kat->sm, kat->smlen);
    off += kat->smlen;

    sha256(out, buf, off);
    free(buf);
}

static void bytes_to_hex(const unsigned char *in, size_t inlen, char *out)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < inlen; ++i) {
        out[2 * i] = hex[in[i] >> 4];
        out[2 * i + 1] = hex[in[i] & 0x0f];
    }
    out[2 * inlen] = '\0';
}

static int compare_field(const char *name,
                         const unsigned char *got,
                         const unsigned char *want,
                         size_t len,
                         int count)
{
    if (memcmp(got, want, len) != 0) {
        fprintf(stderr, "count=%d mismatch in %s\n", count, name);
        return -1;
    }
    return 0;
}

static int parse_args(int argc, char **argv, kat_options *opts)
{
    int i;

    opts->verbose = 0;
    opts->rsp_path = "../python/test/PQCsignKAT_128.rsp";

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--verbose") == 0) {
            opts->verbose = 1;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "usage: %s [--verbose]\n", argv[0]);
            return -1;
        } else {
            opts->rsp_path = argv[i];
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    kat_options opts;
    FILE *in_fp;
    int case_count = 0;

    if (parse_args(argc, argv, &opts) != 0) {
        return 1;
    }

    in_fp = fopen(opts.rsp_path, "r");
    if (in_fp == NULL) {
        fprintf(stderr, "failed to open %s\n", opts.rsp_path);
        return 1;
    }

    for (;;) {
        kat_case expected;
        kat_case generated;
        unsigned char *opened;
        size_t opened_len = 0;
        int loaded = load_case_from_rsp(in_fp, &expected);
        unsigned char expected_hash[32];
        unsigned char generated_hash[32];
        char expected_hex[65];
        char generated_hex[65];

        if (loaded < 0) {
            fprintf(stderr, "failed to parse %s\n", opts.rsp_path);
            fclose(in_fp);
            return 1;
        }
        if (loaded == 0) {
            break;
        }

        memset(&generated, 0, sizeof(generated));
        generated.count = expected.count;
        memcpy(generated.seed, expected.seed, sizeof(generated.seed));
        generated.mlen = expected.mlen;
        generated.msg =
            (unsigned char *)malloc(generated.mlen == 0 ? 1 : generated.mlen);
        generated.sm =
            (unsigned char *)malloc(expected.smlen == 0 ? 1 : expected.smlen);
        opened = (unsigned char *)malloc(expected.mlen == 0 ? 1 : expected.mlen);

        if (generated.msg == NULL || generated.sm == NULL || opened == NULL) {
            fprintf(stderr, "allocation failed\n");
            free(generated.msg);
            free(generated.sm);
            free(opened);
            free_case(&expected);
            fclose(in_fp);
            return 1;
        }

        memcpy(generated.msg, expected.msg, generated.mlen);
        randombytes_init(expected.seed, NULL, 256);

        if (crypto_sign_keypair(generated.pk, generated.sk) != 0) {
            fprintf(stderr, "count=%d keypair generation failed\n", expected.count);
            free(opened);
            free_case(&generated);
            free_case(&expected);
            fclose(in_fp);
            return 1;
        }
        if (crypto_sign(generated.sm,
                        &generated.smlen,
                        generated.msg,
                        generated.mlen,
                        generated.sk) != 0) {
            fprintf(stderr, "count=%d signing failed\n", expected.count);
            free(opened);
            free_case(&generated);
            free_case(&expected);
            fclose(in_fp);
            return 1;
        }
        if (crypto_sign_open(opened,
                             &opened_len,
                             generated.sm,
                             generated.smlen,
                             generated.pk) != 0) {
            fprintf(stderr, "count=%d open failed\n", expected.count);
            free(opened);
            free_case(&generated);
            free_case(&expected);
            fclose(in_fp);
            return 1;
        }

        hash_case_stable(expected_hash, &expected);
        hash_case_stable(generated_hash, &generated);
        bytes_to_hex(expected_hash, sizeof(expected_hash), expected_hex);
        bytes_to_hex(generated_hash, sizeof(generated_hash), generated_hex);

        if (opts.verbose) {
            printf("count=%d expected_sha256=%s generated_sha256=%s\n",
                   expected.count,
                   expected_hex,
                   generated_hex);
        }

        if (compare_field("pk",
                          generated.pk,
                          expected.pk,
                          sizeof(generated.pk),
                          expected.count) != 0 ||
            compare_field("sk",
                          generated.sk,
                          expected.sk,
                          sizeof(generated.sk),
                          expected.count) != 0 ||
            generated.smlen != expected.smlen ||
            compare_field("sm",
                          generated.sm,
                          expected.sm,
                          generated.smlen,
                          expected.count) != 0 ||
            opened_len != expected.mlen ||
            compare_field("msg",
                          opened,
                          expected.msg,
                          expected.mlen,
                          expected.count) != 0 ||
            memcmp(expected_hash, generated_hash, sizeof(expected_hash)) != 0) {
            if (generated.smlen != expected.smlen) {
                fprintf(stderr,
                        "count=%d mismatch in smlen: got=%zu want=%zu\n",
                        expected.count,
                        generated.smlen,
                        expected.smlen);
            }
            if (opened_len != expected.mlen) {
                fprintf(stderr,
                        "count=%d mismatch in opened length: got=%zu want=%zu\n",
                        expected.count,
                        opened_len,
                        expected.mlen);
            }
            if (memcmp(expected_hash, generated_hash, sizeof(expected_hash)) != 0) {
                fprintf(stderr,
                        "count=%d case hash mismatch: expected=%s generated=%s\n",
                        expected.count,
                        expected_hex,
                        generated_hex);
            }
            free(opened);
            free_case(&generated);
            free_case(&expected);
            fclose(in_fp);
            return 1;
        }

        ++case_count;
        free(opened);
        free_case(&generated);
        free_case(&expected);
    }

    fclose(in_fp);

    printf("All %d KATs passed.\n", case_count);
    return 0;
}
