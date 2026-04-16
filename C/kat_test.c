#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    int has_pk;
    int has_sk;
    int has_smlen;
    int has_sm;
} kat_case;

typedef struct {
    const char *req_path;
    const char *rsp_path;
    const char *out_path;
    int limit;
    int count_flag;
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

static void free_cases(kat_case *cases, size_t count)
{
    size_t i;

    if (cases == NULL) {
        return;
    }
    for (i = 0; i < count; ++i) {
        free_case(&cases[i]);
    }
    free(cases);
}

static int clone_case_fields(kat_case *dst, const kat_case *src)
{
    memset(dst, 0, sizeof(*dst));
    dst->count = src->count;
    memcpy(dst->seed, src->seed, sizeof(dst->seed));
    dst->mlen = src->mlen;
    dst->msg = (unsigned char *)malloc(dst->mlen == 0 ? 1 : dst->mlen);
    if (dst->msg == NULL) {
        return -1;
    }
    if (dst->mlen > 0) {
        memcpy(dst->msg, src->msg, dst->mlen);
    }
    return 0;
}

static int load_case(FILE *fp, kat_case *kat)
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
        } else if (strcmp(key, "pk") == 0 && *val != '\0') {
            if (parse_hex(val, kat->pk, sizeof(kat->pk)) != 0) {
                return -1;
            }
            kat->has_pk = 1;
        } else if (strcmp(key, "sk") == 0 && *val != '\0') {
            if (parse_hex(val, kat->sk, sizeof(kat->sk)) != 0) {
                return -1;
            }
            kat->has_sk = 1;
        } else if (strcmp(key, "smlen") == 0 && *val != '\0') {
            kat->smlen = (size_t)strtoull(val, NULL, 10);
            kat->has_smlen = 1;
        } else if (strcmp(key, "sm") == 0) {
            if (*val != '\0') {
                kat->sm = (unsigned char *)malloc(kat->smlen == 0 ? 1 : kat->smlen);
                if (kat->sm == NULL) {
                    return -1;
                }
                if (parse_hex(val, kat->sm, kat->smlen) != 0) {
                    return -1;
                }
                kat->has_sm = 1;
            }
            return have_count ? 1 : 0;
        }
    }

    return 0;
}

static int load_cases(const char *path, kat_case **out_cases, size_t *out_count)
{
    FILE *fp;
    kat_case *cases = NULL;
    size_t count = 0;
    size_t cap = 0;

    *out_cases = NULL;
    *out_count = 0;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    for (;;) {
        kat_case tmp;
        int rc = load_case(fp, &tmp);

        if (rc < 0) {
            fclose(fp);
            free_cases(cases, count);
            return -1;
        }
        if (rc == 0) {
            break;
        }

        if (count == cap) {
            size_t new_cap = cap == 0 ? 16 : 2 * cap;
            kat_case *new_cases =
                (kat_case *)realloc(cases, new_cap * sizeof(*new_cases));
            if (new_cases == NULL) {
                fclose(fp);
                free_case(&tmp);
                free_cases(cases, count);
                return -1;
            }
            cases = new_cases;
            cap = new_cap;
        }

        cases[count++] = tmp;
    }

    fclose(fp);
    *out_cases = cases;
    *out_count = count;
    return 0;
}

static int write_hex_field(FILE *fp,
                           const char *label,
                           const unsigned char *buf,
                           size_t len)
{
    size_t i;

    if (fprintf(fp, "%s = ", label) < 0) {
        return -1;
    }
    for (i = 0; i < len; ++i) {
        if (fprintf(fp, "%02X", buf[i]) < 0) {
            return -1;
        }
    }
    return fprintf(fp, "\n") < 0 ? -1 : 0;
}

static int write_case(FILE *fp, const kat_case *kat)
{
    if (fprintf(fp, "count = %d\n", kat->count) < 0) {
        return -1;
    }
    if (write_hex_field(fp, "seed", kat->seed, sizeof(kat->seed)) != 0) {
        return -1;
    }
    if (fprintf(fp, "mlen = %zu\n", kat->mlen) < 0) {
        return -1;
    }
    if (write_hex_field(fp, "msg", kat->msg, kat->mlen) != 0) {
        return -1;
    }
    if (write_hex_field(fp, "pk", kat->pk, sizeof(kat->pk)) != 0) {
        return -1;
    }
    if (write_hex_field(fp, "sk", kat->sk, sizeof(kat->sk)) != 0) {
        return -1;
    }
    if (fprintf(fp, "smlen = %zu\n", kat->smlen) < 0) {
        return -1;
    }
    if (write_hex_field(fp, "sm", kat->sm, kat->smlen) != 0) {
        return -1;
    }
    return fprintf(fp, "\n") < 0 ? -1 : 0;
}

static int write_rsp_file(const char *path, const kat_case *cases, size_t count)
{
    FILE *fp;
    size_t i;

    fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }

    for (i = 0; i < count; ++i) {
        if (write_case(fp, &cases[i]) != 0) {
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

static int run_kats(const kat_case *req_cases,
                    size_t req_count,
                    int count_flag,
                    kat_case **out_cases,
                    size_t *out_count)
{
    kat_case *generated;
    size_t i;

    *out_cases = NULL;
    *out_count = 0;

    generated = (kat_case *)calloc(req_count == 0 ? 1 : req_count, sizeof(*generated));
    if (generated == NULL) {
        return -1;
    }

    for (i = 0; i < req_count; ++i) {
        unsigned char *opened;
        size_t opened_len = 0;

        if (count_flag) {
            printf("KAT generation count = %d\n", req_cases[i].count);
        }

        if (clone_case_fields(&generated[i], &req_cases[i]) != 0) {
            free_cases(generated, i);
            return -1;
        }

        opened = (unsigned char *)malloc(generated[i].mlen == 0 ? 1 : generated[i].mlen);
        generated[i].sm =
            (unsigned char *)malloc(generated[i].mlen + CRYPTO_BYTES);
        if (opened == NULL || generated[i].sm == NULL) {
            free(opened);
            free_cases(generated, i + 1);
            return -1;
        }

        randombytes_init(req_cases[i].seed, NULL, 256);

        if (crypto_sign_keypair(generated[i].pk, generated[i].sk) != SPX_SUCCESS) {
            fprintf(stderr, "crypto_sign_keypair failed at count=%d\n", req_cases[i].count);
            free(opened);
            free_cases(generated, i + 1);
            return -1;
        }

        if (crypto_sign(generated[i].sm,
                        &generated[i].smlen,
                        generated[i].msg,
                        generated[i].mlen,
                        generated[i].sk) != SPX_SUCCESS) {
            fprintf(stderr, "crypto_sign failed at count=%d\n", req_cases[i].count);
            free(opened);
            free_cases(generated, i + 1);
            return -1;
        }

        if (crypto_sign_open(opened,
                             &opened_len,
                             generated[i].sm,
                             generated[i].smlen,
                             generated[i].pk) != SPX_SUCCESS) {
            fprintf(stderr, "crypto_sign_open failed at count=%d\n", req_cases[i].count);
            free(opened);
            free_cases(generated, i + 1);
            return -1;
        }

        if (opened_len != generated[i].mlen ||
            (opened_len > 0 && memcmp(opened, generated[i].msg, opened_len) != 0)) {
            fprintf(stderr, "crypto_sign_open returned bad message at count=%d\n",
                    req_cases[i].count);
            free(opened);
            free_cases(generated, i + 1);
            return -1;
        }

        generated[i].has_pk = 1;
        generated[i].has_sk = 1;
        generated[i].has_smlen = 1;
        generated[i].has_sm = 1;

        free(opened);
    }

    *out_cases = generated;
    *out_count = req_count;
    return 0;
}

static int compare_cases(const kat_case *generated,
                         const kat_case *reference,
                         size_t count,
                         int count_flag)
{
    size_t i;

    for (i = 0; i < count; ++i) {
        if (count_flag) {
            printf("KAT test count = %d\n", reference[i].count);
        }

        if (generated[i].count != reference[i].count) {
            fprintf(stderr, "count=%d mismatch in count\n", reference[i].count);
            return -1;
        }
        if (memcmp(generated[i].seed, reference[i].seed, sizeof(generated[i].seed)) != 0) {
            fprintf(stderr, "count=%d mismatch in seed\n", reference[i].count);
            return -1;
        }
        if (generated[i].mlen != reference[i].mlen) {
            fprintf(stderr, "count=%d mismatch in mlen\n", reference[i].count);
            return -1;
        }
        if ((generated[i].mlen > 0 &&
             memcmp(generated[i].msg, reference[i].msg, generated[i].mlen) != 0)) {
            fprintf(stderr, "count=%d mismatch in msg\n", reference[i].count);
            return -1;
        }
        if (memcmp(generated[i].pk, reference[i].pk, sizeof(generated[i].pk)) != 0) {
            fprintf(stderr, "count=%d mismatch in pk\n", reference[i].count);
            return -1;
        }
        if (memcmp(generated[i].sk, reference[i].sk, sizeof(generated[i].sk)) != 0) {
            fprintf(stderr, "count=%d mismatch in sk\n", reference[i].count);
            return -1;
        }
        if (generated[i].smlen != reference[i].smlen) {
            fprintf(stderr, "count=%d mismatch in smlen\n", reference[i].count);
            return -1;
        }
        if ((generated[i].smlen > 0 &&
             memcmp(generated[i].sm, reference[i].sm, generated[i].smlen) != 0)) {
            fprintf(stderr, "count=%d mismatch in sm\n", reference[i].count);
            return -1;
        }
    }

    return 0;
}

static void limit_cases(kat_case *cases, size_t *count, int limit)
{
    size_t i;

    if (limit < 0 || (size_t)limit >= *count) {
        return;
    }

    for (i = (size_t)limit; i < *count; ++i) {
        free_case(&cases[i]);
    }
    *count = (size_t)limit;
}

static int parse_args(int argc, char **argv, kat_options *opts)
{
    int i;

    opts->req_path = "../C/test/PQCsignKAT_128.req";
    opts->rsp_path = "../C/test/PQCsignKAT_128.rsp";
    opts->out_path = "../C/test/PQCsignKAT_128_gen_c.rsp";
    opts->limit = -1;
    opts->count_flag = 0;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--req") == 0 && i + 1 < argc) {
            opts->req_path = argv[++i];
        } else if (strcmp(argv[i], "--rsp") == 0 && i + 1 < argc) {
            opts->rsp_path = argv[++i];
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            opts->out_path = argv[++i];
        } else if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
            opts->limit = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--count") == 0) {
            opts->count_flag = 1;
        } else {
            fprintf(stderr,
                    "usage: %s [--req path] [--rsp path] [--out path] [--limit n] [--count]\n",
                    argv[0]);
            return -1;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    kat_options opts;
    kat_case *req_cases = NULL;
    kat_case *rsp_cases = NULL;
    kat_case *gen_cases = NULL;
    size_t req_count = 0;
    size_t rsp_count = 0;
    size_t gen_count = 0;

    if (parse_args(argc, argv, &opts) != 0) {
        return 1;
    }

    if (load_cases(opts.req_path, &req_cases, &req_count) != 0) {
        fprintf(stderr, "Missing or unreadable .req file: %s\n", opts.req_path);
        return 1;
    }
    if (load_cases(opts.rsp_path, &rsp_cases, &rsp_count) != 0) {
        fprintf(stderr, "Missing or unreadable .rsp file: %s\n", opts.rsp_path);
        free_cases(req_cases, req_count);
        return 1;
    }

    limit_cases(req_cases, &req_count, opts.limit);
    limit_cases(rsp_cases, &rsp_count, opts.limit);

    if (run_kats(req_cases,
                 req_count,
                 opts.count_flag,
                 &gen_cases,
                 &gen_count) != 0) {
        free_cases(req_cases, req_count);
        free_cases(rsp_cases, rsp_count);
        free_cases(gen_cases, gen_count);
        return 1;
    }

    printf("Generation Done.\n");

    if (write_rsp_file(opts.out_path, gen_cases, gen_count) != 0) {
        fprintf(stderr, "Failed to write generated rsp file: %s\n", opts.out_path);
        free_cases(req_cases, req_count);
        free_cases(rsp_cases, rsp_count);
        free_cases(gen_cases, gen_count);
        return 1;
    }

    printf("Wrote to file %s\n", opts.out_path);

    if (gen_count != rsp_count) {
        fprintf(stderr, "KAT count mismatch: gen=%zu, ref=%zu\n", gen_count, rsp_count);
        free_cases(req_cases, req_count);
        free_cases(rsp_cases, rsp_count);
        free_cases(gen_cases, gen_count);
        return 1;
    }

    printf("Testing %s against %s\n", opts.out_path, opts.rsp_path);
    if (compare_cases(gen_cases, rsp_cases, gen_count, opts.count_flag) != 0) {
        free_cases(req_cases, req_count);
        free_cases(rsp_cases, rsp_count);
        free_cases(gen_cases, gen_count);
        return 1;
    }

    printf("All %zu KATs passed. File:%s\n", gen_count, opts.out_path);

    free_cases(req_cases, req_count);
    free_cases(rsp_cases, rsp_count);
    free_cases(gen_cases, gen_count);
    return 0;
}
