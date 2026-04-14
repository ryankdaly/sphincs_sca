CC ?= cc
CFLAGS ?= -std=c99 -O2 -Wall -Wextra -Wpedantic

LIB_SOURCES = \
	sha256_core.c \
	spx_address.c \
	spx_bytes.c \
	spx_fors.c \
	spx_hash.c \
	spx_rng.c \
	spx_sign.c \
	spx_thash.c \
	spx_utils.c \
	spx_wots.c

KAT_SOURCES = kat_test.c

all: kat_test


kat_test: $(LIB_SOURCES) $(KAT_SOURCES)
	$(CC) $(CFLAGS) -I. $(LIB_SOURCES) $(KAT_SOURCES) -o $@

clean:
	rm -f kat_test

.PHONY: all clean
