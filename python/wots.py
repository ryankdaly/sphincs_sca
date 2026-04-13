"""
Wots.py


"""



from params import (
    SPX_N,
    SPX_WOTS_W,
    SPX_WOTS_LOGW,
    SPX_WOTS_LEN,
    SPX_WOTS_LEN1,
    SPX_WOTS_LEN2,
)
from address import ull_to_bytes
from hash_sha256 import prf_addr
from thash_sha256_simple import thash
from address import set_hash_addr, set_chain_addr


def wots_gen_sk(sk, sk_seed, wots_addr):
    """
    static void wots_gen_sk(unsigned char *sk, const unsigned char *sk_seed, uint32_t wots_addr[8])

    Computes one WOTS secret-key element.
    Expects the address to be complete up to the chain address.
    """
    if sk is None:
        raise ValueError("wots_gen_sk: sk must not be None")
    if sk_seed is None:
        raise ValueError("wots_gen_sk: sk_seed must not be None")
    if wots_addr is None:
        raise ValueError("wots_gen_sk: wots_addr must not be None")
    if len(sk) < SPX_N:
        raise ValueError("wots_gen_sk: sk buffer too small")

        # Make sure that the hash address is actually zeroed.
    set_hash_addr(wots_addr, 0)

    # Generate the sk element
    prf_addr(sk, sk_seed, wots_addr)



def gen_chain(out, input, start, steps, pub_seed, addr):
    """
    static void gen_chain(unsigned char *out, const unsigned char *in, unsigned int start, unsigned int steps, const unsigned char *pub_seed, uint32_t addr[8])
    """
    if out is None:
        raise ValueError("gen_chain: out must not be None")
    if input is None:
        raise ValueError("gen_chain: input must not be None")
    if pub_seed is None:
        raise ValueError("gen_chain: pub_seed must not be None")
    if addr is None:
        raise ValueError("gen_chain: addr must not be None")
    if len(out) < SPX_N:
        raise ValueError("gen_chain: out buffer too small")
    if len(input) < SPX_N:
        raise ValueError("gen_chain: input buffer too small")

    # Initializes out with the value at the position 'start'
    out[:SPX_N] = input[:SPX_N]

    # Iterate steps, calls to the hash function
    i = start
    while i < (start + steps) and i < SPX_WOTS_W:
        set_hash_addr(addr, i)
        thash(out, out, 1, pub_seed, addr)
        i += 1


def base_w(output, out_len, input):
    """
    static void base_w(unsigned int *output, const int out_len, const unsigned char *input)
    """
    if output is None:
        raise ValueError("base_w: output must not be None")
    if input is None:
        raise ValueError("base_w: input must not be None")
    if len(output) < out_len:
        raise ValueError("base_w: output buffer too small")

    in_idx = 0
    out_idx = 0
    total = 0
    bits = 0

    for _ in range(out_len):
        if bits == 0:
            total = input[in_idx]
            in_idx += 1
            bits += 8

        bits -= SPX_WOTS_LOGW
        output[out_idx] = (total >> bits) & (SPX_WOTS_W - 1)
        out_idx += 1

def wots_checksum(csum_base_w, msg_base_w):
    """
    static void wots_checksum(unsigned int *csum_base_w, const unsigned int *msg_base_w)
    """
    if csum_base_w is None:
        raise ValueError("wots_checksum: csum_base_w must not be None")
    if msg_base_w is None:
        raise ValueError("wots_checksum: msg_base_w must not be None")
    if len(csum_base_w) < SPX_WOTS_LEN2:
        raise ValueError("wots_checksum: csum_base_w buffer too small")
    if len(msg_base_w) < SPX_WOTS_LEN1:
        raise ValueError("wots_checksum: msg_base_w buffer too small")

    csum = 0

    # Now we compute the checksum
    for i in range(SPX_WOTS_LEN1):
        csum += SPX_WOTS_W - 1 - msg_base_w[i]

    # Converts the checksum to base_w
    # check the expected empty zero bits are at the least significant bits
    shift = ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8)
    csum = csum << shift

    csum_len = (SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) // 8
    csum_bytes = bytearray(csum_len)
    ull_to_bytes(csum_bytes, csum_len, csum)

    base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes)


def chain_lengths(lengths, msg):
    """
    static void chain_lengths(unsigned int *lengths, const unsigned char *msg)

    This function takes a message and derives the matching chain lengths
    """
    if lengths is None:
        raise ValueError("chain_lengths: lengths must not be None")
    if msg is None:
        raise ValueError("chain_lengths: msg must not be None")
    if len(lengths) < SPX_WOTS_LEN:
        raise ValueError("chain_lengths: lengths buffer too small")
    if len(msg) < SPX_N:
        raise ValueError("chain_lengths: msg buffer too small")

    base_w(lengths, SPX_WOTS_LEN1, msg)
    #wots_checksum(lengths[SPX_WOTS_LEN1:], lengths)

    csum_part = [0] * SPX_WOTS_LEN2
    wots_checksum(csum_part, lengths[:SPX_WOTS_LEN1])
    for i in range(SPX_WOTS_LEN2):
        lengths[SPX_WOTS_LEN1 + i] = csum_part[i]


def wots_gen_pk(pk, sk_seed, pub_seed, addr):
    """
    void wots_gen_pk(unsigned char *pk, const unsigned char *sk_seed, const unsigned char *pub_seed, uint32_t addr[8])
    """
    if pk is None:
        raise ValueError("wots_gen_pk: pk must not be None")
    if sk_seed is None:
        raise ValueError("wots_gen_pk: sk_seed must not be None")
    if pub_seed is None:
        raise ValueError("wots_gen_pk: pub_seed must not be None")
    if addr is None:
        raise ValueError("wots_gen_pk: addr must not be None")
    if len(pk) < SPX_WOTS_LEN * SPX_N:
        raise ValueError("wots_gen_pk: pk buffer too small")

    for i in range(SPX_WOTS_LEN):
        set_chain_addr(addr, i)

        offset = i * SPX_N
        elem = bytearray(SPX_N)

        wots_gen_sk(elem, sk_seed, addr)
        gen_chain(elem, elem, 0, SPX_WOTS_W - 1, pub_seed, addr)

        pk[offset:offset + SPX_N] = elem


def wots_sign(sig, msg, sk_seed, pub_seed, addr):
    """
    void wots_sign(unsigned char *sig, const unsigned char *msg, const unsigned char *sk_seed, const unsigned char *pub_seed, uint32_t addr[8])
    """
    if sig is None:
        raise ValueError("wots_sign: sig must not be None")
    if msg is None:
        raise ValueError("wots_sign: msg must not be None")
    if sk_seed is None:
        raise ValueError("wots_sign: sk_seed must not be None")
    if pub_seed is None:
        raise ValueError("wots_sign: pub_seed must not be None")
    if addr is None:
        raise ValueError("wots_sign: addr must not be None")
    if len(sig) < SPX_WOTS_LEN * SPX_N:
        raise ValueError("wots_sign: sig buffer too small")
    if len(msg) < SPX_N:
        raise ValueError("wots_sign: msg buffer too small")

    lengths = [0] * SPX_WOTS_LEN
    chain_lengths(lengths, msg)

    for i in range(SPX_WOTS_LEN):
        set_chain_addr(addr, i)

        offset = i * SPX_N
        elem = bytearray(SPX_N)

        wots_gen_sk(elem, sk_seed, addr)
        gen_chain(elem, elem, 0, lengths[i], pub_seed, addr)

        sig[offset:offset + SPX_N] = elem


def wots_pk_from_sig(pk, sig, msg, pub_seed, addr):
    """
    void wots_pk_from_sig(unsigned char *pk, const unsigned char *sig, const unsigned char *msg, const unsigned char *pub_seed, uint32_t addr[8])
    """
    if pk is None:
        raise ValueError("wots_pk_from_sig: pk must not be None")
    if sig is None:
        raise ValueError("wots_pk_from_sig: sig must not be None")
    if msg is None:
        raise ValueError("wots_pk_from_sig: msg must not be None")
    if pub_seed is None:
        raise ValueError("wots_pk_from_sig: pub_seed must not be None")
    if addr is None:
        raise ValueError("wots_pk_from_sig: addr must not be None")
    if len(pk) < SPX_WOTS_LEN * SPX_N:
        raise ValueError("wots_pk_from_sig: pk buffer too small")
    if len(sig) < SPX_WOTS_LEN * SPX_N:
        raise ValueError("wots_pk_from_sig: sig buffer too small")
    if len(msg) < SPX_N:
        raise ValueError("wots_pk_from_sig: msg buffer too small")

    lengths = [0] * SPX_WOTS_LEN
    chain_lengths(lengths, msg)

    for i in range(SPX_WOTS_LEN):
        set_chain_addr(addr, i)

        offset = i * SPX_N
        elem = bytearray(SPX_N)
        elem[:] = sig[offset:offset + SPX_N]

        gen_chain(elem, elem, lengths[i], SPX_WOTS_W - 1 - lengths[i], pub_seed, addr)

        pk[offset:offset + SPX_N] = elem