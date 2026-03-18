import hashlib

from params import SPX_N


SPX_SHA256_BLOCK_BYTES = 64
SPX_SHA256_OUTPUT_BYTES = 32

if SPX_SHA256_OUTPUT_BYTES < SPX_N:
    raise ValueError("Linking against SHA-256 with N larger than 32 bytes is not supported")

SPX_SHA256_ADDR_BYTES = 22

_sha256_state_registry = {}


def _load_bigendian_64(x):
    return int.from_bytes(bytes(x[:8]), byteorder="big")


def _store_bigendian_64(x, u):
    x[:8] = int(u & 0xFFFFFFFFFFFFFFFF).to_bytes(8, byteorder="big")


def _u32_to_bytes(value):
    return int(value & 0xFFFFFFFF).to_bytes(4, byteorder="big")


def _ensure_state_buffer(state):
    if state is None:
        raise ValueError("state must not be None")
    if len(state) < 40:
        raise ValueError("state buffer must be at least 40 bytes")


def _ensure_out_buffer(out, needed):
    if out is None:
        raise ValueError("out must not be None")
    if len(out) < needed:
        raise ValueError(f"output buffer must be at least {needed} bytes")


def _ensure_bytes_like(data, name):
    if data is None:
        raise ValueError(f"{name} must not be None")


def _get_state_ctx(state):
    ctx = _sha256_state_registry.get(id(state))
    if ctx is None:
        raise ValueError("state was not initialized with sha256_inc_init")
    return ctx


def _sync_state_bytes_from_ctx(state):
    ctx = _get_state_ctx(state)
    digest_so_far = ctx["hasher"].copy().digest()
    state[:32] = digest_so_far
    _store_bigendian_64(state[32:40], ctx["bytes_processed"])


def sha256_inc_init(state):
    """
    void sha256_inc_init(uint8_t *state);
    """
    _ensure_state_buffer(state)

    hasher = hashlib.sha256()
    _sha256_state_registry[id(state)] = {
        "hasher": hasher,
        "bytes_processed": 0,
    }
    state[:32] = hasher.copy().digest()
    state[32:40] = b"\x00" * 8


def sha256_inc_blocks(state, input, inblocks):
    """
    void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
    """
    _ensure_state_buffer(state)
    _ensure_bytes_like(input, "input")

    needed = SPX_SHA256_BLOCK_BYTES * inblocks
    if len(input) < needed:
        raise ValueError("sha256_inc_blocks: input buffer is too small")

    ctx = _get_state_ctx(state)
    ctx["hasher"].update(bytes(input[:needed]))
    ctx["bytes_processed"] += needed

    _sync_state_bytes_from_ctx(state)


def sha256_inc_finalize(out, state, input, inlen):
    """
    void sha256_inc_finalize(uint8_t *out, uint8_t *state,
                             const uint8_t *in, size_t inlen);

    Finalizes the incremental hash with the last inlen bytes and writes
    the 32-byte SHA-256 output to out
    """
    _ensure_out_buffer(out, SPX_SHA256_OUTPUT_BYTES)
    _ensure_state_buffer(state)
    _ensure_bytes_like(input, "input")

    if len(input) < inlen:
        raise ValueError("sha256_inc_finalize: input buffer is too small")

    ctx = _get_state_ctx(state)

    final_hasher = ctx["hasher"].copy()
    final_hasher.update(bytes(input[:inlen]))
    digest = final_hasher.digest()

    out[:SPX_SHA256_OUTPUT_BYTES] = digest

    ctx["hasher"].update(bytes(input[:inlen]))
    ctx["bytes_processed"] += inlen
    state[:32] = digest
    _store_bigendian_64(state[32:40], ctx["bytes_processed"])


def sha256(out, input, inlen):
    """
    void sha256(uint8_t *out, const uint8_t *in, size_t inlen);
    """
    _ensure_out_buffer(out, SPX_SHA256_OUTPUT_BYTES)
    _ensure_bytes_like(input, "input")

    if len(input) < inlen:
        raise ValueError("sha256: input buffer is too small")

    digest = hashlib.sha256(bytes(input[:inlen])).digest()
    out[:SPX_SHA256_OUTPUT_BYTES] = digest


def mgf1(out, outlen, input, inlen):
    """
    void mgf1(unsigned char *out, unsigned long outlen, const unsigned char *in, unsigned long inlen)

    MGF1 using SHA-256.
    """
    _ensure_out_buffer(out, outlen)
    _ensure_bytes_like(input, "input")

    if len(input) < inlen:
        raise ValueError("mgf1: input buffer is too small")

    inbuf_prefix = bytes(input[:inlen])
    outbuf = bytearray(SPX_SHA256_OUTPUT_BYTES)

    i = 0
    offset = 0

    while (i + 1) * SPX_SHA256_OUTPUT_BYTES <= outlen:
        inbuf = inbuf_prefix + _u32_to_bytes(i)
        sha256(out[offset:offset + SPX_SHA256_OUTPUT_BYTES], inbuf, len(inbuf))

        digest = hashlib.sha256(inbuf).digest()
        out[offset:offset + SPX_SHA256_OUTPUT_BYTES] = digest

        offset += SPX_SHA256_OUTPUT_BYTES
        i += 1

    remaining = outlen - i * SPX_SHA256_OUTPUT_BYTES
    if remaining > 0:
        inbuf = inbuf_prefix + _u32_to_bytes(i)
        sha256(outbuf, inbuf, len(inbuf))
        out[offset:offset + remaining] = outbuf[:remaining]



#Define a state seeded value for use in thash
state_seeded = bytearray(40)


def seed_state(pub_seed):
    """
    void seed_state(const unsigned char *pub_seed);
    """
    _ensure_bytes_like(pub_seed, "pub_seed")

    if len(pub_seed) < SPX_N:
        raise ValueError("seed_state: pub_seed is too small")

    block = bytearray(SPX_SHA256_BLOCK_BYTES)
    block[:SPX_N] = pub_seed[:SPX_N]
    for i in range(SPX_N, SPX_SHA256_BLOCK_BYTES):
        block[i] = 0

    sha256_inc_init(state_seeded)
    sha256_inc_blocks(state_seeded, block, 1)