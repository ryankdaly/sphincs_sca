"""
rng.py

This file uses the pycryptodome for AES. This dependancy needs to be installed:
pip install pycryptodome


"""

## Import AES from cryptodome
from Crypto.Cipher import AES

RNG_SUCCESS = 0
RNG_BAD_MAXLEN = -1
RNG_BAD_OUTBUF = -2
RNG_BAD_REQ_LEN = -3

class AES_XOF_struct:
    def __init__(self):
        self.buffer = bytearray(16)
        self.buffer_pos = 0
        self.length_remaining = 0
        self.key = bytearray(32)
        self.ctr = bytearray(16)


class AES256_CTR_DRBG_struct:
    def __init__(self):
        self.Key = bytearray(32)
        self.V = bytearray(16)
        self.reseed_counter = 0


DRBG_ctx = AES256_CTR_DRBG_struct()


def handleErrors():
    raise RuntimeError("OpenSSL/Python AES operation failed")

def AES256_ECB(key, ctr, buffer):
    """
    key    - 32-byte AES key
    ctr    - 16-byte plaintext block
    buffer - output bytearray of length >= 16
    """
    if key is None or ctr is None or buffer is None:
        handleErrors()

    if len(key) != 32:
        raise ValueError("AES256_ECB: key must be 32 bytes")
    if len(ctr) != 16:
        raise ValueError("AES256_ECB: ctr must be 16 bytes")
    if len(buffer) < 16:
        raise ValueError("AES256_ECB: buffer must have length at least 16")

    try:
        cipher = AES.new(bytes(key), AES.MODE_ECB)
        out = cipher.encrypt(bytes(ctr))
        buffer[:16] = out
    except Exception as e:
        raise RuntimeError(f"AES256_ECB failed: {e}") from e


def seedexpander_init(ctx, seed, diversifier, maxlen):
    """
    seedexpander_init(AES_XOF_struct *ctx,
                      unsigned char *seed,
                      unsigned char *diversifier,
                      unsigned long maxlen)
    """
    if maxlen >= 0x100000000:
        return RNG_BAD_MAXLEN

    if ctx is None:
        raise ValueError("seedexpander_init: ctx must not be None")
    if seed is None or len(seed) != 32:
        raise ValueError("seedexpander_init: seed must be 32 bytes")
    if diversifier is None or len(diversifier) != 8:
        raise ValueError("seedexpander_init: diversifier must be 8 bytes")

    ctx.length_remaining = maxlen

    ctx.key[:32] = seed[:32]

    ctx.ctr[:8] = diversifier[:8]
    ctx.ctr[11] = maxlen % 256
    maxlen >>= 8
    ctx.ctr[10] = maxlen % 256
    maxlen >>= 8
    ctx.ctr[9] = maxlen % 256
    maxlen >>= 8
    ctx.ctr[8] = maxlen % 256
    ctx.ctr[12:16] = b"\x00\x00\x00\x00"

    ctx.buffer_pos = 16
    ctx.buffer[:] = b"\x00" * 16

    return RNG_SUCCESS

def seedexpander(ctx, x, xlen):
    """
    seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen)

    x should be a bytearray with length >= xlen.
    """
    if x is None:
        return RNG_BAD_OUTBUF
    if xlen >= ctx.length_remaining:
        return RNG_BAD_REQ_LEN
    if len(x) < xlen:
        raise ValueError("seedexpander: output buffer x is too small")

    ctx.length_remaining -= xlen

    offset = 0
    while xlen > 0:
        if xlen <= (16 - ctx.buffer_pos):
            x[offset:offset + xlen] = ctx.buffer[ctx.buffer_pos:ctx.buffer_pos + xlen]
            ctx.buffer_pos += xlen
            return RNG_SUCCESS

        take = 16 - ctx.buffer_pos
        x[offset:offset + take] = ctx.buffer[ctx.buffer_pos:ctx.buffer_pos + take]
        xlen -= take
        offset += take

        AES256_ECB(ctx.key, ctx.ctr, ctx.buffer)
        ctx.buffer_pos = 0

        # incrementing the counter bytes ctr[12..15]
        for i in range(15, 11, -1):
            if ctx.ctr[i] == 0xFF:
                ctx.ctr[i] = 0x00
            else:
                ctx.ctr[i] += 1
                break

    return RNG_SUCCESS


def AES256_CTR_DRBG_Update(provided_data, Key, V):
    """
    AES256_CTR_DRBG_Update(unsigned char *provided_data,
                           unsigned char *Key,
                           unsigned char *V)
    """
    if Key is None or len(Key) != 32:
        raise ValueError("AES256_CTR_DRBG_Update: Key must be 32 bytes")
    if V is None or len(V) != 16:
        raise ValueError("AES256_CTR_DRBG_Update: V must be 16 bytes")
    if provided_data is not None and len(provided_data) != 48:
        raise ValueError("AES256_CTR_DRBG_Update: provided_data must be 48 bytes")

    temp = bytearray(48)

    for i in range(3):
        # incrementing V
        for j in range(15, -1, -1):
            if V[j] == 0xFF:
                V[j] = 0x00
            else:
                V[j] += 1
                break

        AES256_ECB(Key, V, temp[16 * i:16 * (i + 1)])
        block = bytearray(16)
        AES256_ECB(Key, V, block)
        temp[16 * i:16 * (i + 1)] = block

    if provided_data is not None:
        for i in range(48):
            temp[i] ^= provided_data[i]

    Key[:32] = temp[:32]
    V[:16] = temp[32:48]


def randombytes_init(entropy_input, personalization_string, security_strength):
    """
    randombytes_init(unsigned char *entropy_input,
                     unsigned char *personalization_string,
                     int security_strength)
    """
    if entropy_input is None or len(entropy_input) != 48:
        raise ValueError("randombytes_init: entropy_input must be 48 bytes")
    if personalization_string is not None and len(personalization_string) != 48:
        raise ValueError("randombytes_init: personalization_string must be 48 bytes")

    seed_material = bytearray(48)
    seed_material[:48] = entropy_input[:48]

    if personalization_string is not None:
        for i in range(48):
            seed_material[i] ^= personalization_string[i]

    DRBG_ctx.Key[:] = b"\x00" * 32
    DRBG_ctx.V[:] = b"\x00" * 16

    AES256_CTR_DRBG_Update(seed_material, DRBG_ctx.Key, DRBG_ctx.V)
    DRBG_ctx.reseed_counter = 1

def randombytes(x, xlen):
    """
    randombytes(unsigned char *x, unsigned long long xlen)

    x should be a bytearray with length >= xlen.
    """
    if x is None:
        return RNG_BAD_OUTBUF
    if len(x) < xlen:
        raise ValueError("randombytes: output buffer x is too small")

    block = bytearray(16)
    i = 0

    while xlen > 0:
        # increment V
        for j in range(15, -1, -1):
            if DRBG_ctx.V[j] == 0xFF:
                DRBG_ctx.V[j] = 0x00
            else:
                DRBG_ctx.V[j] += 1
                break

        AES256_ECB(DRBG_ctx.Key, DRBG_ctx.V, block)

        if xlen > 15:
            x[i:i + 16] = block
            i += 16
            xlen -= 16
        else:
            x[i:i + xlen] = block[:xlen]
            xlen = 0

    AES256_CTR_DRBG_Update(None, DRBG_ctx.Key, DRBG_ctx.V)
    DRBG_ctx.reseed_counter += 1

    return RNG_SUCCESS

