from params import SPX_N
from sha256 import (
    SPX_SHA256_ADDR_BYTES, 
    SPX_SHA256_OUTPUT_BYTES, 
    #state_seeded,
    sha256_inc_finalize,
    SPX_SHA256_BLOCK_BYTES,
    sha256_inc_init,
    sha256_inc_blocks,
)

def thash(outval: bytearray, 
          inval: bytes|bytearray, 
          inblocks: int,
          pub_seed: bytes | bytearray,
          addr: bytes | bytearray )->None:
    buf = bytearray(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)
    outbuf = bytearray(SPX_SHA256_OUTPUT_BYTES)
    sha2_state = bytearray(40)

    block = bytearray(SPX_SHA256_BLOCK_BYTES)
    block[0:SPX_N] = pub_seed[0:SPX_N]

    sha256_inc_init(sha2_state)
    sha256_inc_blocks(sha2_state, block, 1)

    buf[0:SPX_SHA256_ADDR_BYTES] = addr[0:SPX_SHA256_ADDR_BYTES]
    buf[SPX_SHA256_ADDR_BYTES:SPX_SHA256_ADDR_BYTES + inblocks * SPX_N] = inval[0:inblocks * SPX_N]

    sha256_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)
    outval[0:SPX_N] = outbuf[0:SPX_N]
