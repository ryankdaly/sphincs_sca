#thash_sha256_simple.py

from params import SPX_N
from sha256 import (
    SPX_SHA256_ADDR_BYTES, 
    SPX_SHA256_OUTPUT_BYTES, 
    state_seeded,
)

def thash(outval: bytearray, 
          inval: bytes|bytearray, 
          inblocks: int,
          pub_seed: bytes | bytearray,
          addr: bytes | bytearray )->None:
    buf = bytearray(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)
    outbuf = bytearray(SPX_SHA256_OUTPUT_BYTES)
    sha2_state = bytearray(40)

    _ = pub_seed

    sha2_state[0:40] = state_seeded[0:40]

    buf[0:SPX_SHA256_ADDR_BYTES] = addr[0:SPX_SHA256_ADDR_BYTES]
    buf[SPX_SHA256_ADDR_BYTES:SPX_SHA256_ADDR_BYTES + inblocks * SPX_N] = inval[0:inblocks * SPX_N]

    #insert sha256_inc_finalize here
    outval[0:SPX_N] = outbuf[0:SPX_N]
