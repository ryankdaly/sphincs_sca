# params.py

#hash output length in bytes
SPX_N = 32
#height of the hypertree.
SPX_FULL_HEIGHT = 68
#number of subtree layer
SPX_D = 17
#FORS tree dimensions
SPX_FORS_HEIGHT = 9
SPX_FORS_TREES = 35
#Winternitz parameter
SPX_WOTS_W = 16
#for clarity
SPX_ADDR_BYTES = 32
#WOTS parameters
if SPX_WOTS_W == 256:
    SPX_WOTS_LOGW = 8
elif SPX_WOTS_W == 16:
    SPX_WOTS_LOGW = 4
else:
    raise ValueError ("SPX_WOTS_W assumed 16 or 256")
SPX_WOTS_LEN1 = (8 * SPX_N // SPX_WOTS_LOGW)
#precompute SPX_WOTS_LEN2 = floor(log(len_1 * (w - 1)) / log(w)) + 1
if SPX_WOTS_W == 256:
    if SPX_N <= 1:
        SPX_WOTS_LEN2 = 1
    elif SPX_N <= 256:
        SPX_WOTS_LEN2 = 2
    else:
        raise ValueError ("Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}")
elif SPX_WOTS_W == 16:
    if SPX_N <= 8:
        SPX_WOTS_LEN2 = 2
    elif SPX_N <= 136:
        SPX_WOTS_LEN2 = 3
    elif SPX_N <= 256:
        SPX_WOTS_LEN2 = 4
    else:
        raise ValueError ("Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}")
SPX_WOTS_LEN = (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
SPX_WOTS_BYTES = (SPX_WOTS_LEN * SPX_N)
SPX_WOTS_PK_BYTES = SPX_WOTS_BYTES
#subtree size
SPX_TREE_HEIGHT = (SPX_FULL_HEIGHT // SPX_D)
if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT:
    raise ValueError ("SPX_D should always divide SPX_FULL_HEIGHT")
#FORS parameters
SPX_FORS_MSG_BYTES = ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) // 8)
SPX_FORS_BYTES = ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
SPX_FORS_PK_BYTES = SPX_N
#resulting SPX sizes
SPX_BYTES = (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N)
SPX_PK_BYTES = (2 * SPX_N)
SPX_SK_BYTES = (2 * SPX_N + SPX_PK_BYTES)
# optional
SPX_OPTRAND_BYTES = 32
#offsets
SPX_OFFSET_LAYER = 0
SPX_OFFSET_TREE = 1
SPX_OFFSET_TYPE = 9
SPX_OFFSET_KP_ADDR2 = 12
SPX_OFFSET_KP_ADDR1 = 13
SPX_OFFSET_CHAIN_ADDR = 17
SPX_OFFSET_HASH_ADDR = 21
SPX_OFFSET_TREE_HGT = 17
SPX_OFFSET_TREE_INDEX = 18
#api
CRYPTO_SECRETKEYBYTES = SPX_SK_BYTES
CRYPTO_PUBLICKEYBYTES = SPX_PK_BYTES
CRYPTO_BYTES = SPX_BYTES
CRYPTO_SEEDBYTES = 3*SPX_N
