"""
PQCgenKAT_sign.py


"""


from rng import randombytes_init, randombytes
from sign import (
    CRYPTO_ALGNAME,
    CRYPTO_SECRETKEYBYTES,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_BYTES,
    crypto_sign_keypair,
    crypto_sign,
    crypto_sign_open,
)

MAX_MARKER_LEN = 50

KAT_SUCCESS = 0
KAT_FILE_OPEN_ERROR = -1
KAT_DATA_ERROR = -3
KAT_CRYPTO_FAILURE = -4

AlgName = "algorithm name placeholder"

def FindMarker(infile, marker):
    """
    int FindMarker(FILE *infile, const char *marker)

    Searches forward in the file until marker is found and leaves the file position immediately after the marker
    Returns 1 if found, else 0
    """
    if infile is None:
        return 0

    marker = str(marker)
    length = len(marker)
    if length > MAX_MARKER_LEN - 1:
        length = MAX_MARKER_LEN - 1
        marker = marker[:length]

    line_chars = []

    for _ in range(length):
        ch = infile.read(1)
        if ch == "":
            return 0
        line_chars.append(ch)

    line = "".join(line_chars)

    while True:
        if line == marker:
            return 1

        ch = infile.read(1)
        if ch == "":
            return 0

        line = line[1:] + ch


def ReadHex(infile, A, Length, string_marker):
    """
    int ReadHex(FILE *infile, unsigned char *A, int Length, char *str)

    Reads a hexadecimal value that follows the given marker string and writes the parsed bytes into A
    Returns 1 on success, 0 on failure
    """
    if infile is None or A is None:
        return 0

    if Length == 0:
        if len(A) > 0:
            A[0] = 0x00
        return 1

    if len(A) < Length:
        raise ValueError("ReadHex: output buffer A is too small")

    for i in range(Length):
        A[i] = 0x00

    started = 0

    if not FindMarker(infile, string_marker):
        return 0

    while True:
        ch = infile.read(1)
        if ch == "":
            break

        if not ch.isdigit() and ch.lower() not in "abcdef":
            if not started:
                if ch == "\n":
                    break
                else:
                    continue
            else:
                break

        started = 1

        if "0" <= ch <= "9":
            ich = ord(ch) - ord("0")
        elif "A" <= ch <= "F":
            ich = ord(ch) - ord("A") + 10
        elif "a" <= ch <= "f":
            ich = ord(ch) - ord("a") + 10
        else:
            ich = 0

        for i in range(Length - 1):
            A[i] = ((A[i] << 4) & 0xFF) | (A[i + 1] >> 4)
        A[Length - 1] = ((A[Length - 1] << 4) & 0xFF) | ich

    return 1


def fprintBstr(fp, S, A, L):
    """
    void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
    """
    fp.write(str(S))

    if L == 0:
        fp.write("00\n")
        return

    if A is None:
        raise ValueError("fprintBstr: A must not be None when L > 0")
    if len(A) < L:
        raise ValueError("fprintBstr: buffer A is too small")

    fp.write("".join(f"{A[i]:02X}" for i in range(L)))
    fp.write("\n")


def _read_decimal_after_marker(infile, marker):
    """
    Helper function for main
    """
    if not FindMarker(infile, marker):
        return None

    digits = []
    while True:
        ch = infile.read(1)
        if ch == "":
            break
        if ch.isdigit():
            digits.append(ch)
        elif digits:
            break

    if not digits:
        return None

    return int("".join(digits))


def main():
    fn_req = f"PQCsignKAT_{CRYPTO_SECRETKEYBYTES}.req"
    fn_rsp = f"PQCsignKAT_{CRYPTO_SECRETKEYBYTES}.rsp"

    try:
        fp_req = open(fn_req, "w", encoding="ascii")
    except OSError:
        print(f"Couldn't open <{fn_req}> for write")
        return KAT_FILE_OPEN_ERROR

    try:
        fp_rsp = open(fn_rsp, "w", encoding="ascii")
    except OSError:
        fp_req.close()
        print(f"Couldn't open <{fn_rsp}> for write")
        return KAT_FILE_OPEN_ERROR

    seed = bytearray(48)
    msg = bytearray(3300)
    entropy_input = bytearray(range(48))

    randombytes_init(entropy_input, None, 256)

    for i in range(100):
        fp_req.write(f"count = {i}\n")

        randombytes(seed, 48)
        fprintBstr(fp_req, "seed = ", seed, 48)

        mlen = 33 * (i + 1)
        fp_req.write(f"mlen = {mlen}\n")

        randombytes(msg, mlen)
        fprintBstr(fp_req, "msg = ", msg, mlen)

        fp_req.write("pk =\n")
        fp_req.write("sk =\n")
        fp_req.write("smlen =\n")
        fp_req.write("sm =\n\n")

    fp_req.close()

    try:
        fp_req = open(fn_req, "r", encoding="ascii")
    except OSError:
        fp_rsp.close()
        print(f"Couldn't open <{fn_req}> for read")
        return KAT_FILE_OPEN_ERROR

    fp_rsp.write(f"# {CRYPTO_ALGNAME}\n\n")

    done = 0
    while not done:
        count = _read_decimal_after_marker(fp_req, "count = ")
        if count is None:
            done = 1
            break

        fp_rsp.write(f"count = {count}\n")

        if not ReadHex(fp_req, seed, 48, "seed = "):
            print(f"ERROR: unable to read 'seed' from <{fn_req}>")
            fp_req.close()
            fp_rsp.close()
            return KAT_DATA_ERROR

        fprintBstr(fp_rsp, "seed = ", seed, 48)
        randombytes_init(seed, None, 256)

        mlen = _read_decimal_after_marker(fp_req, "mlen = ")
        if mlen is None:
            print(f"ERROR: unable to read 'mlen' from <{fn_req}>")
            fp_req.close()
            fp_rsp.close()
            return KAT_DATA_ERROR

        fp_rsp.write(f"mlen = {mlen}\n")

        m = bytearray(mlen)
        m1 = bytearray(mlen + CRYPTO_BYTES)
        sm = bytearray(mlen + CRYPTO_BYTES)

        if not ReadHex(fp_req, m, int(mlen), "msg = "):
            print(f"ERROR: unable to read 'msg' from <{fn_req}>")
            fp_req.close()
            fp_rsp.close()
            return KAT_DATA_ERROR

        fprintBstr(fp_rsp, "msg = ", m, mlen)

        pk = bytearray(CRYPTO_PUBLICKEYBYTES)
        sk = bytearray(CRYPTO_SECRETKEYBYTES)

        ret_val = crypto_sign_keypair(pk, sk)
        if ret_val != 0:
            print(f"crypto_sign_keypair returned <{ret_val}>")
            fp_req.close()
            fp_rsp.close()
            return KAT_CRYPTO_FAILURE

        fprintBstr(fp_rsp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES)
        fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES)

        smlen_box = [0]
        ret_val = crypto_sign(sm, smlen_box, m, mlen, sk)
        smlen = smlen_box[0]

        if ret_val != 0:
            print(f"crypto_sign returned <{ret_val}>")
            fp_req.close()
            fp_rsp.close()
            return KAT_CRYPTO_FAILURE

        fp_rsp.write(f"smlen = {smlen}\n")
        fprintBstr(fp_rsp, "sm = ", sm, smlen)
        fp_rsp.write("\n")

        mlen1_box = [0]
        ret_val = crypto_sign_open(m1, mlen1_box, sm, smlen, pk)
        mlen1 = mlen1_box[0]

        if ret_val != 0:
            print(f"crypto_sign_open returned <{ret_val}>")
            fp_req.close()
            fp_rsp.close()
            return KAT_CRYPTO_FAILURE

        if mlen != mlen1:
            print(
                f"crypto_sign_open returned bad 'mlen': "
                f"Got <{mlen1}>, expected <{mlen}>"
            )
            fp_req.close()
            fp_rsp.close()
            return KAT_CRYPTO_FAILURE

        if m[:mlen] != m1[:mlen]:
            print("crypto_sign_open returned bad 'm' value")
            fp_req.close()
            fp_rsp.close()
            return KAT_CRYPTO_FAILURE

    fp_req.close()
    fp_rsp.close()

    return KAT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())