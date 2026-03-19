#main.py

from dataclasses import dataclass
import argparse
from pathlib import Path
from typing import Iterable

from rng import randombytes_init
from sign import (
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
    CRYPTO_BYTES,
    crypto_sign_keypair,
    crypto_sign,
    crypto_sign_open
)

@dataclass
class KAT:
    count: int
    seed: bytes
    mlen: int
    msg: bytes
    pk: bytes | None = None
    sk: bytes | None = None
    smlen: int | None = None
    sm: bytes | None = None

def parse_hex_field(val: str) -> bytes:
    val = val.strip()
    if val == "":
        return b""
    return bytes.fromhex(val)

def parse_kat_file(path: str | Path)->list[KAT]:
    kats: list[KAT] = []
    text = Path(path).read_text(encoding="ascii")
    cases = [case.strip() for case in text.split("\n\n") if case.strip()]

    for case in cases:
        fields: dict[str, str] = {}
        for line in case.splitlines():
            if " = " not in line:
                continue
            k, v = line.split(" = ", 1)
            fields[k.strip()] = v.strip()

        if "count" not in fields:
            continue

        kats.append(
            KAT(
                                count=int(fields["count"]),
                seed=parse_hex_field(fields.get("seed", "")),
                mlen=int(fields.get("mlen", "0") or 0),
                msg=parse_hex_field(fields.get("msg", "")),
                pk=parse_hex_field(fields["pk"]) if "pk" in fields and fields["pk"] else None,
                sk=parse_hex_field(fields["sk"]) if "sk" in fields and fields["sk"] else None,
                smlen=int(fields["smlen"]) if "smlen" in fields and fields["smlen"] else None,
                sm=parse_hex_field(fields["sm"]) if "sm" in fields and fields["sm"] else None,
            )
        )
    
    return kats
    
def run_kats(req_kats: list[KAT]) -> tuple[list[KAT], list[tuple[int, str]]]:
    gen: list[KAT] = []
    fails: list[tuple[int, str]] = []

    for kat in req_kats:
        try:
            print("KAT generation count ="+str(kat.count))
            randombytes_init(bytearray(kat.seed), None, 256)

            pk = bytearray(CRYPTO_PUBLICKEYBYTES)
            sk = bytearray(CRYPTO_SECRETKEYBYTES)
            sig_test = crypto_sign_keypair(pk, sk)
            if sig_test!=0:
                raise RuntimeError("crypto_sign_keypair failed at count="+str(kat.count))
            
            sm = bytearray(kat.mlen+CRYPTO_BYTES)
            smlen_list = [0]
            sig_test = crypto_sign(sm, smlen_list, kat.msg, kat.mlen, sk)
            if sig_test!=0:
                raise RuntimeError("crypto_sign failed at count="+str(kat.count))
            smlen = smlen_list[0]

            open_sig = bytearray(kat.mlen)
            openlen = [0]
            sig_test = crypto_sign_open(open_sig, openlen, sm[:smlen], smlen, pk)
            if sig_test!=0:
                raise RuntimeError("crypto_sign_open failed at count="+str(kat.count))
            
            gen.append(
                KAT(
                    count=kat.count,
                    seed=kat.seed,
                    mlen=kat.mlen,
                    msg=kat.msg,
                    pk=bytes(pk),
                    sk=bytes(sk),
                    smlen=smlen,
                    sm=bytes(sm[:smlen]),
                )
            )

        except Exception as exc:
            fails.append((kat.count, str(exc)))

    return gen, fails

def format_rsp(kats: Iterable[KAT]) -> str:
    lines = []
    for kat in kats:
        lines.append(f"count = {kat.count}")
        lines.append(f"seed = {kat.seed.hex().upper()}")
        lines.append(f"mlen = {kat.mlen}")
        lines.append(f"msg = {kat.msg.hex().upper()}")
        lines.append(f"pk = {(kat.pk or b'').hex().upper()}")
        lines.append(f"sk = {(kat.sk or b'').hex().upper()}")
        lines.append(f"smlen = {kat.smlen if kat.smlen is not None else ''}")
        lines.append(f"sm = {(kat.sm or b'').hex().upper()}")
        lines.append("")
    return "\n".join(lines)

def compare_kats(gen: list[KAT], ref: list[KAT])->list[tuple[int, list[str]]]:
    fails: list[tuple[int, list[str]]] = []

    for i in range(min(len(ref), len(gen))):
        print("KAT test count ="+str(i))
        case_fail: list[str] = []
        if gen[i].count != ref[i].count:
            case_fail.append("count")
        if gen[i].seed != ref[i].seed:
            case_fail.append("seed")
        if gen[i].mlen != ref[i].mlen:
            case_fail.append("mlen")
        if gen[i].msg != ref[i].msg:
            case_fail.append("msg")
        if gen[i].pk != ref[i].pk:
            case_fail.append("pk")
        if gen[i].sk != ref[i].sk:
            case_fail.append("sk")
        if gen[i].smlen != ref[i].smlen:
            case_fail.append("smlen")
        if gen[i].sm != ref[i].sm:
            case_fail.append("sm")

        if case_fail:
            fails.append((ref[i].count, case_fail))

    return fails

def main()->int:
    argparser = argparse.ArgumentParser()
    argparser.add_argument("--req", type=Path, default=None, help="Override req path")
    argparser.add_argument("--rsp", type=Path, default=None, help="Override rsp path")
    argparser.add_argument("--limit", type=int, default=None, help="max KATs to test")
    args = argparser.parse_args()
    
    test_dir = Path(__file__).resolve().parent / "test"
    req_path = test_dir / "PQCsignKAT_128.req"
    rsp_path = test_dir / "PQCsignKAT_128.rsp"

    if args.req is not None:
        req_path = args.req
    if args.rsp is not None:
        rsp_path = args.rsp
    rsp_gen_path = rsp_path.with_name(rsp_path.stem+"_gen"+rsp_path.suffix)

    if not req_path.exists():
        print("Missing .req file")
        return 1
    if not rsp_path.exists():
        print("Missing .rsp file")
        return 1
    
    req_kats = parse_kat_file(req_path)
    rsp_kats = parse_kat_file(rsp_path)

    if args.limit is not None:
        req_kats = req_kats[:args.limit]
        rsp_kats = rsp_kats[:args.limit]

    gen_kats, fail_kats = run_kats(req_kats)

    print("Generation Done.")

    rsp_gen_path.parent.mkdir(parents=True, exist_ok=True)
    rsp_gen_path.write_text(format_rsp(gen_kats), encoding="ascii")

    print("Wrote to file "+str(rsp_gen_path))

    if fail_kats:
        print("KAT Generation Failures:")
        for count, msg in fail_kats:
            print(msg)
        return 1

    if len(gen_kats) != len(rsp_kats):
        print("KAT count mismatch: gen="+str(len(gen_kats))+", ref="+str(len(rsp_kats)))
        return 1
    
    print("Testing "+str(rsp_gen_path)+" against " +str(rsp_path))
    fail_kats = compare_kats(gen_kats, rsp_kats)

    if fail_kats:
        print("KAT Test Failures:")
        for count, fields in fail_kats:
            print("count="+str(count)+" at "+", ".join(fields))
        return 1
    
    print("All "+str(len(gen_kats))+" KATs passed. File:"+str(rsp_gen_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())