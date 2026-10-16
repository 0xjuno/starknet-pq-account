"""Independent check of a browser (noble) Falcon-512 signature against the on-chain SHAKE-256
acceptance rule, computed with falcon.py + pq-accounts' falcon_signer helpers.

Input JSON (stdin): {"hash": "0x..", "nonce_hex": "..", "s2": [..512 ints..], "h": [..512 ints..]}
Output JSON: {"ok": bool, "norm": int, "pkFelts": [hex..], "sigFelts": [hex..]}
"""
import argparse
import json
import sys
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--falcon-py", type=Path, required=True)
    p.add_argument("--signer-dir", type=Path, required=True)
    args = p.parse_args()
    sys.path.insert(0, str(args.falcon_py))
    sys.path.insert(0, str(args.signer_dir))
    from ntt import ntt, mul_zq  # type: ignore
    from falcon_signer import pack_512, h2p_shake256, centered, Q, SIG_BOUND_512  # type: ignore

    req = json.loads(sys.stdin.read())
    message_hash = int(req["hash"], 16)
    salt = bytes.fromhex(req["nonce_hex"])
    h = [int(v) for v in req["h"]]
    s1 = [int(v) % Q for v in req["s2"]]  # transmitted Falcon component, on-chain "s1"

    point = h2p_shake256(message_hash, salt)
    mul_hint = mul_zq(s1, h)
    norm = sum(centered((point[i] - mul_hint[i]) % Q) ** 2 + centered(s1[i]) ** 2 for i in range(512))
    ok = norm <= SIG_BOUND_512
    salt_a = int.from_bytes(salt[:20], "little")
    salt_b = int.from_bytes(salt[20:], "little")
    print(json.dumps({
        "ok": ok,
        "norm": norm,
        "pkFelts": [hex(v) for v in pack_512(ntt(h))],
        "sigFelts": [hex(v) for v in pack_512(s1) + [salt_a, salt_b] + pack_512(mul_hint)],
    }))


if __name__ == "__main__":
    main()
