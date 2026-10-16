"""Deterministic Falcon-512 key generation from a 64-byte seed (prototype of the
"Starknet PQ key backup v0" profile). TESTNET / DEMO ONLY.

The seed is expanded with SHAKE-256 into a byte stream that replaces os.urandom inside
falcon.py's NTRU key generation (ntrugen.gen_poly -> samplerz). The same seed therefore
always yields the same Falcon key, so a mnemonic backup can restore it.

Non-normative: this reproduces keys only with the pinned falcon.py checkout. A production
profile should seed the Falcon reference C keygen with its SHAKE-256 PRNG instead (the
approach Algorand's falcon-signatures uses for Falcon-1024).

Usage: python -I falcon_from_seed.py --falcon-py <checkout> --seed-hex <128 hex> --key <out.json>
Writes the same key-file format as pq-accounts' falcon_signer.py.
"""
import argparse
import base64
import json
import pickle
import sys
from pathlib import Path

from hashlib import shake_256


class ShakeStream:
    """Deterministic randombytes(k) backed by one SHAKE-256 XOF stream."""

    def __init__(self, seed: bytes, domain: bytes):
        self.seed = domain + seed
        self.offset = 0
        self.buf = b""

    def randombytes(self, k: int) -> bytes:
        need = self.offset + k
        if need > len(self.buf):
            # Re-squeeze a longer prefix; XOF output is prefix-stable.
            self.buf = shake_256(self.seed).digest(max(need, 2 * len(self.buf), 4096))
        out = self.buf[self.offset:need]
        self.offset = need
        return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--falcon-py", type=Path, required=True)
    p.add_argument("--signer-dir", type=Path, required=True,
                   help="directory of pq-accounts falcon_signer.py (for the on-chain key packing)")
    p.add_argument("--seed-hex", required=True)
    p.add_argument("--key", type=Path, required=True)
    args = p.parse_args()

    sys.path.insert(0, str(args.signer_dir))
    from falcon_signer import pack_512  # type: ignore

    seed = bytes.fromhex(args.seed_hex.removeprefix("0x"))
    if len(seed) != 64:
        raise SystemExit("seed must be 64 bytes")

    sys.path.insert(0, str(args.falcon_py))
    import falcon as fpy  # type: ignore
    import ntrugen  # type: ignore
    from ntt import div_zq, ntt  # type: ignore

    stream = ShakeStream(seed, b"starknet-pq-backup-v0/falcon-512/keygen")
    real_samplerz = ntrugen.samplerz
    ntrugen.samplerz = lambda mu, sigma, sigmin, randombytes=None: real_samplerz(
        mu, sigma, sigmin, randombytes=stream.randombytes)
    try:
        scheme = fpy.Falcon(512)
        sk, _vk = scheme.keygen()
    finally:
        ntrugen.samplerz = real_samplerz

    f, g, _F, _G, _B0, _T = sk
    h = div_zq(g, f)
    public_key = pack_512(ntt(h))
    args.key.parent.mkdir(parents=True, exist_ok=True)
    args.key.write_text(json.dumps({
        "format": "pq-accounts-falcon-python-v1",
        "scheme": "falcon-512",
        "derivation": "starknet-pq-backup-v0 (deterministic, testnet only)",
        "public_key": [hex(v) for v in public_key],
        "h": h,
        "secret_pickle_b64": base64.b64encode(pickle.dumps(sk)).decode("ascii"),
    }, indent=2) + "\n")
    print(json.dumps({"publicKey": [hex(v) for v in public_key], "bytesUsed": stream.offset}))


if __name__ == "__main__":
    main()
