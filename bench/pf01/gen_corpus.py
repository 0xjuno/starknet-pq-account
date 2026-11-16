#!/usr/bin/env python3
"""Generate the PF-01 public Falcon-512 SHAKE-256 corpus.

The challenge scores the mean Sierra gas over 27 held-out signatures, 11 needing eight SHAKE-256
blocks and 16 needing nine. That corpus is private, so this script builds a public one in the
same mix: three falcon.py keys, messages derived from a fixed label, and salts searched until
the hash-to-point needs the wanted number of blocks (the search costs only SHAKE time, so the
block count is chosen before signing). Every signature is checked against the challenge's
reference verifier before it is written.

Signing uses falcon.py's ffSampling sampler, which draws from os.urandom, so a rerun gives a
different (equally valid) corpus. The committed corpus.json is the pinned artifact.

Usage:
    python3 -I bench/pf01/gen_corpus.py --falcon-py PATH --reference PATH/falcon512.py \
        [--out bench/pf01/corpus.json]
Dependencies (for falcon.py): numpy, pycryptodome, beartype.
"""

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

LABEL = b"starknet-pq-account/pf01-corpus-v1"
FELT_PRIME = 2**251 + 17 * 2**192 + 1
# (eight-block, nine-block) signatures per key: 11 and 16 in total, the evaluator's mix.
PLAN = [(4, 5), (4, 5), (3, 6)]


def derive(*parts: object) -> bytes:
    return hashlib.sha512(LABEL + b"|" + b"|".join(str(p).encode() for p in parts)).digest()


def load_reference(path: Path):
    spec = importlib.util.spec_from_file_location("falcon512_reference", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def words_used(ref, message: int, salt: bytes) -> int:
    """How many 16-bit words the hash-to-point reads (finer than the block count)."""
    shake = hashlib.shake_256(salt + message.to_bytes(32, "little"))
    stream = shake.digest(ref.WORDS_PER_BLOCK * 2 * 12)
    accepted = used = 0
    while accepted < ref.N:
        word = (stream[2 * used] << 8) | stream[2 * used + 1]
        used += 1
        if word < ref.ACCEPT_BELOW:
            accepted += 1
    return used


def find_salt(ref, message: int, key: int, index: int, blocks: int, worst: bool) -> bytes:
    """First salt (or, with `worst`, the most expensive of the first 2,000 matching salts)
    whose hash-to-point needs exactly `blocks` blocks."""
    best = None
    matches = 0
    ctr = 0
    while True:
        salt = derive("salt", key, index, ctr)[:40]
        ctr += 1
        _, b = ref.hash_to_point(message, salt)
        if b != blocks:
            continue
        if not worst:
            return salt
        used = words_used(ref, message, salt)
        if best is None or used > best[0]:
            best = (used, salt)
        matches += 1
        if matches == 2000:
            return best[1]


def sign(scheme, mul_zq, sk, h, point, bound):
    _, _, _, _, B0_fft, T_fft = sk
    while True:
        s = scheme.__sample_preimage__(B0_fft, T_fft, point)
        norm = sum(c * c for c in s[0]) + sum(c * c for c in s[1])
        if norm <= bound:
            break
    s1 = [c % 12289 for c in s[1]]
    return s1, mul_zq(s1, h)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--falcon-py", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path(__file__).with_name("corpus.json"))
    args = parser.parse_args()

    sys.path.insert(0, str(args.falcon_py))
    import falcon as fpy  # noqa: E402
    from ntt import div_zq, mul_zq, ntt  # noqa: E402

    ref = load_reference(args.reference)
    scheme = fpy.Falcon(512)
    assert scheme.param.sig_bound == ref.SIG_BOUND

    vectors = []
    for key, (n8, n9) in enumerate(PLAN):
        print(f"key {key}: keygen...", flush=True)
        sk, _ = scheme.keygen()
        f, g = sk[0], sk[1]
        h = div_zq(g, f)
        pk = ref.pack_512(ntt(h))
        wanted = [8] * n8 + [9] * n9
        for index, blocks in enumerate(wanted):
            message = int.from_bytes(derive("msg", key, index)[:32], "big") % FELT_PRIME
            # The last nine-block signature of the last key is the most expensive salt found.
            worst = key == len(PLAN) - 1 and index == len(wanted) - 1
            salt = find_salt(ref, message, key, index, blocks, worst)
            point, b = ref.hash_to_point(message, salt)
            assert b == blocks
            s1, hint = sign(scheme, mul_zq, sk, h, point, ref.SIG_BOUND)
            salt_a = int.from_bytes(salt[:20], "little")
            salt_b = int.from_bytes(salt[20:], "little")
            signature = ref.pack_512(s1) + [salt_a, salt_b] + ref.pack_512(hint)
            verdict = ref.verify(message, pk, signature)
            assert verdict.valid and verdict.blocks == blocks, verdict
            vectors.append({
                "id": len(vectors),
                "key": key,
                "blocks": blocks,
                "words_used": words_used(ref, message, salt),
                "norm": verdict.norm,
                "worst_salt_search": worst,
                "message": hex(message),
                "public_key": [hex(x) for x in pk],
                "signature": [hex(x) for x in signature],
            })
            print(f"  #{vectors[-1]['id']}: {blocks} blocks, {vectors[-1]['words_used']} words, "
                  f"norm {verdict.norm}", flush=True)

    args.out.write_text(json.dumps({
        "description": "Public Falcon-512 SHAKE-256 corpus for PF-01 (11 eight-block, 16 nine-block).",
        "label": LABEL.decode(),
        "signer": "tprest/falcon.py 5145a818c9512b4a443507d3375e75dae3076af6",
        "reference": "https://postquantum.provably.fast/reference/falcon512.py",
        "reference_sha256": hashlib.sha256(args.reference.read_bytes()).hexdigest(),
        "vectors": vectors,
    }, indent=1) + "\n")
    print(f"wrote {args.out} ({len(vectors)} vectors)")


if __name__ == "__main__":
    main()
