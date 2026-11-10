#!/usr/bin/env python3
"""Generate the PF-03 differential vectors, each with the reference verifier's verdict.

The challenge's reference verifier (falcon512.py) is the authority: every vector's `expected`
is what it answers. Categories:

  valid      falcon.py and noble signatures, including messages 0 and p - 1, salts of all
             zero and all 0xff bytes (salt halves 0 and 2^160 - 1), salts that read many SHAKE
             words, and a signature whose norm is just under the bound;
  tampered   message, salt and s1/hint changes, another key, swapped felts, an s1 re-hinted to
             match (passes the hint check, fails the norm), and a signature just over the bound;
  malformed  non-canonical encodings just past each range, salt halves of 2^160, wrong lengths;
  random     seeded random mutations of valid vectors.

Norm-edge signatures add multiples of x^k * (g, -f) to a sampled signature (s0, s1). That keeps
s0 + s1 * h = point, because g - f * h = 0 mod q, and moves the norm in steps of a few thousand,
so a greedy walk lands just under, then just over, the bound.

Usage:
    node bench/pf03/noble_vectors.mjs > NOBLE.json
    python3 -I bench/pf03/gen_vectors.py --falcon-py PATH --reference PATH/falcon512.py \
        --noble NOBLE.json [--seed 1] [--out bench/pf03/vectors.json]
Dependencies (for falcon.py): numpy, pycryptodome, beartype.
"""

import argparse
import hashlib
import importlib.util
import json
import random
import sys
from pathlib import Path

import numpy as np

LABEL = b"starknet-pq-account/pf03-v1"
FELT_PRIME = 2**251 + 17 * 2**192 + 1
Q = 12289
Q9 = Q**9
Q8 = Q**8
RANDOM_MUTATIONS = 60


def derive(*parts: object) -> bytes:
    return hashlib.sha512(LABEL + b"|" + b"|".join(str(p).encode() for p in parts)).digest()


def load_reference(path: Path):
    spec = importlib.util.spec_from_file_location("falcon512_reference", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def words_used(ref, message: int, salt: bytes) -> int:
    stream = hashlib.shake_256(salt + message.to_bytes(32, "little")).digest(ref.WORDS_PER_BLOCK * 2 * 12)
    accepted = used = 0
    while accepted < ref.N:
        word = (stream[2 * used] << 8) | stream[2 * used + 1]
        used += 1
        accepted += word < ref.ACCEPT_BELOW
    return used


def centered(x: int) -> int:
    x %= Q
    return x if x <= (Q - 1) // 2 else x - Q


class Key:
    def __init__(self, scheme, mods, ref, name: str):
        div_zq, self.mul_zq, ntt = mods
        self.scheme, self.ref, self.name = scheme, ref, name
        self.sk, _ = scheme.keygen()
        self.f, self.g = self.sk[0], self.sk[1]
        self.h = div_zq(self.g, self.f)
        self.pk = ref.pack_512(ntt(self.h))

    def sample(self, point):
        _, _, _, _, B0_fft, T_fft = self.sk
        while True:
            s = self.scheme.__sample_preimage__(B0_fft, T_fft, point)
            if sum(c * c for c in s[0]) + sum(c * c for c in s[1]) <= self.ref.SIG_BOUND:
                return [list(s[0]), list(s[1])]

    def felts(self, salt: bytes, s1: list[int]) -> list[int]:
        s1q = [c % Q for c in s1]
        hint = self.mul_zq(s1q, self.h)
        return self.ref.pack_512(s1q) + [int.from_bytes(salt[:20], "little"),
                                         int.from_bytes(salt[20:], "little")] + self.ref.pack_512(hint)


def rotations(poly: list[int]) -> np.ndarray:
    """Row k is poly * x^k mod (x^512 + 1)."""
    n = len(poly)
    rows = np.zeros((n, n), dtype=np.int64)
    for k in range(n):
        for i, c in enumerate(poly):
            j = i + k
            rows[k, j % n] += c if j < n else -c
    return rows


def norm_edge(key: Key, s, bound: int):
    """Walk s = (s0, s1) by +-x^k (g, -f) to the closest norm <= bound, then one step over it.
    Returns (under, over) as (s0, s1, norm) triples."""
    G, F = rotations(key.g), rotations(key.f)
    s0, s1 = np.array(s[0], dtype=np.int64), np.array(s[1], dtype=np.int64)
    b2 = int((G * G).sum(axis=1)[0] + (F * F).sum(axis=1)[0])

    def candidates(s0, s1):
        # norm change for +b_k is 2 <s, b_k> + |b|^2 and for -b_k it is -2 <s, b_k> + |b|^2
        dots = G @ s0 - F @ s1
        return np.concatenate([2 * dots + b2, -2 * dots + b2])

    def step(s0, s1, i):
        k, sign = i % 512, 1 if i < 512 else -1
        return s0 + sign * G[k], s1 - sign * F[k]

    norm = int((s0 * s0).sum() + (s1 * s1).sum())
    while True:
        new = norm + candidates(s0, s1)
        ok = np.where(new <= bound, new, -1)
        i = int(ok.argmax())
        if ok[i] <= norm:
            break
        s0, s1 = step(s0, s1, i)
        norm = int(ok[i])
    new = norm + candidates(s0, s1)
    over = np.where(new > bound, new, np.iinfo(np.int64).max)
    j = int(over.argmin())
    o0, o1 = step(s0, s1, j)
    return (s0.tolist(), s1.tolist(), norm), (o0.tolist(), o1.tolist(), int(over[j]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--falcon-py", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--noble", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", type=Path, default=Path(__file__).with_name("vectors.json"))
    args = parser.parse_args()

    sys.path.insert(0, str(args.falcon_py))
    import falcon as fpy  # noqa: E402
    from ntt import div_zq, mul_zq, ntt  # noqa: E402

    ref = load_reference(args.reference)
    scheme = fpy.Falcon(512)
    assert scheme.param.sig_bound == ref.SIG_BOUND
    vectors = []

    def add(category, description, source, key, message, pk, sig):
        verdict = ref.verify(message, pk, sig)
        vectors.append({
            "id": len(vectors), "category": category, "description": description,
            "source": source, "key": key, "message": hex(message),
            "public_key": [hex(x) for x in pk], "signature": [hex(x) for x in sig],
            "expected": verdict.valid, "reason": verdict.reason,
            "blocks": verdict.blocks, "norm": verdict.norm,
        })
        if category == "valid":
            assert verdict.valid, (description, verdict)
        return vectors[-1]

    print("keygen...", flush=True)
    keys = [Key(scheme, (div_zq, mul_zq, ntt), ref, f"falcon.py-{i}") for i in range(2)]
    k0, k1 = keys

    def signed(key, message, salt):
        point, _ = ref.hash_to_point(message, salt)
        return key.felts(salt, key.sample(point)[1])

    # --- valid ---------------------------------------------------------------------------------
    base_msg = int.from_bytes(derive("msg", 0)[:32], "big") % FELT_PRIME
    base_salt = derive("salt", 0)[:40]
    base = add("valid", "falcon.py signature", "falcon.py", k0.name, base_msg, k0.pk,
               signed(k0, base_msg, base_salt))
    for message, what in [(0, "message 0"), (FELT_PRIME - 1, "message p - 1")]:
        add("valid", what, "falcon.py", k0.name, message, k0.pk,
            signed(k0, message, derive("salt", what)[:40]))
    for salt, what in [(b"\x00" * 40, "salt halves 0, 0"), (b"\xff" * 40, "salt halves 2^160 - 1")]:
        add("valid", what, "falcon.py", k1.name, base_msg, k1.pk, signed(k1, base_msg, salt))

    print("searching high-word salts...", flush=True)
    found, ctr = [], 0
    while len(found) < 3:
        salt = derive("high", ctr)[:40]
        ctr += 1
        if words_used(ref, base_msg, salt) >= 565:
            found.append(salt)
    best = max((derive("high", c)[:40] for c in range(ctr, ctr + 30000)),
               key=lambda s: words_used(ref, base_msg, s))
    for salt in found + [best]:
        add("valid", f"{words_used(ref, base_msg, salt)} SHAKE words", "falcon.py", k1.name,
            base_msg, k1.pk, signed(k1, base_msg, salt))

    print("walking to the norm bound...", flush=True)
    edge_msg = int.from_bytes(derive("msg", "edge")[:32], "big") % FELT_PRIME
    edge_salt = derive("salt", "edge")[:40]
    point, _ = ref.hash_to_point(edge_msg, edge_salt)
    under, over = norm_edge(k0, k0.sample(point), ref.SIG_BOUND)
    add("valid", f"norm {under[2]}, {ref.SIG_BOUND - under[2]} under the bound", "falcon.py",
        k0.name, edge_msg, k0.pk, k0.felts(edge_salt, under[1]))

    noble = json.loads(args.noble.read_text())
    noble_vectors = []
    for v in noble["vectors"]:
        noble_vectors.append(add("valid", "noble signature", "noble", v["key"], int(v["message"], 16),
                                 [int(x, 16) for x in v["public_key"]],
                                 [int(x, 16) for x in v["signature"]]))

    # --- tampered ------------------------------------------------------------------------------
    add("tampered", f"norm {over[2]}, {over[2] - ref.SIG_BOUND} over the bound", "falcon.py",
        k0.name, edge_msg, k0.pk, k0.felts(edge_salt, over[1]))

    def tamper_set(v):
        msg = int(v["message"], 16)
        pk = [int(x, 16) for x in v["public_key"]]
        sig = [int(x, 16) for x in v["signature"]]
        src, key = v["source"], v["key"]
        s1 = ref.unpack_512(sig[:29])
        hint = ref.unpack_512(sig[31:])

        def with_(seq, i, value):
            out = list(seq)
            out[i] = value
            return out

        def swapped(seq, i, j):
            out = list(seq)
            out[i], out[j] = out[j], out[i]
            return out

        add("tampered", "message + 1", src, key, (msg + 1) % FELT_PRIME, pk, sig)
        add("tampered", "salt_a + 1", src, key, msg, pk, with_(sig, 29, sig[29] + 1))
        add("tampered", "salt_b + 1", src, key, msg, pk, with_(sig, 30, sig[30] + 1))
        add("tampered", "s1 felts 0 and 1 swapped", src, key, msg, pk, swapped(sig, 0, 1))
        add("tampered", "hint felts 31 and 32 swapped", src, key, msg, pk, swapped(sig, 31, 32))
        add("tampered", "public key felts 0 and 1 swapped", src, key, msg, swapped(pk, 0, 1), sig)
        bumped = list(s1)
        bumped[0] = (bumped[0] + 1) % Q
        add("tampered", "s1[0] + 1, hint unchanged", src, key, msg, pk,
            ref.pack_512(bumped) + sig[29:31] + sig[31:])
        h = [x for x in __import__("ntt").intt(ref.unpack_512(pk))]
        rehint = mul_zq(bumped, h)
        add("tampered", "s1[0] + 1, re-hinted to match (fails the norm)", src, key, msg, pk,
            ref.pack_512(bumped) + sig[29:31] + ref.pack_512(rehint))
        h_bumped = list(hint)
        h_bumped[511] = (h_bumped[511] + 1) % Q
        add("tampered", "hint[511] + 1", src, key, msg, pk, sig[:31] + ref.pack_512(h_bumped))
        other = k1.pk if pk != k1.pk else k0.pk
        add("tampered", "another key", src, key, msg, other, sig)

    tamper_set(base)
    tamper_set(noble_vectors[2])

    # --- malformed -----------------------------------------------------------------------------
    msg = int(base["message"], 16)
    pk = [int(x, 16) for x in base["public_key"]]
    sig = [int(x, 16) for x in base["signature"]]

    def at(seq, i, value):
        out = list(seq)
        out[i] = value
        return out

    lo = lambda x: x & ((1 << 128) - 1)  # noqa: E731
    hi = lambda x: x >> 128  # noqa: E731
    for where, seq_name, i in [("public key", "pk", 0), ("s1", "sig", 0), ("hint", "sig", 31)]:
        target = pk if seq_name == "pk" else sig
        f = target[i]
        for value, what in [((hi(f) << 128) | Q9, "low half = q^9"),
                            ((Q9 << 128) | lo(f), "high half = q^9"),
                            ((hi(f) << 128) | (Q9 - 1), "low half = q^9 - 1 (canonical, all digits q - 1)"),
                            ((((1 << 123) - 1) << 128) | lo(f), "high half = 2^123 - 1"),
                            (FELT_PRIME - 1, "felt = p - 1")]:
            changed = at(target, i, value)
            add("malformed", f"{where} felt {i}: {what}", "falcon.py", k0.name, msg,
                changed if seq_name == "pk" else pk, sig if seq_name == "pk" else changed)
    for where, seq_name, i in [("public key", "pk", 28), ("s1", "sig", 28), ("hint", "sig", 59)]:
        target = pk if seq_name == "pk" else sig
        for value, what in [(Q8, "last felt = q^8"), (Q8 - 1, "last felt = q^8 - 1 (canonical)"),
                            ((1 << 128) | target[i], "last felt with a high half")]:
            changed = at(target, i, value)
            add("malformed", f"{where} felt {i}: {what}", "falcon.py", k0.name, msg,
                changed if seq_name == "pk" else pk, sig if seq_name == "pk" else changed)
    for i, name in [(29, "salt_a"), (30, "salt_b")]:
        add("malformed", f"{name} = 2^160", "falcon.py", k0.name, msg, pk, at(sig, i, 1 << 160))
        add("malformed", f"{name} = p - 1", "falcon.py", k0.name, msg, pk, at(sig, i, FELT_PRIME - 1))
    for n in (0, 28, 30):
        add("malformed", f"public key of {n} felts", "falcon.py", k0.name, msg, (pk + [0])[:n], sig)
    for n in (0, 31, 59, 61):
        add("malformed", f"signature of {n} felts", "falcon.py", k0.name, msg, pk, (sig + [0])[:n])

    # --- random --------------------------------------------------------------------------------
    rng = random.Random(args.seed)
    pool = [v for v in vectors if v["category"] == "valid"]
    for _ in range(RANDOM_MUTATIONS):
        v = rng.choice(pool)
        pk = [int(x, 16) for x in v["public_key"]]
        sig = [int(x, 16) for x in v["signature"]]
        msg = int(v["message"], 16)
        on_pk = rng.random() < 0.25
        target = pk if on_pk else sig
        i = rng.randrange(len(target))
        op = rng.choice(["+1", "-1", "bit", "random", "half", "zero"])
        f = target[i]
        if op == "+1":
            new = (f + 1) % FELT_PRIME
        elif op == "-1":
            new = (f - 1) % FELT_PRIME
        elif op == "bit":
            new = (f ^ (1 << rng.randrange(251))) % FELT_PRIME
        elif op == "random":
            new = rng.randrange(FELT_PRIME)
        elif op == "half":
            new = (rng.randrange(1 << 123) << 128) | rng.randrange(Q9, 1 << 128)
        else:
            new = 0
        target = at(target, i, new)
        add("random", f"vector {v['id']}: {'public key' if on_pk else 'signature'} felt {i} {op}",
            v["source"], v["key"], msg, target if on_pk else pk, sig if on_pk else target)

    args.out.write_text(json.dumps({
        "description": "PF-03 differential vectors; `expected` is the reference verifier's verdict.",
        "label": LABEL.decode(),
        "seed": args.seed,
        "signers": ["tprest/falcon.py 5145a818c9512b4a443507d3375e75dae3076af6", noble["noble"]],
        "reference": "https://postquantum.provably.fast/reference/falcon512.py",
        "reference_sha256": hashlib.sha256(args.reference.read_bytes()).hexdigest(),
        "vectors": vectors,
    }, indent=1) + "\n")
    counts = {}
    for v in vectors:
        counts[(v["category"], v["expected"])] = counts.get((v["category"], v["expected"]), 0) + 1
    print(f"wrote {args.out}: {len(vectors)} vectors {counts}")


if __name__ == "__main__":
    main()
