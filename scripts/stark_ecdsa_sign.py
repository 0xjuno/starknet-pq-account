"""Minimal STARK-curve ECDSA signer for test fixtures (testnet/demo only, never real funds).

Usage: python stark_ecdsa_sign.py <message_hash_int_or_hex> [private_key_hex]
Prints public key (x-coordinate), r, s as hex.
"""
import hashlib
import sys

P = 2**251 + 17 * 2**192 + 1
ALPHA = 1
BETA = 0x6F21413EFBE40DE150E596D72F7A8C5609AD26C15C915C1F4CDFCB99CEE9E89
N = 0x800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F
G = (
    0x1EF15C18599971B7BECED415A40F0C7DEACFD9B0D1819E03D723D8BC943CFCA,
    0x5668060AA49730B7BE4801DF46EC62DE53ECD11ABE43A32873000C36E8DC1F,
)


def on_curve(pt):
    x, y = pt
    return (y * y - (x * x * x + ALPHA * x + BETA)) % P == 0


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0:
            return None
        lam = (3 * a[0] * a[0] + ALPHA) * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    y = (lam * (a[0] - x) - a[1]) % P
    return (x, y)


def mul(k, pt):
    acc = None
    while k:
        if k & 1:
            acc = add(acc, pt)
        pt = add(pt, pt)
        k >>= 1
    return acc


def sign(z, d):
    # Deterministic nonce (hash of key and message); fine for fixtures, not a production RNG.
    counter = 0
    while True:
        seed = f"{d:x}:{z:x}:{counter}".encode()
        k = int.from_bytes(hashlib.sha256(seed).digest(), "big") % N
        counter += 1
        if k == 0:
            continue
        R = mul(k, G)
        r = R[0]
        if not (0 < r < N and r < 2**251):
            continue
        s = pow(k, -1, N) * (z + r * d) % N
        if s == 0 or pow(s, -1, N) >= 2**251:
            continue
        return r, s


def verify(z, pub_x, r, s):
    # Mirrors corelib check_ecdsa_signature: x(zG + rQ) == x(sR) or x(zG - rQ) == x(sR)
    def lift(x):
        y2 = (x * x * x + ALPHA * x + BETA) % P
        y = pow(y2, (P + 1) // 4, P) if P % 4 == 3 else tonelli(y2)
        return (x, y) if y is not None and (y * y) % P == y2 else None

    Q = lift(pub_x)
    Rp = lift(r)
    if Q is None or Rp is None:
        return False
    sR = mul(s, Rp)
    zG = mul(z, G)
    rQ = mul(r, Q)
    plus = add(zG, rQ)
    minus = add(zG, (rQ[0], (-rQ[1]) % P))
    return (plus is not None and plus[0] == sR[0]) or (minus is not None and minus[0] == sR[0])


def tonelli(n):
    # Tonelli-Shanks square root mod P
    if pow(n, (P - 1) // 2, P) != 1:
        return None
    q, s = P - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    zz = 2
    while pow(zz, (P - 1) // 2, P) != P - 1:
        zz += 1
    m, c, t, r = s, pow(zz, q, P), pow(n, q, P), pow(n, (q + 1) // 2, P)
    while t != 1:
        i, tt = 0, t
        while tt != 1:
            tt = tt * tt % P
            i += 1
        b = pow(c, 1 << (m - i - 1), P)
        m, c, t, r = i, b * b % P, t * b * b % P, r * b % P
    return r


if __name__ == "__main__":
    assert on_curve(G)
    z = int(sys.argv[1], 0)
    d = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x5EED0000000000000000000000000000000000000000000000000000000001
    Q = mul(d, G)
    r, s = sign(z, d)
    assert verify(z, Q[0], r, s), "self-check failed"
    print(f"public_key=0x{Q[0]:x}")
    print(f"r=0x{r:x}")
    print(f"s=0x{s:x}")
