// Turns standard Falcon-512 keys and signatures from @noble/post-quantum (pure JS, runs in the
// browser) into the on-chain layout of the Falcon-512 SHAKE-256 verifier:
//   public key: 29 felts = pack(NTT(h)) in falcon.py's NTT ordering
//   signature:  60 felts = pack(s2 mod q) || salt_a || salt_b || pack(s2 * h mod q)
// The message signed is the 32-byte little-endian encoding of the transaction hash, which is
// exactly what the on-chain SHAKE-256 hash-to-point absorbs after the 40-byte salt.
import { falcon512 } from "@noble/post-quantum/falcon.js";

export const Q = 12289;
const N = 512;
const SQR1 = 1479; // a square root of -1 mod q, falcon.py ntt.py

export function hashToMessage(txHash) {
  let v = BigInt(txHash);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

export function decodePublicKey(pk) {
  if (pk.length !== 897 || pk[0] !== 0x09) throw new Error("expected a Falcon-512 public key");
  const h = new Array(N);
  let acc = 0, bits = 0, pos = 1;
  for (let i = 0; i < N; i++) {
    while (bits < 14) { acc = (acc << 8) | pk[pos++]; bits += 8; }
    bits -= 14;
    h[i] = (acc >>> bits) & 0x3fff;
    acc &= (1 << bits) - 1;
    if (h[i] >= Q) throw new Error("public key coefficient out of range");
  }
  return h;
}

// Falcon Decompress (spec Algorithm 18).
export function decodeSignature(sig) {
  if (sig[0] !== 0x39) throw new Error("expected a Falcon-512 detached signature");
  const nonce = sig.slice(1, 41);
  const data = sig.slice(41);
  const s2 = new Array(N);
  let acc = 0, bits = 0, pos = 0;
  const read = (n) => {
    while (bits < n) { if (pos >= data.length) throw new Error("truncated signature"); acc = (acc << 8) | data[pos++]; bits += 8; }
    bits -= n;
    const v = (acc >>> bits) & ((1 << n) - 1);
    acc &= (1 << bits) - 1;
    return v;
  };
  for (let i = 0; i < N; i++) {
    const sign = read(1);
    const low = read(7);
    let high = 0;
    while (!read(1)) high++;
    const v = low | (high << 7);
    if (sign && v === 0) throw new Error("negative zero");
    s2[i] = sign ? -v : v;
  }
  return { nonce, s2 };
}

export function makeNtt(roots) {
  const split = (f) => [f.filter((_, i) => i % 2 === 0), f.filter((_, i) => i % 2 === 1)];
  const ntt = (f) => {
    const n = f.length;
    if (n === 2) return [(f[0] + SQR1 * f[1]) % Q, ((f[0] - SQR1 * f[1]) % Q + Q) % Q];
    const [f0, f1] = split(f);
    const a = ntt(f0), b = ntt(f1);
    const w = roots[n];
    const out = new Array(n);
    for (let i = 0; i < n / 2; i++) {
      const t = (w[2 * i] * b[i]) % Q;
      out[2 * i] = (a[i] + t) % Q;
      out[2 * i + 1] = ((a[i] - t) % Q + Q) % Q;
    }
    return out;
  };
  return ntt;
}

// Same 29-felt layout as pq-accounts' falcon_signer.py pack_512.
export function pack512(vals) {
  if (vals.length !== N || vals.some((v) => v < 0 || v >= Q)) throw new Error("expected 512 values in [0, q)");
  const half = (chunk) => chunk.reduceRight((acc, c) => acc * BigInt(Q) + BigInt(c), 0n);
  const felts = [];
  for (let j = 0; j < 28; j++) {
    const lo = half(vals.slice(18 * j, 18 * j + 9));
    const hi = half(vals.slice(18 * j + 9, 18 * j + 18));
    felts.push(lo + (hi << 128n));
  }
  felts.push(half(vals.slice(504, 512)));
  return felts;
}

// s2 * h in Z_q[x]/(x^512 + 1), schoolbook (fine for one signature).
export function mulNegacyclic(a, b) {
  const out = new Array(N).fill(0);
  for (let i = 0; i < N; i++) {
    if (a[i] === 0) continue;
    for (let j = 0; j < N; j++) {
      const k = i + j;
      const p = a[i] * b[j];
      if (k < N) out[k] += p; else out[k - N] -= p;
    }
  }
  return out.map((v) => ((v % Q) + Q) % Q);
}

const leInt = (bytes) => bytes.reduceRight((acc, b) => (acc << 8n) | BigInt(b), 0n);

export function publicKeyFelts(pk, ntt) {
  return pack512(ntt(decodePublicKey(pk)));
}

export function signatureFelts(sig, pk) {
  const { nonce, s2 } = decodeSignature(sig);
  const h = decodePublicKey(pk);
  const s2modq = s2.map((v) => ((v % Q) + Q) % Q);
  const hint = mulNegacyclic(s2modq, h);
  return [...pack512(s2modq), leInt(nonce.slice(0, 20)), leInt(nonce.slice(20)), ...pack512(hint)];
}

export function signTxHash(txHash, secretKey) {
  return falcon512.sign(hashToMessage(txHash), secretKey);
}

export { falcon512 };
