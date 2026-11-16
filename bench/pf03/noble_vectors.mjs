// PF-03: fresh Falcon-512 signatures from @noble/post-quantum (the browser signer), converted to
// the on-chain layout by signer/falcon_adapter.mjs. Prints JSON for gen_vectors.py.
//
//   node bench/pf03/noble_vectors.mjs > /tmp/noble.json   (after `npm install` in signer/)
//
// Throwaway keys from fixed seeds; signing randomness comes from noble, so a rerun gives
// different (equally valid) signatures. The committed vectors.json is the pinned artifact.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { falcon512, makeNtt, publicKeyFelts, signatureFelts, signTxHash } from "../../signer/falcon_adapter.mjs";

const ROOTS = new URL("../../signer/falcon_ntt_roots.json", import.meta.url);
const ntt = makeNtt(JSON.parse(readFileSync(ROOTS, "utf8")));
const FELT_PRIME = 2n ** 251n + 17n * 2n ** 192n + 1n;
const label = (...parts) => createHash("sha512").update(["starknet-pq-account/pf03-noble-v1", ...parts].join("|")).digest();

const vectors = [];
for (let key = 0; key < 2; key++) {
  const { publicKey, secretKey } = falcon512.keygen(new Uint8Array(label("key", key).subarray(0, 48)));
  const pk = publicKeyFelts(publicKey, ntt);
  const messages = [0n, FELT_PRIME - 1n];
  for (let i = 0; i < 3; i++) messages.push(BigInt("0x" + label("msg", key, i).toString("hex")) % FELT_PRIME);
  for (const message of messages) {
    const sig = signatureFelts(signTxHash(message, secretKey), publicKey);
    vectors.push({
      source: "noble",
      key: `noble-${key}`,
      message: "0x" + message.toString(16),
      public_key: pk.map((v) => "0x" + BigInt(v).toString(16)),
      signature: sig.map((v) => "0x" + BigInt(v).toString(16)),
    });
  }
}
console.log(JSON.stringify({ noble: "@noble/post-quantum 0.6.1", vectors }));
