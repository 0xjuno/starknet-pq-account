// PF-04: STARK-curve ECDSA signatures over every PF-01 corpus message, so each corpus vector
// becomes a complete hybrid signature. Writes bench/pf04/fixtures.json (committed).
//
//   node bench/pf04/gen_fixtures.mjs      # after `npm install` in signer/
//
// The ECDSA key is intentionally public: benchmark fixtures only, never fund it anywhere.
// Signatures are RFC 6979 deterministic, so rerunning reproduces the committed file.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getPublicKey, getStarkKey, sign, verify } from "../../signer/node_modules/@scure/starknet/lib/esm/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const PUBLIC_TEST_PRIVATE_KEY = "0x1234567890abcdef";
const hex = (n) => "0x" + n.toString(16);

const corpus = JSON.parse(readFileSync(resolve(HERE, "../pf01/corpus.json"), "utf8"));
const ecdsaPublicKey = getStarkKey(PUBLIC_TEST_PRIVATE_KEY);
const vectors = corpus.vectors.map((v) => {
  const msg = v.message.slice(2).padStart(64, "0");
  const sig = sign(msg, PUBLIC_TEST_PRIVATE_KEY.slice(2));
  if (!verify(sig, msg, getPublicKey(PUBLIC_TEST_PRIVATE_KEY.slice(2)))) throw new Error(`vector ${v.id}: ECDSA self-check failed`);
  return { id: v.id, ecdsa_r: hex(sig.r), ecdsa_s: hex(sig.s) };
});

writeFileSync(resolve(HERE, "fixtures.json"), JSON.stringify({
  description: "ECDSA halves of the PF-04 hybrid signatures over bench/pf01/corpus.json messages",
  ecdsa_private_key_PUBLIC_TEST_ONLY: PUBLIC_TEST_PRIVATE_KEY,
  ecdsa_public_key: ecdsaPublicKey,
  vectors,
}, null, 2) + "\n");
console.log(`wrote ${vectors.length} signatures, public key ${ecdsaPublicKey}`);
