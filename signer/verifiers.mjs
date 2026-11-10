// The verifier versions this release pins (release/testnet-v1.json). Setup and migration scripts
// choose their verifier here, never from a state file: PQ_VERIFIER=<id>, default the manifest's
// default_verifier (shake-pf-small-v1). Unknown ids and unpinned class hashes are refused.
import { readFileSync } from "node:fs";
import { RELEASE_MANIFEST } from "./config.mjs";

export const RELEASE = JSON.parse(readFileSync(RELEASE_MANIFEST, "utf8"));
const classHash = (name) => RELEASE.classes[name].class_hash;
const asFelt = (h) => { try { return BigInt(h); } catch { return null; } };

export function verifierClass(id = process.env.PQ_VERIFIER || RELEASE.default_verifier) {
  const name = RELEASE.verifiers[id];
  if (!name) throw new Error(`unknown verifier "${id}"; known: ${Object.keys(RELEASE.verifiers).join(", ")}`);
  return classHash(name);
}

export function pinnedVerifier(hash) {
  const h = asFelt(hash);
  const id = Object.keys(RELEASE.verifiers).find((v) => h !== null && asFelt(verifierClass(v)) === h);
  if (!id) throw new Error(`verifier class ${hash} is not pinned in release/testnet-v1.json`);
  return id;
}

export const MIGRATABLE_CLASS = classHash("HybridMigratableAccount");
export const GUARD = RELEASE.guard_instance;
// Same scheme (SHAKE-256 hash-to-point), so the guarded switch may move between them.
export const ALLOWED_VERIFIERS = Object.keys(RELEASE.verifiers).filter((id) => id.startsWith("shake-")).map((id) => verifierClass(id));

/** The verifier a script migrates to: PQ_VERIFIER, or PQ_VERIFIER_CLASS if it is pinned. SHAKE-256 only. */
export function selectedVerifier(env = process.env) {
  const id = env.PQ_VERIFIER_CLASS ? pinnedVerifier(env.PQ_VERIFIER_CLASS) : env.PQ_VERIFIER || RELEASE.default_verifier;
  const hash = verifierClass(id);
  if (!ALLOWED_VERIFIERS.includes(hash)) throw new Error(`verifier "${id}" is not a SHAKE-256 verifier; these scripts sign with SHAKE-256 Falcon`);
  return { id, classHash: hash };
}
