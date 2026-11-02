// starknet-pq-account kit: what a wallet needs to move an existing account to the hybrid
// ECDSA + Falcon-512 account in place. EXPERIMENTAL, UNAUDITED, TESTNET ONLY.
//
//   const info = await inspectAccount(provider, address);          // which wallet, can it move?
//   const keys = prepareKeys(deriveAccountKeys(words, 0, "argentx"), roots);
//   const calls = migrationCalls(info, keys, { migratableClass, verifierClass });
//   await new Account({ provider, address, signer: keys.ecdsaPrivateKey }).execute(calls);
//   // from now on: new Account({ provider, address, signer: new HybridSigner(keys) })
import { Signer, ec, hash, num, shortString } from "starknet";
import { deriveAccountKeys } from "./pq_keys.mjs";
import { makeNtt, publicKeyFelts, signatureFelts, signTxHash } from "./falcon_adapter.mjs";

export { deriveAccountKeys };
export const REGISTER_DOMAIN = "starknet-pq-register-v1";
export const ROTATE_DOMAIN = "starknet-pq-rotate-v1";

/**
 * Verifier classes built from this repository (contracts/src/hybrid.cairo) and declared on
 * Sepolia. The verifier runs in the account's own storage and decides which signatures pass, so
 * a wallet should only ever install classes it has reviewed. migrationCalls and
 * verifierSwitchCall refuse anything not in `allowedVerifiers` (this list unless the caller
 * passes its own).
 */
export const KNOWN_VERIFIERS = {
  "0x2255fc213bf39d1df2129c9e068b363f2b11a27b70b4b2c48df8ea4275f1c92": "HybridShakeAccount (SHAKE-256 hash-to-point)",
  "0x7f10b6f2f70e72ef87e97844b5f6f13d384c92afcfed2a1233a03524d359d6f": "HybridPoseidonAccount (Poseidon hash-to-point, needs a matching signer)",
};

function assertAllowedVerifier(verifierClass, allowedVerifiers) {
  const allowed = Object.keys(allowedVerifiers).map((h) => BigInt(h));
  if (!allowed.includes(BigInt(verifierClass))) {
    throw new Error(`verifier class ${num.toHex(verifierClass)} is not in allowedVerifiers`);
  }
}

/** Adds the on-chain Falcon public key felts (needs the NTT roots exported from falcon.py). */
export function prepareKeys(keys, roots) {
  return { ...keys, falconFelts: publicKeyFelts(keys.falconPublicKey, makeNtt(roots)).map(num.toHex) };
}

/** Message of the key-possession proof, same as `registration_hash` in migratable.cairo. */
export function registrationHash(ecdsaPublicKey, falconFelts) {
  return hash.computePoseidonHashOnElements([shortString.encodeShortString(REGISTER_DOMAIN), ecdsaPublicKey, ...falconFelts]);
}

/** Message of the rotation proof, same as `rotation_hash` in migratable.cairo: the key pair after the rotation. */
export function rotationHash(ecdsaPublicKey, falconFelts) {
  return hash.computePoseidonHashOnElements([shortString.encodeShortString(ROTATE_DOMAIN), ecdsaPublicKey, ...falconFelts]);
}

/** [r, s, falcon x60]: STARK-curve ECDSA and Falcon-512 (SHAKE-256) over the same hash. */
export function hybridSignature(msgHash, keys) {
  const e = ec.starkCurve.sign(num.toHex(msgHash), keys.ecdsaPrivateKey);
  const falcon = signatureFelts(signTxHash(BigInt(msgHash), keys.falconSecretKey), keys.falconPublicKey);
  return [num.toHex(e.r), num.toHex(e.s), ...falcon.map(num.toHex)];
}

export class HybridSigner extends Signer {
  constructor(keys) { super(keys.ecdsaPrivateKey); this.keys = keys; }
  async signRaw(msgHash) { return hybridSignature(msgHash, this.keys); }
}

/** Serialized MigrationData / migrate() arguments, with the proof. */
export function migrationArgs(keys, verifierClass) {
  const proof = hybridSignature(registrationHash(keys.ecdsaPublicKey, keys.falconFelts), keys);
  return [keys.ecdsaPublicKey, num.toHex(keys.falconFelts.length), ...keys.falconFelts, verifierClass, num.toHex(proof.length), ...proof];
}

/**
 * The calls to sign with the account's CURRENT key. Throws if inspectAccount said no, or if the
 * migration would remove protections the user set up (info.drops) and the caller has not passed
 * acceptDroppedProtections: true after showing them to the user.
 */
export function migrationCalls(info, keys, { migratableClass, verifierClass, acceptDroppedProtections = false, allowedVerifiers = KNOWN_VERIFIERS }) {
  if (!info.migratable) throw new Error(`not migratable: ${info.reason}`);
  if (info.drops?.length && !acceptDroppedProtections) {
    throw new Error(`migration removes: ${info.drops.join("; ")}. Show this to the user and pass acceptDroppedProtections: true to continue.`);
  }
  // The key-possession proof is checked by this same class, so it means nothing if the class is not trusted.
  assertAllowedVerifier(verifierClass, allowedVerifiers);
  const args = migrationArgs(keys, verifierClass);
  if (info.kind === "argent") {
    // Argent's upgrade(class, data) checks SRC6 and library-calls perform_upgrade (0.4+) or,
    // after replacing the class, execute_after_upgrade (0.3.x) with the same data.
    return [{ contractAddress: info.address, entrypoint: "upgrade", calldata: [migratableClass, num.toHex(args.length), ...args] }];
  }
  return [
    { contractAddress: info.address, entrypoint: "upgrade", calldata: [migratableClass] },
    { contractAddress: info.address, entrypoint: "migrate", calldata: args },
  ];
}

/**
 * Calls that move a migrated account from `current` keys to `next` keys (both prepareKeys
 * output). Sign the transaction with the CURRENT keys (HybridSigner). Each proof is signed by the
 * key pair the account holds after that call, so keys the user cannot sign with revert the
 * rotation instead of locking the account.
 */
export function rotationCalls(address, current, next) {
  const calls = [];
  const sameFalcon = current.falconFelts.length === next.falconFelts.length &&
    current.falconFelts.every((f, i) => BigInt(f) === BigInt(next.falconFelts[i]));
  if (!sameFalcon) {
    const pair = { ecdsaPrivateKey: current.ecdsaPrivateKey, falconSecretKey: next.falconSecretKey, falconPublicKey: next.falconPublicKey };
    const proof = hybridSignature(rotationHash(current.ecdsaPublicKey, next.falconFelts), pair);
    calls.push({ contractAddress: address, entrypoint: "rotate_falcon_public_key",
      calldata: [num.toHex(next.falconFelts.length), ...next.falconFelts, num.toHex(proof.length), ...proof] });
  }
  if (BigInt(current.ecdsaPublicKey) !== BigInt(next.ecdsaPublicKey)) {
    const proof = hybridSignature(rotationHash(next.ecdsaPublicKey, next.falconFelts), next);
    calls.push({ contractAddress: address, entrypoint: "rotate_ecdsa_public_key",
      calldata: [next.ecdsaPublicKey, num.toHex(proof.length), ...proof] });
  }
  return calls;
}

/**
 * The call that points a migrated account at another verifier class. The account checks this
 * transaction's own signature against the new class and reverts if it fails, so estimate and
 * simulate with validation on (skipValidate: false): without a signature the call always reverts.
 */
export function verifierSwitchCall(address, verifierClass, { allowedVerifiers = KNOWN_VERIFIERS } = {}) {
  assertAllowedVerifier(verifierClass, allowedVerifiers);
  return { contractAddress: address, entrypoint: "set_verifier_class_hash", calldata: [num.toHex(verifierClass)] };
}

// ---------------------------------------------------------------- account inspection

const classCache = new Map();
const ARGENT_NAMES = ["ArgentAccount", "ArgentAccountXverse", "OkxAccount"];

function abiFunctions(abi) {
  const list = typeof abi === "string" ? JSON.parse(abi) : abi || [];
  const fns = new Map();
  for (const e of list) {
    const items = e.type === "interface" ? e.items : [e];
    for (const it of items || []) if (it.type === "function") fns.set(it.name, (it.inputs || []).map((i) => i.name));
  }
  return fns;
}

const view = async (provider, address, entrypoint) =>
  (await provider.callContract({ contractAddress: address, entrypoint, calldata: [] }, "latest")).map((x) => BigInt(x));

// Storage the migratable class writes. Before migration these must be empty (an OpenZeppelin
// account's Account_public_key is the key being kept, so it is not checked).
const MIGRATION_SLOTS = ["ecdsa_public_key", "falcon_public_key", "Migratable_verifier_class_hash"].map((n) => [n, hash.starknetKeccak(n)]);
async function usedMigrationSlots(provider, address) {
  const used = [];
  for (const [name, slot] of MIGRATION_SLOTS) {
    const r = await provider.getStorageAt(address, num.toHex(slot), "latest");
    if (BigInt(typeof r === "object" ? r.value : r) !== 0n) used.push(name);
  }
  return used;
}
const shortStr = (x) => { try { return shortString.decodeShortString(num.toHex(x)); } catch { return num.toHex(x); } };

/** Wallet family of a class, from its ABI (one RPC call per class, cached). */
export async function classifyClass(provider, classHash, sampleAddress) {
  const key = num.toHex(classHash);
  if (classCache.has(key)) return classCache.get(key);
  const cls = await provider.getClassByHash(key);
  let out;
  if (!cls.sierra_program) {
    out = { kind: "cairo0" };
  } else {
    const f = abiFunctions(cls.abi);
    const up = f.get("upgrade");
    if (f.has("is_falcon_registered")) out = { kind: "pq-hybrid" };
    else if (f.has("get_name") && (f.has("perform_upgrade") || f.has("execute_after_upgrade")) &&
      ["new_implementation,data", "new_implementation,calldata"].includes(up?.join())) {
      const name = shortStr((await view(provider, sampleAddress, "get_name"))[0]);
      const v = await view(provider, sampleAddress, "get_version");
      // Argent code under other names, with the same upgrade callbacks: Xverse (0.4.0 base), OKX (0.3.0 base).
      out = { kind: ARGENT_NAMES.includes(name) ? "argent" : "argent-other", name, version: v.slice(0, 3).map(Number).join(".") };
    } else if (f.has("get_signers") && f.has("get_multisig_threshold") && up?.join() === "upgrade_to") {
      out = { kind: "braavos", version: shortStr((await view(provider, sampleAddress, "get_version"))[0]) };
    } else if (up?.join() === "new_class_hash" && (f.has("get_public_key") || f.has("getPublicKey"))) {
      out = { kind: "openzeppelin" };
    } else if (f.has("get_public_key") || f.has("getPublicKey")) {
      out = { kind: "fixed-key", note: "no self upgrade entry point" };
    } else {
      out = { kind: "other" };
    }
    out.functions = f.size;
  }
  classCache.set(key, out);
  return out;
}

const atLeast = (v, min) => {
  const a = v.split(".").map(Number), b = min.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((a[i] || 0) !== b[i]) return (a[i] || 0) > b[i];
  return true;
};

/**
 * Which wallet the account is and whether this kit can migrate it today.
 * needs: extra signatures the migration transaction requires besides the owner key.
 * drops: protections the user set up that the hybrid account does not keep.
 */
export async function inspectAccount(provider, address) {
  const classHash = num.toHex(await provider.getClassHashAt(address, "latest"));
  const c = await classifyClass(provider, classHash, address);
  const info = { address, classHash, kind: c.kind, version: c.version, migratable: false, needs: [], drops: [], reason: "" };
  switch (c.kind) {
    case "pq-hybrid":
      info.reason = "already a hybrid account";
      break;
    case "argent": {
      // 0.4+ calls perform_upgrade, 0.3.x calls execute_after_upgrade; both are implemented.
      if (!atLeast(c.version, "0.3.0")) { info.reason = `Argent ${c.version}: no upgrade callback`; break; }
      const owners = (await view(provider, address, "get_owners_guids").catch(() => [1n]))[0];
      if (owners > 1n) { info.reason = "Argent account with several owners"; break; }
      const ownerType = await view(provider, address, "get_owner_type").catch(() => [0n]);
      if (ownerType[0] !== 0n) { info.reason = "Argent owner is not a STARK key"; break; }
      const guardians = await view(provider, address, "get_guardians_guids")
        .then((r) => r[0])
        .catch(() => view(provider, address, "get_guardian").then((r) => (r[0] === 0n ? 0n : 1n)));
      if (guardians !== 0n) {
        info.needs.push("guardian co-signature");
        info.drops.push("Argent guardian (account recovery and escape)");
      }
      info.migratable = true;
      break;
    }
    case "braavos": {
      const s = await view(provider, address, "get_signers"); // [n, stark..., m, secp256r1..., k, webauthn...]
      const nStark = Number(s[0]), nSecp = Number(s[1 + nStark]), nWebauthn = Number(s[2 + nStark + nSecp]);
      const threshold = (await view(provider, address, "get_multisig_threshold"))[0];
      if (nStark !== 1) info.reason = `Braavos with ${nStark} STARK signers`;
      else if (nSecp + nWebauthn > 0) info.reason = "Braavos with a hardware or passkey signer (would be dropped)";
      else if (threshold !== 0n) info.reason = "Braavos multisig";
      else {
        info.migratable = true;
        const limit = await view(provider, address, "get_withdrawal_limit_low").catch(() => [0n]);
        if (limit[0] !== 0n) info.drops.push("Braavos daily withdrawal limit");
      }
      break;
    }
    case "openzeppelin":
      info.migratable = true;
      break;
    case "cairo0":
      info.reason = "Cairo 0 account: the wallet must upgrade it to Cairo 1 first";
      break;
    default:
      info.reason = `${c.kind} account`;
  }
  if (info.migratable) {
    const used = await usedMigrationSlots(provider, address);
    if (used.length) {
      info.migratable = false;
      info.reason = `storage the migration writes is already in use: ${used.join(", ")}`;
    }
  }
  return info;
}
