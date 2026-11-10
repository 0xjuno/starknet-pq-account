// The testnet release manifest: every deployed class tied to its artifacts, sources and toolchain.
// TESTNET ONLY.
//
//   cd contracts && scarb build && cd ..
//   node scripts/release_manifest.mjs --check      # offline: artifacts and patches match the manifest
//   node scripts/release_manifest.mjs --chain      # read-only, Sepolia: classes declared, guard deployed
//   node scripts/release_manifest.mjs --write [--commit]   # rebuild it from contracts/target/dev
//
// --manifest PATH checks another copy. --write keeps the recorded declare transactions, guard
// instance and source commit; --commit records the current git HEAD instead.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// starknet.js is installed in signer/, not next to this script.
const { RpcProvider, hash } = await import(createRequire(resolve(REPO, "signer/package.json")).resolve("starknet"));

const TARGET = resolve(REPO, "contracts/target/dev");
const PATCHES = resolve(REPO, "vendor/provably-fast/falcon-512");
const RPC = process.env.PQ_RPC || "https://api.zan.top/public/starknet-sepolia/rpc/v0_10";

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const MANIFEST = resolve(opt("--manifest") || resolve(REPO, "release/testnet-v1.json"));

// What the release contains. Compact and record exceed Sepolia's per-block L2 gas cap when
// declared (bench/pf04), so they are listed for their artifacts only.
const CLASSES = {
  HybridShakeVerifierPfSmall: { role: "verifier", declarable: true },
  HybridShakeAccount: { role: "verifier", declarable: true },
  HybridPoseidonAccount: { role: "verifier", declarable: true },
  HybridMigratableAccount: { role: "account", declarable: true },
  VerifierSwitchGuard: { role: "guard", declarable: true },
  HybridShakeVerifierPfCompact: { role: "verifier", declarable: false },
  HybridShakeVerifierPfRecord: { role: "verifier", declarable: false },
};
// Declare transactions on record (bench/pf04/sepolia.json). The others were declared before
// receipts were kept; --chain confirms they are declared.
const DECLARE_TX = {
  HybridShakeVerifierPfSmall: "0x18feecd71b354a738babe560822d471232d6ec6ff5b5097877bc458b3c0cd62",
  VerifierSwitchGuard: "0x687a8500c3732f619db3a0f8db15ae271a8391282cb52f91b0f3cab69169e23",
};
const TOOLCHAIN = {
  scarb: "2.18.0", cairo: "2.18.0", sierra: "1.8.0", snforge: "0.59.0",
  universal_sierra_compiler: "2.10.3", starknet_js: "10.8.0", noble_post_quantum: "0.6.1",
};

const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const artifact = (name, kind) => resolve(TARGET, `pq_hybrid_${name}.${kind}.json`);
const same = (a, b) => a != null && b != null && BigInt(a) === BigInt(b);

// Starknet 0.14.1 and later hash compiled classes with Blake2s; that is the hash a declare now signs.
function built(name) {
  const sierraPath = artifact(name, "contract_class");
  const casmPath = artifact(name, "compiled_contract_class");
  return {
    class_hash: hash.computeContractClassHash(JSON.parse(readFileSync(sierraPath, "utf8"))),
    compiled_class_hash: hash.computeCompiledClassHashBlake(JSON.parse(readFileSync(casmPath, "utf8"))),
    sierra_sha256: sha256(sierraPath),
    casm_sha256: sha256(casmPath),
  };
}

function patchSums() {
  const sums = {};
  for (const line of readFileSync(resolve(PATCHES, "SHA256SUMS"), "utf8").trim().split("\n")) {
    const [digest, file] = line.trim().split(/\s+/);
    if (sha256(resolve(PATCHES, file)) !== digest) throw new Error(`${file} does not match SHA256SUMS`);
    sums[file] = digest;
  }
  return sums;
}

function write() {
  let old = {};
  try { old = JSON.parse(readFileSync(MANIFEST, "utf8")); } catch {}
  const commit = flag("--commit") || !old.source?.commit
    ? execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPO, encoding: "utf8" }).trim()
    : old.source.commit;
  const classes = {};
  for (const [name, meta] of Object.entries(CLASSES)) {
    classes[name] = {
      role: meta.role,
      ...built(name),
      declarable: meta.declarable,
      declare_tx: old.classes?.[name]?.declare_tx ?? DECLARE_TX[name] ?? null,
    };
  }
  const manifest = {
    release: "testnet-v1",
    network: "SN_SEPOLIA",
    experimental: true,
    note: "Experimental, unaudited, testnet only. Class hashes are Sepolia declarations; compact and record cannot be declared there.",
    source: {
      commit,
      cairo_pq_verifiers: "bece5c07eeea5784e570c01108ec000d2d04ae40",
      provably_fast_patches: patchSums(),
    },
    toolchain: TOOLCHAIN,
    classes,
    verifiers: {
      "shake-pf-small-v1": "HybridShakeVerifierPfSmall",
      "shake-baseline": "HybridShakeAccount",
      poseidon: "HybridPoseidonAccount",
    },
    default_verifier: "shake-pf-small-v1",
    guard_instance: old.guard_instance ?? "0x5093253fe6ee74bce57ae826a72bc94ddf02b6fbe20db5512e744a9a304945e",
    legacy_account_classes: old.legacy_account_classes ?? {},
  };
  writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2) + "\n");
  console.log(`wrote ${MANIFEST} (${Object.keys(classes).length} classes, source ${commit.slice(0, 7)})`);
}

function check() {
  const m = JSON.parse(readFileSync(MANIFEST, "utf8"));
  const bad = [];
  const line = (ok, what) => { console.log(`${ok ? "ok  " : "FAIL"} ${what}`); if (!ok) bad.push(what); };
  for (const name of Object.keys(CLASSES)) {
    const want = m.classes?.[name];
    if (!want) { line(false, `${name}: missing from the manifest`); continue; }
    const got = built(name);
    for (const field of ["class_hash", "compiled_class_hash"]) {
      line(same(want[field], got[field]), `${name} ${field} ${want[field] ?? "(missing)"}${same(want[field], got[field]) ? "" : ` != built ${got[field]}`}`);
    }
    for (const field of ["sierra_sha256", "casm_sha256"]) {
      line(want[field] === got[field], `${name} ${field} ${want[field] ?? "(missing)"}${want[field] === got[field] ? "" : ` != built ${got[field]}`}`);
    }
  }
  const sums = patchSums();
  const pinned = m.source?.provably_fast_patches ?? {};
  for (const file of new Set([...Object.keys(sums), ...Object.keys(pinned)])) {
    line(sums[file] === pinned[file], `patch ${file} ${pinned[file] ?? "(missing)"}${sums[file] === pinned[file] ? "" : ` != SHA256SUMS ${sums[file] ?? "(absent)"}`}`);
  }
  for (const [id, name] of Object.entries(m.verifiers ?? {})) line(!!m.classes?.[name], `verifier ${id} -> ${name}`);
  line(!!m.verifiers?.[m.default_verifier], `default verifier ${m.default_verifier}`);
  if (bad.length) { console.error(`\n${bad.length} mismatch(es) against ${MANIFEST}`); process.exit(1); }
  console.log(`\nmanifest matches the built artifacts and the pinned patches`);
}

async function chain() {
  const m = JSON.parse(readFileSync(MANIFEST, "utf8"));
  const provider = new RpcProvider({ nodeUrl: RPC });
  let bad = 0;
  for (const [name, c] of Object.entries(m.classes)) {
    if (!c.declarable) { console.log(`--   ${name}: not declarable (expected)`); continue; }
    try {
      await provider.getClassByHash(c.class_hash);
      let tx = "";
      if (c.declare_tx) {
        const t = await provider.getTransactionByHash(c.declare_tx);
        if (!same(t.class_hash, c.class_hash)) throw new Error(`declare_tx ${c.declare_tx} declared ${t.class_hash}`);
        if (!same(t.compiled_class_hash, c.compiled_class_hash)) throw new Error(`declare_tx ${c.declare_tx} signed compiled class ${t.compiled_class_hash}`);
        tx = `, declared by ${c.declare_tx.slice(0, 10)}…`;
      }
      console.log(`ok   ${name} ${c.class_hash} is declared${tx}`);
    } catch (e) {
      bad++;
      console.log(`FAIL ${name} ${c.class_hash}: ${e.message.split("\n")[0]}`);
    }
  }
  // Earlier HybridMigratableAccount builds that deployed accounts still run (not rebuildable from
  // this commit): each must be declared, and each listed account must still run it.
  if (!m.legacy_account_classes) { bad++; console.log("FAIL legacy_account_classes: missing from the manifest"); }
  for (const [h, c] of Object.entries(m.legacy_account_classes ?? {})) {
    try {
      await provider.getClassByHash(h);
      for (const a of c.accounts) {
        const runs = await provider.getClassHashAt(a);
        if (!same(runs, h)) throw new Error(`${a} now runs ${runs}`);
      }
      console.log(`ok   legacy ${h} is declared; ${c.accounts.length} listed account(s) run it`);
    } catch (e) {
      bad++;
      console.log(`FAIL legacy ${h}: ${e.message.split("\n")[0]}`);
    }
  }
  const guardClass = await provider.getClassHashAt(m.guard_instance).catch((e) => e.message);
  const ok = same(guardClass, m.classes.VerifierSwitchGuard.class_hash);
  if (!ok) bad++;
  console.log(`${ok ? "ok  " : "FAIL"} guard instance ${m.guard_instance} runs ${guardClass}`);
  if (bad) process.exit(1);
}

if (flag("--write")) write();
else if (flag("--chain")) await chain();
else if (flag("--check")) check();
else { console.error("usage: release_manifest.mjs --check | --chain | --write [--commit] [--manifest PATH]"); process.exit(2); }
