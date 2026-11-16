// PF-05: which deployed hybrid accounts can take a guarded verifier switch (read-only).
//
//   node signer/verifier_switch_inventory.mjs
//
// Collects the Sepolia accounts linked from README.md and contracts/docs/wallet-coverage.md (the
// sender of every linked transaction plus every linked contract), then for each migratable
// class in use checks that it has `set_verifier_class_hash(verifier_class_hash)` and
// `is_valid_signature(hash, signature)`, the two entry points the guarded switch needs, and
// which verifier each account points at. Sends nothing.
import { RpcProvider, num } from "starknet";
import { readFileSync } from "node:fs";
import { RPC } from "./config.mjs";

const REPO = new URL("..", import.meta.url).pathname;

const provider = new RpcProvider({ nodeUrl: RPC });
const docs = ["README.md", "contracts/docs/wallet-coverage.md"].map((f) => readFileSync(`${REPO}/${f}`, "utf8")).join("\n");
const txs = [...new Set(docs.match(/sepolia\.voyager\.online\/tx\/0x[0-9a-f]+/g).map((u) => u.split("/").pop()))];
const linked = [...new Set(docs.match(/sepolia\.voyager\.online\/contract\/0x[0-9a-f]+/g).map((u) => u.split("/").pop()))];

const senders = new Set(linked.map((a) => num.toHex(a)));
for (const tx of txs) {
  const t = await provider.getTransactionByHash(tx).catch(() => null);
  if (t?.sender_address) senders.add(num.toHex(t.sender_address));
}

const fnsOf = (abi) => {
  const list = typeof abi === "string" ? JSON.parse(abi) : abi || [];
  const fns = new Map();
  for (const e of list) for (const it of (e.type === "interface" ? e.items : [e]) || [])
    if (it.type === "function") fns.set(it.name, (it.inputs || []).map((i) => i.name).join(","));
  return fns;
};
const classes = new Map();
const classInfo = async (h) => {
  if (!classes.has(h)) classes.set(h, fnsOf((await provider.getClassByHash(h)).abi));
  return classes.get(h);
};

const rows = [];
for (const address of senders) {
  const classHash = num.toHex(await provider.getClassHashAt(address, "latest"));
  const f = await classInfo(classHash);
  if (!f.has("is_falcon_registered")) continue; // not a migratable hybrid account (deployer, direct accounts)
  const registered = (await provider.callContract({ contractAddress: address, entrypoint: "is_falcon_registered", calldata: [] }))[0] !== "0x0";
  const verifier = num.toHex((await provider.callContract({ contractAddress: address, entrypoint: "get_verifier_class_hash", calldata: [] }))[0]);
  const vf = verifier === "0x0" ? new Map() : await classInfo(verifier);
  rows.push({
    address, classHash, registered, verifier,
    setter: f.get("set_verifier_class_hash") === "verifier_class_hash",
    accountCheck: f.get("is_valid_signature") === "hash,signature",
    verifierCheck: vf.get("is_valid_signature") === "hash,signature",
  });
}

const short = (h) => `${h.slice(0, 10)}…`;
console.log(`${rows.length} migratable hybrid accounts linked from the docs, ${new Set(rows.map((r) => r.classHash)).size} classes\n`);
console.log("| Account | Class | Registered | Verifier | set_verifier_class_hash | is_valid_signature (account / verifier) |");
console.log("| --- | --- | --- | --- | --- | --- |");
for (const r of rows.sort((a, b) => a.classHash.localeCompare(b.classHash)))
  console.log(`| ${short(r.address)} | ${short(r.classHash)} | ${r.registered} | ${short(r.verifier)} | ${r.setter} | ${r.accountCheck} / ${r.verifierCheck} |`);
const count = (key) => [...rows.reduce((m, r) => m.set(r[key], (m.get(r[key]) || 0) + 1), new Map())];
console.log("\nMigratable classes in use:");
for (const [h, n] of count("classHash")) console.log(`  ${h}  ${n} account(s)`);
console.log("Verifiers in use:");
for (const [h, n] of count("verifier")) console.log(`  ${h}  ${n} account(s)`);
const ok = rows.every((r) => !r.registered || (r.setter && r.accountCheck && r.verifierCheck));
console.log(`\nguarded switch supported on every registered account: ${ok}`);
process.exit(ok ? 0 : 1);
