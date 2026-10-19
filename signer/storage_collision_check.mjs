// Read-only mainnet check: before migration, the storage slots HybridMigratableAccount writes must
// be empty in the account (Account_public_key is the exception for OpenZeppelin accounts, where it
// is the key being kept). Reads those slots on up to N accounts per class from a survey file.
//   node storage_collision_check.mjs [per_class=5]
import { RpcProvider, hash, num } from "starknet";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { KEYS } from "./config.mjs";

const provider = new RpcProvider({ nodeUrl: process.env.PQ_MAINNET_RPC || "https://api.zan.top/public/starknet-mainnet/rpc/v0_10" });
const PER_CLASS = Number(process.argv[2] || 5);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function retry(fn, tries = 8) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) {
      if (i + 1 >= tries || !/cu limit|429|rate|too fast|ECONNRESET|fetch failed|timeout/i.test(e?.message || "")) throw e;
      await sleep(1500 * (i + 1));
    }
  }
}

export const SLOTS = {
  Account_public_key: hash.starknetKeccak("Account_public_key"),
  ecdsa_public_key: hash.starknetKeccak("ecdsa_public_key"),
  falcon_public_key: hash.starknetKeccak("falcon_public_key"), // Vec length lives at the base address
  Migratable_verifier_class_hash: hash.starknetKeccak("Migratable_verifier_class_hash"),
};

const file = readdirSync(KEYS).filter((f) => f.startsWith("mainnet-accounts-") && f.endsWith(".json"))
  .sort((a, b) => statSync(`${KEYS}/${a}`).mtimeMs - statSync(`${KEYS}/${b}`).mtimeMs).pop(); // newest survey
if (!file) throw new Error("run mainnet_survey.mjs first");
const rows = JSON.parse(readFileSync(`${KEYS}/${file}`, "utf8")).rows.filter((r) => r.migratable);
const byClass = new Map();
for (const r of rows) { const k = r.classHash; if (!byClass.has(k)) byClass.set(k, []); if (byClass.get(k).length < PER_CLASS) byClass.get(k).push(r); }

let checked = 0, conflicts = 0;
for (const [cls, list] of byClass) {
  const label = `${list[0].kind} ${list[0].version || ""}`.trim();
  const found = {};
  for (const r of list) {
    for (const [name, slot] of Object.entries(SLOTS)) {
      const res = await retry(() => provider.getStorageAt(r.address, num.toHex(slot), "latest"));
      const v = BigInt(typeof res === "object" ? res.value : res); // RPC v0.10 returns { value, last_update_block }
      if (v !== 0n && !(name === "Account_public_key" && r.kind === "openzeppelin")) { found[name] = (found[name] || 0) + 1; conflicts++; }
      await sleep(120);
    }
    checked++;
  }
  console.log(`${label.padEnd(22)} ${cls.slice(0, 10)}… accounts ${list.length}  non-empty slots: ${Object.keys(found).length ? JSON.stringify(found) : "none"}`);
}
console.log(`checked ${checked} accounts in ${byClass.size} classes; unexpected non-empty slots: ${conflicts}`);
