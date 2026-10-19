// Checks the kit's safety gates against live accounts (read-only):
// - an Argent account with a guardian reports needs + drops, and migrationCalls refuses without
//   acceptDroppedProtections
// - a plain account reports no drops and passes the storage pre-check
import { RpcProvider } from "starknet";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { inspectAccount, migrationCalls } from "./pq_account_kit.mjs";
import { KEYS, RPC } from "./config.mjs";

const mainnet = new RpcProvider({ nodeUrl: process.env.PQ_MAINNET_RPC || "https://api.zan.top/public/starknet-mainnet/rpc/v0_10" });
const sepolia = new RpcProvider({ nodeUrl: RPC });
const file = readdirSync(KEYS).filter((f) => f.startsWith("mainnet-accounts-") && f.endsWith(".json"))
  .sort((a, b) => statSync(`${KEYS}/${a}`).mtimeMs - statSync(`${KEYS}/${b}`).mtimeMs).pop();
const rows = JSON.parse(readFileSync(`${KEYS}/${file}`, "utf8")).rows;
const dummyKeys = { ecdsaPublicKey: "0x1", falconFelts: Array(29).fill("0x1"), ecdsaPrivateKey: "0x1", falconSecretKey: null, falconPublicKey: null };
let failed = 0;
const check = (name, ok, detail = "") => { if (!ok) failed++; console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

const guarded = rows.find((r) => r.migratable && r.needs?.length);
const g = await inspectAccount(mainnet, guarded.address);
check("guardian account: migratable, needs co-signature", g.migratable && g.needs.includes("guardian co-signature"));
check("guardian account: drops reported", g.drops.length > 0, g.drops.join("; "));
let refused = false;
try { migrationCalls(g, dummyKeys, { migratableClass: "0x1", verifierClass: "0x2" }); } catch (e) { refused = /acceptDroppedProtections/.test(e.message); }
check("migrationCalls refuses without acceptDroppedProtections", refused);

const plain = rows.find((r) => r.migratable && !r.needs?.length && r.kind === "argent");
const p = await inspectAccount(mainnet, plain.address);
check("plain Argent account: migratable, no drops, storage pre-check passed", p.migratable && p.drops.length === 0, p.reason);

const deployer = readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim();
const d = await inspectAccount(sepolia, deployer);
check("Sepolia OpenZeppelin account: migratable", d.migratable && d.kind === "openzeppelin", d.reason);
process.exit(failed ? 1 : 0);
