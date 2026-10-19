// Read-only mainnet survey: of the accounts that recently sent transactions, how many could this
// kit migrate today? Walks back from the latest block, collects unique INVOKE senders, and runs
// inspectAccount on each. Prints and saves aggregate counts only (no key material is involved).
//   node mainnet_survey.mjs [unique_senders=400]
//   node mainnet_survey.mjs --from <saved survey json>   re-inspect the same senders
import { RpcProvider } from "starknet";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { inspectAccount } from "./pq_account_kit.mjs";
import { KEYS, SURVEY_DIR } from "./config.mjs";

const RPC = process.env.PQ_MAINNET_RPC || "https://api.zan.top/public/starknet-mainnet/rpc/v0_10";
// Classes whose real accounts were deployed and migrated on Sepolia by wallet_migrate_demo.mjs.
const SEPOLIA_TESTED = new Set([
  "0x1a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003", // Argent 0.3.0
  "0x29927c8af6bccf3f6fda035981e765a7bdbf18a2dc0d630494f8758aa908e2b", // Argent 0.3.1
  "0x36078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f", // Argent 0.4.0
  "0x73414441639dcd11d1846f287650a00c60c416b9d3ba45d31c651672125b2c2", // Argent 0.5.0
  "0x816dd0297efc55dc1e7559020a3a825e81ef734b558f03c83325d4da7e6253", // Braavos 1.0.0
  "0x2c8c7e6fbcfb3e8e15a46648e8914c6aa1fc506fc1e7fb3d1e19630716174bc", // Braavos 1.1.0
  "0x3957f9f5a1cbfe918cedc2015c85200ca51a5f7506ecb6de98a5207b759bf8a", // Braavos 1.2.0
  "0x5b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564", // OpenZeppelin
  "0xe2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6", // OpenZeppelin
  "0x663fc01a0dbe1bacc4cd2a4c856eb9784b255a20988aa33d4d52b6fc20bd024", // Xverse (ArgentAccountXverse)
  "0x1c0bb51e2ce73dc007601a1e7725453627254016c28f118251a71bbb0507fcb", // OKX (OkxAccount)
].map((h) => BigInt(h)));
const FROM = process.argv[2] === "--from" ? JSON.parse(readFileSync(process.argv[3], "utf8")) : null;
const TARGET = FROM ? 0 : Number(process.argv[2] || 400);
const provider = new RpcProvider({ nodeUrl: RPC });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function retry(fn, tries = 8) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) {
      const msg = e?.message || "";
      if (i + 1 >= tries || !/cu limit|429|rate|too fast|ECONNRESET|fetch failed|timeout/i.test(msg)) throw e;
      await sleep(1500 * (i + 1));
    }
  }
}

let latest = FROM ? FROM.summary.blocks[1] : await retry(() => provider.getBlockNumber());
const senders = new Map(FROM ? FROM.rows.map((r) => [r.address, r.txs]) : []); // address -> tx count in the window
let block = FROM ? FROM.summary.blocks[0] - 1 : latest, blocks = 0;
while (senders.size < TARGET) {
  const b = await retry(() => provider.getBlockWithTxs(block));
  for (const tx of b.transactions) if (tx.type === "INVOKE" && tx.sender_address) senders.set(tx.sender_address, (senders.get(tx.sender_address) || 0) + 1);
  blocks++; block--;
  await sleep(250);
}
const [first, last] = await Promise.all([block + 1, latest].map((n) => retry(() => provider.getBlockWithTxHashes(n))));
const hours = ((last.timestamp - first.timestamp) / 3600).toFixed(1);
console.log(`blocks ${block + 1}..${latest} (${hours} h), unique senders ${senders.size}`);

const rows = [];
let i = 0;
for (const [address, txs] of senders) {
  let info;
  try { info = await retry(() => inspectAccount(provider, address)); } catch (e) { info = { address, kind: "error", migratable: false, needs: [], reason: (e?.message || "").slice(0, 120) }; }
  rows.push({ ...info, txs });
  if (++i % 50 === 0) console.log(`  inspected ${i}/${senders.size}`);
  await sleep(200);
}

const tally = (key) => rows.reduce((m, r) => ((m[key(r)] = (m[key(r)] || 0) + 1), m), {});
const pct = (n) => `${((100 * n) / rows.length).toFixed(1)}%`;
const migratable = rows.filter((r) => r.migratable);
const noExtra = migratable.filter((r) => r.needs.length === 0);
const tested = migratable.filter((r) => r.classHash && SEPOLIA_TESTED.has(BigInt(r.classHash)));
const txTotal = rows.reduce((s, r) => s + r.txs, 0);
const summary = {
  network: "starknet-mainnet", rpc: RPC, blocks: [block + 1, latest], hours: Number(hours),
  uniqueSenders: rows.length, invokeTxs: txTotal,
  byKind: tally((r) => (r.version ? `${r.kind} ${r.version}` : r.kind)),
  notMigratableReasons: tally((r) => (r.migratable ? "(migratable)" : r.reason || r.kind)),
  migratable: migratable.length, migratableShare: pct(migratable.length),
  migratableWithoutExtraSignatures: noExtra.length, migratableWithoutExtraSignaturesShare: pct(noExtra.length),
  needsGuardian: migratable.length - noExtra.length,
  migratableOnSepoliaTestedClasses: tested.length, migratableOnSepoliaTestedClassesShare: pct(tested.length),
  migratableTxShare: `${((100 * migratable.reduce((s, r) => s + r.txs, 0)) / txTotal).toFixed(1)}%`,
  takenAt: new Date().toISOString(),
};
console.log(JSON.stringify(summary, null, 2));
// Per-account rows stay next to the (gitignored) keys; only the aggregate is published.
mkdirSync(SURVEY_DIR, { recursive: true });
const stamp = summary.takenAt.slice(0, 10) + (FROM ? "-reinspect" : "");
writeFileSync(`${KEYS}/mainnet-accounts-${stamp}.json`, JSON.stringify({ summary, rows }, null, 2));
writeFileSync(`${SURVEY_DIR}/mainnet-summary-${stamp}.json`, JSON.stringify(summary, null, 2));
console.log("aggregate saved under", SURVEY_DIR);
