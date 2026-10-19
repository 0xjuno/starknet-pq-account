// Read-only mainnet measurement: of the BTC staked on Starknet, how much sits in accounts the kit
// can migrate today? BTC delegation pools (staking contract events) -> pool members (NewPoolMember
// events, scanned once across all addresses) -> current delegated amount per member
// (get_pool_member_info_v1) -> inspectAccount on each member. Writes aggregates only to SURVEY_DIR.
import { RpcProvider, hash, num } from "starknet";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { inspectAccount } from "./pq_account_kit.mjs";
import { KEYS, SURVEY_DIR } from "./config.mjs";

const provider = new RpcProvider({ nodeUrl: process.env.PQ_MAINNET_RPC || "https://api.zan.top/public/starknet-mainnet/rpc/v0_10" });
const DEC = { WBTC: 8, tBTC: 18, SolvBTC: 18, LBTC: 8, strkBTC: 8 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function retry(fn, tries = 8) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) {
      if (i + 1 >= tries || !/cu limit|429|rate|too fast|ECONNRESET|fetch failed|timeout/i.test(e?.message || "")) throw e;
      await sleep(1500 * (i + 1));
    }
  }
}

// 0. BTC delegation pools from the staking contract's NewDelegationPool events
//    (keys: selector, staker, pool, token), cached in KEYS/btc-pools.json
const STAKING = "0x00ca1702e64c81d9a07b86bd2c540188d92a2c73cf5cc0e508d949015e7e84a7";
const BTC_TOKENS = {
  "0x3fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac": "WBTC",
  "0x4daa17763b286d1e59b97c283c0b8c949994c361e426a28f743c67bdfe9a32f": "tBTC",
  "0x593e034dda23eea82d2ba9a30960ed42cf4a01502cc2351dc9b9881f9931a68": "SolvBTC",
  "0x36834a40984312f7f7de8d31e3f6305b325389eaeea5b1c0664b2fb936461a4": "LBTC",
  "0x787150e306e6eae6e3f79dea881770e8bbff2c1b8eb490f969669ee945b3135": "strkBTC",
};
if (!existsSync(`${KEYS}/btc-pools.json`)) {
  const poolKey = hash.getSelectorFromName("NewDelegationPool");
  const found = [];
  let t;
  do {
    const r = await retry(() => provider.getEvents({ address: STAKING, keys: [[poolKey], [], [], Object.keys(BTC_TOKENS)], from_block: { block_number: 0 }, to_block: "latest", chunk_size: 1000, continuation_token: t }));
    for (const e of r.events) found.push({ staker: num.toHex(e.keys[1]), pool: num.toHex(e.keys[2]), token: BTC_TOKENS[num.toHex(e.keys[3])], block: e.block_number });
    t = r.continuation_token;
    await sleep(150);
  } while (t);
  writeFileSync(`${KEYS}/btc-pools.json`, JSON.stringify(found, null, 2));
}
const pools = JSON.parse(readFileSync(`${KEYS}/btc-pools.json`, "utf8"));
const poolToken = new Map(pools.map((p) => [BigInt(p.pool), p.token]));
const fromBlock = Math.min(...pools.map((p) => p.block));
console.log(`pools ${pools.length}, scanning NewPoolMember from block ${fromBlock}`);

// 1. members: one scan over all addresses, keep events emitted by a BTC pool
const key = hash.getSelectorFromName("NewPoolMember");
const members = new Map(); // `${pool}:${member}` -> {pool, member, token}
let token, page = 0;
do {
  const r = await retry(() => provider.getEvents({ keys: [[key]], from_block: { block_number: fromBlock }, to_block: "latest", chunk_size: 1000, continuation_token: token }));
  for (const e of r.events) {
    const t = poolToken.get(BigInt(e.from_address));
    if (!t) continue;
    const member = num.toHex(e.keys[1]);
    members.set(`${num.toHex(e.from_address)}:${member}`, { pool: num.toHex(e.from_address), member, token: t });
  }
  token = r.continuation_token; page++;
  if (page % 20 === 0) console.log(`  page ${page}, members ${members.size}`);
  await sleep(150);
} while (token);
console.log(`members (pool, account) pairs: ${members.size}`);

// 2. current delegated amount per member
const rows = [];
for (const m of members.values()) {
  let amount = 0n;
  try {
    const r = await retry(() => provider.callContract({ contractAddress: m.pool, entrypoint: "get_pool_member_info_v1", calldata: [m.member] }));
    // Option<PoolMemberInfoV1>: [0 = Some, reward_address, amount, ...] or [1 = None]
    if (BigInt(r[0]) === 0n) amount = BigInt(r[2]);
  } catch { amount = -1n; }
  if (amount > 0n) rows.push({ ...m, btc: Number(amount) / 10 ** DEC[m.token] });
  await sleep(120);
}
console.log(`members with stake: ${rows.length}`);

// 3. classify each delegating account (cached per class inside the kit)
const byAddr = new Map();
for (const r of rows) {
  if (!byAddr.has(r.member)) {
    let info;
    try { info = await retry(() => inspectAccount(provider, r.member)); } catch (e) { info = { kind: "error", migratable: false, needs: [], reason: (e?.message || "").slice(0, 80) }; }
    byAddr.set(r.member, info);
    await sleep(150);
  }
  Object.assign(r, { kind: byAddr.get(r.member).kind, version: byAddr.get(r.member).version, migratable: byAddr.get(r.member).migratable, reason: byAddr.get(r.member).reason, needs: byAddr.get(r.member).needs });
}

const sum = (xs) => xs.reduce((s, r) => s + r.btc, 0);
const total = sum(rows);
const groupBy = (f) => rows.reduce((m, r) => { const k = f(r); m[k] = (m[k] || 0) + r.btc; return m; }, {});
const round = (o) => Object.fromEntries(Object.entries(o).sort((a, b) => b[1] - a[1]).map(([k, v]) => [k, Number(v.toFixed(4))]));
const migr = rows.filter((r) => r.migratable);
const summary = {
  network: "starknet-mainnet", takenAt: new Date().toISOString(), pools: pools.length,
  delegatorAccounts: byAddr.size, positions: rows.length, stakedBtcInPools: Number(total.toFixed(4)),
  migratableBtc: Number(sum(migr).toFixed(4)), migratableShare: `${((100 * sum(migr)) / total).toFixed(1)}%`,
  migratableAccounts: [...byAddr.values()].filter((i) => i.migratable).length,
  btcByToken: round(groupBy((r) => r.token)),
  btcByAccountKind: round(groupBy((r) => (r.version ? `${r.kind} ${r.version}` : r.kind))),
  btcNotMigratableByReason: round(rows.filter((r) => !r.migratable).reduce((m, r) => { const k = r.reason || r.kind; m[k] = (m[k] || 0) + r.btc; return m; }, {})),
};
console.log(JSON.stringify(summary, null, 2));
writeFileSync(`${KEYS}/btc-staking-members.json`, JSON.stringify(rows, null, 2));
mkdirSync(SURVEY_DIR, { recursive: true });
writeFileSync(`${SURVEY_DIR}/btc-staking-coverage-${summary.takenAt.slice(0, 10)}.json`, JSON.stringify(summary, null, 2));
