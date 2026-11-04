// Read-only mainnet measurement: of the validators staking on Starknet, how many staker and
// operational accounts can the kit migrate in place today? Stakers (NewStaker events on the staking
// contract) -> current info (get_staker_info_v1, staker_pool_info) -> inspectAccount on the staker
// and operational addresses. Writes aggregates only to SURVEY_DIR.
import { RpcProvider, hash, num } from "starknet";
import { writeFileSync, mkdirSync } from "node:fs";
import { inspectAccount } from "./pq_account_kit.mjs";
import { KEYS, SURVEY_DIR } from "./config.mjs";

const provider = new RpcProvider({ nodeUrl: process.env.PQ_MAINNET_RPC || "https://api.zan.top/public/starknet-mainnet/rpc/v0_10" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function retry(fn, tries = 10) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) {
      if (i + 1 >= tries || !/cu limit|429|rate|too fast|ECONNRESET|fetch failed|timeout/i.test(e?.message || "")) throw e;
      await sleep(1500 * (i + 1));
    }
  }
}
const call = (contractAddress, entrypoint, calldata = []) =>
  retry(() => provider.callContract({ contractAddress, entrypoint, calldata }, "latest")).then((r) => r.map((x) => BigInt(x)));

const STAKING = "0x00ca1702e64c81d9a07b86bd2c540188d92a2c73cf5cc0e508d949015e7e84a7";
const STRK = 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938dn;
const BTC_DEC = {
  "0x3fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac": 8, // WBTC
  "0x4daa17763b286d1e59b97c283c0b8c949994c361e426a28f743c67bdfe9a32f": 18, // tBTC
  "0x593e034dda23eea82d2ba9a30960ed42cf4a01502cc2351dc9b9881f9931a68": 18, // SolvBTC
  "0x36834a40984312f7f7de8d31e3f6305b325389eaeea5b1c0664b2fb936461a4": 8, // LBTC
  "0x787150e306e6eae6e3f79dea881770e8bbff2c1b8eb490f969669ee945b3135": 8, // strkBTC
};

// 1. every staker that ever staked
const key = hash.getSelectorFromName("NewStaker");
const stakers = new Set();
let token;
do {
  const r = await retry(() => provider.getEvents({ address: STAKING, keys: [[key]], from_block: { block_number: 0 }, to_block: "latest", chunk_size: 1000, continuation_token: token }));
  for (const e of r.events) stakers.add(num.toHex(e.keys[1]));
  token = r.continuation_token;
  await sleep(150);
} while (token);
console.log(`stakers ever: ${stakers.size}`);

// 2. current state: staking now (no exit intent, own stake > 0), operational address, pools
const rows = [];
for (const staker of stakers) {
  // Option<StakerInfoV1>: [0 = Some, reward, operational, unstake_time Option (0, ts | 1), amount_own, ...]
  const s = await call(STAKING, "get_staker_info_v1", [staker]);
  if (s[0] !== 0n) continue;
  const operational = num.toHex(s[2]);
  const exiting = s[3] === 0n;
  const ownStrk = Number(exiting ? s[5] : s[4]) / 1e18;
  if (exiting || ownStrk <= 0) continue;
  // StakerPoolInfoV2: commission Option (0, c | 1), pools: [len, (pool, token, amount)...]
  const p = await call(STAKING, "staker_pool_info", [staker]);
  let i = p[0] === 0n ? 2 : 1;
  const n = Number(p[i++]);
  let delegatedStrk = 0, delegatedBtc = 0;
  for (let k = 0; k < n; k++, i += 3) {
    const tok = num.toHex(p[i + 1]), amount = p[i + 2];
    if (p[i + 1] === STRK) delegatedStrk += Number(amount) / 1e18;
    else if (BTC_DEC[tok] !== undefined) delegatedBtc += Number(amount) / 10 ** BTC_DEC[tok];
  }
  rows.push({ staker, operational, ownStrk, delegatedStrk, delegatedBtc });
  await sleep(100);
}
console.log(`staking now: ${rows.length}`);

// 3. classify staker and operational accounts (cached per class inside the kit)
const seen = new Map();
async function inspect(address) {
  if (!seen.has(address)) {
    let info;
    try { info = await retry(() => inspectAccount(provider, address)); } catch (e) { info = { kind: "error", migratable: false, needs: [], drops: [], reason: (e?.message || "").slice(0, 80) }; }
    seen.set(address, info);
    await sleep(150);
  }
  return seen.get(address);
}
for (const r of rows) {
  const a = await inspect(r.staker), b = await inspect(r.operational);
  Object.assign(r, {
    stakerKind: a.version ? `${a.kind} ${a.version}` : a.kind, stakerMigratable: a.migratable, stakerReason: a.reason, stakerNeeds: a.needs,
    operationalKind: b.version ? `${b.kind} ${b.version}` : b.kind, operationalMigratable: b.migratable, operationalReason: b.reason,
    sameAccount: BigInt(r.staker) === BigInt(r.operational),
  });
}

const sum = (xs, f) => xs.reduce((t, r) => t + f(r), 0);
const strk = (r) => r.ownStrk + r.delegatedStrk;
const count = (f) => rows.reduce((m, r) => { const k = f(r); m[k] = (m[k] || 0) + 1; return m; }, {});
const sorted = (o) => Object.fromEntries(Object.entries(o).sort((a, b) => b[1] - a[1]));
const pct = (a, b) => `${((100 * a) / b).toFixed(1)}%`;
const stakerOk = rows.filter((r) => r.stakerMigratable);
const bothOk = rows.filter((r) => r.stakerMigratable && r.operationalMigratable);
const summary = {
  network: "starknet-mainnet", takenAt: new Date().toISOString(), stakersEver: stakers.size, stakingNow: rows.length,
  strkStaked: Math.round(sum(rows, strk)), btcDelegated: Number(sum(rows, (r) => r.delegatedBtc).toFixed(4)),
  stakerMigratable: { validators: stakerOk.length, share: pct(stakerOk.length, rows.length), strkShare: pct(sum(stakerOk, strk), sum(rows, strk)), btcShare: pct(sum(stakerOk, (r) => r.delegatedBtc), sum(rows, (r) => r.delegatedBtc)) },
  bothMigratable: { validators: bothOk.length, share: pct(bothOk.length, rows.length), strkShare: pct(sum(bothOk, strk), sum(rows, strk)) },
  stakerNeedsGuardian: rows.filter((r) => r.stakerNeeds?.includes("guardian co-signature")).length,
  sameStakerAndOperational: rows.filter((r) => r.sameAccount).length,
  stakerKinds: sorted(count((r) => r.stakerKind)),
  operationalKinds: sorted(count((r) => r.operationalKind)),
  stakerNotMigratable: sorted(count((r) => (r.stakerMigratable ? null : r.stakerReason || r.stakerKind))),
};
delete summary.stakerNotMigratable.null;
console.log(JSON.stringify(summary, null, 2));
writeFileSync(`${KEYS}/validator-accounts.json`, JSON.stringify(rows, null, 2));
mkdirSync(SURVEY_DIR, { recursive: true });
writeFileSync(`${SURVEY_DIR}/validator-coverage-${summary.takenAt.slice(0, 10)}.json`, JSON.stringify(summary, null, 2));
