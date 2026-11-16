// Brings a cached BTC delegation pool list (KEYS/btc-pools.json, written by btc_staking_coverage.mjs)
// up to date: scans NewDelegationPool events only from the block after the last cached pool, in
// bounded block windows, because a single scan from genesis can stall on public RPC nodes.
//   PQ_KEYS_DIR=<dir> node btc_pools_update.mjs <cached btc-pools.json>
import { RpcProvider, hash, num } from "starknet";
import { readFileSync, writeFileSync } from "node:fs";
import { KEYS } from "./config.mjs";

const provider = new RpcProvider({ nodeUrl: process.env.PQ_MAINNET_RPC || "https://api.zan.top/public/starknet-mainnet/rpc/v0_10" });
const STAKING = "0x00ca1702e64c81d9a07b86bd2c540188d92a2c73cf5cc0e508d949015e7e84a7";
const BTC_TOKENS = {
  "0x3fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac": "WBTC",
  "0x4daa17763b286d1e59b97c283c0b8c949994c361e426a28f743c67bdfe9a32f": "tBTC",
  "0x593e034dda23eea82d2ba9a30960ed42cf4a01502cc2351dc9b9881f9931a68": "SolvBTC",
  "0x36834a40984312f7f7de8d31e3f6305b325389eaeea5b1c0664b2fb936461a4": "LBTC",
  "0x787150e306e6eae6e3f79dea881770e8bbff2c1b8eb490f969669ee945b3135": "strkBTC",
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function retry(fn, tries = 8) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) {
      if (i + 1 >= tries) throw e;
      await sleep(1500 * (i + 1));
    }
  }
}
const cached = JSON.parse(readFileSync(process.argv[2], "utf8"));
const seen = new Set(cached.map((p) => BigInt(p.pool)));
const from = Math.max(...cached.map((p) => p.block)) + 1;
const latest = await retry(() => provider.getBlockNumber());
const key = hash.getSelectorFromName("NewDelegationPool");
const STEP = 50000;
let added = 0;
for (let a = from; a <= latest; a += STEP) {
  const b = Math.min(latest, a + STEP - 1);
  let t;
  do {
    const r = await retry(() => provider.getEvents({ address: STAKING, keys: [[key], [], [], Object.keys(BTC_TOKENS)], from_block: { block_number: a }, to_block: { block_number: b }, chunk_size: 1000, continuation_token: t }));
    for (const e of r.events) {
      const pool = num.toHex(e.keys[2]);
      if (seen.has(BigInt(pool))) continue;
      seen.add(BigInt(pool));
      cached.push({ staker: num.toHex(e.keys[1]), pool, token: BTC_TOKENS[num.toHex(e.keys[3])], block: e.block_number });
      added++;
    }
    t = r.continuation_token;
    await sleep(120);
  } while (t);
}
writeFileSync(`${KEYS}/btc-pools.json`, JSON.stringify(cached, null, 2));
console.log(`pools: ${cached.length} (${added} new since block ${from}, scanned to ${latest})`);
