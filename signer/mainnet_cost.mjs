// Read-only: what a transfer from each account type would cost on Starknet mainnet right now.
// Gas amounts are measured on Sepolia (same execution); prices come from the latest mainnet block.
import { RpcProvider } from "starknet";
import { readFileSync } from "node:fs";
import { KEYS } from "./config.mjs";

const sepolia = new RpcProvider({ nodeUrl: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10" });
const mainnet = new RpcProvider({ nodeUrl: "https://api.zan.top/public/starknet-mainnet/rpc/v0_10" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const migrate = JSON.parse(readFileSync(`${KEYS}/migrate-state.json`, "utf8"));
const browser = JSON.parse(readFileSync(`${KEYS}/browser-state.json`, "utf8"));
const samples = [
  ["OpenZeppelin ECDSA transfer (baseline)", migrate.fundTx],
  ["Hybrid transfer, Poseidon Falcon verifier", migrate.hybridTransferTx],
  ["Hybrid transfer, standard SHAKE-256 verifier (browser path)", browser.nodeTransferTx],
];

const blk = await mainnet.getBlockWithTxHashes("latest");
const l2 = BigInt(blk.l2_gas_price.price_in_fri), l1d = BigInt(blk.l1_data_gas_price.price_in_fri), l1 = BigInt(blk.l1_gas_price.price_in_fri);
const cg = await (await fetch("https://api.coingecko.com/api/v3/simple/price?ids=starknet&vs_currencies=usd")).json();
const usd = cg.starknet.usd;
console.log(`mainnet block ${blk.block_number}: l2 ${l2} fri, l1_data ${l1d} fri, l1 ${l1} fri; STRK $${usd}`);

for (const [label, tx] of samples) {
  await sleep(1200);
  const rc = await sepolia.getTransactionReceipt(tx);
  const r = rc.execution_resources;
  const fee = BigInt(r.l2_gas) * l2 + BigInt(r.l1_data_gas) * l1d + BigInt(r.l1_gas || 0) * l1;
  const strk = Number(fee) / 1e18;
  console.log(`${label}: l2_gas ${r.l2_gas}, l1_data_gas ${r.l1_data_gas} -> ${strk.toFixed(4)} STRK = $${(strk * usd).toFixed(4)}`);
}
