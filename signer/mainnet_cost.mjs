// Read-only: what each transaction type would cost on Starknet mainnet right now.
// Gas amounts are measured on Sepolia (same execution); prices come from the latest mainnet block.
import { RpcProvider } from "starknet";

const sepolia = new RpcProvider({ nodeUrl: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10" });
const mainnet = new RpcProvider({ nodeUrl: "https://api.zan.top/public/starknet-mainnet/rpc/v0_10" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Sepolia receipts (README, release/testnet-v1-evidence.json, bench/pf04, bench/pf06).
const samples = [
  ["Transfer: OpenZeppelin ECDSA account (baseline)", "0x28f916139a098e3fddb66102741c11bed434a506ef00706c2a92589bccfa300"],
  ["Transfer: hybrid, Poseidon Falcon verifier", "0x521ff2b341561abb0bc71581a4feaf650311bf0398176b5d7f1dc2c16343d57"],
  ["Transfer: hybrid, OpenZeppelin SHAKE-256 verifier (public demo, browser page)", "0x1b91c2a024c764ddefbfdd0a9d3cb59c2edbab814b379672039707ec50c7362"],
  ["Transfer: hybrid, Provably Fast small verifier (same account and page, after the switch)", "0x2854921d79ec2759beb7056fbb2780ede391b4ca3f84b2b56da2de629ca3706"],
  ["One-time: migration from Argent 0.5.0, OpenZeppelin SHAKE-256 verifier", "0x2bd473956e65ee2a017ddcfd4b5a03710fa329f1fdfa60e0de2c05f4dd91f77"],
  ["One-time: migration from Argent 0.5.0, small verifier", "0x61e91e09b78489dc91a445ec1842c1d72cff6bf792b715c1f9c6fda3d417aa9"],
  ["One-time: guarded switch baseline -> small (public demo)", "0xd651842233b8f5448e0453674bef2bd95afa6c2b2cc64850be84b7e7b40547"],
  ["One-time: declare HybridShakeVerifierPfSmall", "0x18feecd71b354a738babe560822d471232d6ec6ff5b5097877bc458b3c0cd62"],
];

const blk = await mainnet.getBlockWithTxHashes("latest");
const l2 = BigInt(blk.l2_gas_price.price_in_fri), l1d = BigInt(blk.l1_data_gas_price.price_in_fri), l1 = BigInt(blk.l1_gas_price.price_in_fri);
const cg = await (await fetch("https://api.coingecko.com/api/v3/simple/price?ids=starknet&vs_currencies=usd")).json();
const usd = cg.starknet.usd;
console.log(`mainnet block ${blk.block_number} (${new Date(blk.timestamp * 1000).toISOString()}): l2 ${l2} fri, l1_data ${l1d} fri, l1 ${l1} fri; STRK $${usd} (CoinGecko simple/price)`);

for (const [label, tx] of samples) {
  await sleep(1200);
  const rc = await sepolia.getTransactionReceipt(tx);
  const r = rc.execution_resources;
  const fee = BigInt(r.l2_gas) * l2 + BigInt(r.l1_data_gas) * l1d + BigInt(r.l1_gas || 0) * l1;
  const strk = Number(fee) / 1e18;
  console.log(`${label}: l2_gas ${r.l2_gas}, l1_data_gas ${r.l1_data_gas} -> ${strk.toFixed(4)} STRK = $${(strk * usd).toFixed(4)}`);
}
