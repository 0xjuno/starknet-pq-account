// ECDSA-only transfer from a hybrid account: must be rejected in __validate__. TESTNET ONLY.
//   node negative_test.mjs                  the demo.mjs account (.keys/demo-state.json)
//   node negative_test.mjs <run> <wallet>   a wallet_migrate_demo.mjs account, e.g. pf04-small argent-0.5.0;
//                                           its ECDSA key comes from that wallet's words in .keys/
import { Account, CallData, RpcProvider, Signer, cairo, ec, num } from "starknet";
import { readFileSync } from "node:fs";
import { KEYS, RPC } from "./config.mjs";
import { deriveAccountKeys } from "./pq_keys.mjs";
const provider = new RpcProvider({ nodeUrl: RPC });
const [run, wallet] = process.argv.slice(2);
let address, privateKey;
if (wallet) {
  address = JSON.parse(readFileSync(`${KEYS}/wallet-matrix-state-${run}.json`, "utf8"))[wallet].address;
  // Same ECDSA profiles as wallet_migrate_demo.mjs: Argent and Braavos derivations, "pq" for the rest.
  const profile = wallet.startsWith("argent-") ? "argentx" : wallet.startsWith("braavos-") ? "braavos" : "pq";
  privateKey = deriveAccountKeys(readFileSync(`${KEYS}/wallet-${run}-${wallet}-mnemonic.txt`, "utf8").trim(), 0, profile).ecdsaPrivateKey;
} else {
  address = JSON.parse(readFileSync(`${KEYS}/demo-state.json`, "utf8")).hybridAddress;
  privateKey = JSON.parse(readFileSync(`${KEYS}/hybrid-ecdsa.json`, "utf8")).privateKey;
}
const dep = readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim();
// Simulates an attacker who can forge the classical ECDSA key (e.g. quantum) but has no Falcon key.
class EcdsaOnly extends Signer { async signRaw(h) { const s = ec.starkCurve.sign(num.toHex(h), privateKey); return [num.toHex(s.r), num.toHex(s.s)]; } }
const acc = new Account({ provider, address, signer: new EcdsaOnly(privateKey) });
// Sepolia evicts zero-tip transactions from the mempool; pay the tip recent blocks paid.
const TIP = (await provider.getEstimateTip("latest", { maxBlocks: 5 })).recommendedTip;
const b = await provider.getBlockWithTxHashes("latest");
const rb = { l1_gas: { max_amount: 0n, max_price_per_unit: BigInt(b.l1_gas_price.price_in_fri) * 2n }, l1_data_gas: { max_amount: 5000n, max_price_per_unit: BigInt(b.l1_data_gas_price.price_in_fri) * 2n }, l2_gas: { max_amount: 60000000n, max_price_per_unit: BigInt(b.l2_gas_price.price_in_fri) * 2n } };
try {
  const n = await provider.getNonceForAddress(address, "latest");
  const r = await acc.execute({ contractAddress: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d", entrypoint: "transfer", calldata: CallData.compile({ recipient: dep, amount: cairo.uint256(1n) }) }, { nonce: n, tip: TIP, resourceBounds: rb });
  console.log("UNEXPECTED: accepted", r.transaction_hash);
  process.exitCode = 1;
} catch (e) {
  // Only a validation failure counts: a nonce, balance or RPC error says nothing about the account.
  const m = (e?.message || String(e));
  const ok = /validate/i.test(m) && /panicked|invalid signature/i.test(m);
  console.log(ok ? "REJECTED in __validate__ as expected:" : "UNCLEAR (not a validation failure):", m.slice(m.lastIndexOf("\n") + 1).slice(0, 300));
  if (!ok) process.exitCode = 1;
}
