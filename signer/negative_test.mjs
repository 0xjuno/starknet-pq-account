import { Account, CallData, RpcProvider, Signer, cairo, ec, num } from "starknet";
import { readFileSync } from "node:fs";
import { KEYS, RPC } from "./config.mjs";
const provider = new RpcProvider({ nodeUrl: RPC });
const st = JSON.parse(readFileSync(`${KEYS}/demo-state.json`, "utf8"));
const hk = JSON.parse(readFileSync(`${KEYS}/hybrid-ecdsa.json`, "utf8"));
const dep = readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim();
// Simulates an attacker who can forge the classical ECDSA key (e.g. quantum) but has no Falcon key.
class EcdsaOnly extends Signer { async signRaw(h) { const s = ec.starkCurve.sign(num.toHex(h), hk.privateKey); return [num.toHex(s.r), num.toHex(s.s)]; } }
const acc = new Account({ provider, address: st.hybridAddress, signer: new EcdsaOnly(hk.privateKey) });
// Sepolia evicts zero-tip transactions from the mempool; pay the tip recent blocks paid.
const TIP = (await provider.getEstimateTip("latest", { maxBlocks: 5 })).recommendedTip;
const b = await provider.getBlockWithTxHashes("latest");
const rb = { l1_gas: { max_amount: 0n, max_price_per_unit: BigInt(b.l1_gas_price.price_in_fri) * 2n }, l1_data_gas: { max_amount: 5000n, max_price_per_unit: BigInt(b.l1_data_gas_price.price_in_fri) * 2n }, l2_gas: { max_amount: 60000000n, max_price_per_unit: BigInt(b.l2_gas_price.price_in_fri) * 2n } };
try {
  const n = await provider.getNonceForAddress(st.hybridAddress, "latest");
  const r = await acc.execute({ contractAddress: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d", entrypoint: "transfer", calldata: CallData.compile({ recipient: dep, amount: cairo.uint256(1n) }) }, { nonce: n, tip: TIP, resourceBounds: rb });
  console.log("UNEXPECTED: accepted", r.transaction_hash);
} catch (e) { const m = (e?.message || String(e)); console.log("REJECTED as expected:", m.slice(m.lastIndexOf("\n") + 1).slice(0, 300)); }
