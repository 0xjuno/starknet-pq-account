// Prepares the browser-wallet demo on Sepolia. TESTNET ONLY.
//   1. declare HybridShakeAccount (round-three Falcon-512 with SHAKE-256 hash-to-point) as the verifier class
//   2. new mnemonic -> keys (pq_keys.mjs, profile v0.1); OZ account funded, deployed, migrated in
//      place with the SHAKE verifier and the noble-derived Falcon key
//   3. one hybrid transfer signed exactly the way the browser page signs (noble + adapter)
//   4. writes the page config (public data only) to site/browser-wallet.config.json
import { Account, CallData, RpcProvider, Signer, cairo, ec, hash, json, num } from "starknet";
import { generateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { deriveAccountKeys } from "./pq_keys.mjs";
import { makeNtt, publicKeyFelts, signatureFelts, signTxHash } from "./falcon_adapter.mjs";
import { KEYS, PAGE_CONFIG, ROOTS, RPC, TARGET } from "./config.mjs";
import { registrationHash } from "./pq_account_kit.mjs";

const STATE_FILE = `${KEYS}/browser-state.json`;
const MNEMONIC_FILE = `${KEYS}/browser-mnemonic.txt`;
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const OZ_ACCOUNT_CLASS = "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";
const MIGRATABLE_CLASS = JSON.parse(readFileSync(`${KEYS}/migrate-state.json`, "utf8")).migratableClass;
const VOYAGER = "https://sepolia.voyager.online";
const ntt = makeNtt(JSON.parse(readFileSync(ROOTS, "utf8")));

const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
const log = (...a) => console.log(...a);
const fmt = (wei) => (Number(wei) / 1e18).toFixed(6) + " STRK";
const provider = new RpcProvider({ nodeUrl: RPC });

// Same signer the browser page uses: STARK-curve ECDSA + noble Falcon-512 (SHAKE-256 hash-to-point).
class BrowserHybridSigner extends Signer {
  constructor(keys) { super(keys.ecdsaPrivateKey); this.keys = keys; }
  async signRaw(msgHash) {
    const h = num.toHex(msgHash);
    const e = ec.starkCurve.sign(h, this.keys.ecdsaPrivateKey);
    const f = signatureFelts(signTxHash(BigInt(h), this.keys.falconSecretKey), this.keys.falconPublicKey);
    return [num.toHex(e.r), num.toHex(e.s), ...f.map((x) => num.toHex(x))];
  }
}

async function strkBalance(a) {
  const r = await provider.callContract({ contractAddress: STRK, entrypoint: "balance_of", calldata: [a] });
  return BigInt(r[0]) + (BigInt(r[1]) << 128n);
}
async function classAt(a) { try { return num.toHex(await provider.getClassHashAt(a)); } catch { return null; } }
async function bounds(l2Max, mult = [3n, 2n], dataMax = 5000n) {
  const b = await provider.getBlockWithTxHashes("latest");
  return {
    l1_gas: { max_amount: 0n, max_price_per_unit: BigInt(b.l1_gas_price.price_in_fri) * 2n },
    l1_data_gas: { max_amount: dataMax, max_price_per_unit: BigInt(b.l1_data_gas_price.price_in_fri) * 2n },
    l2_gas: { max_amount: l2Max, max_price_per_unit: (BigInt(b.l2_gas_price.price_in_fri) * mult[0]) / mult[1] },
  };
}
const transferCall = (to, amount) => ({ contractAddress: STRK, entrypoint: "transfer", calldata: CallData.compile({ recipient: to, amount: cairo.uint256(amount) }) });

async function main() {
  const deployer = JSON.parse(readFileSync(`${KEYS}/deployer-ecdsa.json`, "utf8"));
  const deployerAddress = readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim();
  const deployerAcc = new Account({ provider, address: deployerAddress, signer: deployer.privateKey });
  const balance = await strkBalance(deployerAddress);
  log("deployer:", fmt(balance));

  // 1. SHAKE verifier class
  if (!state.shakeClass) {
    const b = await provider.getBlockWithTxHashes("latest");
    const l2Max = 4700000000n;
    const maxFee = l2Max * ((BigInt(b.l2_gas_price.price_in_fri) * 5n) / 4n);
    log("declare HybridShakeAccount: max fee", fmt(maxFee));
    if (balance < maxFee + 5n * 10n ** 18n) { log("NEED FUNDS: top up the deployer from https://faucet.starknet.io and rerun."); return; }
    const sierra = json.parse(readFileSync(`${TARGET}/pq_hybrid_HybridShakeAccount.contract_class.json`, "utf8"));
    const casm = json.parse(readFileSync(`${TARGET}/pq_hybrid_HybridShakeAccount.compiled_contract_class.json`, "utf8"));
    const nonce = await provider.getNonceForAddress(deployerAddress, "latest");
    const d = await deployerAcc.declareIfNot({ contract: sierra, casm }, { nonce, tip: 0n, resourceBounds: await bounds(l2Max, [5n, 4n], 200000n) });
    if (d.transaction_hash) {
      const rc = await provider.waitForTransaction(d.transaction_hash);
      log("declare fee:", rc.actual_fee ? fmt(BigInt(rc.actual_fee.amount)) : "n/a");
      state.shakeDeclareTx = d.transaction_hash;
    }
    state.shakeClass = d.class_hash; save();
    log("SHAKE verifier class:", d.class_hash);
  }

  // 2. keys, account, in-place migration
  if (!existsSync(MNEMONIC_FILE)) writeFileSync(MNEMONIC_FILE, generateMnemonic(wordlist, 256) + "\n");
  const keys = deriveAccountKeys(readFileSync(MNEMONIC_FILE, "utf8").trim(), 0);
  const falconFelts = publicKeyFelts(keys.falconPublicKey, ntt).map((x) => num.toHex(x));
  const address = hash.calculateContractAddressFromHash(keys.ecdsaPublicKey, OZ_ACCOUNT_CLASS, [keys.ecdsaPublicKey], 0);
  state.address = address; save();
  log("account:", address);
  if (!(await classAt(address))) {
    if ((await strkBalance(address)) < 8n * 10n ** 18n) {
      const nonce = await provider.getNonceForAddress(deployerAddress, "latest");
      const t = await deployerAcc.execute(transferCall(address, 9n * 10n ** 18n), { nonce, tip: 0n });
      await provider.waitForTransaction(t.transaction_hash);
    }
    const oz = new Account({ provider, address, signer: keys.ecdsaPrivateKey });
    const r = await oz.deployAccount({ classHash: OZ_ACCOUNT_CLASS, constructorCalldata: [keys.ecdsaPublicKey], addressSalt: keys.ecdsaPublicKey, contractAddress: address }, { tip: 0n });
    await provider.waitForTransaction(r.transaction_hash);
    state.deployTx = r.transaction_hash; save();
    log("OZ account deployed:", `${VOYAGER}/tx/${r.transaction_hash}`);
  }
  if ((await classAt(address)) === num.toHex(OZ_ACCOUNT_CLASS)) {
    const oz = new Account({ provider, address, signer: keys.ecdsaPrivateKey });
    const nonce = await provider.getNonceForAddress(address, "latest");
    const proof = await new BrowserHybridSigner(keys).signRaw(registrationHash(keys.ecdsaPublicKey, falconFelts));
    const m = await oz.execute([
      { contractAddress: address, entrypoint: "upgrade", calldata: [MIGRATABLE_CLASS] },
      { contractAddress: address, entrypoint: "migrate", calldata: [keys.ecdsaPublicKey, num.toHex(falconFelts.length), ...falconFelts, state.shakeClass, num.toHex(proof.length), ...proof] },
    ], { nonce, tip: 0n, resourceBounds: await bounds(250000000n) });
    await provider.waitForTransaction(m.transaction_hash);
    state.migrationTx = m.transaction_hash; save();
    log("migrated (SHAKE verifier):", `${VOYAGER}/tx/${m.transaction_hash}`);
  }
  const onchain = await provider.callContract({ contractAddress: address, entrypoint: "get_falcon_public_key", calldata: [] }, "latest");
  log("on-chain Falcon key = noble-derived key:", JSON.stringify(onchain.slice(1).map((x) => num.toHex(x))) === JSON.stringify(falconFelts));

  // 3. one transfer signed the browser way
  if (!state.nodeTransferTx) {
    const acc = new Account({ provider, address, signer: new BrowserHybridSigner(keys) });
    const nonce = await provider.getNonceForAddress(address, "latest");
    const x = await acc.execute(transferCall(deployerAddress, 10n ** 16n), { nonce, tip: 0n, resourceBounds: await bounds(120000000n) });
    const rc = await provider.waitForTransaction(x.transaction_hash);
    state.nodeTransferTx = x.transaction_hash; state.nodeTransferResources = rc.execution_resources || null;
    state.nodeTransferFee = rc.actual_fee ? rc.actual_fee.amount : null; save();
    log("transfer signed with noble Falcon:", `${VOYAGER}/tx/${x.transaction_hash}`, rc.execution_status || "", rc.actual_fee ? fmt(BigInt(rc.actual_fee.amount)) : "");
  }

  // 4. page config: public data only
  writeFileSync(PAGE_CONFIG, JSON.stringify({ rpc: RPC, account: address, strk: STRK, recipient: deployerAddress, voyager: VOYAGER }, null, 2));
  log("page config written");
}

main().catch((e) => { console.error("ERROR:", e?.message || e); let c = e?.cause; while (c) { console.error("  cause:", c.message || c); c = c.cause; } process.exit(1); });
