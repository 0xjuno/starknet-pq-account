// Public demo account for docs/index.html. Its mnemonic is published on purpose so anyone can
// try the browser signer. TESTNET ONLY: it holds Sepolia STRK with no value and is refilled.
//   1. declare the current HybridMigratableAccount (adds rotate_ecdsa_public_key)
//   2. new mnemonic -> OZ account, funded, deployed, migrated in place with the SHAKE verifier
//   3. one hybrid transfer signed the browser way
import { Account, CallData, RpcProvider, Signer, cairo, ec, hash, json, num } from "starknet";
import { generateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { deriveAccountKeys } from "./pq_keys.mjs";
import { makeNtt, publicKeyFelts, signatureFelts, signTxHash } from "./falcon_adapter.mjs";
import { KEYS, ROOTS, RPC, TARGET } from "./config.mjs";
import { registrationHash } from "./pq_account_kit.mjs";

const STATE_FILE = `${KEYS}/public-demo-state.json`;
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const OZ_ACCOUNT_CLASS = "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";
const SHAKE_CLASS = JSON.parse(readFileSync(`${KEYS}/browser-state.json`, "utf8")).shakeClass;
const VOYAGER = "https://sepolia.voyager.online";
const FUND = 50n * 10n ** 18n;
const ntt = makeNtt(JSON.parse(readFileSync(ROOTS, "utf8")));

const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
const log = (...a) => console.log(...a);
const fmt = (wei) => (Number(wei) / 1e18).toFixed(4) + " STRK";
const provider = new RpcProvider({ nodeUrl: RPC });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
  const r = await provider.callContract({ contractAddress: STRK, entrypoint: "balance_of", calldata: [a] }, "latest");
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

const deployer = JSON.parse(readFileSync(`${KEYS}/deployer-ecdsa.json`, "utf8"));
const deployerAddress = readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim();
const deployerAcc = new Account({ provider, address: deployerAddress, signer: deployer.privateKey });
// Sepolia evicts zero-tip transactions from the mempool; pay the tip recent blocks paid.
const TIP = (await provider.getEstimateTip("latest", { maxBlocks: 5 })).recommendedTip;
log("deployer:", fmt(await strkBalance(deployerAddress)));

// 1. current migratable class
if (!state.migratableClass) {
  const sierra = json.parse(readFileSync(`${TARGET}/pq_hybrid_HybridMigratableAccount.contract_class.json`, "utf8"));
  const casm = json.parse(readFileSync(`${TARGET}/pq_hybrid_HybridMigratableAccount.compiled_contract_class.json`, "utf8"));
  const nonce = await provider.getNonceForAddress(deployerAddress, "latest");
  const d = await deployerAcc.declareIfNot({ contract: sierra, casm }, { nonce, tip: TIP, resourceBounds: await bounds(800000000n, [5n, 4n], 200000n) });
  if (d.transaction_hash) { const rc = await provider.waitForTransaction(d.transaction_hash); log("declare fee:", rc.actual_fee ? fmt(BigInt(rc.actual_fee.amount)) : "n/a"); }
  state.migratableClass = d.class_hash; save();
  log("migratable class (with ECDSA rotation):", d.class_hash);
}

// 2. public demo account
if (!state.mnemonic) { state.mnemonic = generateMnemonic(wordlist, 256); save(); }
const keys = deriveAccountKeys(state.mnemonic, 0);
const falconFelts = publicKeyFelts(keys.falconPublicKey, ntt).map((x) => num.toHex(x));
const address = hash.calculateContractAddressFromHash(keys.ecdsaPublicKey, OZ_ACCOUNT_CLASS, [keys.ecdsaPublicKey], 0);
state.address = address; save();
log("public demo account:", address);
if (!(await classAt(address))) {
  if ((await strkBalance(address)) < FUND / 2n) {
    const nonce = await provider.getNonceForAddress(deployerAddress, "latest");
    const t = await deployerAcc.execute(transferCall(address, FUND), { nonce, tip: TIP });
    await provider.waitForTransaction(t.transaction_hash);
  }
  await sleep(1500);
  const oz = new Account({ provider, address, signer: keys.ecdsaPrivateKey });
  const r = await oz.deployAccount({ classHash: OZ_ACCOUNT_CLASS, constructorCalldata: [keys.ecdsaPublicKey], addressSalt: keys.ecdsaPublicKey, contractAddress: address }, { tip: TIP });
  await provider.waitForTransaction(r.transaction_hash);
  state.deployTx = r.transaction_hash; save();
  log("OZ account deployed:", `${VOYAGER}/tx/${r.transaction_hash}`);
}
await sleep(1500);
if ((await classAt(address)) === num.toHex(OZ_ACCOUNT_CLASS)) {
  const oz = new Account({ provider, address, signer: keys.ecdsaPrivateKey });
  const nonce = await provider.getNonceForAddress(address, "latest");
  const proof = await new BrowserHybridSigner(keys).signRaw(registrationHash(keys.ecdsaPublicKey, falconFelts));
  const m = await oz.execute([
    { contractAddress: address, entrypoint: "upgrade", calldata: [state.migratableClass] },
    { contractAddress: address, entrypoint: "migrate", calldata: [keys.ecdsaPublicKey, num.toHex(falconFelts.length), ...falconFelts, SHAKE_CLASS, num.toHex(proof.length), ...proof] },
  ], { nonce, tip: TIP, resourceBounds: await bounds(250000000n) });
  await provider.waitForTransaction(m.transaction_hash);
  state.migrationTx = m.transaction_hash; save();
  log("migrated in place:", `${VOYAGER}/tx/${m.transaction_hash}`);
}

// 3. one browser-style transfer
await sleep(1500);
if (!state.transferTx) {
  const acc = new Account({ provider, address, signer: new BrowserHybridSigner(keys) });
  const nonce = await provider.getNonceForAddress(address, "latest");
  const x = await acc.execute(transferCall(deployerAddress, 10n ** 16n), { nonce, tip: TIP, resourceBounds: await bounds(70000000n, [5n, 4n]) });
  const rc = await provider.waitForTransaction(x.transaction_hash);
  state.transferTx = x.transaction_hash; save();
  log("browser-style transfer:", `${VOYAGER}/tx/${x.transaction_hash}`, rc.execution_status || "");
}
log("balance:", fmt(await strkBalance(address)));
