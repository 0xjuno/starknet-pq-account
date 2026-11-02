// Sepolia check of key rotation and verifier changes on a migrated account, driven by
// pq_account_kit.mjs. TESTNET ONLY.
//   1. deploy a fresh OpenZeppelin account and migrate it to the current HybridMigratableAccount
//   2. rotate both keys to index 1 of the same words (rotationCalls): succeeds, and only the new
//      keys sign afterwards
//   3. rotate to a Falcon key nobody holds: reverted on-chain, keys unchanged
//   4. switch to the Poseidon verifier (another scheme): reverted on-chain, verifier unchanged
//   5. switch to the SHAKE-256 verifier again: succeeds; a final transfer still goes through
// Idempotent; resumes from .keys/rotation-sepolia-state.json.   node rotation_sepolia.mjs
import { Account, CallData, RpcProvider, cairo, hash, json, num } from "starknet";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { generateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import {
  HybridSigner, KNOWN_VERIFIERS, deriveAccountKeys, hybridSignature, inspectAccount, migrationCalls,
  prepareKeys, rotationCalls, rotationHash, verifierSwitchCall,
} from "./pq_account_kit.mjs";
import { KEYS, ROOTS, RPC, TARGET } from "./config.mjs";

const STATE_FILE = `${KEYS}/rotation-sepolia-state.json`;
const WORDS_FILE = `${KEYS}/rotation-sepolia-mnemonic.txt`;
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const OZ_CLASS = "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";
const VOYAGER = "https://sepolia.voyager.online";
const [SHAKE, POSEIDON] = Object.keys(KNOWN_VERIFIERS);

const provider = new RpcProvider({ nodeUrl: RPC });
const roots = JSON.parse(readFileSync(ROOTS, "utf8"));
const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
const log = (...a) => console.log(...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let TIP = 0n; // Sepolia evicts zero-tip transactions; set from recent blocks in main()

async function retry(fn, tries = 10) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) {
      if (i + 1 >= tries || !/cu limit|too fast|429|rate|ECONNRESET|fetch failed/i.test(e?.message || "")) throw e;
      await sleep(3000 * (i + 1));
    }
  }
}

async function bounds(l2Max) {
  const b = await retry(() => provider.getBlockWithTxHashes("latest"));
  return {
    l1_gas: { max_amount: 0n, max_price_per_unit: BigInt(b.l1_gas_price.price_in_fri) * 2n },
    l1_data_gas: { max_amount: 5000n, max_price_per_unit: BigInt(b.l1_data_gas_price.price_in_fri) * 2n },
    l2_gas: { max_amount: l2Max, max_price_per_unit: (BigInt(b.l2_gas_price.price_in_fri) * 3n) / 2n },
  };
}

async function receipt(txHash) {
  try { await provider.waitForTransaction(txHash); } catch { /* reverted: read the receipt below */ }
  for (let i = 0; i < 40; i++) {
    try {
      const r = await provider.getTransactionReceipt(txHash);
      const v = r.value ?? r;
      if (v.execution_status) return v;
    } catch { /* not yet known */ }
    await sleep(3000);
  }
  throw new Error(`no receipt for ${txHash}`);
}

// Sends with fixed bounds (no fee estimate), so a call that reverts in __execute__ still lands
// on-chain as REVERTED instead of failing in estimation.
async function send(acc, calls, l2Max) {
  const nonce = await retry(() => provider.getNonceForAddress(acc.address, "latest"));
  const t = await retry(async () => acc.execute(calls, { nonce, tip: TIP, resourceBounds: await bounds(l2Max) }));
  const rc = await receipt(t.transaction_hash);
  return { tx: t.transaction_hash, status: rc.execution_status, l2Gas: rc.execution_resources?.l2_gas, revert: rc.revert_reason?.slice(0, 400) };
}

const transferCall = (to, amount) => ({ contractAddress: STRK, entrypoint: "transfer", calldata: CallData.compile({ recipient: to, amount: cairo.uint256(amount) }) });
const read = async (address, entrypoint) =>
  (await retry(() => provider.callContract({ contractAddress: address, entrypoint, calldata: [] }, "latest"))).map((x) => BigInt(x));
async function onChainKeys(address) {
  return { ecdsa: (await read(address, "get_ecdsa_public_key"))[0], falcon: (await read(address, "get_falcon_public_key")).slice(1) };
}
const sameKeys = (onChain, k) => onChain.ecdsa === BigInt(k.ecdsaPublicKey) &&
  onChain.falcon.length === k.falconFelts.length && onChain.falcon.every((f, i) => f === BigInt(k.falconFelts[i]));

async function declareMigratable(deployer) {
  const sierraPath = `${TARGET}/pq_hybrid_HybridMigratableAccount.contract_class.json`;
  const sierra = json.parse(readFileSync(sierraPath, "utf8"));
  const casm = json.parse(readFileSync(`${TARGET}/pq_hybrid_HybridMigratableAccount.compiled_contract_class.json`, "utf8"));
  const classHash = hash.computeContractClassHash(sierra);
  if (state.migratableClass === classHash) return;
  const l2Max = BigInt(Math.ceil(4.2e9 * (statSync(sierraPath).size / 2.2e6) * 2.5));
  log(`declaring HybridMigratableAccount ${classHash}...`);
  const nonce = await retry(() => provider.getNonceForAddress(deployer.address, "latest"));
  const d = await deployer.declareIfNot({ contract: sierra, casm }, { nonce, tip: TIP, resourceBounds: await bounds(l2Max) });
  if (d.transaction_hash) state.declareTx = { tx: d.transaction_hash, status: (await receipt(d.transaction_hash)).execution_status };
  state.migratableClass = d.class_hash; save();
}

async function step(name, fn) {
  if (state[name]) { log(`${name}: ${JSON.stringify(state[name])}`); return state[name]; }
  state[name] = await fn(); save();
  log(`${name}: ${JSON.stringify(state[name])}`);
  return state[name];
}

async function main() {
  const deployerKey = JSON.parse(readFileSync(`${KEYS}/deployer-ecdsa.json`, "utf8")).privateKey;
  const deployerAddress = readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim();
  const deployer = new Account({ provider, address: deployerAddress, signer: deployerKey });
  TIP = (await retry(() => provider.getEstimateTip("latest", { maxBlocks: 5 }))).recommendedTip;
  log("deployer:", deployerAddress, " tip:", TIP);
  await declareMigratable(deployer);
  log("migratable class:", state.migratableClass);

  if (!existsSync(WORDS_FILE)) writeFileSync(WORDS_FILE, generateMnemonic(wordlist, 256));
  const words = readFileSync(WORDS_FILE, "utf8").trim();
  const k0 = prepareKeys(deriveAccountKeys(words, 0, "pq"), roots);
  const k1 = prepareKeys(deriveAccountKeys(words, 1, "pq"), roots);
  const address = hash.calculateContractAddressFromHash(k0.ecdsaPublicKey, OZ_CLASS, [k0.ecdsaPublicKey], 0);
  state.address = address; save();
  log("account:", address);

  await step("deploy", async () => {
    await send(deployer, transferCall(address, 25n * 10n ** 18n), 3000000n);
    const acc = new Account({ provider, address, signer: k0.ecdsaPrivateKey });
    const r = await retry(async () => acc.deployAccount({ classHash: OZ_CLASS, constructorCalldata: [k0.ecdsaPublicKey], addressSalt: k0.ecdsaPublicKey, contractAddress: address },
      { tip: TIP, resourceBounds: await bounds(30000000n) }));
    return { tx: r.transaction_hash, status: (await receipt(r.transaction_hash)).execution_status };
  });

  await step("migrate", async () => {
    const info = await retry(() => inspectAccount(provider, address));
    const calls = migrationCalls(info, k0, { migratableClass: state.migratableClass, verifierClass: SHAKE });
    return send(new Account({ provider, address, signer: k0.ecdsaPrivateKey }), calls, 250000000n);
  });

  const asK0 = new Account({ provider, address, signer: new HybridSigner(k0) });
  const asK1 = new Account({ provider, address, signer: new HybridSigner(k1) });

  await step("rotateBothKeys", async () => {
    const r = await send(asK0, rotationCalls(address, k0, k1), 350000000n);
    return { ...r, storedKeysAreIndex1: sameKeys(await onChainKeys(address), k1) };
  });
  await step("transferWithNewKeys", () => send(asK1, transferCall(deployerAddress, 10n ** 16n), 80000000n));

  await step("rotateToKeyNobodyHolds", async () => {
    const bad = [...k1.falconFelts.slice(0, -1), num.toHex(BigInt(k1.falconFelts.at(-1)) + 1n)];
    const proof = hybridSignature(rotationHash(k1.ecdsaPublicKey, bad), k1);
    const call = { contractAddress: address, entrypoint: "rotate_falcon_public_key", calldata: [num.toHex(bad.length), ...bad, num.toHex(proof.length), ...proof] };
    const r = await send(asK1, [call], 250000000n);
    return { ...r, keysUnchanged: sameKeys(await onChainKeys(address), k1) };
  });

  await step("switchToPoseidonVerifier", async () => {
    const r = await send(asK1, [verifierSwitchCall(address, POSEIDON)], 250000000n);
    return { ...r, verifierUnchanged: (await read(address, "get_verifier_class_hash"))[0] === BigInt(SHAKE) };
  });

  await step("switchToShakeVerifier", async () => {
    const r = await send(asK1, [verifierSwitchCall(address, SHAKE)], 250000000n);
    return { ...r, verifierIsShake: (await read(address, "get_verifier_class_hash"))[0] === BigInt(SHAKE) };
  });
  await step("finalTransfer", () => send(asK1, transferCall(deployerAddress, 10n ** 16n), 80000000n));

  log("\nVoyager:");
  for (const k of ["migrate", "rotateBothKeys", "transferWithNewKeys", "rotateToKeyNobodyHolds", "switchToPoseidonVerifier", "switchToShakeVerifier", "finalTransfer"]) {
    log(`  ${k}: ${VOYAGER}/tx/${state[k].tx} ${state[k].status}`);
  }
}

main().catch((e) => { console.error("ERROR:", e?.message || e); process.exit(1); });
