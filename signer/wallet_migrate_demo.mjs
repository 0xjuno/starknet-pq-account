// Sepolia demo: migrate REAL Argent (0.5.0) and Braavos accounts in place to the hybrid
// ECDSA + Falcon-512 account. TESTNET ONLY.
//   - each account's keys come from its own words, with that wallet's ECDSA derivation
//     (pq_keys.mjs: "argentx", "braavos"); the Falcon key comes from the same words
//   - Argent:  ONE call, upgrade(migratable, MigrationData) -> perform_upgrade
//   - Braavos: ONE tx, multicall [upgrade(migratable), migrate(...)]
//   - both carry a key-possession proof: hybrid signature over registration_hash(ecdsa, falcon)
//   - then a hybrid-signed transfer succeeds and an ECDSA-only transfer is rejected
// Steps are idempotent and resume from .keys/wallet-migrate-state.json.
import { Account, CallData, RpcProvider, Signer, cairo, constants, ec, hash, json, num, shortString } from "starknet";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { generateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { deriveAccountKeys } from "./pq_keys.mjs";
import { makeNtt, publicKeyFelts, signatureFelts, signTxHash } from "./falcon_adapter.mjs";
import { KEYS, ROOTS, RPC, TARGET } from "./config.mjs";

const STATE_FILE = `${KEYS}/wallet-migrate-state.json`;
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const ARGENT_CLASS = "0x073414441639dcd11d1846f287650a00c60c416b9d3ba45d31c651672125b2c2"; // account 0.5.0
const BRAAVOS_BASE = "0x03d16c7a9a60b0593bd202f660a28c5d76e0403601d9ccc7e4fa253b6a70c201";
const BRAAVOS_IMPL = "0x03957f9f5a1cbfe918cedc2015c85200ca51a5f7506ecb6de98a5207b759bf8a";
const VOYAGER = "https://sepolia.voyager.online";
const DOMAIN = "starknet-pq-register-v1";

const SHAKE_VERIFIER = JSON.parse(readFileSync(`${KEYS}/browser-state.json`, "utf8")).shakeClass;
const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
const log = (...a) => console.log(...a);
const fmt = (wei) => (Number(wei) / 1e18).toFixed(6) + " STRK";
const provider = new RpcProvider({ nodeUrl: RPC });
const ntt = makeNtt(JSON.parse(readFileSync(ROOTS, "utf8")));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function retry(fn, tries = 5) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) {
      if (i + 1 >= tries || !/429|rate|ECONNRESET|fetch failed/i.test(e?.message || "")) throw e;
      await sleep(3000 * (i + 1));
    }
  }
}

function walletKeys(name, profile) {
  const file = `${KEYS}/wallet-${name}-mnemonic.txt`;
  if (!existsSync(file)) writeFileSync(file, generateMnemonic(wordlist, 256));
  const k = deriveAccountKeys(readFileSync(file, "utf8").trim(), 0, profile);
  return { ...k, falconFelts: publicKeyFelts(k.falconPublicKey, ntt) };
}

const hybridSignature = (h, k) => {
  const e = ec.starkCurve.sign(num.toHex(h), k.ecdsaPrivateKey);
  return [num.toHex(e.r), num.toHex(e.s), ...signatureFelts(signTxHash(BigInt(h), k.falconSecretKey), k.falconPublicKey).map(num.toHex)];
};
class HybridSigner extends Signer {
  constructor(k) { super(k.ecdsaPrivateKey); this.k = k; }
  async signRaw(msgHash) { return hybridSignature(msgHash, this.k); }
}
// An attacker who forged the classical key but has no Falcon key.
class EcdsaOnlySigner extends Signer {
  constructor(pk) { super(pk); this.pk = pk; }
  async signRaw(msgHash) { const e = ec.starkCurve.sign(num.toHex(msgHash), this.pk); return [num.toHex(e.r), num.toHex(e.s)]; }
}
// Braavos DEPLOY_ACCOUNT: [r, s, impl, AdditionalDeploymentParams..., chain_id, aux_r, aux_s]
class BraavosDeploySigner extends Signer {
  constructor(pk) { super(pk); this.pk = pk; }
  async signRaw(msgHash) {
    const aux = [BRAAVOS_IMPL, 0, 0, 0, 0, 0, 0, 0, 0, 0, constants.StarknetChainId.SN_SEPOLIA].map(num.toHex);
    const a = ec.starkCurve.sign(hash.computePoseidonHashOnElements(aux), this.pk);
    const t = ec.starkCurve.sign(num.toHex(msgHash), this.pk);
    return [num.toHex(t.r), num.toHex(t.s), ...aux, num.toHex(a.r), num.toHex(a.s)];
  }
}

function migrationArgs(k) {
  const registration = hash.computePoseidonHashOnElements([shortString.encodeShortString(DOMAIN), k.ecdsaPublicKey, ...k.falconFelts]);
  const proof = hybridSignature(registration, k);
  // MigrationData { ecdsa_public_key, falcon_public_key: Array, verifier_class_hash, proof: Array }
  return [k.ecdsaPublicKey, num.toHex(k.falconFelts.length), ...k.falconFelts.map(num.toHex), SHAKE_VERIFIER, num.toHex(proof.length), ...proof];
}

async function strkBalance(address) {
  const r = await retry(() => provider.callContract({ contractAddress: STRK, entrypoint: "balance_of", calldata: [address] }));
  return BigInt(r[0]) + (BigInt(r[1]) << 128n);
}
async function classAt(address) {
  try { return num.toHex(await retry(() => provider.getClassHashAt(address))); } catch { return null; }
}
async function bounds(l2Max, l2Mult = [3n, 2n], dataMax = 5000n) {
  const b = await retry(() => provider.getBlockWithTxHashes("latest"));
  return {
    l1_gas: { max_amount: 0n, max_price_per_unit: BigInt(b.l1_gas_price.price_in_fri) * 2n },
    l1_data_gas: { max_amount: dataMax, max_price_per_unit: BigInt(b.l1_data_gas_price.price_in_fri) * 2n },
    l2_gas: { max_amount: l2Max, max_price_per_unit: (BigInt(b.l2_gas_price.price_in_fri) * l2Mult[0]) / l2Mult[1] },
  };
}
const transferCall = (to, amount) => ({ contractAddress: STRK, entrypoint: "transfer", calldata: CallData.compile({ recipient: to, amount: cairo.uint256(amount) }) });
async function send(acc, calls, l2Max) {
  const nonce = await retry(() => provider.getNonceForAddress(acc.address, "latest"));
  const t = await acc.execute(calls, { nonce, tip: 0n, resourceBounds: await bounds(l2Max) });
  const rc = await retry(() => provider.waitForTransaction(t.transaction_hash));
  return { tx: t.transaction_hash, fee: rc.actual_fee?.amount, l2Gas: rc.execution_resources?.l2_gas, status: rc.execution_status };
}

async function declareMigratable(deployerAcc) {
  if (state.migratableClass) return;
  const sierraPath = `${TARGET}/pq_hybrid_HybridMigratableAccount.contract_class.json`;
  const sierra = json.parse(readFileSync(sierraPath, "utf8"));
  const casm = json.parse(readFileSync(`${TARGET}/pq_hybrid_HybridMigratableAccount.compiled_contract_class.json`, "utf8"));
  const l2Max = BigInt(Math.ceil(4.2e9 * (statSync(sierraPath).size / 2.2e6) * 2.5));
  log(`declaring HybridMigratableAccount with migrate/perform_upgrade (l2 max ${l2Max})...`);
  const nonce = await retry(() => provider.getNonceForAddress(deployerAcc.address, "latest"));
  const d = await deployerAcc.declareIfNot({ contract: sierra, casm }, { nonce, tip: 0n, resourceBounds: await bounds(l2Max, [5n, 4n], 200000n) });
  if (d.transaction_hash) {
    const rc = await retry(() => provider.waitForTransaction(d.transaction_hash));
    log("declare fee:", rc.actual_fee ? fmt(BigInt(rc.actual_fee.amount)) : "n/a");
  }
  state.migratableClass = d.class_hash; state.declareTx = d.transaction_hash || null; save();
  log("migratable class:", d.class_hash);
}

async function fund(deployerAcc, address, amount) {
  if ((await strkBalance(address)) >= amount) return;
  log(`  funding ${address} with ${fmt(amount)}...`);
  await send(deployerAcc, transferCall(address, amount), 3000000n);
}

async function checkAndExercise(name, k, deployerAddress) {
  const s = state[name];
  const view = async (entrypoint) => (await retry(() => provider.callContract({ contractAddress: s.address, entrypoint, calldata: [] }, "latest")));
  const cls = await classAt(s.address);
  const registered = (await view("is_falcon_registered"))[0];
  const ecdsaKey = (await view("get_ecdsa_public_key"))[0];
  const falconKey = (await view("get_falcon_public_key")).slice(1);
  s.after = {
    class: cls, migratable: BigInt(cls) === BigInt(state.migratableClass), registered: BigInt(registered) === 1n,
    ecdsaKeyMatchesWords: BigInt(ecdsaKey) === BigInt(k.ecdsaPublicKey),
    falconKeyMatchesWords: falconKey.length === 29 && falconKey.every((f, i) => BigInt(f) === BigInt(k.falconFelts[i])),
    balance: (await strkBalance(s.address)).toString(),
  };
  save();
  log(`  after: ${JSON.stringify(s.after)}`);

  if (!s.hybridTransfer) {
    const acc = new Account({ provider, address: s.address, signer: new HybridSigner(k) });
    s.hybridTransfer = await send(acc, transferCall(deployerAddress, 10n ** 16n), 70000000n); save();
    log(`  hybrid transfer: ${VOYAGER}/tx/${s.hybridTransfer.tx} (${s.hybridTransfer.status}, l2 gas ${s.hybridTransfer.l2Gas})`);
  }
  if (!s.ecdsaOnly) {
    const attacker = new Account({ provider, address: s.address, signer: new EcdsaOnlySigner(k.ecdsaPrivateKey) });
    try {
      const r = await send(attacker, transferCall(deployerAddress, 1n), 70000000n);
      s.ecdsaOnly = "UNEXPECTED: accepted " + r.tx;
    } catch (e) {
      const msg = e?.message || String(e);
      s.ecdsaOnly = /validate/i.test(msg) && /panicked|invalid signature/i.test(msg) ? "rejected in __validate__" : "UNCLEAR: " + msg.slice(-300);
    }
    save();
  }
  log(`  ECDSA-only transfer: ${s.ecdsaOnly}`);
}

async function argent(deployerAcc) {
  const k = walletKeys("argent", "argentx");
  const calldata = [0, k.ecdsaPublicKey, 1].map(num.toHex); // owner Signer::Starknet(pubkey), guardian None
  const address = hash.calculateContractAddressFromHash(k.ecdsaPublicKey, ARGENT_CLASS, calldata, 0);
  const s = (state.argent ||= { address }); save();
  log("ARGENT account (ECDSA key from the words via Argent X derivation):", address);
  if (!(await classAt(address))) {
    await fund(deployerAcc, address, 3n * 10n ** 18n);
    const acc = new Account({ provider, address, signer: k.ecdsaPrivateKey });
    const r = await acc.deployAccount({ classHash: ARGENT_CLASS, constructorCalldata: calldata, addressSalt: k.ecdsaPublicKey, contractAddress: address },
      { tip: 0n, resourceBounds: await bounds(20000000n) });
    await retry(() => provider.waitForTransaction(r.transaction_hash));
    s.deployTx = r.transaction_hash; save();
    log(`  deployed: ${VOYAGER}/tx/${r.transaction_hash}`);
  }
  if (BigInt((await classAt(address)) || 0) === BigInt(ARGENT_CLASS)) {
    s.version = (await retry(() => provider.callContract({ contractAddress: address, entrypoint: "get_version", calldata: [] }))).map((x) => Number(x)).join(".");
    s.before = { class: ARGENT_CLASS, balance: (await strkBalance(address)).toString() }; save();
    log(`  before: Argent ${s.version}, balance ${fmt(BigInt(s.before.balance))}`);
    const acc = new Account({ provider, address, signer: k.ecdsaPrivateKey });
    const data = migrationArgs(k);
    const call = { contractAddress: address, entrypoint: "upgrade", calldata: [state.migratableClass, num.toHex(data.length), ...data] };
    log(`  migrating: upgrade(migratable, MigrationData of ${data.length} felts), signed by the Argent owner key...`);
    s.migration = await send(acc, call, 150000000n); save();
    log(`  migration: ${VOYAGER}/tx/${s.migration.tx} (${s.migration.status}, l2 gas ${s.migration.l2Gas}, fee ${fmt(BigInt(s.migration.fee))})`);
  }
  await checkAndExercise("argent", k, deployerAcc.address);
}

async function braavos(deployerAcc) {
  const k = walletKeys("braavos", "braavos");
  const address = hash.calculateContractAddressFromHash(k.ecdsaPublicKey, BRAAVOS_BASE, [k.ecdsaPublicKey], 0);
  const s = (state.braavos ||= { address }); save();
  log("BRAAVOS account (ECDSA key from the words via BIP32 m/44'/9004'/0'/0/0):", address);
  if (!(await classAt(address))) {
    await fund(deployerAcc, address, 3n * 10n ** 18n);
    const acc = new Account({ provider, address, signer: new BraavosDeploySigner(k.ecdsaPrivateKey) });
    const r = await acc.deployAccount({ classHash: BRAAVOS_BASE, constructorCalldata: [k.ecdsaPublicKey], addressSalt: k.ecdsaPublicKey, contractAddress: address },
      { tip: 0n, resourceBounds: await bounds(30000000n) });
    await retry(() => provider.waitForTransaction(r.transaction_hash));
    s.deployTx = r.transaction_hash; save();
    log(`  deployed: ${VOYAGER}/tx/${r.transaction_hash}`);
  }
  if (BigInt((await classAt(address)) || 0) === BigInt(BRAAVOS_IMPL)) {
    s.before = { class: BRAAVOS_IMPL, balance: (await strkBalance(address)).toString() }; save();
    log(`  before: Braavos impl, balance ${fmt(BigInt(s.before.balance))}`);
    const acc = new Account({ provider, address, signer: k.ecdsaPrivateKey });
    const calls = [
      { contractAddress: address, entrypoint: "upgrade", calldata: [state.migratableClass] },
      { contractAddress: address, entrypoint: "migrate", calldata: migrationArgs(k) },
    ];
    log("  migrating: multicall [upgrade(migratable), migrate(...)], signed by the Braavos stark key...");
    s.migration = await send(acc, calls, 150000000n); save();
    log(`  migration: ${VOYAGER}/tx/${s.migration.tx} (${s.migration.status}, l2 gas ${s.migration.l2Gas}, fee ${fmt(BigInt(s.migration.fee))})`);
  }
  await checkAndExercise("braavos", k, deployerAcc.address);
}

async function main() {
  const deployer = JSON.parse(readFileSync(`${KEYS}/deployer-ecdsa.json`, "utf8"));
  const deployerAddress = readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim();
  const deployerAcc = new Account({ provider, address: deployerAddress, signer: deployer.privateKey });
  log("deployer:", deployerAddress, fmt(await strkBalance(deployerAddress)), " verifier (SHAKE):", SHAKE_VERIFIER);
  await declareMigratable(deployerAcc);
  const only = process.argv[2];
  if (!only || only === "argent") await argent(deployerAcc);
  if (!only || only === "braavos") await braavos(deployerAcc);
}

main().catch((e) => { console.error("ERROR:", e?.message || e); process.exit(1); });
