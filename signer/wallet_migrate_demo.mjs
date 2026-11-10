// Sepolia matrix: deploy REAL accounts of each wallet class seen on mainnet (Argent 0.3.0 to 0.5.0,
// Braavos 1.0.0 to 1.2.0, OpenZeppelin) and migrate each in place to the hybrid ECDSA + Falcon-512
// account using only pq_account_kit.mjs. TESTNET ONLY.
//   - keys come from fresh words with that wallet's ECDSA derivation (pq_keys.mjs profiles);
//     the Falcon key comes from the same words
//   - inspectAccount says which wallet it is and whether it can move; migrationCalls builds the
//     transaction (Argent: one upgrade call; Braavos, OpenZeppelin: [upgrade, migrate])
//   - then: stored keys equal the keys from the words, balance dropped by exactly the fee,
//     a hybrid-signed transfer succeeds, an ECDSA-only transfer is rejected
// Idempotent; resumes from .keys/wallet-matrix-state.json.   node wallet_migrate_demo.mjs [name ...]
// PQ_MATRIX_RUN=<tag> starts a separate run (own state file and fresh words), e.g. after a new
// HybridMigratableAccount class. The verifier and the migratable class are pinned in
// release/testnet-v1.json (verifiers.mjs): PQ_VERIFIER=<id> picks the verifier, default the small
// Provably Fast verifier; PQ_VERIFIER_CLASS=<hash> also works if that hash is pinned.
// --print-config prints the choice and sends nothing.
import { Account, CallData, RpcProvider, Signer, cairo, constants, ec, hash, num } from "starknet";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { generateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { HybridSigner, deriveAccountKeys, inspectAccount, migrationCalls, prepareKeys } from "./pq_account_kit.mjs";
import { KEYS, ROOTS, RPC } from "./config.mjs";
import { MIGRATABLE_CLASS, selectedVerifier } from "./verifiers.mjs";

const RUN = process.env.PQ_MATRIX_RUN || "";
const STATE_FILE = `${KEYS}/wallet-matrix-state${RUN ? `-${RUN}` : ""}.json`;
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const BRAAVOS_BASE = "0x03d16c7a9a60b0593bd202f660a28c5d76e0403601d9ccc7e4fa253b6a70c201";
const VOYAGER = "https://sepolia.voyager.online";
// Argent 0.3.x classes run the whole migration in Cairo-steps accounting: about 140-155M L2 gas,
// against about 70-75M from newer classes.
const MIGRATION_L2_MAX = 250000000n;

// Class hashes as used on mainnet (all also declared on Sepolia).
const WALLETS = {
  "argent-0.3.0": { profile: "argentx", cls: "0x1a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003", ctor: (pk) => [pk, 0] },
  "argent-0.3.1": { profile: "argentx", cls: "0x29927c8af6bccf3f6fda035981e765a7bdbf18a2dc0d630494f8758aa908e2b", ctor: (pk) => [pk, 0] },
  "argent-0.4.0": { profile: "argentx", cls: "0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f", ctor: (pk) => [0, pk, 1] },
  "argent-0.5.0": { profile: "argentx", cls: "0x073414441639dcd11d1846f287650a00c60c416b9d3ba45d31c651672125b2c2", ctor: (pk) => [0, pk, 1] },
  // Argent forks shipped by other wallets. Their seed derivation is not published, so these use
  // the "pq" profile: the test covers the upgrade path, not key derivation.
  "xverse": { profile: "pq", cls: "0x663fc01a0dbe1bacc4cd2a4c856eb9784b255a20988aa33d4d52b6fc20bd024", ctor: (pk) => [0, pk, 1] },
  "okx": { profile: "pq", cls: "0x1c0bb51e2ce73dc007601a1e7725453627254016c28f118251a71bbb0507fcb", ctor: (pk) => [pk, 0] },
  "braavos-1.0.0": { profile: "braavos", impl: "0x816dd0297efc55dc1e7559020a3a825e81ef734b558f03c83325d4da7e6253" },
  "braavos-1.1.0": { profile: "braavos", impl: "0x2c8c7e6fbcfb3e8e15a46648e8914c6aa1fc506fc1e7fb3d1e19630716174bc" },
  "braavos-1.2.0": { profile: "braavos", impl: "0x3957f9f5a1cbfe918cedc2015c85200ca51a5f7506ecb6de98a5207b759bf8a" },
  "openzeppelin-a": { profile: "pq", cls: "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564", ctor: (pk) => [pk] },
  "openzeppelin-b": { profile: "pq", cls: "0xe2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6", ctor: (pk) => [pk] },
};

const VERIFIER = selectedVerifier();
const SHAKE_VERIFIER = VERIFIER.classHash;
const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
// A run keeps the classes it started with: resuming it with others would mix them in one record.
if (state.migratableClass && BigInt(state.migratableClass) !== BigInt(MIGRATABLE_CLASS)) {
  throw new Error(`${STATE_FILE} was started with migratable class ${state.migratableClass}, not ${MIGRATABLE_CLASS}; start a new run (PQ_MATRIX_RUN)`);
}
for (const [name, w] of Object.entries(state)) {
  const used = w?.before?.verifierClass;
  if (used && BigInt(used) !== BigInt(SHAKE_VERIFIER)) {
    throw new Error(`${STATE_FILE} was started with verifier ${used} (${name}), not ${SHAKE_VERIFIER}; set PQ_VERIFIER to match, or start a new run (PQ_MATRIX_RUN)`);
  }
}
if (process.argv.includes("--print-config")) {
  console.log(`verifier: ${VERIFIER.id} ${SHAKE_VERIFIER}\nmigratable class: ${MIGRATABLE_CLASS}`);
  process.exit(0);
}
const log = (...a) => console.log(...a);
const fmt = (wei) => (Number(wei) / 1e18).toFixed(6) + " STRK";
const provider = new RpcProvider({ nodeUrl: RPC });
const roots = JSON.parse(readFileSync(ROOTS, "utf8"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Sepolia evicts zero-tip transactions from the mempool; set in main() from recent blocks.
let TIP = 0n;

async function retry(fn, tries = 6) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) {
      if (i + 1 >= tries || !/cu limit|too fast|429|rate|ECONNRESET|fetch failed/i.test(e?.message || "")) throw e;
      await sleep(3000 * (i + 1));
    }
  }
}

function walletKeys(name, profile) {
  const file = `${KEYS}/wallet-${RUN ? `${RUN}-` : ""}${name}-mnemonic.txt`;
  if (!existsSync(file)) writeFileSync(file, generateMnemonic(wordlist, 256));
  return prepareKeys(deriveAccountKeys(readFileSync(file, "utf8").trim(), 0, profile), roots);
}

// An attacker who forged the classical key but has no Falcon key.
class EcdsaOnlySigner extends Signer {
  constructor(pk) { super(pk); this.pk = pk; }
  async signRaw(msgHash) { const e = ec.starkCurve.sign(num.toHex(msgHash), this.pk); return [num.toHex(e.r), num.toHex(e.s)]; }
}
// Braavos DEPLOY_ACCOUNT: [r, s, impl, AdditionalDeploymentParams..., chain_id, aux_r, aux_s]
class BraavosDeploySigner extends Signer {
  constructor(pk, impl) { super(pk); this.pk = pk; this.impl = impl; }
  async signRaw(msgHash) {
    const aux = [this.impl, 0, 0, 0, 0, 0, 0, 0, 0, 0, constants.StarknetChainId.SN_SEPOLIA].map(num.toHex);
    const a = ec.starkCurve.sign(hash.computePoseidonHashOnElements(aux), this.pk);
    const t = ec.starkCurve.sign(num.toHex(msgHash), this.pk);
    return [num.toHex(t.r), num.toHex(t.s), ...aux, num.toHex(a.r), num.toHex(a.s)];
  }
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
  const t = await retry(async () => acc.execute(calls, { nonce, tip: TIP, resourceBounds: await bounds(l2Max) }));
  const rc = await retry(() => provider.waitForTransaction(t.transaction_hash));
  return { tx: t.transaction_hash, fee: rc.actual_fee?.amount, l2Gas: rc.execution_resources?.l2_gas, status: rc.execution_status };
}
const errTail = (e) => { const m = e?.message || String(e); return m.slice(Math.max(0, m.length - 300)); };


async function deploy(name, w, k, deployerAcc) {
  const braavos = !!w.impl;
  const ctor = braavos ? [k.ecdsaPublicKey] : w.ctor(k.ecdsaPublicKey).map(num.toHex);
  const deployClass = braavos ? BRAAVOS_BASE : w.cls;
  const address = hash.calculateContractAddressFromHash(k.ecdsaPublicKey, deployClass, ctor, 0);
  const s = (state[name] ||= { address }); save();
  if (await classAt(address)) return s;
  if ((await strkBalance(address)) < 25n * 10n ** 17n) await send(deployerAcc, transferCall(address, 25n * 10n ** 17n), 3000000n);
  const acc = new Account({ provider, address, signer: braavos ? new BraavosDeploySigner(k.ecdsaPrivateKey, w.impl) : k.ecdsaPrivateKey });
  const r = await retry(async () => acc.deployAccount({ classHash: deployClass, constructorCalldata: ctor, addressSalt: k.ecdsaPublicKey, contractAddress: address },
    { tip: TIP, resourceBounds: await bounds(30000000n) }));
  const rc = await retry(() => provider.waitForTransaction(r.transaction_hash));
  s.deployTx = r.transaction_hash; s.deployStatus = rc.execution_status; save();
  return s;
}

async function run(name, deployerAcc) {
  const w = WALLETS[name];
  const k = walletKeys(name, w.profile);
  log(`\n${name}`);
  let s;
  try { s = await deploy(name, w, k, deployerAcc); } catch (e) {
    (state[name] ||= {}).deployError = errTail(e); save();
    log(`  deploy failed: ${state[name].deployError}`); return;
  }
  log(`  account ${s.address}${s.deployTx ? ` (deployed ${s.deployTx})` : ""}`);

  if (s.migration && s.migration.status !== "SUCCEEDED") {
    (s.failedMigrations ||= []).push(s.migration); delete s.migration; save();
  }
  if (!s.migration) {
    const info = await retry(() => inspectAccount(provider, s.address));
    s.inspectBefore = info; save();
    log(`  inspect: ${info.kind} ${info.version || ""} migratable=${info.migratable} needs=[${info.needs}] ${info.reason}`);
    if (!info.migratable) return;
    // Fee bound for the migration (MIGRATION_L2_MAX at 1.5x the current price) must fit the balance.
    const balance = await strkBalance(s.address);
    if (balance < 9n * 10n ** 18n) await send(deployerAcc, transferCall(s.address, 9n * 10n ** 18n - balance), 3000000n);
    s.before = { class: info.classHash, balance: (await strkBalance(s.address)).toString(), verifierClass: SHAKE_VERIFIER }; save();
    const calls = migrationCalls(info, k, { migratableClass: state.migratableClass, verifierClass: SHAKE_VERIFIER });
    try {
      s.migration = await send(new Account({ provider, address: s.address, signer: k.ecdsaPrivateKey }), calls, MIGRATION_L2_MAX); save();
    } catch (e) { s.migrationError = errTail(e); save(); log(`  migration failed: ${s.migrationError}`); return; }
    log(`  migration (${calls.map((c) => c.entrypoint).join(" + ")}): ${VOYAGER}/tx/${s.migration.tx} ${s.migration.status}, l2 gas ${s.migration.l2Gas}`);
    if (s.migration.status !== "SUCCEEDED") return;
  }

  const info = await retry(() => inspectAccount(provider, s.address));
  const read = async (ep) => retry(() => provider.callContract({ contractAddress: s.address, entrypoint: ep, calldata: [] }, "latest"));
  const falconKey = (await read("get_falcon_public_key")).slice(1);
  s.after = {
    kind: info.kind,
    ecdsaKeyMatchesWords: BigInt((await read("get_ecdsa_public_key"))[0]) === BigInt(k.ecdsaPublicKey),
    falconKeyMatchesWords: falconKey.length === 29 && falconKey.every((f, i) => BigInt(f) === BigInt(k.falconFelts[i])),
    balanceDropEqualsFee: BigInt(s.before.balance) - (await strkBalance(s.address)) === BigInt(s.migration.fee),
  };
  save();
  log(`  after: ${JSON.stringify(s.after)}`);
  if (!s.hybridTransfer) {
    s.hybridTransfer = await send(new Account({ provider, address: s.address, signer: new HybridSigner(k) }), transferCall(deployerAcc.address, 10n ** 16n), 70000000n); save();
  }
  log(`  hybrid transfer: ${VOYAGER}/tx/${s.hybridTransfer.tx} ${s.hybridTransfer.status}`);
  if (!s.ecdsaOnly) {
    try {
      const r = await send(new Account({ provider, address: s.address, signer: new EcdsaOnlySigner(k.ecdsaPrivateKey) }), transferCall(deployerAcc.address, 1n), 70000000n);
      s.ecdsaOnly = "UNEXPECTED: accepted " + r.tx;
    } catch (e) {
      const m = e?.message || String(e);
      s.ecdsaOnly = /validate/i.test(m) && /panicked|invalid signature/i.test(m) ? "rejected in __validate__" : "UNCLEAR: " + errTail(e);
    }
    save();
  }
  log(`  ECDSA-only transfer: ${s.ecdsaOnly}`);
}

async function main() {
  const deployer = JSON.parse(readFileSync(`${KEYS}/deployer-ecdsa.json`, "utf8"));
  const deployerAddress = readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim();
  const deployerAcc = new Account({ provider, address: deployerAddress, signer: deployer.privateKey });
  TIP = (await retry(() => provider.getEstimateTip("latest", { maxBlocks: 5 }))).recommendedTip;
  log("deployer:", deployerAddress, fmt(await strkBalance(deployerAddress)), " verifier (SHAKE):", SHAKE_VERIFIER, " tip:", TIP);
  // Pinned and declared on Sepolia (scripts/release_manifest.mjs --chain).
  state.migratableClass = MIGRATABLE_CLASS; save();
  log("migratable class:", MIGRATABLE_CLASS, " verifier:", VERIFIER.id);
  const names = process.argv.length > 2 ? process.argv.slice(2) : Object.keys(WALLETS);
  for (const name of names) { await run(name, deployerAcc); await sleep(2000); }
}

main().catch((e) => { console.error("ERROR:", e?.message || e); process.exit(1); });
