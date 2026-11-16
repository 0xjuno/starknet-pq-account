// PF-06 on Sepolia: the guarded verifier switch on an already migrated account, from the baseline
// SHAKE-256 verifier (HybridShakeAccount) to the small Provably Fast verifier and back. TESTNET ONLY.
//
//   PQ_MATRIX_RUN=pf06-baseline PQ_VERIFIER=shake-baseline \
//     node wallet_migrate_demo.mjs argent-0.5.0        # a fresh account, migrated with the baseline verifier
//   node pf06_sepolia.mjs guard                        # deploy one VerifierSwitchGuard (class declared by PF-04)
//   node pf06_sepolia.mjs switch --dry                 # simulate the switch to small; sends nothing
//   node pf06_sepolia.mjs switch                       # baseline -> small, transfers, small -> baseline
//   node pf06_sepolia.mjs receipts                     # writes bench/pf06/sepolia.json
//
// Every step is recorded in .keys/pf06-sepolia-state.json and skipped once done. Any failed check
// throws before the next send. sepolia.json holds transaction hashes and receipts only, never keys
// or words.
import { Account, CallData, RpcProvider, Signer, cairo, ec, hash, json, num } from "starknet";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { HybridSigner, deriveAccountKeys, prepareKeys, switchVerifier } from "./pq_account_kit.mjs";
import { KEYS, ROOTS, RPC, TARGET } from "./config.mjs";
import { ALLOWED_VERIFIERS, RELEASE, verifierClass } from "./verifiers.mjs";

const provider = new RpcProvider({ nodeUrl: RPC });
const STATE_FILE = `${KEYS}/pf06-sepolia-state.json`;
const OUT = resolve(TARGET, "../../../bench/pf06/sepolia.json");
const RUN = "pf06-baseline";
const PROFILES = { "argent-0.5.0": "argentx", "braavos-1.2.0": "braavos", "argent-0.3.1": "argentx" };
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
// Pinned class hashes (release/testnet-v1.json).
const BASELINE = verifierClass("shake-baseline"); // HybridShakeAccount
const SMALL = verifierClass("shake-pf-small-v1"); // HybridShakeVerifierPfSmall
const POSEIDON = verifierClass("poseidon"); // HybridPoseidonAccount
const GUARD_CLASS = RELEASE.classes.VerifierSwitchGuard.class_hash;
const GUARD_SALT = "0x706636";
const ALLOWED = ALLOWED_VERIFIERS;
// Above a hybrid transfer on either verifier (about 30M on small, 54M on the baseline).
const TRANSFER_L2_MAX = 70000000n;

const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const same = (a, b) => BigInt(a) === BigInt(b);

async function retry(fn, tries = 6) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) {
      if (i + 1 >= tries || !/cu limit|too fast|429|rate|ECONNRESET|fetch failed/i.test(e?.message || "")) throw e;
      await sleep(3000 * (i + 1));
    }
  }
}

// An attacker who forged the classical key but has no Falcon key.
class EcdsaOnlySigner extends Signer {
  constructor(pk) { super(pk); this.pk = pk; }
  async signRaw(msgHash) { const e = ec.starkCurve.sign(num.toHex(msgHash), this.pk); return [num.toHex(e.r), num.toHex(e.s)]; }
}

function deployerAccount() {
  const deployer = JSON.parse(readFileSync(`${KEYS}/deployer-ecdsa.json`, "utf8"));
  return new Account({ provider, address: readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim(), signer: deployer.privateKey });
}

function wallet(name) {
  const s = JSON.parse(readFileSync(`${KEYS}/wallet-matrix-state-${RUN}.json`, "utf8"))[name];
  if (s?.migration?.status !== "SUCCEEDED") throw new Error(`${RUN} ${name} is not migrated; run wallet_migrate_demo.mjs first`);
  const words = readFileSync(`${KEYS}/wallet-${RUN}-${name}-mnemonic.txt`, "utf8").trim();
  const keys = prepareKeys(deriveAccountKeys(words, 0, PROFILES[name]), JSON.parse(readFileSync(ROOTS, "utf8")));
  return { run: s, keys, address: s.address };
}

const view = async (address, entrypoint) =>
  (await retry(() => provider.callContract({ contractAddress: address, entrypoint, calldata: [] }, "latest"))).map(num.toHex);
const tip = async () => (await retry(() => provider.getEstimateTip("latest", { maxBlocks: 5 }))).recommendedTip || 100000000n;
const transferCall = (to, amount) => ({ contractAddress: STRK, entrypoint: "transfer", calldata: CallData.compile({ recipient: to, amount: cairo.uint256(amount) }) });

async function strkBalance(address) {
  const r = await retry(() => provider.callContract({ contractAddress: STRK, entrypoint: "balance_of", calldata: [address] }));
  return BigInt(r[0]) + (BigInt(r[1]) << 128n);
}

async function bounds(l2Max) {
  const b = await retry(() => provider.getBlockWithTxHashes("latest"));
  return {
    l1_gas: { max_amount: 0n, max_price_per_unit: BigInt(b.l1_gas_price.price_in_fri) * 2n },
    l1_data_gas: { max_amount: 5000n, max_price_per_unit: BigInt(b.l1_data_gas_price.price_in_fri) * 2n },
    l2_gas: { max_amount: l2Max, max_price_per_unit: (BigInt(b.l2_gas_price.price_in_fri) * 3n) / 2n },
  };
}

async function waitFor(tx) {
  const rc = await retry(() => provider.waitForTransaction(tx));
  if (rc.execution_status !== "SUCCEEDED") throw new Error(`${tx} ${rc.execution_status}: ${rc.revert_reason}`);
  return { tx, status: rc.execution_status };
}

async function assertState(address, keys, verifier, label) {
  const [pointer] = await view(address, "get_verifier_class_hash");
  const [ecdsa] = await view(address, "get_ecdsa_public_key");
  const falcon = (await view(address, "get_falcon_public_key")).slice(1);
  const ok = same(pointer, verifier) && same(ecdsa, keys.ecdsaPublicKey) &&
    falcon.length === keys.falconFelts.length && falcon.every((f, i) => same(f, keys.falconFelts[i]));
  if (!ok) throw new Error(`${label}: pointer ${pointer} (expected ${verifier}) or keys changed`);
  return { verifier: pointer, keysUnchanged: true };
}

async function guard() {
  const sierra = json.parse(readFileSync(`${TARGET}/pq_hybrid_VerifierSwitchGuard.contract_class.json`, "utf8"));
  const built = hash.computeContractClassHash(sierra);
  if (!same(built, GUARD_CLASS)) throw new Error(`built guard class ${built} is not the pinned ${GUARD_CLASS}`);
  await retry(() => provider.getClassByHash(GUARD_CLASS)); // throws if not declared
  // UDC with unique = false: the address depends only on the salt, class and (empty) calldata.
  const address = num.toHex(hash.calculateContractAddressFromHash(GUARD_SALT, GUARD_CLASS, [], 0));
  const deployed = await retry(() => provider.getClassHashAt(address)).catch(() => null);
  if (deployed) {
    if (!same(deployed, GUARD_CLASS)) throw new Error(`${address} runs class ${deployed}, not the guard`);
    console.log(`guard already deployed at ${address}`);
  } else {
    const d = await deployerAccount().deployContract({ classHash: GUARD_CLASS, salt: GUARD_SALT, unique: false, constructorCalldata: [] }, { tip: await tip() });
    await waitFor(d.transaction_hash);
    state.guardDeploy = { tx: d.transaction_hash };
    console.log(`guard deployed at ${address}: ${d.transaction_hash}`);
  }
  state.guard = address;
  save();
}

async function switchSteps(name, dry) {
  if (!state.guard) throw new Error("no guard; run `pf06_sepolia.mjs guard` first");
  const w = wallet(name);
  const hybrid = new Account({ provider, address: w.address, signer: new HybridSigner(w.keys) });
  const deployer = readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim();
  const s = (state.switch ??= {});
  s.wallet = name;
  s.account = w.address;
  const step = async (key, fn) => {
    if (s[key]) { console.log(`${key}: done (${s[key].tx ?? s[key].result})`); return; }
    s[key] = await fn();
    save();
    console.log(`${key}: ${s[key].tx ?? ""} ${s[key].status ?? s[key].result}`);
  };
  const guarded = async (to) => {
    const t = await tip();
    const r = await switchVerifier(hybrid, to, { guard: state.guard, allowed: ALLOWED, tip: t, dryRun: dry });
    if (dry) return r;
    return { ...(await waitFor(r.transaction_hash)), tip: t.toString() };
  };
  const transfer = async () => {
    const nonce = await retry(() => provider.getNonceForAddress(w.address, "latest"));
    const t = await hybrid.execute(transferCall(deployer, 1n), { nonce, tip: await tip(), resourceBounds: await bounds(TRANSFER_L2_MAX) });
    return waitFor(t.transaction_hash);
  };

  if (dry) {
    if (!s.toSmall) await assertState(w.address, w.keys, BASELINE, "before the switch");
    const r = await guarded(s.toSmall ? BASELINE : SMALL);
    console.log(`dry run of the switch to ${s.toSmall ? "baseline" : "small"}: no revert, fee ${Number(r.simulation.overall_fee) / 1e18} STRK, L2 gas bound ${r.simulation.resourceBounds.l2_gas.max_amount}`);
    return;
  }
  if (!s.toSmall) await assertState(w.address, w.keys, BASELINE, "before the switch");
  await step("toSmall", async () => ({ ...(await guarded(SMALL)), ...(await assertState(w.address, w.keys, SMALL, "after the switch to small")) }));
  await step("transferOnSmall", transfer);
  await step("ecdsaOnlyOnSmall", async () => {
    const forged = new Account({ provider, address: w.address, signer: new EcdsaOnlySigner(w.keys.ecdsaPrivateKey) });
    try {
      const nonce = await retry(() => provider.getNonceForAddress(w.address, "latest"));
      const r = await forged.execute(transferCall(deployer, 1n), { nonce, tip: await tip(), resourceBounds: await bounds(TRANSFER_L2_MAX) });
      throw new Error(`ECDSA-only transfer was accepted: ${r.transaction_hash}`);
    } catch (e) {
      const m = e?.message || String(e);
      if (/was accepted/.test(m)) throw e;
      if (!(/validate/i.test(m) && /invalid signature/i.test(m))) throw new Error(`ECDSA-only transfer failed for another reason: ${m.slice(-300)}`);
      return { result: "rejected in __validate__" };
    }
  });
  await step("poseidonRefused", async () => {
    try {
      await switchVerifier(hybrid, POSEIDON, { guard: state.guard, allowed: [...ALLOWED, POSEIDON], tip: await tip(), dryRun: true });
    } catch (e) {
      const m = e?.message || String(e);
      if (/would revert.*signature rejected/s.test(m)) return { result: "refused after simulation: Guard: signature rejected" };
      throw new Error(`Poseidon switch failed for another reason: ${m.slice(-300)}`);
    }
    throw new Error("the switch to the Poseidon verifier simulated without reverting");
  });
  await step("toBaseline", async () => ({ ...(await guarded(BASELINE)), ...(await assertState(w.address, w.keys, BASELINE, "after the switch back")) }));
  await step("transferOnBaseline", transfer);
}

async function receipt(tx) {
  const rc = await retry(() => provider.getTransactionReceipt(tx));
  const blk = await retry(() => provider.getBlockWithTxHashes(rc.block_number));
  await sleep(500);
  return {
    tx, status: rc.execution_status, block: rc.block_number, timestamp: blk.timestamp,
    l2_gas: Number(rc.execution_resources.l2_gas), l1_data_gas: Number(rc.execution_resources.l1_data_gas),
    l1_gas: Number(rc.execution_resources.l1_gas || 0), fee_fri: BigInt(rc.actual_fee.amount).toString(),
    l2_gas_price_fri: BigInt(blk.l2_gas_price.price_in_fri).toString(),
  };
}

async function receipts() {
  const s = state.switch;
  if (!s?.transferOnBaseline) throw new Error("run `pf06_sepolia.mjs switch` to the end first");
  const runState = JSON.parse(readFileSync(`${KEYS}/wallet-matrix-state-${RUN}.json`, "utf8"));
  const run = runState[s.wallet];
  const out = {
    description: "PF-06 Sepolia receipts: guarded verifier switch baseline -> small -> baseline; see bench/pf06/README.md",
    generated_utc: new Date().toISOString(),
    classes: { baseline: BASELINE, small: SMALL, guard: GUARD_CLASS, migratable: runState.migratableClass ?? null },
    guard: { address: state.guard, deploy: state.guardDeploy ? await receipt(state.guardDeploy.tx) : null },
    account: { wallet: s.wallet, address: s.account },
    migration: {
      verifierClass: run.before?.verifierClass,
      migration: await receipt(run.migration.tx),
      hybridTransfer: run.hybridTransfer ? await receipt(run.hybridTransfer.tx) : null,
      keysPreserved: run.after ? run.after.ecdsaKeyMatchesWords && run.after.falconKeyMatchesWords : null,
      balanceDropEqualsFee: run.after?.balanceDropEqualsFee ?? null,
      ecdsaOnlyTransfer: run.ecdsaOnly ?? null,
    },
    steps: {},
  };
  for (const key of ["toSmall", "transferOnSmall", "ecdsaOnlyOnSmall", "poseidonRefused", "toBaseline", "transferOnBaseline"]) {
    const v = s[key];
    out.steps[key] = v.tx ? { ...(await receipt(v.tx)), ...(v.verifier ? { verifierAfter: v.verifier, keysUnchanged: v.keysUnchanged } : {}) } : { result: v.result };
  }
  writeFileSync(OUT, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${OUT}`);
}

const [cmd, ...args] = process.argv.slice(2);
const dry = args.includes("--dry");
const name = args.find((a) => !a.startsWith("--")) || "argent-0.5.0";
if (cmd === "guard") await guard();
else if (cmd === "switch") await switchSteps(name, dry);
else if (cmd === "receipts") await receipts();
else if (cmd === "balance") {
  const d = deployerAccount();
  console.log(`deployer ${d.address}: ${Number(await strkBalance(d.address)) / 1e18} STRK`);
} else { console.error("usage: pf06_sepolia.mjs guard | switch [WALLET] [--dry] | receipts | balance"); process.exit(1); }
