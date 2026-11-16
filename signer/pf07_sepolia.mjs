// PF-07 on Sepolia: move the PUBLIC demo account (README words, docs/index.html) from the baseline
// SHAKE-256 verifier to the small Provably Fast verifier through the guard, and collect the
// release evidence. TESTNET ONLY.
//
//   node pf07_sepolia.mjs balance                  # deployer and demo account balances
//   node pf07_sepolia.mjs switch-demo --dry        # simulate the guarded switch; sends nothing
//   node pf07_sepolia.mjs topup AMOUNT_STRK        # deployer -> demo account, if it is low
//   node pf07_sepolia.mjs switch-demo              # baseline -> small, then checks pointer and keys
//   node pf07_sepolia.mjs browser STEP TX          # record a passkey_e2e.mjs transfer
//                                                  #   (STEP: oldPageBefore | oldPageAfter | newPage)
//   node pf07_sepolia.mjs evidence --clean-state PATH   # writes release/testnet-v1-evidence.json
//
// Steps are recorded in .keys/pf07-sepolia-state.json and skipped once done. The evidence file
// holds transaction hashes and receipts only, never keys or words (the demo words are public in
// README.md anyway).
import { Account, CallData, RpcProvider, cairo, hash, num } from "starknet";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { HybridSigner, deriveAccountKeys, prepareKeys, switchVerifier } from "./pq_account_kit.mjs";
import { KEYS, ROOTS, RPC } from "./config.mjs";
import { ALLOWED_VERIFIERS, GUARD, RELEASE, pinnedVerifier, verifierClass } from "./verifiers.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = resolve(REPO, "release/testnet-v1-evidence.json");
const provider = new RpcProvider({ nodeUrl: RPC });
const STATE_FILE = `${KEYS}/pf07-sepolia-state.json`;
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const DEMO = "0x343e3df576edca452f2cc6ac5247fc38a3641912f545e25468e3b7e7de1c0db";
const OZ_ACCOUNT_CLASS = "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";
const BASELINE = verifierClass("shake-baseline");
const SMALL = verifierClass("shake-pf-small-v1");
const BROWSER_STEPS = ["oldPageBefore", "oldPageAfter", "newPage"];

const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const same = (a, b) => BigInt(a) === BigInt(b);
const strk = (fri) => `${(Number(fri) / 1e18).toFixed(4)} STRK`;

async function retry(fn, tries = 6) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) {
      if (i + 1 >= tries || !/cu limit|too fast|429|rate|ECONNRESET|fetch failed/i.test(e?.message || "")) throw e;
      await sleep(3000 * (i + 1));
    }
  }
}

function demoKeys() {
  const words = readFileSync(resolve(REPO, "README.md"), "utf8").match(/```text\n((?:[a-z]+ ){23}[a-z]+)\n```/)[1];
  const keys = prepareKeys(deriveAccountKeys(words, 0, "pq"), JSON.parse(readFileSync(ROOTS, "utf8")));
  const address = hash.calculateContractAddressFromHash(keys.ecdsaPublicKey, OZ_ACCOUNT_CLASS, [keys.ecdsaPublicKey], 0);
  if (!same(address, DEMO)) throw new Error(`README words give ${address}, not the public demo account`);
  return keys;
}
function deployerAccount() {
  const deployer = JSON.parse(readFileSync(`${KEYS}/deployer-ecdsa.json`, "utf8"));
  return new Account({ provider, address: readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim(), signer: deployer.privateKey });
}
const view = async (address, entrypoint) =>
  (await retry(() => provider.callContract({ contractAddress: address, entrypoint, calldata: [] }, "latest"))).map(num.toHex);
async function strkBalance(address) {
  const r = await retry(() => provider.callContract({ contractAddress: STRK, entrypoint: "balance_of", calldata: [address] }));
  return BigInt(r[0]) + (BigInt(r[1]) << 128n);
}
async function waitFor(tx) {
  const rc = await retry(() => provider.waitForTransaction(tx));
  if (rc.execution_status !== "SUCCEEDED") throw new Error(`${tx} ${rc.execution_status}: ${rc.revert_reason}`);
  return { tx, status: rc.execution_status };
}
async function assertState(keys, verifier, label) {
  const [pointer] = await view(DEMO, "get_verifier_class_hash");
  const [ecdsa] = await view(DEMO, "get_ecdsa_public_key");
  const falcon = (await view(DEMO, "get_falcon_public_key")).slice(1);
  const ok = same(pointer, verifier) && same(ecdsa, keys.ecdsaPublicKey) &&
    falcon.length === keys.falconFelts.length && falcon.every((f, i) => same(f, keys.falconFelts[i]));
  if (!ok) throw new Error(`${label}: pointer ${pointer} (expected ${verifier}) or keys changed`);
  return { verifier: pointer, keysUnchanged: true };
}
async function assertGuard() {
  const cls = await retry(() => provider.getClassHashAt(GUARD));
  if (!same(cls, RELEASE.classes.VerifierSwitchGuard.class_hash)) throw new Error(`${GUARD} runs ${cls}, not the pinned guard`);
}

async function switchDemo(dry) {
  const keys = demoKeys();
  await assertGuard();
  if (state.switch) { console.log(`switch: done (${state.switch.tx})`); await assertState(keys, SMALL, "after the switch"); return; }
  await assertState(keys, BASELINE, "before the switch");
  const hybrid = new Account({ provider, address: DEMO, signer: new HybridSigner(keys) });
  // No tip given: starknet.js estimates the recommended tip for the simulation and the send.
  const r = await switchVerifier(hybrid, SMALL, { guard: GUARD, allowed: ALLOWED_VERIFIERS, dryRun: dry });
  if (dry) {
    const b = r.simulation.resourceBounds.l2_gas;
    console.log(`dry run of the switch to small: no revert, fee ${strk(r.simulation.overall_fee)}, L2 gas bound ${b.max_amount} at ${b.max_price_per_unit} fri`);
    console.log(`  balance needed for the bound: ${strk(BigInt(b.max_amount) * BigInt(b.max_price_per_unit))}; demo account holds ${strk(await strkBalance(DEMO))}`);
    return;
  }
  const sent = await waitFor(r.transaction_hash);
  state.switch = { ...sent, ...(await assertState(keys, SMALL, "after the switch")) };
  save();
  console.log(`switch: ${sent.tx} SUCCEEDED, pointer = small (${pinnedVerifier(state.switch.verifier)}), keys unchanged`);
}

async function topup(amount) {
  const fri = BigInt(Math.round(Number(amount) * 1e6)) * 10n ** 12n;
  if (!(fri > 0n && fri <= 20n * 10n ** 18n)) throw new Error("top-up between 0 and 20 STRK");
  const d = deployerAccount();
  const t = await d.execute({ contractAddress: STRK, entrypoint: "transfer", calldata: CallData.compile({ recipient: DEMO, amount: cairo.uint256(fri) }) });
  (state.topups ??= []).push(await waitFor(t.transaction_hash));
  save();
  console.log(`top-up ${amount} STRK: ${t.transaction_hash}; demo account now ${strk(await strkBalance(DEMO))}`);
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

async function evidence(cleanStatePath) {
  if (!state.switch) throw new Error("run `pf07_sepolia.mjs switch-demo` first");
  for (const s of BROWSER_STEPS) if (!state.browser?.[s]) throw new Error(`record the ${s} browser transfer first`);
  const clean = JSON.parse(readFileSync(cleanStatePath, "utf8"))["braavos-1.2.0"];
  if (clean?.migration?.status !== "SUCCEEDED") throw new Error(`${cleanStatePath}: braavos-1.2.0 is not migrated`);
  const browser = {};
  for (const s of BROWSER_STEPS) browser[s] = await receipt(state.browser[s]);
  const out = {
    description: "PF-07 Sepolia evidence for testnet-v1; see release/README.md",
    generated_utc: new Date().toISOString(),
    release: RELEASE.release,
    publicDemo: {
      account: DEMO,
      guard: GUARD,
      topups: await Promise.all((state.topups ?? []).map((t) => receipt(t.tx))),
      switchToSmall: { ...(await receipt(state.switch.tx)), verifierAfter: state.switch.verifier, keysUnchanged: state.switch.keysUnchanged },
      browser: {
        note: "signer/passkey_e2e.mjs, headless Chromium: public demo words -> passkey lock -> reload -> unlock -> transfer",
        oldPageBeforeSwitch: browser.oldPageBefore,
        oldPageAfterSwitch: browser.oldPageAfter,
        newPage: browser.newPage,
      },
    },
    cleanCheckout: {
      note: "fresh git clone, empty keys directory except the deployer key, no PQ_VERIFIER set: wallet_migrate_demo.mjs braavos-1.2.0",
      wallet: "braavos-1.2.0",
      address: clean.address,
      verifierClass: clean.before?.verifierClass,
      verifierId: pinnedVerifier(clean.before.verifierClass),
      migration: await receipt(clean.migration.tx),
      hybridTransfer: clean.hybridTransfer ? await receipt(clean.hybridTransfer.tx) : null,
      keysPreserved: clean.after ? clean.after.ecdsaKeyMatchesWords && clean.after.falconKeyMatchesWords : null,
      balanceDropEqualsFee: clean.after?.balanceDropEqualsFee ?? null,
      ecdsaOnlyTransfer: clean.ecdsaOnly ?? null,
    },
  };
  writeFileSync(OUT, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${OUT}`);
}

const [cmd, ...args] = process.argv.slice(2);
if (cmd === "switch-demo") await switchDemo(args.includes("--dry"));
else if (cmd === "topup") await topup(args[0]);
else if (cmd === "browser") {
  if (!BROWSER_STEPS.includes(args[0]) || !/^0x[0-9a-f]+$/i.test(args[1] || "")) throw new Error(`usage: browser ${BROWSER_STEPS.join("|")} TX`);
  await waitFor(args[1]);
  (state.browser ??= {})[args[0]] = args[1];
  save();
  console.log(`${args[0]}: ${args[1]}`);
} else if (cmd === "evidence") {
  const i = args.indexOf("--clean-state");
  if (i < 0 || !args[i + 1]) throw new Error("usage: evidence --clean-state PATH");
  await evidence(args[i + 1]);
} else if (cmd === "balance") {
  const d = readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim();
  console.log(`deployer ${d}: ${strk(await strkBalance(d))}`);
  console.log(`public demo ${DEMO}: ${strk(await strkBalance(DEMO))}, verifier ${pinnedVerifier((await view(DEMO, "get_verifier_class_hash"))[0])}`);
} else { console.error("usage: pf07_sepolia.mjs balance | switch-demo [--dry] | topup STRK | browser STEP TX | evidence --clean-state PATH"); process.exit(1); }
