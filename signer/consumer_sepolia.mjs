// What a contract pays to check a hybrid account's signature, measured on Sepolia. TESTNET ONLY.
// Deploys contracts/src/consumer.cairo (SignatureConsumer), then, for three accounts, sends
// check_many(account, hash, signature, 0) and check_many(..., N) and takes (gas(N) - gas(0)) / N
// from the receipts: the cost of one `is_valid_signature` call made by another contract, with the
// transaction's own overhead taken out. Measured from two senders, see `senders` below.
//   ECDSA:    the deployer itself (OpenZeppelin account, 2-felt signature)
//   baseline: the rotation run's account (class 0x5faf94f2, OpenZeppelin SHAKE-256 verifier)
//   small:    the public demo account (Provably Fast small verifier)
// Idempotent; resumes from .keys/consumer-sepolia-state.json.   node consumer_sepolia.mjs
import { Account, CallData, RpcProvider, ec, hash, json, num } from "starknet";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { HybridSigner, deriveAccountKeys, hybridSignature, prepareKeys } from "./pq_account_kit.mjs";
import { KEYS, ROOTS, RPC, TARGET } from "./config.mjs";

const STATE_FILE = `${KEYS}/consumer-sepolia-state.json`;
const N = 4;
const MSG = hash.computePoseidonHashOnElements([BigInt("0x" + Buffer.from("consumer-gas-v1").toString("hex"))]);
const PUBLIC_DEMO = "0x343e3df576edca452f2cc6ac5247fc38a3641912f545e25468e3b7e7de1c0db";
const PUBLIC_WORDS = "clip west volume icon sibling act dirt easily magnet fuel rigid robust lunar pause deer crisp reunion slogan wrist choice wisdom scene blossom salt";
const VOYAGER = "https://sepolia.voyager.online";

const provider = new RpcProvider({ nodeUrl: RPC });
const roots = JSON.parse(readFileSync(ROOTS, "utf8"));
const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
const log = (...a) => console.log(...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let TIP = 0n;

async function retry(fn, tries = 10) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) {
      if (i + 1 >= tries || !/cu limit|too fast|429|rate|ECONNRESET|fetch failed|timeout/i.test(e?.message || "")) throw e;
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
  try { await provider.waitForTransaction(txHash); } catch { /* reverted: read below */ }
  for (let i = 0; i < 40; i++) {
    try { const r = await provider.getTransactionReceipt(txHash); const v = r.value ?? r; if (v.execution_status) return v; } catch {}
    await sleep(3000);
  }
  throw new Error(`no receipt for ${txHash}`);
}
async function send(acc, calls, l2Max) {
  const nonce = await retry(() => provider.getNonceForAddress(acc.address, "latest"));
  const t = await retry(async () => acc.execute(calls, { nonce, tip: TIP, resourceBounds: await bounds(l2Max) }));
  const rc = await receipt(t.transaction_hash);
  return { tx: t.transaction_hash, status: rc.execution_status, l2Gas: Number(rc.execution_resources?.l2_gas ?? 0), revert: rc.revert_reason?.slice(0, 300) };
}

async function main() {
  const deployerKey = JSON.parse(readFileSync(`${KEYS}/deployer-ecdsa.json`, "utf8")).privateKey;
  const deployerAddress = readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim();
  const deployer = new Account({ provider, address: deployerAddress, signer: deployerKey });
  TIP = (await retry(() => provider.getEstimateTip("latest", { maxBlocks: 5 }))).recommendedTip;

  if (!state.consumer) {
    const sierra = json.parse(readFileSync(`${TARGET}/pq_hybrid_SignatureConsumer.contract_class.json`, "utf8"));
    const casm = json.parse(readFileSync(`${TARGET}/pq_hybrid_SignatureConsumer.compiled_contract_class.json`, "utf8"));
    const nonce = await retry(() => provider.getNonceForAddress(deployer.address, "latest"));
    const d = await retry(async () => deployer.declareIfNot({ contract: sierra, casm }, { nonce, tip: TIP, resourceBounds: await bounds(400000000n) }));
    if (d.transaction_hash) await receipt(d.transaction_hash);
    state.consumerClass = d.class_hash; save();
    const dep = await retry(async () => deployer.deployContract({ classHash: d.class_hash, constructorCalldata: [], salt: num.toHex(BigInt(MSG) & ((1n << 200n) - 1n)) },
      { tip: TIP, resourceBounds: await bounds(30000000n) }));
    await receipt(dep.transaction_hash);
    state.consumer = dep.contract_address; state.deployTx = dep.transaction_hash; save();
  }
  log("consumer:", state.consumer);

  // Signatures over MSG by each account's keys.
  const rot = JSON.parse(readFileSync(`${KEYS}/rotation-sepolia-state-v2.json`, "utf8"));
  const rotKeys = prepareKeys(deriveAccountKeys(readFileSync(`${KEYS}/rotation-sepolia-mnemonic-v2.txt`, "utf8").trim(), 1, "pq"), roots);
  const demoKeys = prepareKeys(deriveAccountKeys(PUBLIC_WORDS, 0, "pq"), roots);
  const e = ec.starkCurve.sign(num.toHex(MSG), deployerKey);
  const accounts = {
    ecdsa: { address: deployerAddress, signature: [num.toHex(e.r), num.toHex(e.s)] },
    baseline: { address: rot.address, signature: hybridSignature(MSG, rotKeys) },
    small: { address: PUBLIC_DEMO, signature: hybridSignature(MSG, demoKeys) },
  };
  const verifierOf = async (a) => num.toHex((await retry(() => provider.callContract({ contractAddress: a, entrypoint: "get_verifier_class_hash", calldata: [] }))).at(0));
  accounts.baseline.verifier = await verifierOf(accounts.baseline.address);
  accounts.small.verifier = await verifierOf(accounts.small.address);

  // Who sends the measuring transaction matters. Starknet charges a call in Cairo steps when a
  // caller above it in the transaction runs a class compiled to Sierra before 1.7, and Cairo steps
  // cost more L2 gas than the Sierra gas the same code uses otherwise. So the checks are measured
  // twice: sent by the deployer (OpenZeppelin class 0x05b4b537, Sierra 1.6.0) and by the rotation
  // run's migrated account (class 0x5faf94f2, Sierra 1.8.0, signing with both keys).
  const hybridSender = new Account({ provider, address: rot.address, signer: new HybridSigner(rotKeys) });
  const senders = {
    "sierra-1.6": { account: deployer, note: "OpenZeppelin account 0x05b4b537 (Sierra 1.6.0): checks run in Cairo-steps accounting", l2Max: 900000000n },
    "sierra-1.8": { account: hybridSender, note: "migrated account 0x5faf94f2 (Sierra 1.8.0): checks run in Sierra gas", l2Max: 600000000n },
  };
  // Earlier runs kept one sender's results at the top level of the state file.
  state.runs ||= {};
  if (state.ecdsa && !state.runs["sierra-1.6"]) { state.runs["sierra-1.6"] = { ecdsa: state.ecdsa, baseline: state.baseline, small: state.small }; delete state.ecdsa; delete state.baseline; delete state.small; save(); }

  // The migrated sender pays several hundred million L2 gas per measuring transaction.
  const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
  const bal = async (a) => { const r = await retry(() => provider.callContract({ contractAddress: STRK, entrypoint: "balance_of", calldata: [a] })); return BigInt(r[0]) + (BigInt(r[1]) << 128n); };
  if ((await bal(rot.address)) < 60n * 10n ** 18n) {
    const top = 60n * 10n ** 18n - (await bal(rot.address));
    const r = await send(deployer, [{ contractAddress: STRK, entrypoint: "transfer", calldata: CallData.compile([rot.address, top, 0]) }], 3000000n);
    log(`topped up the migrated sender with ${Number(top) / 1e18} STRK: ${r.status}`);
  }

  for (const [sender, cfg] of Object.entries(senders)) {
    const run = (state.runs[sender] ||= {});
    run.sender = cfg.account.address; run.note = cfg.note;
    for (const [name, a] of Object.entries(accounts)) {
      const s = (run[name] ||= { address: a.address, verifier: a.verifier, signatureFelts: a.signature.length });
      // A free read first: the signature has to pass, or the measurement means nothing.
      const ok = await retry(() => provider.callContract({ contractAddress: state.consumer, entrypoint: "check", calldata: CallData.compile([a.address, MSG, a.signature]) }));
      s.checkPasses = BigInt(ok[0]) === 1n; save();
      if (!s.checkPasses) throw new Error(`${name}: signature does not pass is_valid_signature`);
      for (const times of [0, N]) {
        const key = `times${times}`;
        if (s[key]?.status === "SUCCEEDED") continue;
        const call = { contractAddress: state.consumer, entrypoint: "check_many", calldata: CallData.compile([a.address, MSG, a.signature, times]) };
        s[key] = await send(cfg.account, [call], cfg.l2Max); save();
        log(`${sender} ${name} x${times}: ${s[key].status} ${s[key].l2Gas} L2 gas ${VOYAGER}/tx/${s[key].tx}`);
        if (s[key].status !== "SUCCEEDED") throw new Error(`${sender} ${name} x${times}: ${s[key].revert}`);
      }
      s.perCheckL2Gas = Math.round((s[`times${N}`].l2Gas - s.times0.l2Gas) / N); save();
      log(`${sender} ${name}: one is_valid_signature call from a contract = ${(s.perCheckL2Gas / 1e6).toFixed(2)}M L2 gas`);
    }
  }
  state.n = N; state.message = num.toHex(MSG); state.takenAt = new Date().toISOString(); save();
}

main().catch((e) => { console.error("ERROR:", e?.message || e); process.exit(1); });
