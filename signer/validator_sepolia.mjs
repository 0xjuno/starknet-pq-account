// Sepolia check that a validator's accounts can move to hybrid signatures in place, at the same
// addresses, while the validator keeps attesting. Driven by pq_account_kit.mjs. TESTNET ONLY.
//   1. deploy two fresh OpenZeppelin accounts: staker (index 0) and operational (index 1)
//   2. the staker stakes 2 STRK with that operational address (Sepolia minimum is 1 STRK)
//   3. once the stake is in effect (K epochs later), the operational account attests with ECDSA
//   4. both accounts migrate in place to HybridMigratableAccount; the staking contract still
//      lists the same staker and operational addresses
//   5. next epoch, the operational account attests with the hybrid signature
//   6. an ECDSA-only attestation from the same account is rejected at validation
//   7. the staker signals exit with the hybrid signature, waits the exit window, withdraws
// Idempotent; resumes from .keys/validator-sepolia-state.json.   node validator_sepolia.mjs
// Takes a few hours: an epoch is 231 blocks and the stake takes K epochs to come into effect.
import { Account, CallData, RpcProvider, cairo, hash, json, num } from "starknet";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { generateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { HybridSigner, KNOWN_VERIFIERS, deriveAccountKeys, inspectAccount, migrationCalls, prepareKeys } from "./pq_account_kit.mjs";
import { KEYS, ROOTS, RPC, TARGET } from "./config.mjs";

const STATE_FILE = `${KEYS}/validator-sepolia-state.json`;
const WORDS_FILE = `${KEYS}/validator-sepolia-mnemonic.txt`;
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const OZ_CLASS = "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";
// Sepolia staking and attestation contracts (docs.starknet.io, chain info)
const STAKING = "0x03745ab04a431fc02871a139be6b93d9260b0ff3e779ad9c8b377183b23109f1";
const ATTESTATION = "0x03f32e152b9637c31bfcf73e434f78591067a01ba070505ff6ee195642c9acfb";
const STAKE_AMOUNT = 2n * 10n ** 18n;
const MIN_ATTESTATION_WINDOW = 11n; // attestation.cairo: a block hash is readable 10 blocks later
const VOYAGER = "https://sepolia.voyager.online";
const [SHAKE] = Object.keys(KNOWN_VERIFIERS);

const provider = new RpcProvider({ nodeUrl: RPC });
const roots = JSON.parse(readFileSync(ROOTS, "utf8"));
const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let TIP = 0n; // Sepolia evicts zero-tip transactions; set from recent blocks in main()

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

// Fixed bounds, no fee estimate: a call that reverts in __execute__ still lands as REVERTED.
async function send(acc, calls, l2Max) {
  const nonce = await retry(() => provider.getNonceForAddress(acc.address, "latest"));
  const t = await retry(async () => acc.execute(calls, { nonce, tip: TIP, resourceBounds: await bounds(l2Max) }));
  const rc = await receipt(t.transaction_hash);
  return { tx: t.transaction_hash, status: rc.execution_status, block: rc.block_number, l2Gas: rc.execution_resources?.l2_gas, revert: rc.revert_reason?.slice(0, 300) };
}

const view = async (contractAddress, entrypoint, calldata = []) =>
  (await retry(() => provider.callContract({ contractAddress, entrypoint, calldata }, "latest"))).map((x) => BigInt(x));
const transferCall = (to, amount) => ({ contractAddress: STRK, entrypoint: "transfer", calldata: CallData.compile({ recipient: to, amount: cairo.uint256(amount) }) });
const currentEpoch = async () => (await view(STAKING, "get_current_epoch"))[0];
const blockNumber = () => retry(() => provider.getBlockNumber());
// AttestationInfo: staker_address, stake, epoch_len, epoch_id, current_epoch_starting_block.
// Right after `stake` the staking contract has no balance history for the staker yet and the
// view reverts ("Penultimate does not exist"); treat that as a stake not in effect.
async function attestationInfo(operational) {
  try {
    const r = await view(STAKING, "get_attestation_info_by_operational_address", [operational]);
    return { staker: num.toHex(r[0]), stake: r[1], epochLen: r[2], epochId: r[3], epochStart: r[4] };
  } catch (e) {
    if (!/Penultimate|does not exist/i.test(e?.message || "")) throw e;
    return { staker: null, stake: 0n, epochId: await currentEpoch() };
  }
}
// Option<StakerInfoV1>: 0 = Some, reward, operational, unstake_time Option, amount_own, ...
async function stakerInfo(staker) {
  const r = await view(STAKING, "get_staker_info_v1", [staker]);
  if (r[0] !== 0n) return null;
  return { reward: num.toHex(r[1]), operational: num.toHex(r[2]), exiting: r[3] === 0n, amountOwn: r[3] === 0n ? r[5] : r[4] };
}

async function waitForNextEpoch(epochId) {
  for (;;) {
    const e = await currentEpoch();
    if (e > epochId) return e;
    await sleep(30000);
  }
}

// One attestation from `acc` (the operational account), whichever epoch it lands in.
async function attestOnce(acc, operational, l2Max) {
  for (let attempt = 0; attempt < 6; attempt++) {
    const info = await attestationInfo(operational);
    if (info.stake === 0n) {
      log(`  epoch ${info.epochId}: stake not in effect yet, waiting for the next epoch`);
      await waitForNextEpoch(info.epochId); continue;
    }
    const done = (await view(ATTESTATION, "is_attestation_done_in_curr_epoch", [info.staker]))[0] === 1n;
    if (done) {
      log(`  epoch ${info.epochId}: already attested, waiting for the next epoch`);
      await waitForNextEpoch(info.epochId); continue;
    }
    const target = (await view(ATTESTATION, "get_current_epoch_target_attestation_block", [operational]))[0];
    const windowSize = (await view(ATTESTATION, "attestation_window"))[0];
    let now = BigInt(await blockNumber());
    log(`  epoch ${info.epochId}: target block ${target}, window ${target + MIN_ATTESTATION_WINDOW}..${target + windowSize}, now ${now}`);
    if (now > target + windowSize) {
      log("  window already passed, waiting for the next epoch");
      await waitForNextEpoch(info.epochId); continue;
    }
    while (now < target + MIN_ATTESTATION_WINDOW) { await sleep(10000); now = BigInt(await blockNumber()); }
    const blockHash = (await retry(() => provider.getBlockWithTxHashes(Number(target)))).block_hash;
    const r = await send(acc, [{ contractAddress: ATTESTATION, entrypoint: "attest", calldata: [blockHash] }], l2Max);
    const out = { ...r, epoch: info.epochId.toString(), targetBlock: target.toString(), sentAtBlock: now.toString() };
    if (r.status === "SUCCEEDED") return out;
    log(`  attestation reverted: ${r.revert}`);
    await waitForNextEpoch(info.epochId);
  }
  throw new Error("attestation did not succeed in 6 attempts");
}

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
  log(`${name}...`);
  state[name] = await fn(); save();
  log(`${name}: ${JSON.stringify(state[name])}`);
  return state[name];
}

async function deployOz(deployer, k, address) {
  await send(deployer, transferCall(address, 20n * 10n ** 18n), 3000000n);
  const acc = new Account({ provider, address, signer: k.ecdsaPrivateKey });
  const r = await retry(async () => acc.deployAccount({ classHash: OZ_CLASS, constructorCalldata: [k.ecdsaPublicKey], addressSalt: k.ecdsaPublicKey, contractAddress: address },
    { tip: TIP, resourceBounds: await bounds(30000000n) }));
  return { tx: r.transaction_hash, status: (await receipt(r.transaction_hash)).execution_status };
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
  const kS = prepareKeys(deriveAccountKeys(words, 0, "pq"), roots);
  const kO = prepareKeys(deriveAccountKeys(words, 1, "pq"), roots);
  const staker = hash.calculateContractAddressFromHash(kS.ecdsaPublicKey, OZ_CLASS, [kS.ecdsaPublicKey], 0);
  const operational = hash.calculateContractAddressFromHash(kO.ecdsaPublicKey, OZ_CLASS, [kO.ecdsaPublicKey], 0);
  Object.assign(state, { staker, operational }); save();
  log("staker:", staker, "\noperational:", operational);

  await step("deployStaker", () => deployOz(deployer, kS, staker));
  await step("deployOperational", () => deployOz(deployer, kO, operational));

  const stakerEcdsa = new Account({ provider, address: staker, signer: kS.ecdsaPrivateKey });
  const operationalEcdsa = new Account({ provider, address: operational, signer: kO.ecdsaPrivateKey });

  await step("stake", async () => {
    const r = await send(stakerEcdsa, [
      { contractAddress: STRK, entrypoint: "approve", calldata: CallData.compile({ spender: STAKING, amount: cairo.uint256(STAKE_AMOUNT) }) },
      { contractAddress: STAKING, entrypoint: "stake", calldata: [staker, operational, num.toHex(STAKE_AMOUNT)] },
    ], 20000000n);
    return { ...r, epoch: (await currentEpoch()).toString(), registered: (await stakerInfo(staker))?.operational === operational };
  });

  await step("attestEcdsa", () => attestOnce(operationalEcdsa, operational, 30000000n));

  for (const [name, address, k, acc] of [["migrateOperational", operational, kO, operationalEcdsa], ["migrateStaker", staker, kS, stakerEcdsa]]) {
    await step(name, async () => {
      const info = await retry(() => inspectAccount(provider, address));
      const r = await send(acc, migrationCalls(info, k, { migratableClass: state.migratableClass, verifierClass: SHAKE }), 250000000n);
      const classNow = num.toHex(await retry(() => provider.getClassHashAt(address, "latest")));
      return { ...r, classIsMigratable: classNow === num.toHex(state.migratableClass) };
    });
  }
  await step("stakingContractAfterMigration", async () => {
    const s = await stakerInfo(staker);
    return { stakerStillListed: !!s, operationalUnchanged: s?.operational === operational, amountOwn: s?.amountOwn.toString() };
  });

  const stakerHybrid = new Account({ provider, address: staker, signer: new HybridSigner(kS) });
  const operationalHybrid = new Account({ provider, address: operational, signer: new HybridSigner(kO) });

  await step("attestHybrid", () => attestOnce(operationalHybrid, operational, 150000000n));

  await step("ecdsaOnlyRejected", async () => {
    // Same account, same call, but a plain ECDSA signature: the hybrid account refuses it.
    const target = (await view(ATTESTATION, "get_current_epoch_target_attestation_block", [operational]))[0];
    const blockHash = (await retry(() => provider.getBlockWithTxHashes(Number(target)))).block_hash;
    try {
      const r = await send(operationalEcdsa, [{ contractAddress: ATTESTATION, entrypoint: "attest", calldata: [blockHash] }], 150000000n);
      return { rejected: false, ...r };
    } catch (e) {
      return { rejected: true, error: (e?.message || String(e)).replace(/\s+/g, " ").slice(0, 200) };
    }
  });

  await step("unstakeIntent", async () => {
    const r = await send(stakerHybrid, [{ contractAddress: STAKING, entrypoint: "unstake_intent", calldata: [] }], 150000000n);
    return { ...r, exiting: (await stakerInfo(staker))?.exiting === true };
  });

  await step("unstakeAction", async () => {
    const exitWindow = (await view(STAKING, "contract_parameters_v1"))[5];
    log(`  exit window ${exitWindow}s, waiting`);
    await sleep(Number(exitWindow) * 1000 + 60000);
    const before = (await view(STRK, "balanceOf", [staker]))[0];
    const r = await send(stakerHybrid, [{ contractAddress: STAKING, entrypoint: "unstake_action", calldata: [staker] }], 150000000n);
    const after = (await view(STRK, "balanceOf", [staker]))[0];
    return { ...r, strkReturned: (Number(after - before) / 1e18).toFixed(3), stakerRemoved: (await stakerInfo(staker)) === null };
  });

  log("\nVoyager:");
  for (const k of ["stake", "attestEcdsa", "migrateOperational", "migrateStaker", "attestHybrid", "unstakeIntent", "unstakeAction"]) {
    log(`  ${k}: ${VOYAGER}/tx/${state[k].tx} ${state[k].status}`);
  }
}

main().catch((e) => { console.error("ERROR:", e?.message || e); process.exit(1); });
