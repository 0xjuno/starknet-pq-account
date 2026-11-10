// PF-05: the guarded verifier switch as real transactions, on every migratable class version
// deployed on Sepolia, against a local devnet that forks Sepolia. Nothing is sent to Sepolia.
//
//   docker run --rm -p 127.0.0.1:5050:5050 shardlabs/starknet-devnet-rs:0.10.1 \
//     --seed 0 --fork-network https://api.zan.top/public/starknet-sepolia/rpc/v0_10
//   (cd contracts && scarb build) && node signer/verifier_switch_devnet.mjs
//
// For each class version it deploys a fresh account with a public test key and the deployed
// HybridShakeAccount verifier, then sends: the guarded switch to the candidate (PQ_SWITCH_CANDIDATE,
// default HybridShakeVerifierPfSmall, the verifier PF-04 selected),
// a transfer validated by it, the incompatible HybridPoseidonAccount through the guard, a
// signature lifted from another switch, an ECDSA-only switch, outsider calls, and the guarded
// switch back. Every transaction is validated by the protocol with its real hash and signature.
// Devnet's L2 gas accounting differs from Sepolia's (a baseline transfer reads about 2.6x the
// Sepolia receipt), so this checks behaviour only; gas figures come from PF-04.
import { Account, CallData, RpcProvider, cairo, num, transaction } from "starknet";
import { readFileSync } from "node:fs";
import { HybridSigner, deriveAccountKeys, prepareKeys, switchVerifier, verifierSwitchCalls } from "./pq_account_kit.mjs";
import { ROOTS, TARGET } from "./config.mjs";

const DEVNET = process.env.PQ_DEVNET || "http://127.0.0.1:5050";
// Migratable classes in use on Sepolia (contracts/docs/verifier-replacement.md, 2026-10-27).
const MIGRATABLE = {
  "0x4b067679dbb29516dd79fba49ba1f1b2bc3973b33c74881ff56098d19e27a78": "current (2026-10-19)",
  "0x660679aa09bef2ef29e1a2ebe21ee85d87bacde8746430b380425db5dd3c31b": "Argent and Braavos demo accounts",
  "0x7b6d5ed4cbb6c7a2633dd9139c25ffb76bb608cafbba9e424a277a885432b25": "public demo account",
  "0xae4154b7e35c9475f4875757bcfa2b19ca88fc2e9bd9fa793e82a91ef5815f": "in-place OpenZeppelin migration",
};
const SHAKE = "0x2255fc213bf39d1df2129c9e068b363f2b11a27b70b4b2c48df8ea4275f1c92"; // HybridShakeAccount
const POSEIDON = "0x7f10b6f2f70e72ef87e97844b5f6f13d384c92afcfed2a1233a03524d359d6f"; // HybridPoseidonAccount
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
// Public test mnemonic: TESTNET / DEVNET ONLY, never fund it anywhere real.
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// What a failed signature check in __validate__ looks like ('Account: invalid signature').
const INVALID_SIG = /validate.*invalid signature/is;
const provider = new RpcProvider({ nodeUrl: `${DEVNET}/rpc` });
const rpc = async (method, params = {}) => {
  const r = await (await fetch(`${DEVNET}/rpc`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) })).json();
  if (r.error) throw new Error(`${method}: ${JSON.stringify(r.error)}`);
  return r.result;
};
const artifact = (name) => ({
  contract: JSON.parse(readFileSync(`${TARGET}/pq_hybrid_${name}.contract_class.json`, "utf8")),
  casm: JSON.parse(readFileSync(`${TARGET}/pq_hybrid_${name}.compiled_contract_class.json`, "utf8")),
});
const wait = (h) => provider.waitForTransaction(h, { retryInterval: 200, successStates: ["ACCEPTED_ON_L2", "PRE_CONFIRMED"] });
const view = async (address, entrypoint) => (await provider.callContract({ contractAddress: address, entrypoint, calldata: [] }, "latest")).map(num.toHex);
const transfer = (to) => ({ contractAddress: STRK, entrypoint: "transfer", calldata: CallData.compile({ recipient: to, amount: cairo.uint256(1n) }) });

let failed = 0;
const rows = [];
const check = (cls, name, ok, detail = "") => {
  if (!ok) failed++;
  rows.push({ cls, name, ok, detail });
  console.log(`${ok ? "ok  " : "FAIL"} ${cls.slice(0, 10)} ${name}${detail ? ": " + detail : ""}`);
};
const rejects = async (fn) => { try { await fn(); return null; } catch (e) { return String(e.message || e); } };

if ((await provider.getChainId()) !== "0x534e5f5345504f4c4941") throw new Error(`${DEVNET} is not a fork of Sepolia`);
const [pre] = await rpc("devnet_getPredeployedAccounts");
const deployer = new Account({ provider, address: pre.address, signer: pre.private_key });

// Declare the candidate and the guard on the fork if Sepolia does not have them, deploy the guard.
const declared = {};
const CANDIDATE_NAME = process.env.PQ_SWITCH_CANDIDATE || "HybridShakeVerifierPfSmall";
// Declared on Sepolia by PF-04 (bench/pf04/sepolia.json); a rebuild that drifted from it must not pass.
const SMALL = "0x333aa6a603a1edcf37867d774d65220528e684ed496f5d8a73ce24fcafb0fb1";
for (const name of [CANDIDATE_NAME, "VerifierSwitchGuard"]) {
  const d = await deployer.declareIfNot(artifact(name));
  if (d.transaction_hash) await wait(d.transaction_hash);
  declared[name] = num.toHex(d.class_hash);
}
const CANDIDATE = declared[CANDIDATE_NAME];
if (CANDIDATE_NAME === "HybridShakeVerifierPfSmall" && CANDIDATE !== SMALL) throw new Error(`built small class ${CANDIDATE} is not the declared ${SMALL}`);
const g = await deployer.deployContract({ classHash: declared.VerifierSwitchGuard, salt: "0x1" });
await wait(g.transaction_hash);
const guard = g.contract_address;
const allowed = [SHAKE, CANDIDATE, POSEIDON];
console.log(`devnet ${DEVNET}, guard ${guard}, candidate ${CANDIDATE_NAME} ${CANDIDATE}\n`);

let lastAccount;
const keys = prepareKeys(deriveAccountKeys(MNEMONIC, 0, "pq"), JSON.parse(readFileSync(ROOTS, "utf8")));

for (const [cls, label] of Object.entries(MIGRATABLE)) {
  const ctor = [keys.ecdsaPublicKey, num.toHex(keys.falconFelts.length), ...keys.falconFelts, SHAKE];
  const dep = await deployer.deployContract({ classHash: cls, constructorCalldata: ctor, salt: cls.slice(0, 20) });
  await wait(dep.transaction_hash);
  const address = dep.contract_address;
  await rpc("devnet_mint", { address, amount: 10 ** 21, unit: "FRI" });
  const acc = new Account({ provider, address, signer: new HybridSigner(keys), cairoVersion: "1" });
  const pointer = async () => (await view(address, "get_verifier_class_hash"))[0];
  const keysUnchanged = async () =>
    BigInt((await view(address, "get_ecdsa_public_key"))[0]) === BigInt(keys.ecdsaPublicKey) &&
    (await view(address, "get_falcon_public_key")).slice(1).join() === keys.falconFelts.map((f) => num.toHex(f)).join();
  lastAccount = address;
  console.log(`${cls} (${label}): account ${address}`);

  const fee0 = await acc.estimateInvokeFee(transfer(deployer.address), { skipValidate: false });
  const t0 = await wait((await acc.execute(transfer(deployer.address), { resourceBounds: fee0.resourceBounds })).transaction_hash);
  check(cls, "hybrid transfer validated by baseline", t0.execution_status === "SUCCEEDED");

  // starknet.js estimates without validation by default, so with no signature the guard rejects.
  const calls = await verifierSwitchCalls(provider, address, CANDIDATE, { guard, allowed });
  const unsigned = await rejects(() => acc.estimateInvokeFee(calls));
  check(cls, "default (unsigned) estimate of a compatible switch fails", /signature rejected/.test(unsigned ?? ""), unsigned === null ? "estimate succeeded" : /signature rejected/.test(unsigned) ? "" : unsigned.slice(0, 300));

  const on = await switchVerifier(acc, CANDIDATE, { guard, allowed });
  const onReceipt = await wait(on.transaction_hash);
  check(cls, "guarded switch to candidate succeeds", onReceipt.execution_status === "SUCCEEDED" && (await pointer()) === CANDIDATE);

  const fee = await acc.estimateInvokeFee(transfer(deployer.address), { skipValidate: false });
  const t = await acc.execute(transfer(deployer.address), { resourceBounds: fee.resourceBounds });
  const tReceipt = await wait(t.transaction_hash);
  check(cls, "hybrid transfer validated by candidate", tReceipt.execution_status === "SUCCEEDED");

  const dry = await rejects(() => switchVerifier(acc, POSEIDON, { guard, allowed, dryRun: true }));
  check(cls, "kit refuses the Poseidon verifier after simulating", /would revert.*signature rejected/s.test(dry ?? ""), dry === null ? "simulation passed" : /would revert.*signature rejected/s.test(dry) ? "" : dry.slice(0, 400));

  const bad = await acc.execute(await verifierSwitchCalls(provider, address, POSEIDON, { guard, allowed }), { resourceBounds: on.simulation.resourceBounds });
  const badReceipt = await provider.waitForTransaction(bad.transaction_hash, { retryInterval: 200, successStates: ["ACCEPTED_ON_L2", "PRE_CONFIRMED"], errorStates: [] });
  check(cls, "Poseidon verifier sent anyway: reverted, pointer and keys unchanged",
    badReceipt.execution_status === "REVERTED" && /signature rejected/.test(badReceipt.revert_reason) && (await pointer()) === CANDIDATE && (await keysUnchanged()));

  // The signature commits to the calls: one signed for switching back cannot carry another switch.
  const nonce = await acc.getNonce();
  const back = await verifierSwitchCalls(provider, address, SHAKE, { guard, allowed });
  const details = {
    walletAddress: address, chainId: await provider.getChainId(), cairoVersion: "1", nonce, version: "0x3", tip: 0n,
    resourceBounds: on.simulation.resourceBounds, paymasterData: [], accountDeploymentData: [],
    nonceDataAvailabilityMode: "L1", feeDataAvailabilityMode: "L1",
  };
  const lifted = await acc.signer.signTransaction(back, details);
  const replay = await rejects(() => provider.invokeFunction(
    { contractAddress: address, calldata: transaction.getExecuteCalldata(calls, "1"), signature: lifted },
    { ...details, nonce }));
  // Control: the same signature with the calls it was made for passes validation (simulated only).
  const own = await provider.getSimulateTransaction([{ type: "INVOKE", contractAddress: address, calldata: transaction.getExecuteCalldata(back, "1"), signature: lifted, ...details }], { skipValidate: false })
    .then((r) => r.simulated_transactions[0].transaction_trace).catch((e) => ({ error: String(e.message) }));
  check(cls, "control: that signature validates with its own calls", !own.error && !own.validate_invocation?.revert_reason && !own.execute_invocation?.revert_reason,
    own.error?.slice(0, 300) ?? "");
  check(cls, "signature lifted from another switch is rejected in validation", INVALID_SIG.test(replay ?? "") && (await pointer()) === CANDIDATE,
    replay === null ? "accepted" : INVALID_SIG.test(replay) ? "" : replay.slice(0, 300));

  const ecdsaOnly = new Account({ provider, address, signer: keys.ecdsaPrivateKey, cairoVersion: "1" });
  const eo = await rejects(() => ecdsaOnly.execute(back, { resourceBounds: on.simulation.resourceBounds }));
  check(cls, "ECDSA-only switch is rejected in validation", INVALID_SIG.test(eo ?? "") && (await pointer()) === CANDIDATE,
    eo === null ? "accepted" : INVALID_SIG.test(eo) ? "" : eo.slice(0, 300));

  const outsider = await rejects(() => deployer.execute([{ contractAddress: address, entrypoint: "set_verifier_class_hash", calldata: [POSEIDON] }]));
  check(cls, "outsider calling the setter is refused", /only self/.test(outsider ?? "") && (await pointer()) === CANDIDATE);

  const off = await switchVerifier(acc, SHAKE, { guard, allowed });
  const offReceipt = await wait(off.transaction_hash);
  check(cls, "guarded switch back to baseline succeeds", offReceipt.execution_status === "SUCCEEDED" && (await pointer()) === SHAKE && (await keysUnchanged()));
  console.log();
}

const out = await rejects(() => deployer.execute([{ contractAddress: guard, entrypoint: "assert_compatible", calldata: [lastAccount, CANDIDATE] }]));
check("guard", "the guard refuses a caller other than the account", /caller is not account/.test(out ?? ""), out === null ? "accepted" : /caller is not account/.test(out) ? "" : out.slice(0, 400));

console.log(`\n${rows.filter((r) => r.ok).length}/${rows.length} checks passed`);
process.exit(failed ? 1 : 0);
