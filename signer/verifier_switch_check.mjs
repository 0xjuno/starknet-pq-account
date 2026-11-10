// PF-05: checks verifierSwitchCalls's read-only gates offline, against a provider stub that
// serves the ABIs of this repository's compiled classes (run `scarb build` in contracts/ first).
//
//   node signer/verifier_switch_check.mjs
//
// The on-chain behaviour of the switch itself is tested in contracts/src/tests_guard.cairo.
import { readFileSync } from "node:fs";
import { switchVerifier, verifierSwitchCalls } from "./pq_account_kit.mjs";
import { TARGET } from "./config.mjs";

const abi = (name) => JSON.parse(readFileSync(`${TARGET}/pq_hybrid_${name}.contract_class.json`, "utf8")).abi;
const CLASSES = {
  "0xa1": abi("HybridMigratableAccount"),
  "0xb1": abi("HybridShakeAccount"), // installed verifier
  "0xb2": abi("HybridShakeVerifierPfCompact"), // candidate
  "0xb3": abi("HybridPoseidonAccount"), // declared, has is_valid_signature, other scheme
  "0xc1": abi("VerifierSwitchGuard"),
};
const ACCOUNT = "0x111", GUARD = "0x222", NOT_A_GUARD = "0x333", OTHER_ACCOUNT = "0x444";
const contracts = { [ACCOUNT]: "0xa1", [GUARD]: "0xc1", [NOT_A_GUARD]: "0xb1", [OTHER_ACCOUNT]: "0xb1" };
let registered = 1n;

const provider = {
  async getClassHashAt(address) {
    const c = contracts[address];
    if (!c) throw new Error("contract not found");
    return c;
  },
  async getClassByHash(h) {
    if (!CLASSES[h]) throw new Error("class hash not found");
    return { sierra_program: ["0x1"], abi: CLASSES[h] };
  },
  async callContract({ contractAddress, entrypoint }) {
    if (contractAddress !== ACCOUNT) throw new Error("unexpected call");
    if (entrypoint === "is_falcon_registered") return [`0x${registered.toString(16)}`];
    if (entrypoint === "get_verifier_class_hash") return ["0xb1"];
    throw new Error(`unexpected view ${entrypoint}`);
  },
};

let failed = 0;
const check = (name, ok, detail = "") => { if (!ok) failed++; console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };
const allowed = ["0xb1", "0xb2", "0xb3", "0x0", "0x999", "0xc1"];
async function refuses(name, args, pattern) {
  try {
    await verifierSwitchCalls(provider, ...args);
    check(name, false, "did not throw");
  } catch (e) {
    check(name, pattern.test(e.message), e.message);
  }
}

const calls = await verifierSwitchCalls(provider, ACCOUNT, "0xb2", { guard: GUARD, allowed });
check("compatible candidate: set_verifier_class_hash then assert_compatible",
  calls.length === 2 &&
  calls[0].contractAddress === ACCOUNT && calls[0].entrypoint === "set_verifier_class_hash" && calls[0].calldata.join() === "0xb2" &&
  calls[1].contractAddress === GUARD && calls[1].entrypoint === "assert_compatible" && calls[1].calldata.join() === `${ACCOUNT},0xb2`,
  JSON.stringify(calls));

await refuses("candidate not in the allowed list", [ACCOUNT, "0xb2", { guard: GUARD, allowed: ["0xb3"] }], /allowed list/);
await refuses("no allowed list", [ACCOUNT, "0xb2", { guard: GUARD }], /allowed list/);
await refuses("zero class hash", [ACCOUNT, "0x0", { guard: GUARD, allowed }], /zero/);
await refuses("undeclared class", [ACCOUNT, "0x999", { guard: GUARD, allowed }], /not declared/);
await refuses("class without is_valid_signature", [ACCOUNT, "0xc1", { guard: GUARD, allowed }], /no is_valid_signature/);
await refuses("verifier already installed", [ACCOUNT, "0xb1", { guard: GUARD, allowed }], /already installed/);
await refuses("not a migratable account", [OTHER_ACCOUNT, "0xb2", { guard: GUARD, allowed }], /not a migratable hybrid account/);
await refuses("no guard at the address", [ACCOUNT, "0xb2", { guard: "0x555", allowed }], /no guard deployed/);
await refuses("guard address is another contract", [ACCOUNT, "0xb2", { guard: NOT_A_GUARD, allowed }], /not a verifier switch guard/);
registered = 0n;
await refuses("account not migrated yet", [ACCOUNT, "0xb2", { guard: GUARD, allowed }], /not migrated/);
registered = 1n;
// A same-ABI verifier of another scheme passes these read-only checks; the guard rejects it on
// chain (tests_guard.cairo: incompatible_scheme_reverts_the_whole_transaction).
const other = await verifierSwitchCalls(provider, ACCOUNT, "0xb3", { guard: GUARD, allowed });
check("other-scheme verifier passes the read-only checks (the guard catches it)", other.length === 2);

// switchVerifier passes an explicit tip to both the simulation and the send, and leaves it out
// when none is given so that starknet.js estimates one (Sepolia evicts zero-tip transactions).
const seen = {};
const simBounds = { l2_gas: { max_amount: "0x1", max_price_per_unit: "0x1" } };
const stub = {
  provider, address: ACCOUNT,
  async simulateTransaction(txs, details) {
    seen.simulate = details;
    return { simulated_transactions: [{ transaction_trace: {}, resourceBounds: simBounds }] };
  },
  async execute(calls, details) {
    seen.execute = details;
    return { transaction_hash: "0x1" };
  },
};
await switchVerifier(stub, "0xb2", { guard: GUARD, allowed, tip: 123n });
check("switchVerifier simulates with validation and the tip", seen.simulate?.skipValidate === false && seen.simulate?.tip === 123n, JSON.stringify(seen.simulate, (k, v) => typeof v === "bigint" ? `${v}n` : v));
check("switchVerifier sends with the simulated bounds and the tip", seen.execute?.tip === 123n && seen.execute?.resourceBounds === simBounds, JSON.stringify(seen.execute, (k, v) => typeof v === "bigint" ? `${v}n` : v));

await switchVerifier(stub, "0xb2", { guard: GUARD, allowed });
check("switchVerifier without a tip leaves it to starknet.js", seen.simulate && !("tip" in seen.simulate) && !("tip" in seen.execute), JSON.stringify([seen.simulate, seen.execute], (k, v) => typeof v === "bigint" ? `${v}n` : v));

process.exit(failed ? 1 : 0);
