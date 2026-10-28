// Sepolia demo: in-place migration of an existing OpenZeppelin ECDSA account to the hybrid
// ECDSA + Falcon-512 account, keeping the SAME address and funds. TESTNET ONLY.
// Steps (idempotent, resumes from saved state):
//   1. create a fresh "existing user" OZ account (new testnet keys), fund + deploy it
//   2. declare the thin HybridMigratableAccount class (verification is library-called into
//      the HybridPoseidonAccount class declared by demo.mjs)
//   3. ONE tx signed by the old ECDSA key: [upgrade(migratable), migrate(keys, verifier, proof)]
//   4. check: same address, new class, keys stored, balance only moved by fees
//   5. hybrid-signed transfer succeeds; ECDSA-only transfer is rejected
import { Account, CallData, RpcProvider, Signer, cairo, ec, hash, json, num } from "starknet";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { FALCON_PY, FALCON_SIGNER, KEYS, PY, RPC, TARGET } from "./config.mjs";
import { registrationHash } from "./pq_account_kit.mjs";

const STATE_FILE = `${KEYS}/migrate-state.json`;
const USER_ECDSA = `${KEYS}/migrate-user-ecdsa.json`;
const USER_FALCON = `${KEYS}/migrate-user-falcon.json`;
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const OZ_ACCOUNT_CLASS = "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";
const SCHEME = "falcon-512-poseidon";
const VOYAGER = "https://sepolia.voyager.online";

const demoState = JSON.parse(readFileSync(`${KEYS}/demo-state.json`, "utf8"));
const VERIFIER_CLASS = demoState.classHash; // HybridPoseidonAccount, declared 10-15

const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
const log = (...a) => console.log(...a);
const fmt = (wei) => (Number(wei) / 1e18).toFixed(6) + " STRK";
const provider = new RpcProvider({ nodeUrl: RPC });
// Sepolia evicts zero-tip transactions from the mempool; set in main() from recent blocks.
let TIP = 0n;

function falcon(action, hashHex) {
  const req = { action, scheme: SCHEME };
  if (hashHex) req.payload = { hash: hashHex };
  const r = spawnSync(PY, [FALCON_SIGNER, "--falcon-py", FALCON_PY, "--key", USER_FALCON], {
    input: JSON.stringify(req), encoding: "utf8", maxBuffer: 20e6,
  });
  if (r.status !== 0) throw new Error(`falcon signer failed: ${r.stderr}`);
  return JSON.parse(r.stdout);
}

class HybridSigner extends Signer {
  constructor(pk) { super(pk); this.pk = pk; }
  async signRaw(msgHash) {
    const h = num.toHex(msgHash);
    const e = ec.starkCurve.sign(h, this.pk);
    return [num.toHex(e.r), num.toHex(e.s), ...falcon("sign-hash", h).signature];
  }
}
// Simulates an attacker who forged the classical key (e.g. quantum) but has no Falcon key.
class EcdsaOnlySigner extends Signer {
  constructor(pk) { super(pk); this.pk = pk; }
  async signRaw(msgHash) {
    const e = ec.starkCurve.sign(num.toHex(msgHash), this.pk);
    return [num.toHex(e.r), num.toHex(e.s)];
  }
}

async function strkBalance(address) {
  const r = await provider.callContract({ contractAddress: STRK, entrypoint: "balance_of", calldata: [address] });
  return BigInt(r[0]) + (BigInt(r[1]) << 128n);
}
async function classAt(address) {
  try { return num.toHex(await provider.getClassHashAt(address)); } catch { return null; }
}
async function bounds(l2Max, l2Mult = [3n, 2n], dataMax = 5000n) {
  const b = await provider.getBlockWithTxHashes("latest");
  return {
    l1_gas: { max_amount: 0n, max_price_per_unit: BigInt(b.l1_gas_price.price_in_fri) * 2n },
    l1_data_gas: { max_amount: dataMax, max_price_per_unit: BigInt(b.l1_data_gas_price.price_in_fri) * 2n },
    l2_gas: { max_amount: l2Max, max_price_per_unit: (BigInt(b.l2_gas_price.price_in_fri) * l2Mult[0]) / l2Mult[1] },
  };
}
const transferCall = (to, amount) => ({
  contractAddress: STRK, entrypoint: "transfer",
  calldata: CallData.compile({ recipient: to, amount: cairo.uint256(amount) }),
});

async function main() {
  const deployer = JSON.parse(readFileSync(`${KEYS}/deployer-ecdsa.json`, "utf8"));
  const deployerAddress = readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim();
  const deployerAcc = new Account({ provider, address: deployerAddress, signer: deployer.privateKey });
  TIP = (await provider.getEstimateTip("latest", { maxBlocks: 5 })).recommendedTip;
  log("deployer:", deployerAddress, fmt(await strkBalance(deployerAddress)));
  log("verifier class (library-called):", VERIFIER_CLASS);

  // 0. keys for the simulated existing user (TESTNET ONLY)
  if (!existsSync(USER_ECDSA)) {
    const privateKey = "0x" + randomBytes(31).toString("hex");
    const publicKey = ec.starkCurve.getStarkKey(privateKey);
    writeFileSync(USER_ECDSA, JSON.stringify({ privateKey, publicKey, note: "TESTNET ONLY" }, null, 2));
  }
  const user = JSON.parse(readFileSync(USER_ECDSA, "utf8"));
  if (!existsSync(USER_FALCON)) {
    log("generating the user's Falcon-512 key (NTRU solve, may take a while)...");
    const r = spawnSync(PY, [FALCON_SIGNER, "keygen", "--falcon-py", FALCON_PY, "--key", USER_FALCON], { encoding: "utf8", maxBuffer: 20e6 });
    if (r.status !== 0) throw new Error(`falcon keygen failed: ${r.stderr}`);
  }
  const falconPk = falcon("public-key").publicKey;
  const userAddress = hash.calculateContractAddressFromHash(user.publicKey, OZ_ACCOUNT_CLASS, [user.publicKey], 0);
  state.userAddress = userAddress; save();
  log("user account (OZ):", userAddress);

  // 1. fund + deploy the classical OZ account
  if (!(await classAt(userAddress))) {
    if ((await strkBalance(userAddress)) < 5n * 10n ** 18n) {
      log("funding user with 6 STRK...");
      const nonce = await provider.getNonceForAddress(deployerAddress, "latest");
      const t = await deployerAcc.execute(transferCall(userAddress, 6n * 10n ** 18n), { nonce, tip: TIP });
      await provider.waitForTransaction(t.transaction_hash);
      state.fundTx = t.transaction_hash; save();
    }
    log("deploying the user's classical OZ account...");
    const userAcc = new Account({ provider, address: userAddress, signer: user.privateKey });
    const r = await userAcc.deployAccount({
      classHash: OZ_ACCOUNT_CLASS, constructorCalldata: [user.publicKey],
      addressSalt: user.publicKey, contractAddress: userAddress,
    }, { tip: TIP });
    await provider.waitForTransaction(r.transaction_hash);
    state.userDeployTx = r.transaction_hash; save();
    log("OZ account deployed:", `${VOYAGER}/tx/${r.transaction_hash}`);
  }

  // 2. declare the thin migratable class
  if (!state.migratableClass) {
    const sierraPath = `${TARGET}/pq_hybrid_HybridMigratableAccount.contract_class.json`;
    const sierra = json.parse(readFileSync(sierraPath, "utf8"));
    const casm = json.parse(readFileSync(`${TARGET}/pq_hybrid_HybridMigratableAccount.compiled_contract_class.json`, "utf8"));
    const hybridSize = statSync(`${TARGET}/pq_hybrid_HybridPoseidonAccount.contract_class.json`).size;
    const ratio = statSync(sierraPath).size / hybridSize;
    // Hybrid class declare measured ~4.11e9 L2 gas; scale by size with 2x headroom.
    const l2Max = BigInt(Math.ceil(4.2e9 * ratio * 2));
    log(`declaring HybridMigratableAccount (size ratio ${ratio.toFixed(3)}, l2 max ${l2Max})...`);
    const nonce = await provider.getNonceForAddress(deployerAddress, "latest");
    const d = await deployerAcc.declareIfNot({ contract: sierra, casm }, { nonce, tip: TIP, resourceBounds: await bounds(l2Max, [5n, 4n], 200000n) });
    if (d.transaction_hash) {
      const rc = await provider.waitForTransaction(d.transaction_hash);
      log("declare fee:", rc.actual_fee ? fmt(BigInt(rc.actual_fee.amount)) : "n/a");
    }
    state.migratableClass = d.class_hash; state.declareTx = d.transaction_hash || null; save();
    log("migratable class:", d.class_hash);
  }

  // 3. the migration: one tx, validated by the OLD class with the OLD (ECDSA) key
  const before = { class: await classAt(userAddress), balance: await strkBalance(userAddress) };
  if (before.class === num.toHex(OZ_ACCOUNT_CLASS)) {
    state.before = { class: before.class, balance: before.balance.toString() }; save();
    log("BEFORE: class", before.class, "balance", fmt(before.balance));
    const userAcc = new Account({ provider, address: userAddress, signer: user.privateKey });
    // Key-possession proof: a hybrid signature by the new keys over the registration hash.
    const proof = await new HybridSigner(user.privateKey).signRaw(registrationHash(user.publicKey, falconPk));
    const calls = [
      { contractAddress: userAddress, entrypoint: "upgrade", calldata: [state.migratableClass] },
      { contractAddress: userAddress, entrypoint: "migrate",
        calldata: [user.publicKey, num.toHex(falconPk.length), ...falconPk, VERIFIER_CLASS, num.toHex(proof.length), ...proof] },
    ];
    log("migrating in place: [upgrade, migrate(keys, proof)] signed by the ECDSA key...");
    const nonce = await provider.getNonceForAddress(userAddress, "latest");
    const m = await userAcc.execute(calls, { nonce, tip: TIP, resourceBounds: await bounds(150000000n) });
    const rc = await provider.waitForTransaction(m.transaction_hash);
    state.migrationTx = m.transaction_hash;
    state.migrationFee = rc.actual_fee ? rc.actual_fee.amount : null; save();
    log("migration tx:", `${VOYAGER}/tx/${m.transaction_hash}`, "fee", rc.actual_fee ? fmt(BigInt(rc.actual_fee.amount)) : "n/a");
  }

  // 4. checks
  const after = { class: await classAt(userAddress), balance: await strkBalance(userAddress) };
  const view = (entrypoint) => provider.callContract({ contractAddress: userAddress, entrypoint, calldata: [] }, "latest");
  const registered = (await view("is_falcon_registered"))[0];
  const ecdsaKey = (await view("get_ecdsa_public_key"))[0];
  const verifier = (await view("get_verifier_class_hash"))[0];
  state.after = { class: after.class, balance: after.balance.toString(), registered, ecdsaKey, verifier }; save();
  log("AFTER: same address", userAddress);
  log("  class:", after.class, after.class === num.toHex(state.migratableClass) ? "(migratable)" : "(UNEXPECTED)");
  log("  falcon registered:", registered, " ecdsa key kept:", num.toHex(ecdsaKey) === num.toHex(user.publicKey));
  log("  verifier class:", num.toHex(verifier));
  log("  balance:", fmt(after.balance), "(before", fmt(BigInt(state.before.balance)) + ")");

  // 5a. hybrid-signed transfer must succeed
  if (!state.hybridTransferTx) {
    const hybridAcc = new Account({ provider, address: userAddress, signer: new HybridSigner(user.privateKey) });
    log("hybrid-signed transfer (ECDSA + Falcon) of 0.1 STRK...");
    const nonce = await provider.getNonceForAddress(userAddress, "latest");
    const x = await hybridAcc.execute(transferCall(deployerAddress, 10n ** 17n), { nonce, tip: TIP, resourceBounds: await bounds(60000000n) });
    const rc = await provider.waitForTransaction(x.transaction_hash);
    state.hybridTransferTx = x.transaction_hash;
    state.hybridTransferFee = rc.actual_fee ? rc.actual_fee.amount : null;
    state.hybridTransferResources = rc.execution_resources || null; save();
    log("hybrid transfer:", `${VOYAGER}/tx/${x.transaction_hash}`, "fee", rc.actual_fee ? fmt(BigInt(rc.actual_fee.amount)) : "n/a");
    log("resources:", JSON.stringify(rc.execution_resources));
  }

  // 5b. ECDSA-only transfer must be rejected
  if (!state.negativeResult) {
    const attacker = new Account({ provider, address: userAddress, signer: new EcdsaOnlySigner(user.privateKey) });
    try {
      const nonce = await provider.getNonceForAddress(userAddress, "latest");
      const r = await attacker.execute(transferCall(deployerAddress, 1n), { nonce, tip: TIP, resourceBounds: await bounds(60000000n, [2n, 1n]) });
      state.negativeResult = "UNEXPECTED: accepted " + r.transaction_hash;
    } catch (e) {
      const msg = e?.message || String(e);
      state.negativeResult = "REJECTED: " + msg.slice(msg.lastIndexOf("\n") + 1).slice(0, 300);
    }
    save();
  }
  log("ECDSA-only transfer:", state.negativeResult);
  log("account page:", `${VOYAGER}/contract/${userAddress}`);
}

main().catch((e) => { console.error("ERROR:", e?.message || e); let c = e?.cause; while (c) { console.error("  cause:", c.code || "", c.message || c); c = c.cause; } process.exit(1); });
