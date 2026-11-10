// "Starknet PQ key backup v0" demo: ONE 24-word mnemonic restores BOTH the classical
// STARK-curve ECDSA key and the Falcon-512 key of a migrated hybrid account. TESTNET ONLY.
// Steps (idempotent, resumes from saved state):
//   1. new mnemonic -> derive ECDSA (m/44'/9004'/0'/0/i + grindKey) and Falcon (HKDF-SHA512 ->
//      SHAKE-256 stream -> falcon.py keygen); derive twice and require identical keys
//   2. OZ account from the derived ECDSA key, funded + deployed, then migrated in place
//      (upgrade + register the derived Falcon key) exactly like migrate_demo.mjs
//   3. "lose the device": delete every derived key file
//   4. restore from the mnemonic alone and send a hybrid-signed transfer with the restored keys
import { Account, CallData, RpcProvider, Signer, cairo, ec, hash, num } from "starknet";
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { HDKey } from "@scure/bip32";
import { getStarkKey, grindKey } from "@scure/starknet";
import { hkdf } from "@noble/hashes/hkdf";
import { sha512 } from "@noble/hashes/sha2";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { FALCON_FROM_SEED, FALCON_PY, FALCON_SIGNER, KEYS, PY, RPC, SIGNER_DIR } from "./config.mjs";
import { registrationHash } from "./pq_account_kit.mjs";

const STATE_FILE = `${KEYS}/backup-state.json`;
const MNEMONIC_FILE = `${KEYS}/backup-mnemonic.txt`;
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const OZ_ACCOUNT_CLASS = "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";
const SCHEME = "falcon-512-poseidon";
const VOYAGER = "https://sepolia.voyager.online";
const PROFILE = { salt: "starknet-pq-backup-v0", ecdsaPath: (i) => `m/44'/9004'/0'/0/${i}`, falconInfo: (i) => `falcon-512/account/${i}` };

const VERIFIER_CLASS = JSON.parse(readFileSync(`${KEYS}/demo-state.json`, "utf8")).classHash;
const MIGRATABLE_CLASS = JSON.parse(readFileSync(`${KEYS}/migrate-state.json`, "utf8")).migratableClass;

const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
const log = (...a) => console.log(...a);
const fmt = (wei) => (Number(wei) / 1e18).toFixed(6) + " STRK";
const provider = new RpcProvider({ nodeUrl: RPC });
// Sepolia evicts zero-tip transactions from the mempool; set in main() from recent blocks.
let TIP = 0n;
const utf8 = (s) => new TextEncoder().encode(s);

// --- the backup profile -------------------------------------------------------------
function deriveKeys(mnemonic, index, falconKeyFile) {
  if (!validateMnemonic(mnemonic, wordlist)) throw new Error("invalid mnemonic");
  const seed = mnemonicToSeedSync(mnemonic); // BIP39, empty passphrase
  const node = HDKey.fromMasterSeed(seed).derive(PROFILE.ecdsaPath(index));
  const g = grindKey(node.privateKey);
  const ecdsaPriv = g.startsWith("0x") ? g : "0x" + g;
  const ecdsaPub = num.toHex(getStarkKey(ecdsaPriv));
  const falconSeed = hkdf(sha512, seed, utf8(PROFILE.salt), utf8(PROFILE.falconInfo(index)), 64);
  const r = spawnSync(PY, ["-I", FALCON_FROM_SEED, "--falcon-py", FALCON_PY, "--signer-dir", SIGNER_DIR,
    "--seed-hex", Buffer.from(falconSeed).toString("hex"), "--key", falconKeyFile], { encoding: "utf8", maxBuffer: 20e6 });
  if (r.status !== 0) throw new Error(`falcon_from_seed failed: ${r.stderr}`);
  const falconPk = JSON.parse(r.stdout).publicKey;
  return { ecdsaPriv, ecdsaPub, falconPk, falconKeyFile };
}

// --- signing helpers ----------------------------------------------------------------
function falconSign(keyFile, hashHex) {
  const r = spawnSync(PY, [FALCON_SIGNER, "--falcon-py", FALCON_PY, "--key", keyFile], {
    input: JSON.stringify({ action: "sign-hash", scheme: SCHEME, payload: { hash: hashHex } }), encoding: "utf8", maxBuffer: 20e6,
  });
  if (r.status !== 0) throw new Error(`falcon signer failed: ${r.stderr}`);
  return JSON.parse(r.stdout).signature;
}
class HybridSigner extends Signer {
  constructor(pk, keyFile) { super(pk); this.pk = pk; this.keyFile = keyFile; }
  async signRaw(msgHash) {
    const h = num.toHex(msgHash);
    const e = ec.starkCurve.sign(h, this.pk);
    return [num.toHex(e.r), num.toHex(e.s), ...falconSign(this.keyFile, h)];
  }
}
async function strkBalance(address) {
  const r = await provider.callContract({ contractAddress: STRK, entrypoint: "balance_of", calldata: [address] });
  return BigInt(r[0]) + (BigInt(r[1]) << 128n);
}
async function classAt(address) {
  try { return num.toHex(await provider.getClassHashAt(address)); } catch { return null; }
}
async function bounds(l2Max) {
  const b = await provider.getBlockWithTxHashes("latest");
  return {
    l1_gas: { max_amount: 0n, max_price_per_unit: BigInt(b.l1_gas_price.price_in_fri) * 2n },
    l1_data_gas: { max_amount: 5000n, max_price_per_unit: BigInt(b.l1_data_gas_price.price_in_fri) * 2n },
    l2_gas: { max_amount: l2Max, max_price_per_unit: (BigInt(b.l2_gas_price.price_in_fri) * 3n) / 2n },
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
  log("deployer:", fmt(await strkBalance(deployerAddress)));

  // 1. mnemonic + deterministic derivation, twice
  if (!existsSync(MNEMONIC_FILE)) writeFileSync(MNEMONIC_FILE, generateMnemonic(wordlist, 256) + "\n");
  const mnemonic = readFileSync(MNEMONIC_FILE, "utf8").trim();
  log("mnemonic: 24 words, stored at", MNEMONIC_FILE, "(TESTNET ONLY)");
  const a = deriveKeys(mnemonic, 0, `${KEYS}/backup-falcon-A.json`);
  const b = deriveKeys(mnemonic, 0, `${KEYS}/backup-falcon-B.json`);
  const same = a.ecdsaPub === b.ecdsaPub && JSON.stringify(a.falconPk) === JSON.stringify(b.falconPk);
  state.determinism = same; state.ecdsaPub = a.ecdsaPub; state.falconPkHead = a.falconPk.slice(0, 2); save();
  log("derived twice, identical:", same, " ecdsa pub:", a.ecdsaPub);
  if (!same) throw new Error("derivation is not deterministic");

  // 2. OZ account from the derived ECDSA key, then in-place migration
  const address = hash.calculateContractAddressFromHash(a.ecdsaPub, OZ_ACCOUNT_CLASS, [a.ecdsaPub], 0);
  state.address = address; save();
  log("account:", address);
  if (!(await classAt(address))) {
    if ((await strkBalance(address)) < 5n * 10n ** 18n) {
      const nonce = await provider.getNonceForAddress(deployerAddress, "latest");
      const t = await deployerAcc.execute(transferCall(address, 6n * 10n ** 18n), { nonce, tip: TIP });
      await provider.waitForTransaction(t.transaction_hash);
    }
    const oz = new Account({ provider, address, signer: a.ecdsaPriv });
    const r = await oz.deployAccount({ classHash: OZ_ACCOUNT_CLASS, constructorCalldata: [a.ecdsaPub], addressSalt: a.ecdsaPub, contractAddress: address }, { tip: TIP });
    await provider.waitForTransaction(r.transaction_hash);
    state.deployTx = r.transaction_hash; save();
    log("OZ account deployed:", `${VOYAGER}/tx/${r.transaction_hash}`);
  }
  if ((await classAt(address)) === num.toHex(OZ_ACCOUNT_CLASS)) {
    const oz = new Account({ provider, address, signer: a.ecdsaPriv });
    const nonce = await provider.getNonceForAddress(address, "latest");
    const proof = await new HybridSigner(a.ecdsaPriv, `${KEYS}/backup-falcon-A.json`).signRaw(registrationHash(a.ecdsaPub, a.falconPk));
    const m = await oz.execute([
      { contractAddress: address, entrypoint: "upgrade", calldata: [MIGRATABLE_CLASS] },
      { contractAddress: address, entrypoint: "migrate", calldata: [a.ecdsaPub, num.toHex(a.falconPk.length), ...a.falconPk, VERIFIER_CLASS, num.toHex(proof.length), ...proof] },
    ], { nonce, tip: TIP, resourceBounds: await bounds(150000000n) });
    await provider.waitForTransaction(m.transaction_hash);
    state.migrationTx = m.transaction_hash; save();
    log("migrated in place:", `${VOYAGER}/tx/${m.transaction_hash}`);
  }

  // 3. lose the device: delete every derived key file
  for (const f of [`${KEYS}/backup-falcon-A.json`, `${KEYS}/backup-falcon-B.json`, `${KEYS}/backup-falcon-restored.json`]) rmSync(f, { force: true });
  log("device lost: derived key files deleted; only the 24 words remain");

  // 4. restore from the mnemonic alone, then sign with the restored keys
  const restored = deriveKeys(mnemonic, 0, `${KEYS}/backup-falcon-restored.json`);
  const onchainFalcon = await provider.callContract({ contractAddress: address, entrypoint: "get_falcon_public_key", calldata: [] }, "latest");
  const onchainEcdsa = await provider.callContract({ contractAddress: address, entrypoint: "get_ecdsa_public_key", calldata: [] }, "latest");
  const falconMatch = JSON.stringify(onchainFalcon.slice(1).map((x) => num.toHex(x))) === JSON.stringify(restored.falconPk.map((x) => num.toHex(x)));
  const ecdsaMatch = num.toHex(onchainEcdsa[0]) === restored.ecdsaPub;
  state.restoreMatchesOnchain = { falcon: falconMatch, ecdsa: ecdsaMatch }; save();
  log("restored keys match the on-chain keys:", { falcon: falconMatch, ecdsa: ecdsaMatch });

  if (!state.restoredTransferTx) {
    const acc = new Account({ provider, address, signer: new HybridSigner(restored.ecdsaPriv, restored.falconKeyFile) });
    const nonce = await provider.getNonceForAddress(address, "latest");
    const x = await acc.execute(transferCall(deployerAddress, 10n ** 17n), { nonce, tip: TIP, resourceBounds: await bounds(60000000n) });
    const rc = await provider.waitForTransaction(x.transaction_hash);
    state.restoredTransferTx = x.transaction_hash; state.restoredTransferStatus = rc.execution_status || rc.status || null; save();
    log("transfer signed with RESTORED keys:", `${VOYAGER}/tx/${x.transaction_hash}`, rc.execution_status || "");
  }
  log("account page:", `${VOYAGER}/contract/${address}`);
}

main().catch((e) => { console.error("ERROR:", e?.message || e); let c = e?.cause; while (c) { console.error("  cause:", c.code || "", c.message || c); c = c.cause; } process.exit(1); });
