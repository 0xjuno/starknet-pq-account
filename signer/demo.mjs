// Sepolia demo for the hybrid ECDSA + Falcon-512 account. TESTNET ONLY.
// Steps (idempotent, resumes from saved state):
//   1. deploy a classical OZ "deployer" account (needs faucet STRK at its address)
//   2. declare HybridPoseidonAccount
//   3. fund + deploy a hybrid account (its own deploy tx is hybrid-signed)
//   4. send a hybrid-signed transfer and print the receipt
import { Account, CallData, RpcProvider, Signer, cairo, ec, hash, json, num } from "starknet";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { FALCON_PY, FALCON_SIGNER, KEYS, PY, RPC, TARGET } from "./config.mjs";

const STATE_FILE = `${KEYS}/demo-state.json`;
const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const OZ_ACCOUNT_CLASS = "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";
const FALCON_KEY = `${KEYS}/falcon-key.json`;
const SCHEME = "falcon-512-poseidon";
const HYBRID_SALT = "0x1";
const VOYAGER = "https://sepolia.voyager.online";

const state = existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")) : {};
const save = () => writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
const log = (...a) => console.log(...a);

function falcon(action, hashHex) {
  const req = { action, scheme: SCHEME };
  if (hashHex) req.payload = { hash: hashHex };
  const r = spawnSync(PY, [FALCON_SIGNER, "--falcon-py", FALCON_PY, "--key", FALCON_KEY], {
    input: JSON.stringify(req), encoding: "utf8", maxBuffer: 20e6,
  });
  if (r.status !== 0) throw new Error(`falcon signer failed: ${r.stderr}`);
  return JSON.parse(r.stdout);
}

// Signs every transaction hash with BOTH schemes: [ecdsa_r, ecdsa_s, ...falcon(60)].
class HybridSigner extends Signer {
  constructor(ecdsaPrivateKey) {
    super(ecdsaPrivateKey);
    this.ecdsaPrivateKey = ecdsaPrivateKey;
  }
  async signRaw(msgHash) {
    const h = num.toHex(msgHash);
    const e = ec.starkCurve.sign(h, this.ecdsaPrivateKey);
    const f = falcon("sign-hash", h).signature;
    return [num.toHex(e.r), num.toHex(e.s), ...f];
  }
}

const provider = new RpcProvider({ nodeUrl: RPC });
// Sepolia evicts zero-tip transactions from the mempool; set in main() from recent blocks.
let TIP = 0n;

async function strkBalance(address) {
  const r = await provider.callContract({ contractAddress: STRK, entrypoint: "balance_of", calldata: [address] });
  return BigInt(r[0]) + (BigInt(r[1]) << 128n);
}
async function isDeployed(address) {
  try { await provider.getClassHashAt(address); return true; } catch { return false; }
}
const fmt = (wei) => (Number(wei) / 1e18).toFixed(4) + " STRK";

async function main() {
  const deployer = JSON.parse(readFileSync(`${KEYS}/deployer-ecdsa.json`, "utf8"));
  const hybridEcdsa = JSON.parse(readFileSync(`${KEYS}/hybrid-ecdsa.json`, "utf8"));
  const deployerAddress = readFileSync(`${KEYS}/deployer-address.txt`, "utf8").trim();

  log("RPC:", RPC);
  log("deployer:", deployerAddress);
  const bal = await strkBalance(deployerAddress);
  log("deployer balance:", fmt(bal));
  if (bal === 0n) {
    log("\nNEED FUNDS: send Sepolia STRK (faucet) to the deployer address above, then rerun.");
    return;
  }

  const deployerAcc = new Account({ provider, address: deployerAddress, signer: deployer.privateKey });
  TIP = (await provider.getEstimateTip("latest", { maxBlocks: 5 })).recommendedTip;

  // 1. deployer account
  if (!(await isDeployed(deployerAddress))) {
    log("deploying deployer account...");
    const r = await deployerAcc.deployAccount({
      classHash: OZ_ACCOUNT_CLASS, constructorCalldata: [deployer.publicKey],
      addressSalt: deployer.publicKey, contractAddress: deployerAddress,
    }, { tip: TIP });
    await provider.waitForTransaction(r.transaction_hash);
    state.deployerDeployTx = r.transaction_hash; save();
    log("deployer deployed:", `${VOYAGER}/tx/${r.transaction_hash}`);
  }

  // 2. declare hybrid class
  if (!state.classHash) {
    const sierra = json.parse(readFileSync(`${TARGET}/pq_hybrid_HybridPoseidonAccount.contract_class.json`, "utf8"));
    const casm = json.parse(readFileSync(`${TARGET}/pq_hybrid_HybridPoseidonAccount.compiled_contract_class.json`, "utf8"));
    log("declaring HybridPoseidonAccount...");
    const nonce = await provider.getNonceForAddress(deployerAddress, "latest");
    // Large class (~51k Sierra felts): RPC fee estimation times out, so pass explicit bounds
    // derived from the latest block's gas prices (2x headroom). Testnet only.
    const blk = await provider.getBlockWithTxHashes("latest");
    const px = (p) => BigInt(p.price_in_fri) * 2n;
    const resourceBounds = {
      l1_gas: { max_amount: 0n, max_price_per_unit: px(blk.l1_gas_price) },
      l1_data_gas: { max_amount: 200000n, max_price_per_unit: px(blk.l1_data_gas_price) },
      l2_gas: { max_amount: 4500000000n, max_price_per_unit: (BigInt(blk.l2_gas_price.price_in_fri) * 5n) / 4n },
    };
    log("gas prices (fri):", blk.l1_gas_price.price_in_fri, blk.l1_data_gas_price.price_in_fri, blk.l2_gas_price.price_in_fri);
    const d = await deployerAcc.declareIfNot({ contract: sierra, casm }, { nonce, tip: TIP, resourceBounds });
    if (d.transaction_hash) await provider.waitForTransaction(d.transaction_hash);
    state.classHash = d.class_hash; state.declareTx = d.transaction_hash || null; save();
    log("class hash:", d.class_hash);
  }

  // 3. hybrid account address, funding, deployment
  const falconPk = falcon("public-key").publicKey;
  const calldata = [hybridEcdsa.publicKey, num.toHex(falconPk.length), ...falconPk];
  const hybridAddress = hash.calculateContractAddressFromHash(HYBRID_SALT, state.classHash, calldata, 0);
  state.hybridAddress = hybridAddress; save();
  log("hybrid account:", hybridAddress);

  if ((await strkBalance(hybridAddress)) < 2n * 10n ** 18n && !(await isDeployed(hybridAddress))) {
    log("funding hybrid account with 3 STRK...");
    const nonce = await provider.getNonceForAddress(deployerAddress, "latest");
    const t = await deployerAcc.execute({
      contractAddress: STRK, entrypoint: "transfer",
      calldata: CallData.compile({ recipient: hybridAddress, amount: cairo.uint256(3n * 10n ** 18n) }),
    }, { nonce, tip: TIP });
    await provider.waitForTransaction(t.transaction_hash);
  }

  const hybridAcc = new Account({ provider, address: hybridAddress, signer: new HybridSigner(hybridEcdsa.privateKey) });
  // Explicit bounds for hybrid txs: Falcon validation (~34M L2 gas measured) + headroom.
  const hb = await provider.getBlockWithTxHashes("latest");
  const hybridBounds = {
    l1_gas: { max_amount: 0n, max_price_per_unit: BigInt(hb.l1_gas_price.price_in_fri) * 2n },
    l1_data_gas: { max_amount: 5000n, max_price_per_unit: BigInt(hb.l1_data_gas_price.price_in_fri) * 2n },
    l2_gas: { max_amount: 60000000n, max_price_per_unit: (BigInt(hb.l2_gas_price.price_in_fri) * 3n) / 2n },
  };
  if (!(await isDeployed(hybridAddress))) {
    log("deploying hybrid account (deploy tx is ECDSA + Falcon signed)...");
    const r = await hybridAcc.deployAccount({
      classHash: state.classHash, constructorCalldata: calldata,
      addressSalt: HYBRID_SALT, contractAddress: hybridAddress,
    }, { tip: TIP, resourceBounds: hybridBounds });
    await provider.waitForTransaction(r.transaction_hash);
    state.hybridDeployTx = r.transaction_hash; save();
    log("hybrid deployed:", `${VOYAGER}/tx/${r.transaction_hash}`);
  }

  // 4. hybrid-signed transfer
  log("sending hybrid-signed transfer of 0.1 STRK back to deployer...");
  const hnonce = await provider.getNonceForAddress(hybridAddress, "latest");
  const x = await hybridAcc.execute({
    contractAddress: STRK, entrypoint: "transfer",
    calldata: CallData.compile({ recipient: deployerAddress, amount: cairo.uint256(10n ** 17n) }),
  }, { nonce: hnonce, tip: TIP, resourceBounds: hybridBounds });
  const receipt = await provider.waitForTransaction(x.transaction_hash);
  state.hybridTransferTx = x.transaction_hash; save();
  log("transfer:", `${VOYAGER}/tx/${x.transaction_hash}`);
  log("actual fee:", receipt.actual_fee ? fmt(BigInt(receipt.actual_fee.amount)) : "n/a");
  log("execution resources:", JSON.stringify(receipt.execution_resources));
  log("account page:", `${VOYAGER}/contract/${hybridAddress}`);
}

main().catch((e) => { console.error("ERROR:", e?.message || e); let c = e?.cause; while (c) { console.error("  cause:", c.code || "", c.message || c); c = c.cause; } process.exit(1); });
