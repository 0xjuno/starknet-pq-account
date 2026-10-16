// Shared paths for the demo scripts. Override with environment variables.
// TESTNET ONLY: keys written under KEYS are plain JSON files and must never hold real funds.
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const RPC = process.env.PQ_RPC || "https://api.zan.top/public/starknet-sepolia/rpc/v0_10";
export const KEYS = process.env.PQ_KEYS_DIR || resolve(REPO, ".keys");
export const PY = process.env.PQ_PYTHON || "python";
// falcon.py checkout (https://github.com/tprest/falcon.py), pinned commit 5145a818c9512b4a443507d3375e75dae3076af6
export const FALCON_PY = process.env.FALCON_PY_DIR || resolve(REPO, "..", "falcon.py");
export const SIGNER_DIR = resolve(REPO, "vendor/cairo-pq-verifiers/pq-accounts/signers/falcon-python");
export const FALCON_SIGNER = resolve(SIGNER_DIR, "falcon_signer.py");
export const FALCON_FROM_SEED = resolve(REPO, "scripts/falcon_from_seed.py");
export const TARGET = resolve(REPO, "contracts/target/dev");
export const SCRIPTS = resolve(REPO, "scripts");
export const ROOTS = resolve(REPO, "signer/falcon_ntt_roots.json");
export const BROWSER_FIXTURE = resolve(REPO, "contracts/src/tests_browser.cairo");
export const PAGE_CONFIG = resolve(REPO, "signer/browser-wallet.config.json");
