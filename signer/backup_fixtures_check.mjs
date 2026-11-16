// PF-07: the published demo words still restore the keys stored on the public demo account
// (backup profile v0.1: noble Falcon-512, profile "pq", index 0), and that account's verifier is a
// pinned one. Read-only on Sepolia; sends nothing. TESTNET ONLY.
//
//   node signer/backup_fixtures_check.mjs
//
// The Falcon fixtures themselves (noble v0.1 from the browser, falcon.py v0) are checked on every
// verifier, small included, by contracts/src/tests_pf.cairo: each_verifier_accepts_the_browser_signature,
// candidates_accept_the_browser_signature_directly, candidates_agree_with_the_baseline_on_the_falcon_py_fixture.
import { RpcProvider, hash, num } from "starknet";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deriveAccountKeys, prepareKeys } from "./pq_account_kit.mjs";
import { ROOTS, RPC } from "./config.mjs";
import { pinnedVerifier } from "./verifiers.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ACCOUNT = "0x343e3df576edca452f2cc6ac5247fc38a3641912f545e25468e3b7e7de1c0db";
const OZ_ACCOUNT_CLASS = "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";
const provider = new RpcProvider({ nodeUrl: RPC });
const same = (a, b) => BigInt(a) === BigInt(b);

let failed = 0;
const check = (name, ok, detail = "") => { if (!ok) failed++; console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };

const readme = readFileSync(resolve(REPO, "README.md"), "utf8");
const words = readme.match(/```text\n((?:[a-z]+ ){23}[a-z]+)\n```/)[1];
const template = readFileSync(resolve(REPO, "signer/browser-wallet.template.html"), "utf8");
check("README and the page publish the same demo words", template.includes(`const PUBLIC_DEMO_MNEMONIC = "${words}";`));

const keys = prepareKeys(deriveAccountKeys(words, 0, "pq"), JSON.parse(readFileSync(ROOTS, "utf8")));
// The page computes the address the same way: OpenZeppelin account, salt = ECDSA public key.
const address = hash.calculateContractAddressFromHash(keys.ecdsaPublicKey, OZ_ACCOUNT_CLASS, [keys.ecdsaPublicKey], 0);
check("the words give the public demo account's address", same(address, ACCOUNT), address);

const view = (entrypoint) => provider.callContract({ contractAddress: ACCOUNT, entrypoint, calldata: [] }, "latest");
const ecdsa = await view("get_ecdsa_public_key");
check("stored ECDSA key = key from the words", same(ecdsa[0], keys.ecdsaPublicKey), num.toHex(ecdsa[0]));
const falcon = await view("get_falcon_public_key");
check("stored Falcon key = key from the words", falcon.length - 1 === keys.falconFelts.length && falcon.slice(1).every((x, i) => same(x, keys.falconFelts[i])),
  `${falcon.length - 1} felts`);
const verifier = num.toHex((await view("get_verifier_class_hash"))[0]);
let id;
try { id = pinnedVerifier(verifier); } catch (e) { id = e.message; }
check("the account's verifier is pinned", !/not pinned/.test(id), `${verifier} (${id})`);

process.exit(failed ? 1 : 0);
