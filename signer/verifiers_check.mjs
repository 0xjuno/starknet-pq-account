// PF-07: checks the verifier choice every setup and migration script makes (verifiers.mjs), offline.
// Each script's --print-config runs with an empty keys directory, as in a clean checkout.
//
//   node signer/verifiers_check.mjs
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifierLabel } from "./page_verifier.mjs";
import { ALLOWED_VERIFIERS, MIGRATABLE_CLASS, RELEASE, pinnedVerifier, selectedVerifier, verifierClass } from "./verifiers.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SMALL = "0x333aa6a603a1edcf37867d774d65220528e684ed496f5d8a73ce24fcafb0fb1";
const BASELINE = "0x2255fc213bf39d1df2129c9e068b363f2b11a27b70b4b2c48df8ea4275f1c92";
const POSEIDON = "0x7f10b6f2f70e72ef87e97844b5f6f13d384c92afcfed2a1233a03524d359d6f";
const MIGRATABLE = "0x4b067679dbb29516dd79fba49ba1f1b2bc3973b33c74881ff56098d19e27a78";

let failed = 0;
const check = (name, ok, detail = "") => { if (!ok) failed++; console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? ": " + detail : ""}`); };
function throws(name, fn, pattern) {
  try { fn(); check(name, false, "did not throw"); } catch (e) { check(name, pattern.test(e.message), e.message); }
}

check("default verifier is small", verifierClass() === SMALL && RELEASE.default_verifier === "shake-pf-small-v1", verifierClass());
check("shake-baseline is HybridShakeAccount", verifierClass("shake-baseline") === BASELINE);
throws("an unknown id is refused", () => verifierClass("nope"), /^unknown verifier "nope"; known: shake-pf-small-v1, shake-baseline, poseidon$/);
throws("an unpinned hash is refused", () => pinnedVerifier("0x1234"), /^verifier class 0x1234 is not pinned in release\/testnet-v1\.json$/);
throws("a malformed hash is refused", () => pinnedVerifier("small"), /is not pinned/);
check("a pinned hash maps to its id", pinnedVerifier("0x" + SMALL.slice(2).toUpperCase()) === "shake-pf-small-v1");
check("ALLOWED_VERIFIERS holds both SHAKE verifiers, not Poseidon",
  ALLOWED_VERIFIERS.length === 2 && ALLOWED_VERIFIERS.includes(SMALL) && ALLOWED_VERIFIERS.includes(BASELINE) && !ALLOWED_VERIFIERS.includes(POSEIDON));
check("MIGRATABLE_CLASS is pinned", MIGRATABLE_CLASS === MIGRATABLE);
check("selectedVerifier: PQ_VERIFIER picks the id", selectedVerifier({ PQ_VERIFIER: "shake-baseline" }).classHash === BASELINE);
check("selectedVerifier: PQ_VERIFIER_CLASS must be pinned", selectedVerifier({ PQ_VERIFIER_CLASS: SMALL }).id === "shake-pf-small-v1");
throws("selectedVerifier: an unpinned PQ_VERIFIER_CLASS is refused", () => selectedVerifier({ PQ_VERIFIER_CLASS: "0x1234" }), /not pinned/);
throws("selectedVerifier: the scripts sign SHAKE-256, so Poseidon is refused", () => selectedVerifier({ PQ_VERIFIER: "poseidon" }), /not a SHAKE-256 verifier/);

// The page's verifier label (page_verifier.mjs, inlined into docs/index.html by build_page.mjs).
const LABELS = { [SMALL]: "Provably Fast small (shake-pf-small-v1)", [BASELINE]: "OpenZeppelin SHAKE-256 (shake-baseline)" };
check("label: small", verifierLabel("0x0" + SMALL.slice(2), LABELS) === "Provably Fast small (shake-pf-small-v1)", verifierLabel(SMALL, LABELS));
check("label: a class not in the map is named, not guessed", verifierLabel(POSEIDON, LABELS) === `unknown verifier class ${POSEIDON}`, verifierLabel(POSEIDON, LABELS));
check("label: no verifier means not migrated", verifierLabel(null, LABELS) === "not migrated");
const page = readFileSync(join(HERE, "../docs/index.html"), "utf8");
const pageConfig = JSON.parse(page.match(/^const CONFIG = (.*);$/m)[1]);
check("the built page maps each pinned verifier to its label",
  pageConfig.verifiers?.[SMALL] === "Provably Fast small (shake-pf-small-v1)" && pageConfig.verifiers?.[BASELINE] === "OpenZeppelin SHAKE-256 (shake-baseline)" && pageConfig.verifiers?.[POSEIDON] === "Poseidon (poseidon)",
  JSON.stringify(pageConfig.verifiers));

// Clean checkout: no state files, nothing sent.
for (const script of ["wallet_migrate_demo.mjs", "browser_setup.mjs", "public_demo_setup.mjs"]) {
  const keys = mkdtempSync(join(tmpdir(), "pq-empty-keys-"));
  const run = (env) => spawnSync(process.execPath, [join(HERE, script), "--print-config"], {
    encoding: "utf8", env: { ...process.env, PQ_VERIFIER: "", PQ_VERIFIER_CLASS: "", PQ_KEYS_DIR: keys, PQ_RPC: "http://127.0.0.1:9", ...env },
  });
  const r = run({});
  const out = r.stdout + r.stderr;
  check(`${script} --print-config, empty keys dir`, r.status === 0 && out.includes(`verifier: shake-pf-small-v1 ${SMALL}`) && out.includes(`migratable class: ${MIGRATABLE}`), out.trim().split("\n").join(" | "));
  const u = run({ PQ_VERIFIER: "nope" });
  check(`${script} refuses an unknown PQ_VERIFIER`, u.status !== 0 && /unknown verifier "nope"/.test(u.stderr), (u.stdout + u.stderr).trim().split("\n").pop());
}

// Resuming a run started with another migratable class or verifier is refused, not silently mixed.
{
  const keys = mkdtempSync(join(tmpdir(), "pq-old-run-"));
  writeFileSync(join(keys, "wallet-matrix-state-old.json"), JSON.stringify({ migratableClass: "0x660679aa09bef2ef29e1a2ebe21ee85d87bacde8746430b380425db5dd3c31b" }));
  writeFileSync(join(keys, "wallet-matrix-state-oldv.json"), JSON.stringify({ migratableClass: MIGRATABLE, "argent-0.5.0": { before: { verifierClass: BASELINE } } }));
  const run = (tag, env = {}) => spawnSync(process.execPath, [join(HERE, "wallet_migrate_demo.mjs"), "--print-config"], {
    encoding: "utf8", env: { ...process.env, PQ_VERIFIER: "", PQ_VERIFIER_CLASS: "", PQ_KEYS_DIR: keys, PQ_RPC: "http://127.0.0.1:9", PQ_MATRIX_RUN: tag, ...env },
  });
  const a = run("old");
  check("resuming a run on another migratable class is refused", a.status !== 0 && /was started with migratable class 0x660679aa/.test(a.stderr), (a.stdout + a.stderr).trim().split("\n").find((l) => /Error|migratable/.test(l)));
  const b = run("oldv");
  check("resuming a run on another verifier is refused", b.status !== 0 && /was started with verifier 0x2255/.test(b.stderr), (b.stdout + b.stderr).trim().split("\n").find((l) => /Error|verifier/.test(l)));
  const c = run("oldv", { PQ_VERIFIER: "shake-baseline" });
  check("resuming it with its own verifier works", c.status === 0, (c.stdout + c.stderr).trim().split("\n")[0]);
}

process.exit(failed ? 1 : 0);
