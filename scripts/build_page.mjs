// Builds docs/index.html (the hosted browser demo) from signer/browser-wallet.template.html.
//
//   node scripts/build_page.mjs           # write docs/index.html
//   node scripts/build_page.mjs --check   # exit 1 if docs/index.html is not what this builds
//
// The page gets: the public page config (signer/browser-wallet.config.json), a label for each
// verifier pinned in release/testnet-v1.json, the Falcon NTT roots, and verifierLabel from
// signer/page_verifier.mjs. Everything in it is public.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(resolve(REPO, path), "utf8");
const OUT = resolve(REPO, "docs/index.html");
const LABELS = {
  "shake-pf-small-v1": "Provably Fast small (shake-pf-small-v1)",
  "shake-baseline": "OpenZeppelin SHAKE-256 (shake-baseline)",
  poseidon: "Poseidon (poseidon)",
};

const release = JSON.parse(read("release/testnet-v1.json"));
const verifiers = {};
for (const [id, name] of Object.entries(release.verifiers)) {
  if (!LABELS[id]) throw new Error(`no page label for verifier "${id}"; add one to scripts/build_page.mjs`);
  verifiers[release.classes[name].class_hash] = LABELS[id];
}
const config = { ...JSON.parse(read("signer/browser-wallet.config.json")), verifiers };
const labelFn = read("signer/page_verifier.mjs").replace(/^\/\/.*\n/gm, "").replace(/^export /m, "").trim();

const fill = (text, marker, value) => {
  if (text.split(marker).length !== 2) throw new Error(`template must contain ${marker} exactly once`);
  return text.replace(marker, () => value);
};
let page = read("signer/browser-wallet.template.html");
page = fill(page, "__CONFIG__", JSON.stringify(config));
page = fill(page, "__ROOTS__", read("signer/falcon_ntt_roots.json").trim());
page = fill(page, "__PAGE_VERIFIER__", labelFn);

if (process.argv.includes("--check")) {
  if (readFileSync(OUT, "utf8") !== page) { console.error("docs/index.html is out of date: run node scripts/build_page.mjs"); process.exit(1); }
  console.log("docs/index.html matches the template, config, manifest and roots");
} else {
  writeFileSync(OUT, page);
  console.log(`wrote ${OUT}`);
}
