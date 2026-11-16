#!/usr/bin/env bash
# PF-04: declare size of Provably Fast board entries as this project's verifier class.
#
#   bench/pf04/screen.sh JOB_ID...
#
# For each job: download its patch from the board into a temporary copy of this repository, put it
# in the compact slot, build contracts/, and print the CASM and Sierra felts of
# `HybridShakeVerifierPfCompact` and its declare L2 gas against the block cap (see summarize.py).
# The board reports CASM only, which does not predict the declare size. Nothing in the repository
# is changed. Needs scarb 2.18.0, curl, rsync and python3; about 45 seconds per job.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
[ $# -gt 0 ] || { echo "usage: screen.sh JOB_ID..." >&2; exit 1; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
SLOT=compact-fj_3a0b1c78817845a68e1e907928a541e4.patch

for job in "$@"; do
  [[ $job =~ ^fj_[0-9a-f]{32}$ ]] || { echo "not a job id: $job" >&2; exit 1; }
  w=$WORK/$job
  mkdir -p "$w"
  rsync -a --exclude target --exclude node_modules --exclude .git --exclude .keys \
    --exclude .snfoundry_cache "$REPO/" "$w/"
  f=$w/vendor/provably-fast/falcon-512
  curl -sf -o "$f/$SLOT" "https://postquantum.provably.fast/api/participation/falcon/jobs/$job/patch"
  # Untrusted input: the patch may only modify or create Cairo sources of the two crates. Check the
  # paths git apply itself will write (both sides, via --numstat), and reject renames, copies, mode
  # changes and deletions (--summary), before make_crates.sh applies it.
  allowed='^crates/(falcon_512|ntt)/src/[A-Za-z0-9_/]+\.cairo$'
  paths=$(git apply --numstat "$f/$SLOT" | cut -f3-) || { echo "$job: not a valid patch, skipped" >&2; continue; }
  if [ -z "$paths" ] || grep -Ev "$allowed" <<< "$paths" >&2; then
    echo "$job: patch touches other files, skipped" >&2; continue
  fi
  if git apply --summary "$f/$SLOT" | grep -Ev '^ create mode 100644 crates/(falcon_512|ntt)/src/[A-Za-z0-9_/]+\.cairo$' | grep . >&2; then
    echo "$job: patch renames, copies, deletes or changes modes, skipped" >&2; continue
  fi
  (cd "$f" && shasum -a 256 compact-*.patch record-*.patch small-*.patch > SHA256SUMS)
  "$f/make_crates.sh" > /dev/null
  (cd "$w/contracts" && scarb build > "$w/build.log" 2>&1) || { echo "$job: build failed" >&2; continue; }
  python3 -I - "$w/contracts/target/dev" "$job" <<'PY'
import json, sys
target, job = sys.argv[1], sys.argv[2]
name = "HybridShakeVerifierPfCompact"
sierra = json.load(open(f"{target}/pq_hybrid_{name}.contract_class.json"))
casm = json.load(open(f"{target}/pq_hybrid_{name}.compiled_contract_class.json"))
abi = len(json.dumps(sierra["abi"], separators=(",", ":")))
c, s = len(casm["bytecode"]), len(sierra["sierra_program"])
gas = 1280 * (32 * (c + s) + abi)
print(f"{job} casm={c} sierra={s} declare_l2_gas={gas} of_block_cap={gas / 5.8e9:.1%}")
PY
done
