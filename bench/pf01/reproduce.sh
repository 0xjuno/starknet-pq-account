#!/usr/bin/env bash
# PF-01: reproduce the Falcon-512 SHAKE-256 baseline and both Provably Fast candidates locally.
#
#   bench/pf01/reproduce.sh WORK_DIR
#
# Needs scarb 2.18.0, snforge 0.59.0 and universal-sierra-compiler 2.9.1 on PATH, plus git and
# python3. WORK_DIR receives the upstream clone, one git worktree per variant and the raw logs;
# bench/pf01/results.json is rewritten from them. Nothing outside WORK_DIR and results.json is
# changed, and nothing is sent anywhere.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
HERE=$REPO/bench/pf01
PATCHES=$REPO/vendor/provably-fast/falcon-512
BASELINE_COMMIT=bece5c07eeea5784e570c01108ec000d2d04ae40
WORK=${1:?usage: reproduce.sh WORK_DIR}
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)

need() {
  local got
  got=$("$1" --version 2>/dev/null | head -1 | awk '{print $2}')
  [ "$got" = "$2" ] || { echo "$1 $2 required, found ${got:-none}" >&2; exit 1; }
}
need scarb 2.18.0
need snforge 0.59.0
need universal-sierra-compiler 2.9.1

# Build with mainnet's audited libfuncs, as the challenge does, and fail on any other libfunc
# (Scarb only warns by default).
audited() {
  sed -i.orig 's/^allowed-libfuncs-list.name = "experimental"/allowed-libfuncs-deny = true\
allowed-libfuncs-list.name = "audited"/' "$1"
  grep -q '^allowed-libfuncs-deny = true' "$1"
}

echo "== patch digests"
(cd "$PATCHES" && shasum -a 256 -c SHA256SUMS)

echo "== upstream baseline $BASELINE_COMMIT"
UP=$WORK/upstream
if [ ! -d "$UP/.git" ]; then
  git init -q "$UP"
  git -C "$UP" remote add origin https://github.com/OpenZeppelin/cairo-pq-verifiers.git
  git -C "$UP" fetch -q --depth 1 origin "$BASELINE_COMMIT"
  git -C "$UP" checkout -q FETCH_HEAD
fi
[ "$(git -C "$UP" rev-parse HEAD)" = "$BASELINE_COMMIT" ]

echo "== vendored crates match the baseline"
for crate in bench_interface ecdsa_stark falcon_512 ntt; do
  diff -r "$UP/crates/$crate" "$REPO/vendor/cairo-pq-verifiers/crates/$crate"
done
diff "$UP/LICENSE" "$REPO/vendor/cairo-pq-verifiers/LICENSE"
diff "$UP/pq-accounts/signers/falcon-python/falcon_signer.py" \
  "$REPO/vendor/cairo-pq-verifiers/pq-accounts/signers/falcon-python/falcon_signer.py"
echo "identical"

for variant in baseline compact record; do
  echo "== $variant"
  ws=$WORK/ws-$variant
  if [ ! -d "$ws" ]; then
    git -C "$UP" worktree add -q --detach "$ws" "$BASELINE_COMMIT"
    patch=$(ls "$PATCHES"/"$variant"-*.patch 2>/dev/null || true)
    [ -z "$patch" ] || git -C "$ws" apply "$patch"
    audited "$ws/pq-accounts/contracts/Scarb.toml"
  fi
  python3 -I "$HERE/gen_bench_tests.py" "$HERE/corpus.json" "$ws/crates/falcon_512/tests/pf01_corpus.cairo"
  (cd "$ws" && snforge test -p pqbench_falcon_512 > "$WORK/$variant.falcon.log" 2>&1) || true
  (cd "$ws" && snforge test -p pqbench_ntt > "$WORK/$variant.ntt.log" 2>&1) || true
  (cd "$ws" && scarb build -p pq_accounts > "$WORK/$variant.build.log" 2>&1)

  # This project's hybrid classes, unchanged, built against the variant's crates.
  hyb=$WORK/hybrid-$variant
  if [ ! -d "$hyb" ]; then
    mkdir -p "$hyb/vendor"
    rsync -a --exclude target "$REPO/contracts/" "$hyb/contracts/"
    ln -s "$ws" "$hyb/vendor/cairo-pq-verifiers"
    audited "$hyb/contracts/Scarb.toml"
  fi
  (cd "$hyb/contracts" && scarb build > "$WORK/$variant.hybrid.log" 2>&1)
done

{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname=$(uname -srm)"
  echo "scarb=$(scarb --version | tr '\n' ' ')"
  echo "snforge=$(snforge --version)"
  echo "usc=$(universal-sierra-compiler --version)"
} > "$WORK/env.txt"

python3 -I "$HERE/summarize.py" "$WORK" "$HERE/corpus.json" "$HERE/results.json"
