#!/usr/bin/env bash
# PF-04: account-level gas, steps, class sizes and libfuncs of this project's hybrid classes with
# the baseline and both Provably Fast verifiers.
#
#   bench/pf04/run.sh            # measure, check budgets, rewrite results.json
#   bench/pf04/run.sh --check    # measure and check budgets only (CI)
#
# Needs scarb 2.18.0, snforge 0.59.0, universal-sierra-compiler 2.10.3 (snforge compiles the test
# classes with it, so it changes gas) and python3. Nothing is sent anywhere. Takes one to five
# minutes on an M-series Mac, depending on what is already compiled.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
MODE=${1:-write}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

need() {
  local got
  got=$("$1" --version 2>/dev/null | head -1 | awk '{print $2}')
  [ "$got" = "$2" ] || { echo "$1 $2 required, found ${got:-none}" >&2; exit 1; }
}
need scarb 2.18.0
need snforge 0.59.0
need universal-sierra-compiler 2.10.3

echo "== paired gas tests"
python3 -I "$HERE/gen_tests.py"
(cd "$HERE" && snforge test > "$WORK/gas.log" 2>&1) || { tail -40 "$WORK/gas.log"; exit 1; }

echo "== entrypoint gas report (cross-check)"
for v in baseline compact record small smallkr direct; do
  (cd "$HERE" && snforge test "validate_${v}_" --gas-report > "$WORK/report-$v.log" 2>&1)
done

echo "== Cairo steps, worst vector"
(cd "$HERE" && snforge test _26 --detailed-resources --tracked-resource cairo-steps > "$WORK/steps.log" 2>&1)

# A clean build of contracts/ against the network's own libfunc list (Scarb does not rebuild
# when only the list changes, hence a fresh copy).
echo "== network libfunc list"
mkdir -p "$WORK/libfuncs"
rsync -a --exclude target "$REPO/contracts/" "$WORK/libfuncs/contracts/"
ln -s "$REPO/vendor" "$WORK/libfuncs/vendor"
cp "$HERE/network_libfuncs.json" "$WORK/libfuncs/contracts/"
sed -i.orig 's/^allowed-libfuncs-list.name = "audited"/allowed-libfuncs-list.path = "network_libfuncs.json"/' \
  "$WORK/libfuncs/contracts/Scarb.toml"
grep -q '^allowed-libfuncs-list.path = "network_libfuncs.json"' "$WORK/libfuncs/contracts/Scarb.toml"
grep -q '^allowed-libfuncs-deny = true' "$WORK/libfuncs/contracts/Scarb.toml"
(cd "$WORK/libfuncs/contracts" && scarb build > "$WORK/libfuncs.log" 2>&1) || { cat "$WORK/libfuncs.log"; exit 1; }
echo "all classes build"

{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname=$(uname -srm)"
  echo "scarb=$(scarb --version | tr '\n' ' ')"
  echo "snforge=$(snforge --version)"
  echo "usc=$(universal-sierra-compiler --version)"
} > "$WORK/env.txt"

out=$HERE/results.json
[ "$MODE" = "--check" ] && out=$WORK/results.json
python3 -I "$HERE/summarize.py" "$WORK" "$WORK/libfuncs/contracts/target/dev" "$out"
