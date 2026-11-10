#!/usr/bin/env bash
# Generate the candidate crates in crates/ from the vendored baseline and the pinned patches.
#
#   vendor/provably-fast/falcon-512/make_crates.sh          # (re)write crates/
#   vendor/provably-fast/falcon-512/make_crates.sh --check  # fail if crates/ differs
#
# Each candidate is `vendor/cairo-pq-verifiers/crates/{falcon_512,ntt}` with its patch applied
# and nothing else changed except the package names: Scarb cannot load two packages with the
# same name, so `pqbench_falcon_512` and `pqbench_ntt` become `..._pf_<candidate>` in the
# manifests and in the `use` paths that name them. `pqbench_interface` is shared, so the
# candidates implement the same `PqSignatureVerifier` trait as the baseline.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BASE=$HERE/../../cairo-pq-verifiers/crates
CANDIDATES="compact:fj_3a0b1c78817845a68e1e907928a541e4 record:fj_c3459a8b07a54bd5828d3fdde899c4e0
  small:fj_dee1326c0eef48e6989ed0338e9e9785"

(cd "$HERE" && shasum -a 256 -c --quiet SHA256SUMS)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/out"

for entry in $CANDIDATES; do
  name=${entry%%:*}
  job=${entry#*:}
  src=$tmp/$name
  mkdir -p "$src/crates"
  cp -R "$BASE/falcon_512" "$BASE/ntt" "$src/crates/"
  (cd "$src" && git apply "$HERE/$name-$job.patch")

  falcon=falcon_512_pf_$name
  ntt=ntt_pf_$name
  mv "$src/crates/falcon_512" "$tmp/out/$falcon"
  mv "$src/crates/ntt" "$tmp/out/$ntt"
  find "$tmp/out/$falcon" "$tmp/out/$ntt" -type f \( -name '*.cairo' -o -name '*.toml' -o -name '*.md' \) \
    -exec perl -pi -e "s/\\bpqbench_falcon_512\\b/pqbench_${falcon}/g; s/\\bpqbench_ntt\\b/pqbench_${ntt}/g; s{path = \"\\.\\./ntt\"}{path = \"../${ntt}\"}g" {} +
done

if [ "${1:-}" = "--check" ]; then
  diff -r "$tmp/out" "$HERE/crates"
  echo "crates/ matches baseline + patches + renames"
else
  mkdir -p "$HERE/crates"
  for dir in "$tmp"/out/*; do
    rm -rf "${HERE:?}/crates/$(basename "$dir")"
    cp -R "$dir" "$HERE/crates/"
  done
  echo "wrote $(ls "$HERE/crates" | tr '\n' ' ')"
fi
