# Third-party code

- `vendor/cairo-pq-verifiers/`: a subset of [OpenZeppelin/cairo-pq-verifiers](https://github.com/OpenZeppelin/cairo-pq-verifiers)
  (crates `bench_interface`, `ecdsa_stark`, `falcon_512`, `ntt`, and `pq-accounts/signers/falcon-python/falcon_signer.py`),
  MIT License, Copyright (c) 2026 OpenZeppelin. Downloaded from the `main` branch on 2026-10-15; identical to
  commit `bece5c07eeea5784e570c01108ec000d2d04ae40` (checked by `bench/pf01/reproduce.sh`). The workspace
  manifest was trimmed to these crates; the code is unchanged. See `vendor/cairo-pq-verifiers/LICENSE`.
- `vendor/provably-fast/falcon-512/`: three patches to that commit from the Provably Fast Falcon-512 gas
  challenge (https://postquantum.provably.fast/), MIT, by the contributors listed in its `PROVENANCE.md`, and
  the crates generated from them (`crates/`, baseline + patch + package renames only). Unaudited and not
  endorsed by OpenZeppelin. SHA-256 digests are in `SHA256SUMS` and `release/testnet-v1.json`:
  - `small-fj_dee1326c0eef48e6989ed0338e9e9785.patch` (`6d4a1195…cadd5`): `HybridShakeVerifierPfSmall`, the
    verifier deployed on Sepolia and the default of release `testnet-v1`.
  - `compact-fj_3a0b1c78817845a68e1e907928a541e4.patch` (`88729bbd…c6324e`): `HybridShakeVerifierPfCompact`,
    built and tested only; it cannot be declared on Sepolia.
  - `record-fj_c3459a8b07a54bd5828d3fdde899c4e0.patch` (`23f3c793…d7b2f9`): `HybridShakeVerifierPfRecord`,
    built and tested only, as compact.
- `contracts/src/utils/execution.cairo` and `contracts/src/utils/interface.cairo` are adapted from the same
  repository (MIT).
- Falcon key generation and signing use [falcon.py](https://github.com/tprest/falcon.py) by Thomas Prest
  (MIT License), commit `5145a818c9512b4a443507d3375e75dae3076af6`. It is not vendored; point `FALCON_PY_DIR`
  at a checkout of that commit. `signer/falcon_ntt_roots.json` holds falcon.py's NTT root constants
  (exported by `scripts/export_ntt_roots.py`).
- Browser and Node Falcon-512 signing use [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum)
  0.6.1 (MIT License), loaded as a dependency or from jsDelivr; it is not vendored.
