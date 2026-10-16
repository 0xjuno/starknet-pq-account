# Third-party code

- `vendor/cairo-pq-verifiers/`: a subset of [OpenZeppelin/cairo-pq-verifiers](https://github.com/OpenZeppelin/cairo-pq-verifiers)
  (crates `bench_interface`, `ecdsa_stark`, `falcon_512`, `ntt`, and `pq-accounts/signers/falcon-python/falcon_signer.py`),
  MIT License, Copyright (c) 2026 OpenZeppelin. Downloaded from the `main` branch on 2026-10-15. The workspace
  manifest was trimmed to these crates; the code is unchanged. See `vendor/cairo-pq-verifiers/LICENSE`.
- `contracts/src/utils/execution.cairo` and `contracts/src/utils/interface.cairo` are adapted from the same
  repository (MIT).
- Falcon key generation and signing use [falcon.py](https://github.com/tprest/falcon.py) by Thomas Prest
  (MIT License), commit `5145a818c9512b4a443507d3375e75dae3076af6`. It is not vendored; point `FALCON_PY_DIR`
  at a checkout of that commit.
