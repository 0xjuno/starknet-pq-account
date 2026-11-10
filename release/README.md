# Release `testnet-v1`

> **Experimental. Unaudited. Testnet only (Starknet Sepolia).** An independent review is still
> outstanding ([#9](https://github.com/Ryun1/starknet-pq-account/issues/9)). Do not hold real funds.

The first versioned release of the hybrid ECDSA + Falcon-512 account integration with the small
Provably Fast verifier (issue #8). It is what a wallet developer needs to reproduce the Sepolia
integration from a clean checkout.

## Contents

[`testnet-v1.json`](testnet-v1.json) pins, for every class this release builds:

| Class | Role | Class hash | On Sepolia |
| --- | --- | --- | --- |
| `HybridShakeVerifierPfSmall` | verifier, **default** (`shake-pf-small-v1`) | `0x333aa6a603a1edcf37867d774d65220528e684ed496f5d8a73ce24fcafb0fb1` | declared ([0x18feecd7…](https://sepolia.voyager.online/tx/0x18feecd71b354a738babe560822d471232d6ec6ff5b5097877bc458b3c0cd62)) |
| `HybridShakeAccount` | verifier (`shake-baseline`) | `0x2255fc213bf39d1df2129c9e068b363f2b11a27b70b4b2c48df8ea4275f1c92` | declared |
| `HybridPoseidonAccount` | verifier (`poseidon`, other scheme) | `0x7f10b6f2f70e72ef87e97844b5f6f13d384c92afcfed2a1233a03524d359d6f` | declared |
| `HybridMigratableAccount` | account | `0x4b067679dbb29516dd79fba49ba1f1b2bc3973b33c74881ff56098d19e27a78` | declared |
| `VerifierSwitchGuard` | guard | `0x44779ad7a4ea11318759272383a06d06fdf1b7c007ba1e5f38a2096e6e26178` | declared ([0x687a8500…](https://sepolia.voyager.online/tx/0x687a8500c3732f619db3a0f8db15ae271a8391282cb52f91b0f3cab69169e23)); instance `0x5093253f…945e` |
| `HybridShakeVerifierPfCompact`, `HybridShakeVerifierPfRecord` | verifiers | see the manifest | cannot be declared (over the block's L2 gas cap) |

It also lists, under `legacy_account_classes`, three earlier `HybridMigratableAccount` builds
that existing accounts still run, with the accounts known to use each:

| Account class | Run by |
| --- | --- |
| `0x7b6d5ed4cbb6c7a2633dd9139c25ffb76bb608cafbba9e424a277a885432b25` | the public demo account `0x343e3df5…c0db` (the switch and browser evidence below ran on it) |
| `0x660679aa09bef2ef29e1a2ebe21ee85d87bacde8746430b380425db5dd3c31b` | the README's Argent and Braavos demo accounts |
| `0xae4154b7e35c9475f4875757bcfa2b19ca88fc2e9bd9fa793e82a91ef5815f` | the README's in-place OpenZeppelin migration, the browser-setup account |

Their sources are earlier commits of this repository, and this commit doesn't rebuild them, so
they have no artifact hashes. `--chain` checks that each is declared and that each listed account
still runs it. All three have `set_verifier_class_hash` and `is_valid_signature`, so the guarded
switch works on them ([`verifier-replacement.md`](../contracts/docs/verifier-replacement.md#deployed-accounts)).
New migrations use the pinned `HybridMigratableAccount`.

For each built class it also records the Blake2s compiled class hash (what a declare signs since Starknet
0.14.1) and the SHA-256 of the Sierra and CASM artifacts. It pins the sources (OpenZeppelin
cairo-pq-verifiers `bece5c07…ae40`, the three Provably Fast patch digests) and the toolchain
(Scarb and Cairo 2.18.0, Sierra 1.8.0, snforge 0.59.0, universal-sierra-compiler 2.10.3,
starknet.js 10.8.0, @noble/post-quantum 0.6.1).

The tooling reads its class hashes only from this file (`signer/verifiers.mjs`), and no longer
from `.keys/*-state.json` files. Set `PQ_VERIFIER=<id>` to choose a verifier.

## Verify it

```sh
(cd signer && npm install --no-package-lock --no-audit --no-fund)
(cd contracts && scarb build)
node scripts/release_manifest.mjs --check   # offline; also run by CI
node scripts/release_manifest.mjs --chain   # read-only: declared on Sepolia, guard instance, declare txs
node scripts/build_page.mjs --check         # docs/index.html is built from its template
node signer/verifiers_check.mjs             # verifier choice, page label, clean-checkout scripts
node signer/backup_fixtures_check.mjs       # read-only: demo words = on-chain keys
```

A fresh build reproduces every pinned hash; this was checked in a fresh clone on 2026-10-27.

## Evidence

- [`testnet-v1-evidence.json`](testnet-v1-evidence.json) (2026-10-27): the public demo account's
  guarded switch to small (86.8M L2 gas, keys unchanged). Three headless-browser passkey runs of
  the demo page, each ending in a transfer: the previous page before the switch (53.9M L2 gas), the
  same page after it (29.5M), and this release's page (28.0M, showing the small verifier). One
  Braavos 1.2.0 migration from a clean checkout with default settings: 48.5M, keys equal the
  words, balance drop equals the fee, hybrid transfer succeeded, ECDSA-only rejected.
- [`bench/pf04`](../bench/pf04/README.md): verifier selection and budgets; migrations of Argent
  0.5.0, Argent 0.3.1 and Braavos 1.2.0 to small.
- [`bench/pf06`](../bench/pf06/README.md): every migration path and the guarded switch in both
  directions.

## Costs

See the README's [cost tables](../README.md#cost-on-mainnet): per-transfer and one-time costs,
from Sepolia receipts priced at a recorded mainnet block.

## Limits

See the README's [Limits](../README.md#limits). In short: testnet only, unaudited, independent
review outstanding (#9). The guarded switch needs a working active verifier, and it doesn't support
Poseidon-verifier accounts or directly deployed `HybridShakeAccount` accounts. Compact and record
can't be declared, and small fits in a block with a 6.2% margin.

## Tagging

After the PR is merged, the maintainer tags the merge commit:

```sh
git tag -a testnet-v1 <merge commit> -m "testnet-v1: small Provably Fast verifier on Sepolia"
git push origin testnet-v1
```
