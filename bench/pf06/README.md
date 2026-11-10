# PF-06: the small verifier through migration and guarded replacement

Evidence that `HybridShakeVerifierPfSmall` (Provably Fast `fj_dee1326c`, class
`0x333aa6a603a1edcf37867d774d65220528e684ed496f5d8a73ce24fcafb0fb1`, selected in
[`bench/pf04`](../pf04/README.md)) works through every migration callback path and through the
guarded verifier switch, in both directions (issue #7). Migration code, the guard and the
verifier classes did not change; only the verifier class hash passed to them did.

Three kinds of evidence, each named where it is used:
- **Cairo tests** (`scarb cairo-test`, `contracts/src/tests_*.cairo`). They set the transaction
  hash and signature by hand and use stand-ins for the Argent and Braavos classes.
- **Devnet** (`signer/verifier_switch_devnet.mjs`): real transactions on a local fork of Sepolia,
  validated by the protocol with their real hash and signature. Behaviour only; devnet's gas
  accounting differs from Sepolia's.
- **Sepolia receipts**: [`bench/pf04/sepolia.json`](../pf04/sepolia.json) (migrations with small,
  2026-10-27) and [`sepolia.json`](sepolia.json) here (the guarded switch, 2026-10-27).

## Acceptance

| Criterion (#7) | Evidence |
| --- | --- |
| All three callback paths migrate with the optimized verifier | Cairo: `argent_upgrade_migrates_to_the_small_verifier` (Argent 0.4+ `perform_upgrade`), `argent_0_3_upgrade_migrates_to_the_small_verifier` (`execute_after_upgrade`), `braavos_upgrade_then_migrate_to_the_small_verifier` (`[upgrade, migrate]`). Sepolia: real Argent 0.5.0, Argent 0.3.1 and Braavos 1.2.0 accounts migrated to small (table below). No path failed. |
| Address and stored keys preserved; nonce and fee as expected | Sepolia, every migration: stored ECDSA and Falcon keys equal the keys derived from the words, and the balance dropped by exactly the fee (`keysPreserved`, `balanceDropEqualsFee`). Migration is in place, so the address is the account's own. |
| Wrong-key proofs revert the entire migration | Cairo, on small, per path: a proof with a valid ECDSA half and a tampered Falcon half (`*_to_small_with_tampered_falcon_proof_reverts`), which is the only wrong proof that reaches the verifier; plus wrong-ECDSA controls. For both Argent paths the test also checks that the class replacement was rolled back with the failed call (a mutation expecting the migratable class fails). |
| Subsequent hybrid transfer succeeds, ECDSA-only rejected, through real validation | Sepolia: after each of the three migrations to small, and again after the guarded switch to small (`transferOnSmall`, `ecdsaOnlyOnSmall`). |
| Guarded switch to and from the optimized verifier on a migrated account | Cairo: `baseline_to_small_is_installed_and_then_validates`, `small_back_to_baseline_restores_the_pointer_and_keys`. Devnet: 45/45 on all four deployed migratable classes ([`devnet.txt`](devnet.txt)). Sepolia: baseline → small → baseline (below). |
| PF-04 checks repeated for the final class | `bench/pf04/run.sh --check` passes on this branch, and the built small class hash is still `0x333aa6a6…afb0fb1` (below). |
| Supported and unsupported existing-account routes documented | [`contracts/docs/verifier-replacement.md`](../../contracts/docs/verifier-replacement.md#supported-routes-to-the-small-verifier). |

Declare validation through small: Cairo `each_verifier_validates_a_declare` (all four verifiers)
and `ecdsa_only_declare_is_rejected_on_the_small_verifier`; on Sepolia, PF-04 declared
`VerifierSwitchGuard` from a small-migrated Argent 0.5.0 account
([0x687a8500…](https://sepolia.voyager.online/tx/0x687a8500c3732f619db3a0f8db15ae271a8391282cb52f91b0f3cab69169e23)).

## Migrations with small (Sepolia, PF-04 run)

| Wallet class | Callback path | Migration | L2 gas | Hybrid transfer | L2 gas |
| --- | --- | --- | ---: | --- | ---: |
| Argent 0.5.0 | `upgrade` → `perform_upgrade` | [0x61e91e09…](https://sepolia.voyager.online/tx/0x61e91e09b78489dc91a445ec1842c1d72cff6bf792b715c1f9c6fda3d417aa9) | 50,330,764 | [0x7a991632…](https://sepolia.voyager.online/tx/0x7a991632a4af996e569cb0c6215a898233c94d42f87dfd3bf35096d8be2707a) | 29,566,303 |
| Argent 0.3.1 | `upgrade` → `execute_after_upgrade` | [0x2aea49f4…](https://sepolia.voyager.online/tx/0x2aea49f4bfe17a5c651ac334c8570931e9185bf59a9eed80895ba32f85bc1c5) | 83,499,920 | [0x47feec23…](https://sepolia.voyager.online/tx/0x47feec231ef96040ec28f68e37fe0e1f2f50a2beae94454c08549c1ae1e93e9) | 29,554,543 |
| Braavos 1.2.0 | `[upgrade, migrate]` | [0x5c8b9dce…](https://sepolia.voyager.online/tx/0x5c8b9dced834bc32593a92978d72a2f8d8493c1a579e47317939006916e9cde) | 48,531,148 | [0x142654a4…](https://sepolia.voyager.online/tx/0x142654a41338070e50af76fa6c9d7c900fcb1107522a4a3b16f70c59e18f8ae) | 29,565,553 |

For each, an ECDSA-only transfer was rejected in `__validate__`.

## Guarded switch on Sepolia: baseline → small → baseline

`signer/pf06_sepolia.mjs`, 2026-10-27, Starknet 0.14.4, about 1.9e10 fri per L2 gas. A fresh
Argent 0.5.0 account (`0x7ae9f9ba…a8dff`) migrated with the baseline `HybridShakeAccount`
verifier ([0x5e50532c…](https://sepolia.voyager.online/tx/0x5e50532c13a0e3a5058eeae41a14ff4213882d71f3ec3e5316fbc1fd20c0d33),
74.7M L2 gas; keys preserved, balance drop equal to the fee, ECDSA-only rejected), then switched
through one `VerifierSwitchGuard` instance at `0x5093253fe6ee74bce57ae826a72bc94ddf02b6fbe20db5512e744a9a304945e`
([deploy](https://sepolia.voyager.online/tx/0x20de579c5518fd93fccdf176e79d3e1609a6caf7126afc4ecb99eb41471a7b4)).
After each switch the script read back the verifier pointer and both keys.

| Step | Transaction | L2 gas | Result |
| --- | --- | ---: | --- |
| Guarded switch baseline → small | [0x4a7277f9…](https://sepolia.voyager.online/tx/0x4a7277f9add5725df18f8c12b7c56a9c832f9a7e185a462ee76f7b44adea98c) | 86,847,396 | pointer = small, keys unchanged |
| Hybrid transfer, validated by small | [0x2e07b9bc…](https://sepolia.voyager.online/tx/0x2e07b9bc578ae0b76a156b8876e72ed825a664932f90e50b90aea71100ba3b6) | 29,553,503 | succeeded |
| ECDSA-only transfer | not included | | rejected in `__validate__` |
| Guarded switch to `HybridPoseidonAccount` | not sent | | `switchVerifier` refused after simulation: `Guard: signature rejected` |
| Guarded switch small → baseline | [0x563207a4…](https://sepolia.voyager.online/tx/0x563207a483ba3d5f69111b39c8395ce32b2096e17098932b67f160930e73867) | 80,951,238 | pointer = baseline, keys unchanged |
| Hybrid transfer, validated by the baseline | [0x4abd791d…](https://sepolia.voyager.online/tx/0x4abd791dbee0f6dda5634bc20936db18964edb4b31e45be055aff6a1f27cd3c) | 49,605,821 | succeeded |

A guarded switch pays for two verifications: the old verifier in `__validate__` and the candidate
in the guard. So each direction costs about one baseline plus one small verification (81–87M), and
a one-off switch to small pays for itself after about four transfers (each about 20M cheaper).

Two operational findings, both handled in the kit or the script:
- **Sepolia evicts zero-tip transactions.** `switchVerifier` leaves the tip to starknet.js, which
  estimates the recommended tip for each call, or takes an explicit `tip` that it uses for both the
  simulation and the send (`signer/pq_account_kit.mjs`, checked offline in
  `signer/verifier_switch_check.mjs`). This run passed `getEstimateTip`'s `recommendedTip`
  (1e8 fri, `0x5f5e100` on both switches).
- **A switch needs more balance than its fee.** starknet.js's bound for the switch back was 143.3M
  L2 gas at 1.5x the gas price, about 4.1 STRK, more than the 3.79 STRK the account then held, so
  the RPC refused it before sending. A 5 STRK top-up from the deployer
  ([0x28f91613…](https://sepolia.voyager.online/tx/0x28f916139a098e3fddb66102741c11bed434a506ef00706c2a92589bccfa300))
  fixed it; the actual fee was 1.58 STRK. Nothing reverted on chain.

All Sepolia fees for this run, migration included: 7.82 STRK (testnet).

## Safety checks that do not depend on the verifier

`migrationCalls`' dropped-protection gate (`acceptDroppedProtections`) and `inspectAccount`'s
storage pre-check run before the verifier is involved: `verifierClass` is only written into the
calldata (`migrationArgs`, `signer/pq_account_kit.mjs`). The small class reads and writes the same
`HybridAccountComponent` storage as the baseline, which `tests_pf.cairo` checks on all four
verifier classes. So those checks are cited from PF-05 and `contracts/docs/wallet-coverage.md`, not
re-run: `signer/kit_safety_check.mjs` reads a mainnet survey file that is not on the machine that
produced this run.

## PF-04 checks repeated

On this branch, after all changes (only tests, scripts and docs changed):

```sh
bench/pf04/run.sh --check      # passes: no budget or network-limit failure
```

The built `HybridShakeVerifierPfSmall` class hash is
`0x333aa6a603a1edcf37867d774d65220528e684ed496f5d8a73ce24fcafb0fb1`, the class declared on
Sepolia; the built `VerifierSwitchGuard` and `HybridShakeAccount` match their deployed hashes too.

## Reproduce

```sh
cd contracts && scarb cairo-test                  # Cairo tests
cd ../signer && node verifier_switch_check.mjs    # kit gates and tip, offline
# Devnet: see the header of signer/verifier_switch_devnet.mjs (PQ_SWITCH_CANDIDATE picks the class)
# Sepolia: see the header of signer/pf06_sepolia.mjs (spends testnet STRK)
```
