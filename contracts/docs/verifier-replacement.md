# Replacing a migrated account's verifier

A migrated `HybridMigratableAccount` checks signatures by library-calling a verifier class
(`Migratable_verifier_class_hash`). `set_verifier_class_hash` changes it, but only checks that
the caller is the account, that it has migrated and that the hash is non-zero. Installing a
verifier that cannot validate the account's signatures would lock it: every later transaction
would fail `__validate__`, including one that tries to switch back.

## The guarded switch

One hybrid-signed transaction from the account:

```
[ account.set_verifier_class_hash(candidate),
  guard.assert_compatible(account, candidate) ]
```

`VerifierSwitchGuard.assert_compatible` (`contracts/src/guard.cairo`) checks that the caller is
the account and that it now points at `candidate`. It then calls
`account.is_valid_signature(tx.transaction_hash, tx.signature)` with this same transaction's
hash and signature. By then that library-calls the candidate in the account's own storage, and
the guard requires `VALIDATED`. Finally it checks the verifier pointer and the keys the account
reports are unchanged. If any check fails it panics, and the whole transaction reverts, leaving
the old verifier in place.

- No new account entry point or class upgrade: it uses `set_verifier_class_hash` and
  `is_valid_signature`, which every deployed migratable class has (see below).
- No separate proof. The transaction hash already commits to the chain, the account, the nonce
  and the candidate in the calldata, so the signature cannot be replayed onto another switch.
- The wallet kit sends it: `switchVerifier(account, candidate, { guard, allowed })` in
  `signer/pq_account_kit.mjs`, where `account` signs with `HybridSigner`. It first builds the
  calls with `verifierSwitchCalls`, which checks, read-only, that:
  - the account is a migrated hybrid account;
  - the candidate is in the wallet's `allowed` list, declared, exposes
    `is_valid_signature(hash, signature)` and isn't already installed;
  - the guard is deployed.

  It then simulates the transaction with validation and the hybrid signature, throws if it would
  revert, and only then sends it with the simulated resource bounds. `dryRun: true` stops after
  the simulation.
- **Don't estimate or simulate it with starknet.js defaults.** They use `skipValidate: true`,
  which sends an empty signature, so the guard rejects even a compatible verifier: the estimate
  fails and `account.execute(calls)` without resource bounds never sends. `switchVerifier`
  simulates with `skipValidate: false`.

## Limits

- **Same scheme only.** The old verifier checks the signature in `__validate__` and the candidate
  checks the same signature in the guard. That works between two SHAKE-256 verifiers (for example
  `HybridShakeAccount` and `HybridShakeVerifierPfCompact`), not between Poseidon and SHAKE-256,
  which need a signature of the candidate's scheme in the calldata. That case isn't supported.
- **One signature.** The check catches gross incompatibility: the wrong hash-to-point, storage,
  ABI or return value. It doesn't catch a verifier that only rejects rare inputs. That's what the
  differential suite (PF-03, `bench/pf03`) is for.
- **Tooling, not an invariant.** `set_verifier_class_hash` and `upgrade` can still be called
  directly in a hybrid-signed transaction and skip the guard.
- **The candidate is trusted code.** It runs in the account's storage and can read or write
  anything there. The guard sees only the verifier pointer and the keys the account reports
  (`get_ecdsa_public_key`, `get_falcon_public_key`), not the mirrored `ecdsa_public_key` slot or
  other storage. It protects against accidental incompatibility, not a hostile class. Allow only
  reviewed, pinned class hashes.
- **Switching back needs a working verifier.** Returning to the baseline uses the same guarded
  switch, so it works only while the active verifier still accepts the account's signatures.
  Nothing recovers an account whose verifier rejects every transaction.
- A failed switch is a reverted transaction: the fee is charged and the nonce advances.

## Tests

`contracts/src/tests_guard.cairo` runs each case as a transaction: `__validate__` with the
signature, then `__execute__` with the calls. Each failing case asserts its revert reason and
that the verifier pointer and keys are unchanged afterwards.

| Case | Result |
| --- | --- |
| baseline SHAKE → `HybridShakeVerifierPfCompact`, then a transaction validated by it | installed, validates |
| compact → baseline | installed |
| baseline SHAKE → `HybridShakeVerifierPfSmall`, then a hybrid and an ECDSA-only transaction | installed; hybrid validates, ECDSA-only rejected |
| small → baseline, then a transaction | pointer and keys restored, validates |
| `HybridPoseidonAccount` (same key, other hash-to-point) | reverts: `Guard: signature rejected` |
| zero class hash | reverts: `Migratable: invalid verifier` |
| undeclared class hash | reverts: `CLASS_HASH_NOT_DECLARED` |
| class without `is_valid_signature` | reverts: `ENTRYPOINT_NOT_FOUND` |
| class answering something other than `VALIDATED` | reverts: `Guard: signature rejected` |
| class that accepts and rewrites the classical key | reverts: `Guard: account state changed`; key restored |
| guard before the switch, or naming another class | reverts: `Guard: verifier not installed` |
| ECDSA-only, Falcon-only, wrong ECDSA key | rejected in `__validate__` |
| outsider calls `__execute__` or the setter | `Account: invalid caller` / `Migratable: only self` |
| guard called by anyone but the account | `Guard: caller is not account` |

When the guard's signature check is removed, the Poseidon and wrong-answer cases fail. When its
state check is removed, the key-rewriting case fails.

`signer/verifier_switch_check.mjs` checks the kit's read-only gates offline against the compiled
ABIs.

### Real transactions on every deployed class version

The Cairo tests set the transaction hash and signature by hand, so they can't show that the hash
binds the signature to the calls. `signer/verifier_switch_devnet.mjs` sends real transactions to
a local devnet that forks Sepolia (nothing reaches Sepolia; the command is in the file header).
For each of the four migratable classes below, it deploys a fresh account with a public test key
and the deployed `HybridShakeAccount` verifier, uses the candidate (`PQ_SWITCH_CANDIDATE`, default
`HybridShakeVerifierPfSmall`, declared on Sepolia; other classes are declared on the fork) and a
fresh guard, and runs these checks. The protocol validates every transaction with its
real hash and signature.

| Check | Result on all four classes |
| --- | --- |
| hybrid transfer, baseline verifier | succeeds |
| starknet.js default (unsigned) fee estimate of a compatible switch | fails: `Guard: signature rejected` |
| `switchVerifier` to the candidate | simulated, sent, succeeds |
| hybrid transfer validated by the candidate | succeeds |
| `switchVerifier` to `HybridPoseidonAccount` | refused after simulation, nothing sent |
| the same switch sent anyway | reverted on chain; pointer and keys unchanged |
| control: a signed switch back, simulated with its own calls | validates |
| the same signature carrying a different switch | rejected in `__validate__`: `Account: invalid signature` |
| ECDSA-only switch | rejected in `__validate__`: `Account: invalid signature` |
| outsider calls `set_verifier_class_hash` | `Migratable: only self` |
| `switchVerifier` back to baseline | succeeds; keys unchanged |
| guard called by a contract other than the named account | `Guard: caller is not account` |

On 2026-10-27, with devnet 0.10.1 forked at Sepolia block 17230151: 45 of 45 checks pass with
compact. Again on 2026-10-27 at block 17238820 (PF-06): 45 of 45 with small
(`bench/pf06/devnet.txt`) and 45 of 45 with compact. With the
guard's signature check removed, the Poseidon verifier is installed and the account is locked:
every later check fails with `Account: invalid signature`, including the switch back.

The script checks behaviour only. Devnet's L2 gas accounting differs from Sepolia's, so gas
figures come from PF-04.

## Deployed accounts

`signer/verifier_switch_inventory.mjs` reads Sepolia (read-only) for every account linked from
`README.md` and `contracts/docs/wallet-coverage.md`. On 2026-10-27 it found 17 migrated accounts
on 4 migratable class versions. All are registered, all have `set_verifier_class_hash` and
`is_valid_signature`, and every verifier they point at has `is_valid_signature`. So the guarded
switch needs no account upgrade on any of them, and the devnet run above shows the switch
working on each of the four classes.

| Migratable class | Accounts | Notes |
| --- | ---: | --- |
| `0x4b067679dbb29516dd79fba49ba1f1b2bc3973b33c74881ff56098d19e27a78` | 11 | current class (2026-10-19); this commit rebuilds to the same hash |
| `0x660679aa09bef2ef29e1a2ebe21ee85d87bacde8746430b380425db5dd3c31b` | 2 | earlier class (Argent and Braavos demo accounts) |
| `0x7b6d5ed4cbb6c7a2633dd9139c25ffb76bb608cafbba9e424a277a885432b25` | 1 | public demo account |
| `0xae4154b7e35c9475f4875757bcfa2b19ca88fc2e9bd9fa793e82a91ef5815f` | 3 | includes the README's in-place OpenZeppelin migration (`0x54370be5…`) |

| Verifier | Accounts | Class |
| --- | ---: | --- |
| `0x2255fc213bf39d1df2129c9e068b363f2b11a27b70b4b2c48df8ea4275f1c92` | 15 | `HybridShakeAccount` (this commit rebuilds to the same hash): can switch to an optimized SHAKE-256 verifier |
| `0x7f10b6f2f70e72ef87e97844b5f6f13d384c92afcfed2a1233a03524d359d6f` | 2 | `HybridPoseidonAccount`: needs a scheme change, not supported by the guarded switch |

Class hashes built with Scarb 2.18.0:

| Class | Class hash | CASM felts | On Sepolia |
| --- | --- | ---: | --- |
| `HybridShakeVerifierPfSmall` | `0x333aa6a603a1edcf37867d774d65220528e684ed496f5d8a73ce24fcafb0fb1` | 64,163 | declared (PF-04) |
| `VerifierSwitchGuard` | `0x44779ad7a4ea11318759272383a06d06fdf1b7c007ba1e5f38a2096e6e26178` | 1,164 | declared (PF-04); one instance at `0x5093253fe6ee74bce57ae826a72bc94ddf02b6fbe20db5512e744a9a304945e` (PF-06) |
| `HybridShakeVerifierPfCompact` | `0x5e121c050ad841f727873ee3412aedcfb2d7c1c9f8c79a53a73251e79d9d4c7` | 71,580 | cannot be declared: over the block's L2 gas limit (`bench/pf04`) |
| `HybridShakeVerifierPfRecord` | `0x281a32f3b7c2eee62405318cd8b074a44ff17f6c804a003f80276b0dc3c905a` | 77,902 | cannot be declared, as compact |

On Sepolia (PF-06, `bench/pf06`): an Argent 0.5.0 account migrated with the baseline verifier was
switched to small through that guard, made a hybrid transfer, rejected an ECDSA-only one, refused
the Poseidon verifier in simulation, switched back and made another transfer. Each switch costs
81–87M L2 gas, since it runs both verifiers once.

## Supported routes to the small verifier

| Account | Route | Evidence |
| --- | --- | --- |
| Migrated, any of the four migratable classes above, on the SHAKE verifier `0x2255fc21…` (15 accounts) | guarded switch (`switchVerifier`) | devnet on all four classes; Sepolia on `0x4b067679…` |
| Migrated, on the Poseidon verifier `0x7f10b6f2…` (2 accounts) | not supported | a scheme change; the guard rejects it |
| Not migrated yet, any wallet class in `wallet-coverage.md` | migrate with `verifierClass` = small | Sepolia: Argent 0.5.0, Argent 0.3.1, Braavos 1.2.0 (`bench/pf04`); Cairo: all three callback paths |
| Directly deployed `HybridShakeAccount` | none | no verifier setter and no upgrade entry point: it stays on the baseline verifier; no in-place replacement is offered |
| Any migrated account, raw `set_verifier_class_hash` or `upgrade` | possible, unguarded | bypasses the guard; not covered and not recommended |
