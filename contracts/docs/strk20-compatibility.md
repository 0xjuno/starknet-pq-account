# STRK20 privacy pool compatibility (analysis, 2026-10-16)

Question: can a hybrid ECDSA + Falcon-512 account (including an account migrated in place)
hold and spend STRK20 shielded balances?

## How the pool authenticates the user

`packages/privacy/src/utils.cairo` in
[starkware-libs/starknet-privacy](https://github.com/starkware-libs/starknet-privacy)
(`assert_valid_signature`) accepts the user account if ANY of three checks passes:

1. Custom validation: only if the account advertises SRC5
   `selector!("is_custom_signature_valid")`.
2. Standard wallet: `is_valid_signature(tx_hash, tx_info.signature)` returns `VALID`.
3. Legacy wallet: `is_valid_signature(CallSet SNIP-12 hash, tx_info.signature)` returns `VALID`.

The pool does not limit the signature length. (The 2-felt checks in the repository are inside
test mock accounts, not in the pool.)

## What our accounts do

- `supports_interface` returns true only for SRC5 and SRC6, so check 1 is skipped.
- `is_valid_signature(tx_hash, [ecdsa_r, ecdsa_s, falcon x 60])` returns `VALID` exactly when
  both signatures verify, so check 2 accepts a hybrid-signed transaction and rejects an
  ECDSA-only one. This path is covered by the unit tests (`deployed_account_accepts_hybrid_signature`,
  `migrated_account_accepts_hybrid_signature`, `*_rejects_ecdsa_only`).

## Not verified yet

- End to end on Sepolia. STRK20 operations are proven in a virtual Starknet execution
  ("unsupported syscalls fail here, at proving time"). Two points need a live run:
  - `HybridMigratableAccount` verifies through `library_call_syscall`; support for it inside the
    virtual OS is not documented.
  - Falcon verification adds about 12M L2 gas to the proven execution.
- Requirements for a live run: a Sepolia proving service and discovery (indexer) service
  (no public endpoints are documented; self-hosting needs roughly a 12-core / 46 GiB machine),
  and a screening attestation route for deposits (the docs point builders to Starkscan
  onboarding). Registration, private transfers and withdrawals need no screening.

Sepolia pool (v2.0): `0x0254a6b2997ef52e9f830ce1f543f6b29768295e8d17e2267d672c552cfe0d91`
