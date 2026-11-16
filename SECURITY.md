# Security

Experimental, not yet audited, Sepolia only. Do not hold real funds in accounts that run these
classes. The known risks are in the README: [Threat model](README.md#threat-model) and
[Security notes](README.md#security-notes).

## Reporting a vulnerability

Please report privately, not in a public issue:

- GitHub: the repository's **Security** tab, "Report a vulnerability" (private advisory), or
- Telegram [@oxjuno](https://t.me/oxjuno).

You will get an answer within three days. Fixes are credited in the commit and the README unless
you ask otherwise. There is no bounty: nothing here is deployed on mainnet.

## Review history

| Date | Who | Scope | Result |
| --- | --- | --- | --- |
| 2026-10-27 | Carlos Castillo ([Zealynx](https://zealynx.io)), [forum](https://community.starknet.io/t/116448/2) | `HybridMigratableAccount` at `1345ece` | Two findings: key rotation without a possession proof, verifier switch without a validity check. Both fixed in `5a1269f`, retested on Sepolia. |
| 2026-11-16 | maintainer, while merging the `testnet-v1` work | `set_verifier_class_hash` with the guard tests | A candidate verifier runs in the account's storage, so it could rewrite a key or the pointer while passing the signature check. The switch now re-reads both keys and the pointer (`4832ddd`). |

## Scope proposed for an independent review

**In scope**

| Component | File | Size |
| --- | --- | --- |
| Migratable account: the three migration paths, the key-possession proof, key rotation, the verifier switch and its state check, `__validate__`, `__execute__`, `is_valid_signature`, `upgrade` | `contracts/src/migratable.cairo` | 456 lines |
| Guarded verifier switch for accounts on earlier classes | `contracts/src/guard.cairo` | 75 lines |
| Hybrid check: how the ECDSA and Falcon-512 results combine, and the verifier entry points (not the Falcon arithmetic) | `contracts/src/hybrid.cairo` | 454 lines |
| Wallet kit: account classification, the refusal rules, the calls it builds, the verifier allow list | `signer/pq_account_kit.mjs` | |
| Key derivation profiles | `signer/pq_keys.mjs` | |

**Out of scope here**, each needing its own review: the Falcon-512 verifier arithmetic
(OpenZeppelin cairo-pq-verifiers, pinned at `bece5c07`) and the Provably Fast patches; the browser
demo page; `recovery/` (research code).

**Questions the review should answer**

1. Can any migration path leave an account with keys its owner cannot sign with, or without a
   working signature check between `upgrade` and `migrate`?
2. After the class is replaced, can storage left by an Argent, Braavos or OpenZeppelin account
   collide with what this class reads or writes?
3. Can anyone other than the account itself trigger a rotation, a verifier switch or an upgrade?
4. The proofs commit to the keys and a domain string, not to the account address or chain. Can
   replaying a proof elsewhere ever hurt the owner?
5. Can a verifier class, running by library call in the account's storage, change state in a way
   the account does not detect?
6. Can `inspectAccount` report an account as migratable when the migration would fail or drop a
   protection without listing it?
