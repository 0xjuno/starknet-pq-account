# Wallet integration guide

For wallet teams (Ready / Argent, Xverse, Braavos, OKX and OpenZeppelin-based wallets) that want
to offer their users an in-place move to post-quantum signatures.

> Experimental. Not yet audited. Sepolia only. Do not offer this on mainnet before an independent
> review of the migration class and the verifier you install.

## What your user gets

- The same address, balance, positions and staking. Nothing is transferred.
- From the migration on, every transaction needs two signatures over the same hash: the STARK-curve
  ECDSA key the account already has, and a new Falcon-512 key. An ECDSA-only transaction is
  rejected in `__validate__`, so a forged ECDSA signature alone cannot move funds.
- Both keys restore from the words the user already has. For Argent X / Ready accounts the ECDSA
  key follows Argent's own derivation, so nothing about the backup changes.

## The flow

| Step | What the wallet does | Kit function |
| --- | --- | --- |
| 1. Check | Read the account's class and settings; decide whether it can move today, and what it would lose | `inspectAccount(provider, address)` |
| 2. Explain | Show `info.drops` (for example an Argent guardian) and `info.needs` (a guardian co-signature) before asking for consent | — |
| 3. Derive | Derive both keys from the user's words; the Falcon key comes from the same seed | `deriveAccountKeys(words, index, profile)`, `prepareKeys(keys, roots)` |
| 4. Migrate | Build the wallet-specific migration and sign it with the **current** ECDSA key | `migrationCalls(info, keys, { migratableClass, verifierClass })` |
| 5. Sign | From now on, sign every transaction with both keys | `new HybridSigner(keys)` |
| 6. Maintain | Rotate keys with proofs; move to another verifier of the same scheme through the guard | `rotationCalls`, `switchVerifier` |

All of it is in [`signer/pq_account_kit.mjs`](../../signer/pq_account_kit.mjs) (starknet.js 10.8,
`@noble/post-quantum` 0.6.1). The class hashes come from
[`release/testnet-v1.json`](../../release/testnet-v1.json) through
[`signer/verifiers.mjs`](../../signer/verifiers.mjs); never take them from user input.

```js
import { Account, RpcProvider } from "starknet";
import { HybridSigner, deriveAccountKeys, inspectAccount, migrationCalls, prepareKeys } from "./pq_account_kit.mjs";
import { MIGRATABLE_CLASS, verifierClass } from "./verifiers.mjs";

const info = await inspectAccount(provider, address);
if (!info.migratable) throw new Error(info.reason);          // e.g. "Braavos multisig"
// show info.drops and info.needs to the user, get consent

const keys = prepareKeys(deriveAccountKeys(words, 0, "argentx"), roots); // "argentx" | "braavos" | "pq"
const calls = migrationCalls(info, keys, {
  migratableClass: MIGRATABLE_CLASS,
  verifierClass: verifierClass("shake-baseline"),           // or "shake-pf-small-v1"
  acceptDroppedProtections: info.drops.length > 0,          // only after the user agreed
});
await new Account({ provider, address, signer: keys.ecdsaPrivateKey }).execute(calls);

const hybrid = new Account({ provider, address, signer: new HybridSigner(keys) });
```

`roots` is [`signer/falcon_ntt_roots.json`](../../signer/falcon_ntt_roots.json): it converts the
Falcon public key into the felts the account stores.

## What each wallet's migration looks like

| Wallet class | Transaction the wallet signs with its current key | Calls |
| --- | --- | --- |
| Argent / Ready 0.4, 0.5; Xverse | `upgrade(migratable, data)`; Argent library-calls `perform_upgrade` | 1 |
| Argent 0.3.0, 0.3.1; OKX | same call; Argent replaces the class, then calls `execute_after_upgrade` | 1 |
| Braavos 1.0 to 1.2; OpenZeppelin | `[upgrade(migratable), migrate(ecdsa_key, falcon_key, verifier, proof)]` | 2 |

In every case the transaction carries a proof: a hybrid signature by both new keys over
`poseidon("starknet-pq-register-v1", ecdsa_key, ...falcon_key)`. If the wallet derived a key the
user cannot sign with, the proof fails and the whole transaction reverts, so the account is never
left in a state nobody can sign for. One real account of each class was migrated this way on
Sepolia: [`wallet-coverage.md`](wallet-coverage.md).

## Keys

| Profile | ECDSA key | Use for |
| --- | --- | --- |
| `argentx` | BIP39 words → Ethereum key `m/44'/60'/0'/0/0` → BIP32 seed → `m/44'/9004'/0'/0/i` → `grindKey` (argent-x `ArgentSigner.ts`) | Argent X / Ready |
| `braavos` | Braavos derivation as implemented by third-party scripts (not from published Braavos code) | Braavos |
| `pq` | BIP39 seed → `m/44'/9004'/0'/0/i` → `grindKey` | OpenZeppelin, and wallets whose derivation is not published |

The Falcon-512 key is the same for every profile: HKDF-SHA512 over the BIP39 seed with salt
`starknet-pq-backup-v0.1` and info `falcon-512/noble/account/{i}`, 48 bytes, as the seed of
`falcon512.keygen`. Details and test evidence: [`key-backup-v0.md`](key-backup-v0.md).
`node signer/wallet_profiles_check.mjs` checks the Argent derivation against argent-x's own test
vectors.

## Signatures

A hybrid signature is 62 felts: `[r, s]` (STARK-curve ECDSA), then the Falcon-512 part in the
layout of the standard SHAKE-256 verifier: the packed `s2` (29 felts), the salt (2) and the
`s2 × h` hint (29). `HybridSigner` builds it; [`signer/falcon_adapter.mjs`](../../signer/falcon_adapter.mjs)
converts a `@noble/post-quantum` signature into that layout, and the demo page does the same in the
browser.

## Things the wallet has to handle

- **Fees.** A hybrid transfer uses about 29.6M L2 gas with the small verifier and 53.9M with the
  OpenZeppelin verifier, against 1.45M for an ECDSA account. A migration uses 70M to 153M
  depending on the wallet class. Set resource bounds from these, or estimate with validation on
  (`skipValidate: false`): starknet.js estimates with `skipValidate: true` by default, which signs
  nothing and under-counts the Falcon check.
- **Tip on Sepolia.** Sepolia evicts zero-tip transactions; use `getEstimateTip`.
- **Guardians.** An Argent account with a guardian needs the guardian's co-signature on the upgrade
  (`info.needs`), and the guardian is gone afterwards (`info.drops`).
- **Not supported yet.** Braavos accounts with a hardware or passkey signer, multisig accounts,
  Cairo 0 accounts and accounts without a self-upgrade entry point (`inspectAccount` says why).
- **After migration.** Paymasters and session keys (SRC-9 outside execution) are not available
  yet; neither are Argent escapes nor Braavos withdrawal limits.
- **Verifier choice.** `migrationCalls` and `switchVerifier` refuse classes outside the pinned
  list. The verifier runs in the account's storage and decides which signatures pass: install only
  classes you have reviewed.
- **Mainnet senders this covers.** In two samples of 400 recent mainnet senders, 90.5% and 87.5%
  used a class this kit migrates ([`wallet-coverage.md`](wallet-coverage.md)).

## A test build in five checks

1. `inspectAccount` on your own Sepolia accounts gives the kind and version you expect.
2. Your derivation of both keys from a fixed test mnemonic matches `deriveAccountKeys`.
3. The migration succeeds on Sepolia with the pinned classes, and the stored keys equal the derived ones.
4. A hybrid-signed transfer succeeds and an ECDSA-only transfer is rejected.
5. On a fresh device, the user's words alone restore both keys and can sign.

`node signer/wallet_migrate_demo.mjs <wallet>` runs checks 1 to 4 end to end on Sepolia for one
wallet class.

## Contact

Juno · Telegram [@oxjuno](https://t.me/oxjuno) · X [@ox_juno](https://x.com/ox_juno) · issues on
this repository.
