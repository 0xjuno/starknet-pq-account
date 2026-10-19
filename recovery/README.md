# Quantum emergency recovery (research prototype)

> **Research prototype. Never put a real seed into this program or any proof of it.** The Stwo
> prover used here is not zero-knowledge (see below).

## Problem

The migration kit in this repository moves accounts to post-quantum signatures before a quantum
computer can break ECDSA. Many owners will never migrate, and some accounts cannot (see
[`../contracts/docs/wallet-coverage.md`](../contracts/docs/wallet-coverage.md)). On the day ECDSA
breaks, an attacker can compute the private key of any account from its public key, which is
readable on-chain.

## Idea

The owner still holds something the attacker does not: the BIP39 seed the wallet derived the key
from. Seed to key is a chain of hashes (HMAC-SHA512 in BIP32, SHA-256 in Starknet's grindKey), so
knowing the private key does not reveal the seed. A proof of "I know a seed that derives this
account's public key", bound to a new post-quantum key, can therefore be produced by the owner
and not by the attacker.

A network rule would then, in an emergency:

1. stop accepting ECDSA-only transactions from accounts that have not migrated;
2. accept, per account, a proof of seed knowledge plus the new post-quantum key, and switch the
   account to it.

The same idea was proposed for Ethereum by Vitalik Buterin
([ethresear.ch, 2024](https://ethresear.ch/t/how-to-hard-fork-to-save-most-users-funds-in-a-quantum-emergency/18901)),
and Olaoluwa Osuntokun built a RISC Zero prototype for Bitcoin BIP-32 / BIP-86 keys
([bitcoindev, 2026-04](https://groups.google.com/g/bitcoindev/c/Q06piCEJhkI),
[bip32-pq-zkp](https://github.com/Roasbeef/bip32-pq-zkp)). This is the Starknet version: Cairo,
Starknet wallet derivations, Stwo.

## What the program does

`src/lib.cairo` is a Cairo executable. Private input: the 64-byte BIP39 seed. Output:
`[profile, index, public_key, binding]`.

| Profile | Derivation reproduced |
| --- | --- |
| `pq`, `braavos` | seed, BIP32 `m/44'/9004'/0'/0/i`, grindKey, STARK public key |
| `argentx` | seed, BIP32 `m/44'/60'/0'/0/0` (Ethereum key), that key as a BIP32 seed, `m/44'/9004'/0'/0/i`, grindKey, STARK public key |

`binding` is echoed into the public output (for example a hash of the owner's new post-quantum
key), so a proof cannot be reused to hand the account to someone else.

Cairo's standard SHA-256 and SHA-512 are Starknet syscalls and are not available to a provable
executable, so the program implements SHA-256, SHA-512, HMAC-SHA512, secp256k1 scalar
multiplication (needed for BIP32's non-hardened steps), BIP32 and grindKey in plain Cairo. The
STARK-curve step uses the `ec_op` builtin. Round constants are generated from their definitions
by [`../signer/recovery_constants.mjs`](../signer/recovery_constants.mjs).

## Results

- `scarb cairo-test`: 7 tests pass. SHA-256, SHA-512 and HMAC-SHA512 (RFC 4231 case 2) match
  their standard vectors, `2G` on secp256k1 matches, and for a public test mnemonic both
  profiles output exactly the key the wallet derivation in
  [`../signer/pq_keys.mjs`](../signer/pq_keys.mjs) produces (vectors from
  [`../signer/recovery_vectors.mjs`](../signer/recovery_vectors.mjs)).
- `scarb execute --target bootloader`: 4,257,716 Cairo steps for the Braavos profile, 8,469,319
  for Argent X (one extra BIP32 chain). One HMAC-SHA512 costs about 230k steps.
- Proving: `scarb prove` does not run on Windows; in WSL with about 7 GB of memory the Stwo
  prover was killed even for a 1M-step test program. Comparable Starknet proofs are reported to
  need about 14 to 18 GB. A proof has not been produced yet.

```sh
cd recovery
scarb cairo-test
scarb execute --arguments-file args/braavos.json --print-program-output --print-resource-usage --target bootloader --output cairo-pie
scarb prove --execute --arguments-file args/braavos.json   # Linux or macOS, enough memory
```

The argument files use the public Hardhat test mnemonic
(`test test test test test test test test test test test junk`).

## Preconditions for a real rule

1. **Zero knowledge.** The proof must reveal nothing about the seed. Stwo is not zero-knowledge
   today: the stwo-cairo README says "the protocol is not zero-knowledge by default", and the
   SNIP-36 discussion calls the current privacy "de facto", with a future phase "may support
   fully zero-knowledge proofs"
   ([stwo-cairo](https://github.com/starkware-libs/stwo-cairo),
   [SNIP-36](https://community.starknet.io/t/snip-36-in-protocol-proof-verification/116123)).
   A non-zero-knowledge STARK opens committed trace values at query points, and the HMAC
   chaining values are as sensitive as the seed. Until a zero-knowledge prover is used, proofs of
   real seeds must not be generated or shared.
2. **Post-quantum soundness.** Hash-based proofs only; no pairing-based wrapper (Groth16 and
   similar are broken by the same quantum computer).
3. **Binding.** The public output must commit to the new post-quantum key or validation code.
4. **On-device proving.** The seed never leaves the owner's device.
5. **Constant trace shape.** The derivation code must not branch on the secret, so the trace
   size reveals nothing.

## Verifying on Starknet

- SNIP-36 (live since v0.14.2) verifies S-two proofs of a single transaction run by a virtual
  Starknet OS, not arbitrary executables, and its proofs are kept by nodes; the derivation would
  have to be ported into a contract call, and large proofs are not yet enabled on Sepolia
  ([v0.14.4 notes](https://community.starknet.io/t/starknet-v0-14-4-prerelease-notes/116341)).
- Herodotus Atlantic proves with Stwo but verifies Stwo proofs on L1 only for now
  ([docs](https://docs.herodotus.cloud/atlantic-api/stwo)).
- A direct Stwo verifier contract is experimental and needs many transactions
  ([example](https://github.com/modeofO/stwo-starknet-verifier)).

## Alternatives

- A zero-knowledge prover today (for example RISC Zero, as in bip32-pq-zkp), with the caveat
  that its zero-knowledge property is targeted but not formally proven, and that its Groth16
  wrapper is not post-quantum ([security model](https://dev.risczero.com/api/security-model)).
- Commit and reveal of a single hardened child key, which avoids the need for zero knowledge
  (raised in the bitcoindev thread above).

## Limits

- Only accounts whose key was derived from a seed by a known derivation can be recovered.
  Accounts created from an imported raw private key cannot.
- The rule must be agreed and deployed before the emergency; otherwise attackers move first.
- Unaudited research code.
