# Starknet PQ key backup, profile v0 (draft)

Status: experimental draft, testnet only, not audited. Prototype for discussion.

## Problem

A hybrid account (STARK-curve ECDSA + Falcon-512) needs two private keys. Wallets today back up
one key with a BIP39 mnemonic. If the Falcon key has its own backup, users will lose it, and
an account that requires both signatures becomes unusable. StarkWare's migration register
lists "key management, recovery" as separate work that wallet teams still have to do.

## Profile

One BIP39 mnemonic (24 words recommended) restores both keys.

1. `seed = BIP39(mnemonic, passphrase)` (PBKDF2-HMAC-SHA512, 2048 iterations, 64 bytes).
2. Classical key (account index `i`):
   - BIP32 secp256k1 path `m/44'/9004'/0'/0/i`, then `grindKey` onto the STARK curve.
   - This is the derivation commonly used by Starknet wallets (Argent lineage). Byte-for-byte
     compatibility with a specific wallet's import is not yet verified.
3. Falcon-512 key (account index `i`):
   - `falcon_seed = HKDF-SHA512(ikm = seed, salt = "starknet-pq-backup-v0", info = "falcon-512/account/i", L = 64)`
   - Expand `"starknet-pq-backup-v0/falcon-512/keygen" || falcon_seed` with SHAKE-256 into a byte
     stream, and use that stream as the only randomness of Falcon key generation.
4. The account stores both public keys on-chain, so a restore can be checked against the
   chain before the user signs anything.

## Reference implementation (non-normative)

- `scripts/falcon_from_seed.py`: replaces `os.urandom` inside falcon.py's NTRU key generation
  (`ntrugen.gen_poly -> samplerz`) with the SHAKE-256 stream. Pinned to falcon.py commit
  `5145a818c9512b4a443507d3375e75dae3076af6`.
- `signer/backup_demo.mjs`: derives both keys, deploys an OpenZeppelin account, migrates it in
  place, deletes every key file, restores from the mnemonic, and signs a transfer.

Limitation: the Python keygen is reproducible only with the pinned falcon.py code. A
normative version should seed the Falcon reference C key generation through its SHAKE-256
PRNG, which is how Algorand's falcon-signatures derives Falcon-1024 keys from a mnemonic, so
that independent implementations produce the same key.

## Sepolia evidence (2026-10-16)

- Derived twice from the same mnemonic: identical ECDSA and Falcon public keys.
- Account: `0x3b7e881e8f16c11e447bc323641dc6f291cab0de5436a789e400e56cd786c3d`
- OpenZeppelin deploy: `0x4700f1c3377f76fe8bc106354db512fc77a28ce4559d999394a3db366bcb582`
- In-place migration: `0x1e6e38a455d25cc7ee237fb462ad764e17a948f94bd1041b96c2c1b685dff82`
- After deleting all key files and restoring from the 24 words, the restored keys matched
  both on-chain public keys, and a transfer signed with them succeeded:
  `0x3ba4e17369011649b2ec02b97df634dfd7cd417630853300fa94b2f80484c57`

## Open questions

- Passphrase handling and per-account indices for multi-account wallets.
- Whether wallets prefer a separate PQ mnemonic (independent failure domains) over one shared
  mnemonic (simpler recovery).
- Verifier upgrades: the migratable account can point at a new verifier class without a new
  migration; the backup profile is independent of that choice.
