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
   - Argent X / Ready uses the same path from a different master seed, so its words give a
     different key here; see "Wallet ECDSA profiles" below.
3. Falcon-512 key (account index `i`):
   - `falcon_seed = HKDF-SHA512(ikm = seed, salt = "starknet-pq-backup-v0", info = "falcon-512/account/i", L = 64)`
   - Expand `"starknet-pq-backup-v0/falcon-512/keygen" || falcon_seed` with SHAKE-256 into a byte
     stream, and use that stream as the only randomness of Falcon key generation.
4. The account stores both public keys on-chain, so a restore can be checked against the
   chain before the user signs anything.

## Profile v0.1: Falcon keygen in JavaScript (browser and Node)

Same mnemonic and ECDSA path as above. The Falcon key uses the deterministic key generation of
[@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) 0.6.1, which accepts a
48-byte seed:

- `falcon_seed48 = HKDF-SHA512(ikm = seed, salt = "starknet-pq-backup-v0.1", info = "falcon-512/noble/account/i", L = 48)`
- `falcon512.keygen(falcon_seed48)`

The same mnemonic gives the same Falcon key in Node (`signer/pq_keys.mjs`) and in the browser
(`docs/index.html`); key generation took about 0.7 s in Node. The browser demo restores both keys
from the mnemonic and its Falcon public key matches the key registered on-chain. The caveat above
still applies: the key is defined by this library's key generation procedure.

## Wallet ECDSA profiles: keep the words a user already has

To migrate an existing wallet account, the classical key must be the one that account already
uses, derived from the words the user already holds. The Falcon key still comes from the BIP39
seed exactly as in v0.1, so it does not depend on the wallet.

| Profile | Classical key | Source |
| --- | --- | --- |
| `pq` | BIP32 from the BIP39 seed, `m/44'/9004'/0'/0/i`, `grindKey` | this document |
| `argentx` | The words give an Ethereum key (BIP32 `m/44'/60'/0'/0/0`, as ethers `HDNodeWallet.fromPhrase`). That 32-byte key, leading zero bytes dropped, is the BIP32 master seed for `m/44'/9004'/0'/0/i`, then `grindKey` | argent-x `ArgentSigner.ts`, `WalletCryptoSharedService.ts` |
| `braavos` | Same computation as `pq` | Third-party scripts only; Braavos does not publish its wallet code. Unconfirmed |

`signer/wallet_profiles_check.mjs` checks the `argentx` profile against the vectors in argent-x
`test/keyDerivation.test.ts` (STARK keys at indices 5 and 7, `grindKey`) and the Ethereum step
against Hardhat's default mnemonic. All four match.

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

## Sepolia evidence: public demo words (2026-10-27)

`signer/backup_fixtures_check.mjs` (read-only) derives profile v0.1 keys from the public demo
words in the README and checks them against the public demo account
`0x343e3df576edca452f2cc6ac5247fc38a3641912f545e25468e3b7e7de1c0db`: same address, same stored ECDSA
and Falcon keys, after its switch to the small verifier as before. The noble (v0.1) and falcon.py
(v0) fixtures verify on every verifier class, small included (`contracts/src/tests_pf.cairo`).

## Sepolia evidence: wallet accounts (2026-10-17)

`signer/wallet_migrate_demo.mjs` creates words for each wallet, deploys a real account from
them (Argent 0.5.0, Braavos), migrates it, and checks that the classical and Falcon keys stored
on-chain are the ones the words produce:

- Argent 0.5.0, `argentx` profile: `0x61228909093cb162adc6e487f816a5c5845b219341914bf1ae0b4894c80023a`
- Braavos, `braavos` profile: `0x2d21d503e80d0725042bde6c2e9be84fad2c7f951e86628f263cc918e2b2c43`

This shows the profiles work for accounts deployed this way. Whether the Braavos app derives the
same key from a user's words is still unconfirmed.

## Open questions

- Passphrase handling and per-account indices for multi-account wallets.
- Whether wallets prefer a separate PQ mnemonic (independent failure domains) over one shared
  mnemonic (simpler recovery).
- Verifier upgrades: the migratable account can point at a new verifier class without a new
  migration; the backup profile is independent of that choice.
