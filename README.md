# starknet-pq-account

Move an existing Starknet account to post-quantum signatures without changing its address or
funds, and back up both keys with one mnemonic.

> **Experimental. Unaudited. Testnet only.** Do not hold real funds with these contracts.

## Why

StarkWare's own assessment of Starknet accounts:

- "Standard Starknet accounts still sign with elliptic-curve cryptography." ... "Account signing is
  only demonstrated. Its implementations are unaudited, and an ordinary user can't adopt it yet."
  ([StarkWare, 2026-10-13](https://starkware.co/blog/what-chains-can-become-post-quantum/))
- "Existing accounts do not change automatically. Wallet support, signing, key management,
  recovery, custody, audits and adoption remain separate work." "Wallet and custody teams decide
  whether to integrate it." ([StarkWare migration register](https://quantum.starkware.co/migration-register))
- "Starknet accounts can swap their verification logic in place, with the same address and same
  assets" ([StarkWare, 2026-07-20](https://starkware.co/blog/starknets-quantum-edge-starks-and-native-account-abstraction/))

This repository is a working prototype of that migration path for ordinary accounts: the
in-place upgrade, the hybrid signature check, and the key backup that wallets would need.

## What is here

| Piece | What it does |
| --- | --- |
| `HybridPoseidonAccount` | New account that accepts a transaction only if BOTH a STARK-curve ECDSA signature and a Falcon-512 signature verify over the same hash. |
| `HybridMigratableAccount` | Thin account class for in-place migration of an existing OpenZeppelin account. Keeps the OZ storage key `Account_public_key`, registers a Falcon key, and library-calls a declared verifier class (swappable later without migrating again). |
| Key backup profile v0 | One BIP39 mnemonic restores both keys. See [`contracts/docs/key-backup-v0.md`](contracts/docs/key-backup-v0.md). |
| Demo scripts | Sepolia scripts for deployment, migration, negative tests and backup/recovery (`signer/`). |

### Migration flow

One transaction, validated by the account's existing class with its existing ECDSA key:

```
multicall [
  self.upgrade(HybridMigratableAccount),                      // replace_class, same address
  self.register_falcon_public_key(falcon_pk, verifier_class), // runs on the new class
]
```

From the next transaction on, the account requires ECDSA AND Falcon. A forged ECDSA signature
alone (the quantum attacker case) is rejected in `__validate__`. If an account is upgraded
without registering a key, it only accepts a single ECDSA-signed `register_falcon_public_key`
self-call, so the atomic flow above is the recommended path.

## Results on Starknet Sepolia

| Step | Transaction |
| --- | --- |
| Hybrid account deploy (deploy tx itself hybrid-signed) | [0x18e2ed9d…](https://sepolia.voyager.online/tx/0x18e2ed9d992074cb618cc03b40618bf4de8cd7a057906ede5b96c00d46ce070) |
| Hybrid-signed transfer | [0x316b9b6e…](https://sepolia.voyager.online/tx/0x316b9b6ef1dde8ed8103e5d9f552fa6a915a7d56db425daf56c80bfabb42f1b) |
| Existing OZ account deployed | [0x7eee5c3f…](https://sepolia.voyager.online/tx/0x7eee5c3f5abe2e547b8fe39c5541a2fd0025938d72c6f31a5e229565104e6bc) |
| In-place migration (same address) | [0x75b5c5e2…](https://sepolia.voyager.online/tx/0x75b5c5e20cb189d72f228d033627c863f781b930df07fefefc3f548186aeef0) |
| Hybrid-signed transfer after migration | [0x521ff2b3…](https://sepolia.voyager.online/tx/0x521ff2b341561abb0bc71581a4feaf650311bf0398176b5d7f1dc2c16343d57) |
| Transfer signed with keys restored from the mnemonic | [0x3ba4e173…](https://sepolia.voyager.online/tx/0x3ba4e17369011649b2ec02b97df634dfd7cd417630853300fa94b2f80484c57) |

- Migrated account [`0x54370be5…4c41`](https://sepolia.voyager.online/contract/0x54370be5a940849f13c01f269d95d06c57d15495da594f3e01dfb6eebdb4c41):
  balance before 3.974179 STRK, after 3.750300 STRK; the difference equals the migration fee exactly.
- An ECDSA-only transfer from the migrated account is rejected in `__validate__`.
- Hybrid validation costs about 15.5M L2 gas (about 16.1M through the migratable library call).
  Observed Sepolia fee for a hybrid transfer: about 0.18 STRK.
- Declaring the thin migratable class cost 3.8 STRK on Sepolia, against 51.6 STRK for the full
  hybrid class, because verification is shared through a library call.

## Security model and limits

- Only account signatures become hybrid. Bridges, data availability, Ethereum settlement and
  sequencing are out of scope.
- Unaudited. The Poseidon Falcon variant uses a Poseidon hash-to-point (cheap, non-standard);
  the SHAKE-256 variant follows the standard and costs about 4x the gas.
- After migration, OpenZeppelin extras such as SRC-9 outside execution and `set_public_key` are
  not available.
- Signing currently runs through a Python Falcon signer; browser and hardware signing are open.
- Key backup reproducibility depends on the pinned falcon.py commit (see the backup doc).

## Quickstart

Requirements: Scarb 2.18.0, Node.js 20+, Python 3.11+ with `numpy`, `pycryptodome` and
`beartype`, and a [falcon.py](https://github.com/tprest/falcon.py) checkout at commit
`5145a818c9512b4a443507d3375e75dae3076af6`.

```
cd contracts
scarb build
scarb cairo-test          # 23 tests

cd ../signer
npm install
# set FALCON_PY_DIR to the falcon.py checkout (PQ_PYTHON, PQ_KEYS_DIR, PQ_RPC are optional)
node setup_keys.mjs     # testnet keys under .keys/ (gitignored); fund the printed address
                        # from the official faucet https://faucet.starknet.io
node demo.mjs           # declare + deploy a hybrid account, hybrid transfer
node migrate_demo.mjs   # migrate an OZ account in place
node backup_demo.mjs    # mnemonic backup and recovery
```

## Credits

Built on [OpenZeppelin cairo-pq-verifiers](https://github.com/OpenZeppelin/cairo-pq-verifiers)
(MIT) and [falcon.py](https://github.com/tprest/falcon.py) (MIT). See [NOTICE.md](NOTICE.md).
License: MIT.
