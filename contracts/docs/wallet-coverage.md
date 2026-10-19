# Wallet coverage

Which existing Starknet accounts this kit can move in place, tested three ways: one real account
per wallet class on Sepolia, a read-only classification of recent mainnet senders, and the same
classification applied to every account that delegates BTC in Starknet staking.

Experimental, unaudited, testnet only. Nothing here touches mainnet funds.

## Sepolia: one real account per wallet class seen on mainnet

`signer/wallet_migrate_demo.mjs` creates fresh words for each wallet, derives the classical key
with that wallet's derivation (`argentx` for Argent, `braavos` for Braavos, `pq` for
OpenZeppelin and for the Xverse and OKX classes, whose wallets do not publish their derivation),
deploys a real account of that class, and migrates it with
`pq_account_kit.mjs` only (`inspectAccount`, then `migrationCalls`). Migratable class:
`0x4b067679dbb29516dd79fba49ba1f1b2bc3973b33c74881ff56098d19e27a78` (declared 2026-10-19, after the
proof-less `register_falcon_public_key` entry point was removed; the earlier run on class
`0x143276dc…` is in the git history of this file).

| Wallet class | Sierra | Migration transaction | L2 gas | Hybrid transfer |
| --- | --- | --- | --- | --- |
| Argent 0.3.0 | 1.2.0 | `upgrade` → `execute_after_upgrade` [0x529ebde1…](https://sepolia.voyager.online/tx/0x529ebde10a7bb139b24b879d0ca9fb3c250db88838b4d58348db3dd933244ad) | 153.5M | [0x7fc70e8f…](https://sepolia.voyager.online/tx/0x7fc70e8fdbe1de3246c8b5cb45a5480c5ac59dfdbd4a21291c13930df0fafb2) |
| Argent 0.3.1 | 1.4.0 | `upgrade` → `execute_after_upgrade` [0x6d4959b5…](https://sepolia.voyager.online/tx/0x6d4959b5a61b74af5290f718558bad4eabc1dc662bcd5af072425873c7132b4) | 138.0M | [0x7a568054…](https://sepolia.voyager.online/tx/0x7a568054220fe93b40f335dde033bfc9fad008a2f1699f6e7c59ed7333ac91c) |
| Argent 0.4.0 | 1.5.0 | `upgrade` → `perform_upgrade` [0x2ae4654a…](https://sepolia.voyager.online/tx/0x2ae4654aa9e0de93a51fbf16aaaefe45da5f70f27432dd45fd01cb471ee39e9) | 138.0M | [0x705794bb…](https://sepolia.voyager.online/tx/0x705794bba5c3afaf48bee13758fc4b754cc6d171ad6b9a30c99c29c49fb5000) |
| Argent 0.5.0 | 1.7.0 | `upgrade` → `perform_upgrade` [0x2bd47395…](https://sepolia.voyager.online/tx/0x2bd473956e65ee2a017ddcfd4b5a03710fa329f1fdfa60e0de2c05f4dd91f77) | 74.7M | [0x348a4cac…](https://sepolia.voyager.online/tx/0x348a4cac1c1b0479057a18f021ac9a65e36f18ee6c5839644ef627fe77309d) |
| Braavos 1.0.0 | 1.4.0 | `[upgrade, migrate]` [0x730e6776…](https://sepolia.voyager.online/tx/0x730e6776644e81ac4489fee95e1d34f942beb3b977ea44a601c341d668e99d5) | 138.0M | [0x67df6c54…](https://sepolia.voyager.online/tx/0x67df6c5491f0ed67a9f973847e49b8f6188129c1a2a002423bc7aede05e0030) |
| Braavos 1.1.0 | 1.6.0 | `[upgrade, migrate]` [0x75116162…](https://sepolia.voyager.online/tx/0x75116162b56ddcf154c74cd26d236479a9ec784228e5801f2779746e2877353) | 138.0M | [0x2e2de23f…](https://sepolia.voyager.online/tx/0x2e2de23fb06a8a660a69f9e3978c7d902cc6788e7b3bf15634f85d747ae490a) |
| Braavos 1.2.0 | 1.7.0 | `[upgrade, migrate]` [0x1a4972fc…](https://sepolia.voyager.online/tx/0x1a4972fc9e3315c62ebaec99a40de4248e86bbe15ebf5f3892bfc33b71e89f5) | 70.1M | [0x1f214500…](https://sepolia.voyager.online/tx/0x1f214500c70833bf88fa6d03c33999a7b23dec0ac188d761c8018d3d078d5c2) |
| OpenZeppelin `0x05b4b537…` | 1.6.0 | `[upgrade, migrate]` [0x65929709…](https://sepolia.voyager.online/tx/0x659297094820bd7073003a020e18ba70d2a90b42b6a3fad406dc980308bbffc) | 153.1M | [0x6277bccd…](https://sepolia.voyager.online/tx/0x6277bccdab16a2c56b1d2e80de68738def7b323c6537c454144b6df034501ae) |
| OpenZeppelin `0xe2eb8f56…` | 1.5.0 | `[upgrade, migrate]` [0x1f190f10…](https://sepolia.voyager.online/tx/0x1f190f1047ade18354f80c8740f34801ee97c7837093add9840d65f1aa9eccf) | 137.6M | [0x242552f6…](https://sepolia.voyager.online/tx/0x242552f6a3908ad2a86a0cef2402a4167b8b7484dbab4eed1f078a86c9dbcea) |
| Xverse (`ArgentAccountXverse`, Argent 0.4.0 base) | 1.5.0 | `upgrade` → `perform_upgrade` [0x3525208b…](https://sepolia.voyager.online/tx/0x3525208bc85b802072088d3f3848a63f45196c81e75211988afe1747fba2b0f) | 153.5M | [0x54028d58…](https://sepolia.voyager.online/tx/0x54028d5862d613c0efd537ecc7ebe360cba24ab1d7f17d8b0eafc4305e70995) |
| OKX (`OkxAccount`, Argent 0.3.0 base) | 1.2.0 | `upgrade` → `execute_after_upgrade` [0x15b32d42…](https://sepolia.voyager.online/tx/0x15b32d429d35db217702152474f20abd1d2aed0cf0005b39c7b1da44b9762a4) | 138.0M | [0x5a2b1568…](https://sepolia.voyager.online/tx/0x5a2b156889466cae83f716c19e2ea5150856a7eb9c233df0a47f136cb83c2f3) |

For all eleven accounts: the classical and Falcon keys stored after migration equal the keys derived
from its words, the balance dropped by exactly the migration fee, the hybrid-signed transfer
succeeded, and an ECDSA-only transfer was rejected in `__validate__`. Sierra versions are read
from the first three felts of each class's `sierra_program`.

### Gas

Migrations started from classes compiled with Sierra 1.7.0 (Argent 0.5.0, Braavos 1.2.0) used
70 to 75M L2 gas. Those started from older classes used 138 to 153M. Our class is Sierra 1.8.0
in both cases, so the difference most likely comes from how Starknet meters execution that
starts in a pre-1.7.0 class; we have not confirmed the exact rule. At the mainnet prices in the
README (11.34 x 10^9 fri per L2 gas, STRK at $0.0775), that is about 0.8 STRK ($0.06) or 1.74
STRK ($0.13), once per account.

## Mainnet: which recent senders could migrate today

`signer/mainnet_survey.mjs` walks back from the latest mainnet block, collects unique INVOKE
senders until it has 400, and classifies each with `inspectAccount`: the class ABI decides the
wallet family (cached per class), then per-account reads check Argent owners and guardians and
Braavos signers and multisig. Read-only; only the aggregate is published
([`signer/survey/mainnet-summary-2026-10-19.json`](../../signer/survey/mainnet-summary-2026-10-19.json)).

Window: blocks 16,587,925 to 16,589,622 (about 0.8 hours on 2026-10-19), 4,839 INVOKE
transactions, 400 unique senders.

- 362 of 400 senders (90.5%) use a class this kit migrates; they sent 93.2% of the INVOKE
  transactions in the window. 3 of them have an Argent guardian, so the migration needs the
  guardian's co-signature.
- 353 of 400 (88.3%) are on the eleven classes migrated on Sepolia above. The other 9 are on
  three further OpenZeppelin-style classes, classified by ABI only.
- Not covered (38): 23 accounts with no self-upgrade entry point, 9 Cairo 0 accounts, 4 Braavos
  accounts with a hardware or passkey signer (migration would drop it), 2 others.

By class: Argent 0.4.0 195 (including 1 Xverse), OpenZeppelin-style 94, Argent 0.3.0 41
(including 2 OKX), Braavos 1.2.0 20, Argent 0.3.1 8, Braavos 1.0.0 5, Argent 0.5.0 2, Braavos
1.1.0 1, other 34.

Limits of this sample: under one hour, counted per sender, so it leans toward frequent senders
such as bots and market makers. It shows which account classes are in active use, not how much
value they hold; the BTC staking measurement below weights by value.

## Mainnet: BTC staked on Starknet

`signer/btc_staking_coverage.mjs` lists every BTC delegation pool of the staking contract
(`NewDelegationPool` events for WBTC, tBTC, SolvBTC, LBTC and strkBTC), every member of those
pools (`NewPoolMember` events), each member's current delegated amount
(`get_pool_member_info_v1`), and classifies each delegating account with `inspectAccount`.
Read-only; aggregate in
[`signer/survey/btc-staking-coverage-2026-10-19.json`](../../signer/survey/btc-staking-coverage-2026-10-19.json).

On 2026-10-19: 484 BTC pools, 882 delegating accounts, 621.3 BTC delegated (SolvBTC 409.8,
WBTC 174.8, strkBTC 30.4, tBTC 5.3, LBTC 1.1).

- 563.6 BTC (90.7%) sits in 788 accounts this kit migrates today; 545.9 BTC of it in Argent
  0.4.0 accounts.
- The ten largest delegating accounts hold 435.1 BTC (70.0%); all ten are Argent accounts that
  migrate with one `upgrade` call. Of the 832 accounts delegating under 1 BTC, 759 (91%) can
  migrate.
- Not covered: 44.9 BTC in accounts of other classes (likely contracts rather than personal
  wallets; unconfirmed), 12.1 BTC in Braavos accounts with a hardware or passkey signer,
  0.8 BTC in an Argent-based class under another name.
