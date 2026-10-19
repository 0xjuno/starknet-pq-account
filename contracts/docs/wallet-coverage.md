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
`0x143276dcf22c5346cbeeff325969fa8ae9ab9f9c609350e4d5c6a36dd0470e0`.

| Wallet class | Sierra | Migration transaction | L2 gas | Hybrid transfer |
| --- | --- | --- | --- | --- |
| Argent 0.3.0 | 1.2.0 | `upgrade` → `execute_after_upgrade` [0x52674417…](https://sepolia.voyager.online/tx/0x5267441721ea1088da786b4d033af0b80cc23e646b7e560df903986bde66256) | 138.0M | [0x479955e5…](https://sepolia.voyager.online/tx/0x479955e55ff8b0e4e8b7712d3b27aaf1e3bebf3bef98db122922d872c4b8aaa) |
| Argent 0.3.1 | 1.4.0 | `upgrade` → `execute_after_upgrade` [0x2bf7012e…](https://sepolia.voyager.online/tx/0x2bf7012e100ae142edaf54597ac2d565111227e6965234d8b7a27944400a29a) | 153.5M | [0x3fd7b204…](https://sepolia.voyager.online/tx/0x3fd7b204e4f683bce4abed5ca79a341b8d44e3c06e3360a8008c8ca8298ccb2) |
| Argent 0.4.0 | 1.5.0 | `upgrade` → `perform_upgrade` [0x492dc4d7…](https://sepolia.voyager.online/tx/0x492dc4d70cb410edc94215b6d8ad6471f0e6ed4aa515f2df1ad97929abe4b93) | 153.5M | [0x74dbefce…](https://sepolia.voyager.online/tx/0x74dbefcea1b6e6e92bda2dd031f95db39ea8f53a4a214636257c717de86b525) |
| Argent 0.5.0 | 1.7.0 | `upgrade` → `perform_upgrade` [0x16997820…](https://sepolia.voyager.online/tx/0x1699782c0921a77b0050eb453b9482b6508c2b29001476570324ad9600afde3) | 74.7M | [0x6ec1417b…](https://sepolia.voyager.online/tx/0x6ec1417bb14e5a172ac81837cf0042d16f1103c1e06afa40bb9aef98d52d16d) |
| Braavos 1.0.0 | 1.4.0 | `[upgrade, migrate]` [0x18e6d066…](https://sepolia.voyager.online/tx/0x18e6d066ec9e8ce7a40b4f7e8de743c4aa271cb0e2b3ad52b54a41218c7d301) | 153.5M | [0x5bdf2ee8…](https://sepolia.voyager.online/tx/0x5bdf2ee8763ee1f0ca25687d735186e767687c630146690a6d88f92d47ee9f3) |
| Braavos 1.1.0 | 1.6.0 | `[upgrade, migrate]` [0x7a4d907b…](https://sepolia.voyager.online/tx/0x7a4d907b0a4a52fff5a83c127065b9cdf6ffbc68f2c8b34be928ff5501445cd) | 153.5M | [0x65eceab5…](https://sepolia.voyager.online/tx/0x65eceab5ef76187e8ca24583a29bd451040f9b507e94c505bc2fd0d2fa32849) |
| Braavos 1.2.0 | 1.7.0 | `[upgrade, migrate]` [0x7774aea8…](https://sepolia.voyager.online/tx/0x7774aea88e5a1189ff2d1166072d0301632a544de2d18d0b2e98fdbd75549e9) | 70.1M | [0x4009135a…](https://sepolia.voyager.online/tx/0x4009135a061be03c16f7f9ea5aec31023ccfbf6a2f0f31c057d92da23c53e99) |
| OpenZeppelin `0x05b4b537…` | 1.6.0 | `[upgrade, migrate]` [0x755848d3…](https://sepolia.voyager.online/tx/0x755848d3d3b40566e783517ed37924768464ffd92395eca081ac2fd7d4bb917) | 153.1M | [0x2e40e275…](https://sepolia.voyager.online/tx/0x2e40e27570fe6d8864cf0a2aa98551ebc9af2d83eb5664ff927bac54e9bda2d) |
| OpenZeppelin `0xe2eb8f56…` | 1.5.0 | `[upgrade, migrate]` [0x7e5fc830…](https://sepolia.voyager.online/tx/0x7e5fc8300af505f1552a02abecd8b28dac2672e09f3690c3f05d1a0051be569) | 153.1M | [0x5e5dbf1b…](https://sepolia.voyager.online/tx/0x5e5dbf1ba447a37813bab63eff02e80a7bffed80b6880fc330b63a9eb86ca86) |
| Xverse (`ArgentAccountXverse`, Argent 0.4.0 base) | 1.5.0 | `upgrade` → `perform_upgrade` [0x3e96037a…](https://sepolia.voyager.online/tx/0x3e96037afe7ca4e8840229297bcd08963a28c063ecf1f86d6851f3d84f2b0c4) | 153.5M | [0x3c71b693…](https://sepolia.voyager.online/tx/0x3c71b693ac671d6f74b7876d0591e3b17177f8d025c3acacbb51b9cb98a187b) |
| OKX (`OkxAccount`, Argent 0.3.0 base) | 1.2.0 | `upgrade` → `execute_after_upgrade` [0x72224057…](https://sepolia.voyager.online/tx/0x722240573f1f23118237b6a7e8531edf1ac0f18b718edca00c7abae1439b451) | 138.0M | [0x4ede165a…](https://sepolia.voyager.online/tx/0x4ede165adcbdd3b3797d0454c80660942313ed74e617f4e92b20eea0f49d872) |

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
