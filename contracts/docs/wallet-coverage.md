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
`0x7efafbfbaf02af30bc17d55366392e129fea252d7597650da45a61d0869f75a` (declared 2026-11-02, with the
checks on key rotation and verifier switches; migration paths unchanged). Runs on earlier classes
(`0x4b067679…`, `0x143276dc…`) are in the git history of this file.

| Wallet class | Sierra | Migration transaction | L2 gas | Hybrid transfer |
| --- | --- | --- | --- | --- |
| Argent 0.3.0 | 1.2.0 | `upgrade` → `execute_after_upgrade` [0x4ec64252…](https://sepolia.voyager.online/tx/0x4ec64252e80e7a20aedf2d081640c02261f8980598a4e8fef1bab4f07ffa8) | 153.5M | [0x62cdc4a6…](https://sepolia.voyager.online/tx/0x62cdc4a667e7ff724039b4329d7680827eb84b79dbdf62eb73677aa0aaf0b05) |
| Argent 0.3.1 | 1.4.0 | `upgrade` → `execute_after_upgrade` [0x4bfd65cf…](https://sepolia.voyager.online/tx/0x4bfd65cf4a697ff4ae6ecceefa7c274f35cbf5ddcd7fac535d031a67dde42e4) | 153.5M | [0x7caa6d04…](https://sepolia.voyager.online/tx/0x7caa6d0479d47c119a73cf3519f9b055b8a0ab0da5ec5efa2cbf4c86d0a0ffd) |
| Argent 0.4.0 | 1.5.0 | `upgrade` → `perform_upgrade` [0x7acb1b1d…](https://sepolia.voyager.online/tx/0x7acb1b1d4551df1e8567dc372f0e6aaead7e78b79c1b43f6d09577f81652a04) | 153.5M | [0x27637237…](https://sepolia.voyager.online/tx/0x27637237d6dbce58886a703c4756418b209d0c4b5d1c585513140467ee30794) |
| Argent 0.5.0 | 1.7.0 | `upgrade` → `perform_upgrade` [0x44be6494…](https://sepolia.voyager.online/tx/0x44be6494aa08210bce48ae436ee117dc320140263c0b8db2aebc72bcebc25e9) | 70.4M | [0x66d26c19…](https://sepolia.voyager.online/tx/0x66d26c1933b08b187d65eb34b50db50ef812d8bac07d5f11f95cabb9660dc84) |
| Braavos 1.0.0 | 1.4.0 | `[upgrade, migrate]` [0x1c9cb5ce…](https://sepolia.voyager.online/tx/0x1c9cb5cea204f820aff8acd1dfdcf081a09c6478e0dbcf78692759b4872be2a) | 138.0M | [0x2c499879…](https://sepolia.voyager.online/tx/0x2c4998793899d17c0de144f43f491c68029d7d57ea55c9a0c7b947f3aed618e) |
| Braavos 1.1.0 | 1.6.0 | `[upgrade, migrate]` [0x38b9eab5…](https://sepolia.voyager.online/tx/0x38b9eab57539e0cd6c731957bd4cb2411a4237d7d7cb1921e20781821228429) | 138.0M | [0x5e13f29b…](https://sepolia.voyager.online/tx/0x5e13f29b67a69795998e98bbfa5f628097aa59f9b1456dc77d6acf314d2e30c) |
| Braavos 1.2.0 | 1.7.0 | `[upgrade, migrate]` [0x1b62ef63…](https://sepolia.voyager.online/tx/0x1b62ef63e2e00ef3d88547d5d6753eeb999c75f58013fab87d7ffdd6d7e97e) | 74.5M | [0x7db82075…](https://sepolia.voyager.online/tx/0x7db82075526e6747bc906126b8e89712bd2e603155143842aac6e8b9b1d3458) |
| OpenZeppelin `0x05b4b537…` | 1.6.0 | `[upgrade, migrate]` [0x2cdd0998…](https://sepolia.voyager.online/tx/0x2cdd0998bc1ab7e3f2e4d10346f6ac14df73cd2ab1ab15e117cf5629bb04547) | 153.1M | [0x685e885c…](https://sepolia.voyager.online/tx/0x685e885c6d923ca4f0136bc4ae5f1de6721574c401993e7f14828c40fe63e53) |
| OpenZeppelin `0xe2eb8f56…` | 1.5.0 | `[upgrade, migrate]` [0x4e30ed81…](https://sepolia.voyager.online/tx/0x4e30ed81be52535d9944e5c9bfed31f9fc126b69d8a06409f240e3860c6cb9e) | 137.6M | [0x6c68453d…](https://sepolia.voyager.online/tx/0x6c68453db1cf65c761eef8c3232a29be54f4730eeba1862c45f7bbb3e13596e) |
| Xverse (`ArgentAccountXverse`, Argent 0.4.0 base) | 1.5.0 | `upgrade` → `perform_upgrade` [0x3ba727f8…](https://sepolia.voyager.online/tx/0x3ba727f8fdb68e781c47e60bf964827f0faff784e337ca6923762603dfcbbd6) | 153.5M | [0x2ed773e7…](https://sepolia.voyager.online/tx/0x2ed773e7876ed574beb500c0bdb0d559061263902b7719c0d9a84acad90ccde) |
| OKX (`OkxAccount`, Argent 0.3.0 base) | 1.2.0 | `upgrade` → `execute_after_upgrade` [0x2003c6cc…](https://sepolia.voyager.online/tx/0x2003c6cc07c1ab6478ca52910c102dd6d468251d1caea764e05b3a1d21491a1) | 138.0M | [0x4f4e1ef6…](https://sepolia.voyager.online/tx/0x4f4e1ef66a4b51a46a77da2029e2c5573cb0d6170f792b33768cad481b604a7) |

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
