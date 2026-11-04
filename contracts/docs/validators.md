# Validators: who can migrate today, and a migrated validator on Sepolia

Two read-only and testnet-only checks of the validator side of in-place migration, run on
2026-11-04. Scripts: `signer/validator_coverage.mjs` (mainnet census, read-only) and
`signer/validator_sepolia.mjs` (Sepolia pilot). Nothing here touches mainnet state.

## 1. Mainnet census (read-only)

Source: the mainnet staking contract `0x00ca1702e64c81d9a07b86bd2c540188d92a2c73cf5cc0e508d949015e7e84a7`.
Every staker is taken from its `NewStaker` events, then `get_staker_info_v1` and
`staker_pool_info` give the current state. "Staking now" means listed, no exit intent, own stake
above zero. Delegated amounts are the contract's last updated values, which can lag the current
epoch by a few epochs. Each staker and operational address is then classified with the same rules
as the wallet matrix (`pq_account_kit.mjs` `inspectAccount`): migratable today means an Argent
0.3+ account with one STARK owner (a guardian means a co-signature is needed), a Braavos account
with one STARK signer and no hardware, passkey or multisig setup, or an OpenZeppelin account.
Summary: `signer/survey/validator-coverage-2026-11-04.json`.

| Measure | Value |
| --- | --- |
| Stakers ever | 275 |
| Staking now | 135 |
| STRK staked (own + delegated) | 1,755,980,594 |
| BTC delegated (five BTC tokens) | 642.59 |
| Staker account migratable today | 111 of 135 (82.2%) |
| Same, weighted by stake | 52.4% of STRK, 2.0% of delegated BTC |
| Staker and operational both migratable | 108 (80.0%), 52.4% of STRK |
| Staker accounts with an Argent guardian (co-signature needed) | 17 |
| Same account used as staker and operational | 15 |

Staker accounts by class: Argent 0.4.0 82, OpenZeppelin 16, Braavos 1.2.0 14, ArgentMultisig 13,
Braavos 1.1.0 6, other 2, Cairo 0 1, Argent 0.3.1 1.

Not migratable today, with share of stake:

| Reason | Stakers | STRK | Delegated BTC |
| --- | --- | --- | --- |
| ArgentMultisig (1-of-2 ×2, 2-of-2 ×1, 2-of-3 ×6, 3-of-5 ×3, 3-of-6 ×1) | 13 | 34.0% | 91.6% |
| Braavos with several STARK signers (3, 4 or 5) | 5 | 11.9% | 6.4% |
| Braavos with a hardware or passkey signer | 3 | 1.6% | 0.0% |
| Other class | 2 | 0.0% | 0.0% |
| Cairo 0 account | 1 | 0.0% | 0.0% |

So the count looks good (82%) but the stake does not (52% of STRK, 2% of BTC): the largest
validators keep their staker account in a multisig, and multisig migration is not something this
repo does. Of the twelve largest stakers by STRK, the largest (320.6M STRK) is an OpenZeppelin
account and migrates; the next three are an ArgentMultisig, a Braavos account with four STARK
signers, and another ArgentMultisig.

Operational accounts are almost all single-key: Argent 0.4.0 75, OpenZeppelin 29, Braavos 1.2.0
25, Argent 0.3.1 2, Braavos 1.1.0 1. Three operational addresses are not deployed yet (only the
address is registered), so nothing can be said about them until they are.

## 2. A validator migrated while staking (Sepolia)

Contracts: staking `0x03745ab04a431fc02871a139be6b93d9260b0ff3e779ad9c8b377183b23109f1`,
attestation `0x03f32e152b9637c31bfcf73e434f78591067a01ba070505ff6ee195642c9acfb` (Starknet docs,
chain info). On Sepolia the minimum stake is 1 STRK, an epoch is 231 blocks, the exit window is
300 s, and the attestation window read from the contract is 40 blocks (the docs page says 30).

Two fresh OpenZeppelin accounts (class `0x05b4b537…3564`): staker
`0x1867774df6f3547fce5c22a1ea47bcd742938b58e7719f22506bda7712fde46`, operational
`0x4b69fe1ec9c07293fa4eb387ed8d9d8759aaf0451320b5ea549cc08ab7277e8`. Migration target: the
current `HybridMigratableAccount` `0x7efafbfbaf02af30bc17d55366392e129fea252d7597650da45a61d0869f75a`
with the baseline SHAKE-256 verifier.

| Step | Signer | Transaction | Result |
| --- | --- | --- | --- |
| `stake` 2 STRK (epoch 78712) | ECDSA | [0x5773a94a…](https://sepolia.voyager.online/tx/0x5773a94ad40365b60b43242bf8a9fdaa985cc9896d9bfed51dba2064bd2d541) | SUCCEEDED, 8.0M L2 gas |
| `attest` (epoch 78713, target block 17608115, sent at 17608131) | ECDSA | [0x7670f04f…](https://sepolia.voyager.online/tx/0x7670f04f48710ece62d78bd24de198cc8ed0f654eaa9debd00550db97f48d11) | SUCCEEDED, 9.4M L2 gas |
| migrate the operational account in place | ECDSA + Falcon proof | [0x44745a05…](https://sepolia.voyager.online/tx/0x44745a056fce36d0eadb3893b55eb41f09f1205f66746057d14309b91a8199c) | SUCCEEDED, 153.1M L2 gas |
| migrate the staker account in place | ECDSA + Falcon proof | [0x28516e9e…](https://sepolia.voyager.online/tx/0x28516e9e0e49886d4a8f5e70c7ebe8c503b2d0c9d40f73fc87b08bcba2d414b) | SUCCEEDED, 153.1M L2 gas |
| `attest` (epoch 78714, target block 17608301, sent at 17608315) | hybrid | [0x25bd8eb4…](https://sepolia.voyager.online/tx/0x25bd8eb4c80cc907cba701ff89823dad9913e0c102adc3bceaea528f92db72b) | SUCCEEDED, 61.4M L2 gas |
| the same `attest` call with an ECDSA-only signature | ECDSA only | not accepted | rejected at validation, `Account: invalid signature` |
| `unstake_intent` | hybrid | [0x4c8c48ec…](https://sepolia.voyager.online/tx/0x4c8c48ec0c2d56f70866b6c24ca3102864cf6fa4fa4d98409ca2e1ba562eaf3) | SUCCEEDED, 56.1M L2 gas |
| `unstake_action` after the 300 s window | hybrid | [0x3203d750…](https://sepolia.voyager.online/tx/0x3203d7500ebea9f880fef4ab9d9fb334cca9d09afd663188ecd40d878a9e113) | SUCCEEDED, 58.9M L2 gas, 2 STRK returned to the staker, staker removed |

Checked after the two migrations and before the hybrid attestation: `get_staker_info_v1` still
returns the same operational address and 2 STRK of own stake for the same staker address. After
the hybrid attestation, `get_last_epoch_attestation_done(staker)` returns 78714.

What this shows: a validator's staker and operational accounts can move to hybrid signatures
without changing address, so the stake, the delegation pool and the attestation schedule are
untouched, and the validator attests in the next epoch as before. What it does not show: this
attestation was sent by the kit's signer (`HybridSigner`), not by a validator client. A validator
client has to produce the hybrid signature itself, which is the remaining piece.

Cost: the hybrid attestation used 61.4M L2 gas against 9.4M for the ECDSA one, with the baseline
verifier. The optimised verifier in this repo (`small`, not the default yet) cut a hybrid transfer
from 53.9M to 29.6M in the README benchmark.

Rerun: `node signer/validator_sepolia.mjs` (needs the deployer keys under `.keys/`; idempotent,
resumes from `.keys/validator-sepolia-state.json`). Takes about twenty minutes when the stake comes
into effect in the next epoch, as it did here.
