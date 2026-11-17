# For contract developers: signatures from migrated accounts

Contracts that accept off-chain signatures (permits, orders, SNIP-12 typed messages, session
approvals) keep working when a user's account migrates to the hybrid account, if they check the
signature the SNIP-6 way. This page says what changes, what to avoid, and what a check costs,
measured on Sepolia.

> Experimental. Not yet audited. Sepolia only.

## What changes

- The address stays the same. The account's signature grows from 2 felts (`[r, s]`) to 62:
  `[r, s]` followed by the Falcon-512 part.
- `is_valid_signature(hash, signature)` still answers `VALIDATED` (`'VALID'`), and only when both
  the ECDSA and the Falcon-512 halves verify over `hash`.
- An ECDSA-only signature is refused, which is the point: once ECDSA keys can be derived from
  public keys, an ECDSA-only signature proves nothing.

## Do and don't

| Do | Don't |
| --- | --- |
| Call `IAccount(signer).is_valid_signature(hash, signature)` and pass the signature through untouched | Read the account's ECDSA public key and verify `[r, s]` yourself |
| Accept signatures of any length | Assume 2 felts, or any fixed length |
| Budget gas per check (below) | Check many signatures inside `__validate__` |

The middle row is not hypothetical. `contracts/src/tests_consumer.cairo` has a test where a
contract reads the migrated account's ECDSA key and checks an ECDSA-only signature itself: it
says yes to exactly the signature the account rejects. Standards that fix the signature length
(for example a session-key format that requires 2 or 4 felts) shut hybrid accounts out the same
way.

## What a check costs

`signer/consumer_sepolia.mjs` deploys `contracts/src/consumer.cairo`, a contract that calls the
account's `is_valid_signature`, and sends `check_many(account, hash, signature, 0)` and
`check_many(..., 4)`. One check is the difference divided by four, so the transaction's own
overhead drops out. Sepolia, 2026-11-17; result in
[`signer/survey/consumer-gas-2026-11-17.json`](../../signer/survey/consumer-gas-2026-11-17.json).

| Signer account | One check, L2 gas | At mainnet prices | Transactions (×0 / ×4) |
| --- | ---: | ---: | --- |
| OpenZeppelin ECDSA account | 0.28M | about 0.005 STRK | [0x2b821f1e…](https://sepolia.voyager.online/tx/0x2b821f1e64ce00ef673f0b193727c2f59dce5415dcee89c5487cc587eb14bd9) / [0x2c41b1c7…](https://sepolia.voyager.online/tx/0x2c41b1c7c6e8ef78a177a6b95f1b9df6167222a191c5d3c01f401d07dec8a1e) |
| Migrated account, OpenZeppelin SHAKE-256 verifier | 49.6M | about 0.94 STRK | [0x511a3957…](https://sepolia.voyager.online/tx/0x511a3957cd9c1456d1f6dbc9052368108bee2f5086f05df64ddb9a88199e091) / [0x10c3c9ff…](https://sepolia.voyager.online/tx/0x10c3c9ff2bfaf7ff3ab82d06d6fecf0d21abc1da5a4b6ff7a46f5490c052d61) |
| Migrated account, Provably Fast small verifier | 25.8M | about 0.49 STRK | [0x11a40f14…](https://sepolia.voyager.online/tx/0x11a40f14a26b100f583b5afdfd4744685dc5b55c2c21cbd4bbbaf49acd0b534) / [0x49acd8d9…](https://sepolia.voyager.online/tx/0x49acd8d9b14875f2eb14e92f1009c743c1a3237cbfa3b94d0cc338f0404bd96) |

Mainnet prices as in the README: block 17043179, 18.88 × 10^9 fri per L2 gas, STRK at $0.0465
(about $0.04 per check with the OpenZeppelin verifier, $0.02 with the small one).

These transactions were sent by a migrated account whose class is Sierra 1.8.0. **Who sends the
transaction matters:** when a class compiled to Sierra before 1.7 runs above the check in the same
transaction, Starknet charges the whole call in Cairo steps, which costs more L2 gas for the same
code. Sent by an OpenZeppelin account of class `0x05b4b537…` (Sierra 1.6.0), the same checks cost:

| Signer account | One check, L2 gas | Transactions (×0 / ×4) |
| --- | ---: | --- |
| OpenZeppelin ECDSA account | 0.22M | [0x7e959a0a…](https://sepolia.voyager.online/tx/0x7e959a0a0442ad7d9bfee1a2a090ad08560619638a731d716d21ec17686a0a4) / [0x3049f6b4…](https://sepolia.voyager.online/tx/0x3049f6b4670721c1df481f80c8ec7971f1ca27bfe1259351ec1e7666c0e9777) |
| Migrated account, OpenZeppelin SHAKE-256 verifier | 123.8M (2.5×) | [0x6476f2ca…](https://sepolia.voyager.online/tx/0x6476f2ca6dd020745de195fada7942e3f844def7b3faae16b8aa8fa05120391) / [0x44f8664b…](https://sepolia.voyager.online/tx/0x44f8664b6e3a6cf276ac732025a7f3c6e9fc0f733b54492a7d75717736ccba6) |
| Migrated account, Provably Fast small verifier | 69.4M (2.7×) | [0x2e6efc65…](https://sepolia.voyager.online/tx/0x2e6efc6556c7c0008d072a766166e527cb6f23484f7ef6c498f146416613c6d) / [0x7c13f629…](https://sepolia.voyager.online/tx/0x7c13f629c67544da9ef8876334f12b069da3ef07f25723ae0cb21a2a3cac2fd) |

## What follows from the numbers

- **Checks inside `__validate__` are bounded.** Validation may use at most 10^8 Sierra gas
  (`validate_max_sierra_gas`). One check against an account on the OpenZeppelin verifier takes
  half of it, so an account or paymaster that validates two such signatures in `__validate__`
  hits the limit; with the small verifier, three fit. Carlos ([Zealynx](https://zealynx.io)) raised this on the forum
  ([/t/116470](https://community.starknet.io/t/116470)); the measurement confirms it for the
  OpenZeppelin verifier.
- **Checks in `__execute__` scale linearly** and are paid by whoever sends the transaction: a
  contract that settles a batch of N signed orders pays about N × 25.8M to N × 49.6M L2 gas.
- **Old sender classes cost more.** A transaction sent from an account whose class is Sierra
  before 1.7 pays about 2.5 times as much for the same check. In
  [`wallet-coverage.md`](wallet-coverage.md) that is every class except Argent 0.5.0 and Braavos
  1.2.0, Argent 0.4.0 included. A migrated account runs a Sierra 1.8.0 class, so once it sends,
  it pays the lower figure.
- **The verifier is the lever.** The small verifier halves the cost against the OpenZeppelin one,
  and the account can switch verifiers without moving (see
  [`verifier-replacement.md`](verifier-replacement.md)).

## Reproduce

```sh
cd contracts && scarb build && scarb cairo-test   # includes tests_consumer.cairo
cd ../signer && node consumer_sepolia.mjs         # needs a funded Sepolia deployer in .keys/
```
