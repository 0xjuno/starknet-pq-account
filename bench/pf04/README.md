# PF-04: account-level benchmarks and limits

Gas, steps, class sizes and libfuncs of this project's hybrid classes with the baseline verifier
and three Provably Fast candidates (issue #5). Bare-verifier figures are in
[`bench/pf01`](../pf01/README.md); correctness is [`bench/pf03`](../pf03/README.md).

Everything here is a **local snforge measurement** (blockifier, Sierra-gas mode), not a Sepolia
receipt. Full-transaction figures from Sepolia are in [Sepolia receipts](#sepolia-receipts).

## Reproduce

```sh
# scarb 2.18.0, snforge 0.59.0 and universal-sierra-compiler 2.10.3 on PATH
bench/pf04/run.sh            # rewrites results.json, fails on a limit or budget
bench/pf04/run.sh --check    # what CI runs: same checks, results.json untouched
bench/pf04/screen.sh JOB...  # declare size of board entries as our verifier class (downloads)
```

`run.sh` takes one to five minutes, depending on what is already compiled, and sends nothing.

## Method

- **Inputs.** The 27 PF-01 corpus signatures (11 eight-block, 16 nine-block, including the
  569-word worst case) become hybrid signatures with an ECDSA half from an intentionally public
  key (`fixtures.json`, from `gen_fixtures.mjs`; RFC 6979, so reproducible). The migration uses
  the key-possession proof in `contracts/src/tests_wallets_fixture.cairo`.
- **Accounts.** A migrated account is `HybridMigratableAccount` holding both keys and the
  verifier class hash, so `__validate__` library-calls the verifier, exactly as on a migrated
  wallet. The candidates exist only as verifier classes; a directly deployed `HybridShakeAccount`
  is measured for the baseline only.
- **Pairs.** `gen_tests.py` writes every measurement as a test and a `setup_` twin that builds the
  same state and inputs without the call. The figure is the difference of their L2 gas, the
  PF-01 method. Cross-check: snforge's own per-entrypoint figure (`--gas-report`) is exactly
  96,090 gas lower on every vector and verifier, the cost of the test calling into the account.
- **Rejected signature.** Valid ECDSA half, Falcon half of another message: the most expensive way
  to fail (ECDSA is checked first, so a bad ECDSA half costs almost nothing).
- **Migration.** A legacy OpenZeppelin-style account (`src/legacy.cairo`) runs `upgrade` to
  `HybridMigratableAccount` and `migrate` with the proof. Real Argent and Braavos classes are
  measured on Sepolia.
- **Steps** are measured separately in Cairo-steps mode, worst vector only.

## Results

Run on 2026-10-27, Darwin arm64, scarb 2.18.0 / cairo 2.18.0 / Sierra 1.8.0, snforge 0.59.0,
universal-sierra-compiler 2.10.3. Full figures in `results.json`. L2 gas:

| Path | baseline | compact | record | small (selected) | small saving |
| --- | ---: | ---: | ---: | ---: | ---: |
| `__validate__`, migrated account, mean | 50,396,185 | 26,431,759 | 26,130,688 | 27,215,883 | 46.0% |
| `__validate__`, migrated account, 8-block mean | 47,820,808 | 25,451,749 | 25,150,129 | 26,231,313 | 45.1% |
| `__validate__`, migrated account, 9-block mean | 52,166,757 | 27,105,517 | 26,804,823 | 27,892,774 | 46.5% |
| `__validate__`, migrated account, worst | 52,177,683 | 27,915,024 | 27,614,917 | 28,722,966 | 45.0% |
| `__validate_declare__`, worst | 52,172,283 | 27,909,624 | 27,609,517 | 28,717,566 | 45.0% |
| `is_valid_signature`, worst | 52,369,363 | 28,106,704 | 27,806,597 | 28,914,646 | 44.8% |
| rejected signature, worst | 52,411,463 | 27,231,021 | 26,915,914 | 27,116,653 | 48.3% |
| migration (`upgrade` + `migrate`) | 69,386,419 | 44,272,637 | 43,971,120 | 45,057,399 | 35.1% |

`__validate_declare__`, `is_valid_signature` and rejection are measured on vectors 0 (first
eight-block) and 26 (worst nine-block). Directly deployed `HybridShakeAccount` validation: mean
50,045,745, worst 51,827,243, about 350k below the migrated account's (no library call). Small
costs 3.0% more than compact per validation (27.2M against 26.4M mean).

Validation steps on the worst vector: 331,338 baseline, 182,602 compact, 179,553 record, 189,908
small.

### Limits and headroom

Sepolia and mainnet both ran Starknet 0.14.4 on 2026-10-27 (`starknet_getBlockWithTxHashes`).
Figures for the selected class (small) unless stated.

| Limit | Value | Source | Here | Headroom |
| --- | ---: | --- | ---: | ---: |
| Validation Sierra gas | 100,000,000 | versioned constants 0.14.4 `validate_max_sierra_gas` | 28,722,966 | 71.3% |
| Validation steps | 1,000,000 | versioned constants 0.14.4 `validate_max_n_steps` | 189,908 | 81.0% |
| **Declare L2 gas (one block)** | 5,800,000,000 | batcher `max_receipt_l2_gas_in_block` | 5,437,624,320 | 6.2% |
| CASM bytecode felts | 81,920 | sierra compiler `DEFAULT_MAX_BYTECODE_SIZE` | 64,163 | 17,757 |
| Sierra program felts | 81,920 | gateway `max_contract_bytecode_size` | 68,569 | 13,351 |
| Declared class object bytes | 4,089,446 | gateway `max_contract_class_object_size` | 3,350,894 | 18.1% |
| Compiled class object bytes | 4,089,446 | class manager `max_compiled_contract_class_object_size` | 1,741,663 | 57.4% |
| Signature felts | 4,000 | gateway `max_signature_length` | 62 | |

Validation (`__validate__` or `__validate_declare__`) with the baseline uses up to 52.2M of the
100M cap (47.8% headroom).

Sources (starkware-libs/sequencer): `crates/blockifier/resources/blockifier_versioned_constants_0_14_4.json`
at `f971cfda`, and `apollo_gateway_config/src/config.rs`,
`apollo_class_manager_config/src/config.rs`, `apollo_sierra_compilation_config/src/config.rs` and
`deployments/sequencer/configs/jsonnet/lib/applicative_config/default_replacers.libsonnet` at
`ced8be53` (main, 2026-10-27). The gateway, class-manager and batcher values are defaults; the
deployed configuration is not public, so they are the best available evidence, not a guarantee.
"Class object bytes" is computed the way the gateway does (compact JSON, ABI as a string), so it
differs slightly from the size of the file Scarb writes.

| Class | CASM felts | Sierra felts | Class object bytes | Compiled object bytes | Declare L2 gas | of block cap |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `HybridShakeAccount` | 53,237 | 53,532 | 2,038,866 | 1,439,349 | 4,377,213,440 | 75.5% |
| `HybridShakeVerifierPfCompact` | 71,580 | 71,809 | 3,149,439 | 2,141,080 | 5,874,137,600 | 101.3% |
| `HybridShakeVerifierPfRecord` | 77,902 | 76,146 | 3,422,453 | 2,329,159 | 6,310,728,960 | 108.8% |
| `HybridShakeVerifierPfSmall` | 64,163 | 68,569 | 3,350,894 | 1,741,663 | 5,437,624,320 | 93.8% |
| `HybridShakeVerifierPfSmallKeyRead` | 63,912 | 68,420 | 3,341,785 | 1,735,081 | 5,421,249,280 | 93.5% |
| `HybridMigratableAccount` | 7,719 | 3,546 | 181,970 | 177,227 | 468,300,800 | 8.1% |
| `HybridPoseidonAccount` | 49,043 | 51,261 | 1,900,820 | 1,331,138 | 4,112,410,880 | 70.9% |
| `VerifierSwitchGuard` | 1,164 | 978 | 36,318 | 27,626 | 88,408,320 | 1.5% |

### Declare size: the limit the board does not check

A declare's L2 gas is mostly the class's code: 1,280 L2 gas per byte (versioned constants 0.14.4
`archival_data_gas_costs.gas_per_code_byte`), with 32 bytes per CASM felt and per Sierra felt,
plus the ABI. `summarize.py` computes it; it matches the network's own declare estimates (Sepolia
`estimateDeclareFee`, 2026-10-27) to within 0.01% for `VerifierSwitchGuard`, compact and small.

A transaction must fit in one block, and the batcher's default block limit on receipt L2 gas is
5.8e9. Compact (5.87e9) and record (6.31e9) exceed it. Compact's declare was accepted by the
gateway and then evicted from the Sepolia mempool on each of three attempts, the last with the
tip recent blocks paid; record was not tried. `run.sh` fails if any class other than these two
exceeds the cap, or if either of them stops exceeding it (`NOT_DECLARABLE` in `summarize.py`).

The board limits CASM felts and Sierra class bytes, which compact and record both satisfy, and
ranks by gas. Smaller board CASM does not mean a smaller declare: entries that moved code out of
CASM often grew Sierra. Board entries screened as `HybridShakeVerifierPf*` (`screen.sh`, all
unbroken on the 2026-10-26 snapshot, which the board still served on 2026-10-27):

| Job | Board gas | Board CASM | CASM | Sierra | Declare L2 gas | of cap | Attacks withstood |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `fj_c3459a8b` (record) | 24,097,870 | 81,152 | 77,902 | 76,146 | 6,310,728,960 | 108.8% | 0 |
| `fj_3a0b1c78` (compact) | 24,399,230 | 72,908 | 71,580 | 71,809 | 5,874,137,600 | 101.3% | 0 |
| `fj_f714ca07` | 24,962,654 | 72,451 | 71,123 | 82,840 | 6,307,248,640 | 108.7% | 3 |
| `fj_ae4ffc56` | 24,989,094 | 64,408 | 63,080 | 78,523 | 5,800,983,040 | 100.0% | 1 |
| `fj_29a40693` | 25,027,734 | 62,251 | 60,923 | 77,399 | 5,666,593,280 | 97.7% | 0 |
| `fj_8777d5b7` | 25,078,934 | 62,303 | 60,975 | 79,735 | 5,764,405,760 | 99.4% | 2 |
| `fj_7c918e54` | 25,113,634 | 62,997 | 61,669 | 84,002 | 5,967,608,320 | 102.9% | 1 |
| **`fj_dee1326c` (small)** | 25,182,444 | 65,491 | 64,163 | 68,569 | 5,437,626,880 | 93.8% | 1 |
| `fj_04b5e7e9` | 25,580,426 | 71,347 | 70,014 | 67,247 | 5,623,134,720 | 97.0% | 2 |
| `fj_b9d48924` | 26,218,820 | 72,367 | 71,029 | 65,849 | 5,607,447,040 | 96.7% | 0 |
| `fj_95e6400d` | 28,527,103 | 60,573 | 59,235 | 61,440 | 4,943,772,160 | 85.2% | |
| `fj_3bc226aa` | 28,673,954 | 52,961 | 51,623 | 57,984 | 4,490,426,880 | 77.4% | |
| `fj_fd14477b` | 28,879,997 | 46,449 | 45,111 | 54,654 | 4,087,298,560 | 70.5% | |

The screen covers every unbroken record-list entry under 26.5M gas that is smaller than compact on
the board, plus three older, smaller ones. The challenge's own accounts are about the size of our
verifier classes (our compact class is 1,328 CASM felts smaller than the board's compact account),
so this is not a cost of the hybrid wrapper: the board's own compact account could not be declared
either. A challenge rule of `1280 * (32 * (CASM + Sierra felts) + ABI bytes) <= 5.8e9`, with room
for a wrapper, would keep entries deployable.

### Libfuncs

`contracts/` is built with `allowed-libfuncs-deny = true` against mainnet's audited list. The
sequencer compiles declared classes against its own bundled list (`DEFAULT_ALLOWED_LIBFUNCS_LIST
= Bundled`), which was narrowed on 2026-09-16, so `run.sh` also builds every class from a clean
copy against that list: `network_libfuncs.json`, from
`crates/apollo_compile_to_casm/resources/allowed_libfuncs.json` at `ced8be53` (Apache-2.0,
SHA-256 `3b4ebcfa…eb0ff9dc`). All classes build. The bundled option first appeared on `main` on
2026-09-16 and the deployed 0.14.4 build may predate it and use the audited list instead; the
classes pass both, so either way they compile. Removing `keccak_syscall` from the list makes the
candidate verifier classes fail, so the check is live. Scarb does not rebuild when only the list
changes, which is why the check uses a fresh copy.

### PF-11: reading the Falcon key once

`HybridShakeVerifierPfSmallKeyRead` ("smallkr" in the tests) is small with one change: the key is
read with its length read once (`read_falcon_public_key_once` in `contracts/src/hybrid.cairo`).
`Vec::at` reads the length again for every element to check bounds, 29 storage reads per signature.
The storage layout is the same, so a migrated account reads the same key, and the guarded switch
installs it over small (`small_to_small_key_read_and_back_keeps_the_keys` in `tests_guard.cairo`).
The other classes are byte-identical to `testnet-v1`.

| Path | small | smallkr | Change |
| --- | ---: | ---: | ---: |
| `__validate__`, migrated account, mean | 27,215,883 | 26,549,273 | -666,610 (-2.4%) |
| `__validate__`, migrated account, worst | 28,722,966 | 28,056,356 | -666,610 |
| `is_valid_signature`, worst | 28,914,646 | 28,248,036 | -666,610 |
| rejected signature, worst | 27,116,653 | 26,450,043 | -666,610 |
| migration (`upgrade` + `migrate`) | 45,057,399 | 44,390,789 | -666,610 |
| validation steps, worst vector | 189,908 | 183,384 | -6,524 |
| declare L2 gas | 5,437,624,320 | 5,421,249,280 | 93.5% of the cap |

The saving is the same on every vector, as expected of a fixed number of storage reads, and
matches the -666,710 starkience reported on Provably Fast for the same change (thread
bt1_fc46cf7e03432c994fa443ec). The class is not declared on Sepolia yet.

## Selection

**Small (`fj_dee1326c`, `HybridShakeVerifierPfSmall`).** It is the cheapest screened entry whose
declare fits a block with a margin (6.2%, about 360M L2 gas), and it passes PF-03 on all 136
vectors. It costs 3.0% more per validation than compact and still saves 46% against the baseline.
Compact and record are faster but cannot be declared; they stay in the repository as measured
comparisons. Among the entries that fit, `fj_29a40693` (97.7%) and `fj_04b5e7e9` (97.0%) leave
too little margin for a future compiler or wrapper change, and the next entries with real margin
cost about 28.5M on the board.

## Budgets

`budgets.json` holds a maximum for every metric in `results.json` (`metrics`): the measured value
plus 1%, never above the network limit for a class that fits it. `run.sh` fails if a metric
exceeds its budget, has no budget, or any class or validation exceeds a network limit. snforge's
figures are deterministic, so any change is real.

A deliberate change (a new verifier, a compiler upgrade) updates `budgets.json` in the same pull
request, with the old and new figures and the reason in the commit message; the reviewer approves
the budget change with the code. Regenerate with `run.sh`, then set each changed budget to the new
value plus 1%.

## Sepolia receipts

Complete transactions on Sepolia (Starknet 0.14.4) on 2026-10-27, collected by
`signer/pf04_sepolia.mjs receipts` into `sepolia.json`. Small: real Argent and Braavos accounts
from fresh words, migrated in place by `signer/wallet_migrate_demo.mjs` (`PQ_MATRIX_RUN=pf04-small`)
to verifier class `0x333aa6a6…afb0fb1`, migratable class `0x4b067679…e27a78`. Baseline: the
`HybridShakeAccount`-verifier runs in `contracts/docs/wallet-coverage.md`, same migratable class.
L2 gas from the receipts:

| Wallet class | Transaction | baseline | small | change |
| --- | --- | ---: | ---: | ---: |
| Argent 0.5.0 (Sierra 1.7.0) | migration (`upgrade` → `perform_upgrade`) | 74,716,214 | 50,330,764 | -32.6% |
| Argent 0.5.0 | hybrid transfer | 53,946,323 | 29,566,303 | -45.2% |
| Braavos 1.2.0 (Sierra 1.7.0) | migration (`[upgrade, migrate]`) | 70,122,982 | 48,531,148 | -30.8% |
| Braavos 1.2.0 | hybrid transfer | 53,952,403 | 29,565,553 | -45.2% |
| Argent 0.3.1 (Sierra 1.4.0) | migration (`upgrade` → `execute_after_upgrade`) | 137,979,920 | 83,499,920 | -39.5% |
| Argent 0.3.1 | hybrid transfer | 49,612,741 | 29,554,543 | -40.4% |

L1 data gas is unchanged (3,328 per migration, 192 per transfer). A single transfer's cost depends
on how many SHAKE blocks its signature's hash-to-point needs: the baseline Argent 0.3.1 transfer
(49.6M) was cheaper than the other two (54.0M), consistent with eight blocks against nine. The three
small transfers happened to land within 12k gas of each other. The transfer projection in PF-00
(53.9M to about 30M, -44%) holds: 53.9M to 29.6M, -45%.

For each small run, `sepolia.json` also records that the stored ECDSA and Falcon keys equal the
keys derived from the words, that the balance dropped by exactly the fee, and that an ECDSA-only
transfer was rejected in `__validate__`.

Declares:

| Class | From | L2 gas | Fee | Transaction |
| --- | --- | ---: | ---: | --- |
| `HybridShakeVerifierPfSmall` | OpenZeppelin deployer | 5,438,297,280 | 103.48 STRK | `0x18feecd7…c0cd62` |
| `VerifierSwitchGuard` | the migrated Argent 0.5.0 account (validated by small) | 117,313,246 | 2.24 STRK | `0x687a8500…169e23` |

The verifier's declare is 0.013% above the code-size formula (the rest is the declare's own
execution). The guard's declare is about 88.4M of code plus about 28.9M of hybrid validation,
matching the local `__validate_declare__` figure (28.7M). Fees are Sepolia's, at about 1.9e10 fri
per L2 gas that day, not mainnet prices.

Two findings from these runs, both handled in the scripts:

- **Sepolia evicts zero-tip transactions.** Every recent transaction paid a tip of 1e8 fri per L2
  gas; the scripts now use `getEstimateTip`. `signer/browser_setup.mjs` and the browser page
  (`signer/browser-wallet.template.html`) still send `tip: 0n` and were not changed here.
- **starknet.js estimates fees with validation skipped** (`skipValidate: true` by default). For a
  hybrid account that omits about 28M L2 gas of Falcon validation, so a bound built from the
  default estimate makes validation run out of gas ("Account validation failed"). The kit's
  `switchVerifier` already estimates with `skipValidate: false`; `pf04_sepolia.mjs` now does too.
