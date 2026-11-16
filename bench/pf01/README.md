# PF-01: baseline and candidate reproduction

Local measurements of OpenZeppelin's Falcon-512 SHAKE-256 verifier and the two pinned
Provably Fast candidates (issue #2). Provenance, digests and contributors are in
[`vendor/provably-fast/falcon-512/PROVENANCE.md`](../../vendor/provably-fast/falcon-512/PROVENANCE.md).

These are bare-verifier figures from the challenge's own harness, not costs of this project's
hybrid account; account-level costs are PF-04 (issue #5).

## Reproduce

```sh
# scarb 2.18.0, snforge 0.59.0 and universal-sierra-compiler 2.9.1 on PATH
bench/pf01/reproduce.sh /tmp/pf01-work
```

The script checks the patch digests, clones the baseline commit, checks that
`vendor/cairo-pq-verifiers` is identical to it, makes one git worktree per variant, applies the
patch, runs `snforge test` for `pqbench_falcon_512` and `pqbench_ntt`, builds upstream's
`pq_accounts`, builds this repository's `contracts/` (unchanged) against the variant's crates,
and rewrites `results.json`. Both builds use mainnet's audited libfunc list with
`allowed-libfuncs-deny = true`, so any other libfunc fails the build (Scarb only warns by
default). It takes about 90 seconds on an M-series Mac.

To regenerate the corpus (not needed to reproduce; the committed one is the pinned artifact):

```sh
python3 -I bench/pf01/gen_corpus.py --falcon-py /path/to/falcon.py \
  --reference /path/to/falcon512.py   # https://postquantum.provably.fast/reference/falcon512.py
```

## Corpus

`corpus.json`: 27 signatures on three tprest/falcon.py keys (commit `5145a818`), 11 needing eight
SHAKE blocks and 16 needing nine, the mix the challenge's held-out set uses. Salts were searched
to hit each block count before signing. The last vector is the most expensive of 2,000
nine-block salts (569 words read). Every vector is accepted by the challenge's reference
verifier (`falcon512.py`, SHA-256 `54624238…ce713e2`). The held-out challenge corpus is private,
so these means are not an exact reproduction of the board's.

## Results

Run on 2026-10-26, Darwin arm64, scarb 2.18.0 / cairo 2.18.0 / Sierra 1.8.0, snforge 0.59.0,
universal-sierra-compiler 2.9.1. L2 gas is Sierra gas from snforge, `verify_N - baseline_N`
(the upstream paired-test method). Account sizes are upstream's `Falcon512ShakeAccount` built
with the audited libfunc list.

| Variant | Mean L2 gas | 8-block mean | 9-block mean | Worst valid | vs baseline | Account CASM felts | Sierra class bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | 48,401,490 | 45,826,113 | 50,172,062 | 50,182,988 | 1.000x | 52,315 | 2,142,604 |
| compact `fj_3a0b1c78` | 24,437,264 | 23,457,254 | 25,111,022 | 25,920,529 | 1.981x | 72,908 | 3,760,793 |
| record `fj_c3459a8b` | 24,136,013 | 23,155,454 | 24,810,148 | 25,620,242 | 2.005x | 81,152 | 4,025,263 |

Limits: 81,920 CASM felts, 4,089,446 Sierra class bytes, 100M L2 gas for validation.

This repository's classes, unchanged, built against each variant's crates (CASM felts; Sierra
class bytes in `results.json`):

| Variant | `HybridShakeAccount` | headroom | `HybridPoseidonAccount` | `HybridMigratableAccount` |
| --- | ---: | ---: | ---: | ---: |
| baseline | 53,237 | 28,683 | 49,043 | 7,719 |
| compact | 73,833 | 8,087 | 53,359 | 7,719 |
| record | 80,155 | 1,765 | 53,359 | 7,719 |

The project's own suite (`scarb cairo-test`, 54 tests including the browser and wallet
fixtures) also passes against both candidates; that check was run by hand and is not part of
the script.

### Against the board (external figures, from the 2026-10-26 snapshot)

| Variant | Board mean | Local mean | Difference | Board CASM / Sierra bytes | Local |
| --- | ---: | ---: | ---: | --- | --- |
| baseline | 48,398,466 | 48,401,490 | +0.006% | 52,315 / 2,142,604 | identical |
| compact | 24,399,230 | 24,437,264 | +0.16% | 72,908 / 3,760,793 | identical |
| record | 24,097,870 | 24,136,013 | +0.16% | 81,152 / 4,025,263 | identical |

The 8-block means agree with the board to within 0.02% for all three. The candidates' 9-block
means are about 0.25% higher than the board's because this corpus includes the 569-word vector;
without it they are within 0.05%.

### Tests

The upstream `pqbench_falcon_512` (plus the corpus) and `pqbench_ntt` suites pass for all three
variants: 108 and 20 tests for the baseline, 114 and 20 for each candidate (the patches add
tests). Building `pq_accounts` with either patch makes `Falcon512ShakeDirectAccount` exceed the
CASM limit (86,621 felts); the hint-variant account used here still fits.

## Findings

1. **Worst-case gas is higher than the board shows.** Among nine-block vectors, candidate gas rises
   about 3.1k-3.3k per extra word read (baseline: about 0.7k) up to 559 words, then jumps by about 840k at 569 words, on both candidates. The
   baseline barely moves (50.16M-50.18M across all nine-block vectors). From 200,000 random salts,
   about 1.2% read more than 560 words and the maximum seen was 575. The board's worst valid
   figures (25.06M compact, 24.76M record) come from its held-out set; the measured worst here
   is 25.92M and 25.62M. Both stay far below the 1.25x rejection rule and the 100M validation
   cap, but PF-03 and PF-04 should include high-word salts.
2. **Both candidates fit as this project's hybrid class, the record narrowly.** Built for real,
   `HybridShakeAccount` is 73,833 felts with the compact patch (8,087 to spare) and 80,155 with
   the record (1,765 to spare, 2.2%). Class sizes do not add: with the record patch the hybrid
   class is smaller than upstream's single-scheme account (81,152).
3. **The patches also change the Poseidon class.** They rewrite shared NTT code, so
   `HybridPoseidonAccount` grows from 49,043 to 53,359 felts even though its hash is untouched.
   PF-02 must keep the existing classes on the baseline crates, or re-measure and re-test them.
4. **Review cost.** Both patches are largely minified and use `bounded-int-utils` and a
   specialised `keccak_syscall` path. Neither had withstood an attack round when pinned.

## Provisional recommendation

**Compact (`fj_3a0b1c78`), by a small margin.** Both fit and both pass the same tests. The
record saves 301k gas (1.2%) per verification. The compact leaves 8,087 felts of class headroom
against the record's 1,765, so the hybrid class can absorb changes without hitting the limit.
The choice is close: if PF-02 ships a verifier-only class (which will be smaller) and PF-03
finds both equally sound, the record's 1.2% may be worth taking. Final selection follows PF-03's
correctness gate and PF-04's account-level measurements.
