# Provably Fast Falcon-512 patches: provenance

Three cumulative patches from the Provably Fast Falcon-512 gas challenge
(https://postquantum.provably.fast/): compact and record pinned for PF-01 (issue #2), small added
in PF-04 (issue #5) because neither of the first two can be declared (see below). They are applied
on top of OpenZeppelin cairo-pq-verifiers at the challenge baseline. None is audited, and none is
reviewed or endorsed by OpenZeppelin.

## Crates

`crates/` holds one `falcon_512` + `ntt` pair per patch, used by the experimental verifier classes
`HybridShakeVerifierPfCompact` and `HybridShakeVerifierPfRecord` (`contracts/src/hybrid.cairo`,
PF-02, issue #3). They are generated, never edited by hand:

```sh
vendor/provably-fast/falcon-512/make_crates.sh          # regenerate
vendor/provably-fast/falcon-512/make_crates.sh --check  # CI: crates/ == baseline + patch + renames
```

Each pair is the vendored baseline crates with the patch applied. The only other change is the
package names (`pqbench_falcon_512_pf_<name>`, `pqbench_ntt_pf_<name>`) and the `use` paths that
name them, because Scarb cannot load two packages with the same name. `bench_interface` is shared
with the baseline, so all three implement the same `PqSignatureVerifier` trait. The baseline
crates and every existing class are unchanged.

## Baseline

- Repository: https://github.com/OpenZeppelin/cairo-pq-verifiers
- Commit: `bece5c07eeea5784e570c01108ec000d2d04ae40` (2026-07-22, "Merge pull request #22 from
  OpenZeppelin/feat/update-disclaimer")
- `vendor/cairo-pq-verifiers/` is byte-identical to this commit for the crates `bench_interface`,
  `ecdsa_stark`, `falcon_512`, `ntt`, the LICENSE and `falcon_signer.py` (checked by
  `bench/pf01/reproduce.sh`); only the workspace `Scarb.toml` was trimmed.

## Patches

Downloaded 2026-10-26 22:58 UTC from
`https://postquantum.provably.fast/api/participation/falcon/jobs/<JOB_ID>/patch`. Digests are in
`SHA256SUMS`. The record digest matches the one recorded during planning
(`23f3c793…d7b2f9`). The small patch was downloaded 2026-10-27 from the same endpoint, twice, with
identical bytes; the board's results response was byte-identical to the 2026-10-26 snapshot at that
time, so the snapshot holds its metadata too. All three patches change only `.cairo` files under `crates/falcon_512/src` and
`crates/ntt/src` (compact and record also add `crates/ntt/src/typed_ntt.cairo`). Accepted challenge patches are MIT
(https://postquantum.provably.fast/agent-brief.md).

| File | Job | Role | Board score (L2 gas) | Board account CASM felts | Author |
| --- | --- | --- | ---: | ---: | --- |
| `compact-fj_3a0b1c78817845a68e1e907928a541e4.patch` | `fj_3a0b1c78817845a68e1e907928a541e4` | compact candidate | 24,399,230 | 72,908 | odinfree |
| `small-fj_dee1326c0eef48e6989ed0338e9e9785.patch` | `fj_dee1326c0eef48e6989ed0338e9e9785` | selected: declarable (PF-04) | 25,182,444 | 65,491 | ryun1 |
| `record-fj_c3459a8b07a54bd5828d3fdde899c4e0.patch` | `fj_c3459a8b07a54bd5828d3fdde899c4e0` | record on 2026-10-26 | 24,097,870 | 81,152 | rukafe0x |

The baseline job is `fj_e72a9f8ffdad44708778069a03438857` (48,398,466 L2 gas; its patch is empty).

## Board state at download

`results-snapshot-2026-10-26.json` is the full response of
`https://postquantum.provably.fast/api/participation/falcon/results` at download time
(SHA-256 `ec1f66a9e1fe4b4fc71f6a64e6a69b35113c67a6d8a8d0870701879b4724723a`).

- `fj_c3459a8b` was still the record. No pinned patch was broken (`breaks` is empty).
- Compact and record showed `attacks_withstood: 0`: no hourly attack round had run against them
  yet. Small (`fj_dee1326c`, submitted 2026-10-21) showed `attacks_withstood: 1` and was not
  broken. Check `breaks` and the board again before adopting any; a later break or withdrawal
  does not change these pinned bytes.

## Contributors

Each patch is cumulative. The `builds_on` metadata in the snapshot lists these GitHub accounts
across each patch's ancestry:

- Compact (26 jobs): derek-flossman, mitchuski, odinfree, omarespejel, realadii, ryun1,
  samrendras, tanctl, zeeshan8281. One ancestor (`fj_f1a4e0e70f2c43e884f8b7067bb8b7de`, by
  omarespejel) is not in the snapshot.
- Record (11 jobs): mitchuski, nadai2010, odinfree, realadii, rukafe0x, starkience, tanctl.
- Small (2 jobs): ryun1. Its root (`fj_04b5e7e9`) lists no parents; its title credits
  `bt1_62a25b4a8267448c7889ee8f`, which the metadata does not resolve to an account.

`builds_on` is self-reported. The record's ancestry stops at two jobs (`fj_d982e293`,
`fj_457c374d`, both by odinfree, about 24.39M gas) that list no parents, so earlier work they
build on is probably not credited in this metadata. The board's per-record contributor lists
are the authority for credit.

## Declare size

The board checks CASM felts and Sierra class bytes, the gateway's per-class limits. A declare must
also fit in one block: it costs 1,280 L2 gas per byte of code (32 bytes per CASM and per Sierra
felt, plus the ABI), against the sequencer's default `max_receipt_l2_gas_in_block` of 5.8e9. As
`HybridShakeVerifierPf*` classes, compact needs 5.87e9 and record 6.31e9; compact's declare was evicted
from the Sepolia mempool on every attempt (record was not tried). Small needs 5.44e9 (93.8% of the cap). Smaller board
CASM does not imply a smaller declare: several smaller-CASM entries carry more Sierra.
`bench/pf04/README.md` has the measurements of eleven entries.

## Known review limitations

- Large parts of all three patches are minified (single-letter identifiers, whole modules on one line),
  so the arithmetic is hard to review by reading.
- All three enable the unstable `bounded-int-utils` Cairo feature and use the existing
  `keccak_syscall` on a specialised path.
- Compact and record inflate the upstream `Falcon512ShakeDirectAccount` past the 81,920-felt CASM limit
  (86,621 felts); the hint-variant account still fits.
- Gas rises steeply for the roughly 1.2% of salts whose hash-to-point reads more than about 560
  words (see `bench/pf01/README.md`).
