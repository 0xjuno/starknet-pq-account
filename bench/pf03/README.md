# PF-03: differential correctness (part 1, test suite)

Every vector in `vectors.json` goes through OpenZeppelin's baseline Falcon-512 SHAKE-256 verifier
and the pinned Provably Fast candidates (issue #4; `small`, `fj_dee1326c`, added in PF-04), and each answer must equal the challenge's
reference verifier (`falcon512.py`, SHA-256 `54624238…ce713e2`). The reference is the authority,
not the unaudited baseline. CI runs it on every push (`falcon-differential` job).

This is part 1. The written review of the candidates' range and packing assumptions (the
issue's "readable explanation" criterion) is not done yet; see [Open](#open).

## Run

```sh
bench/pf03/run.sh    # scarb 2.18.0, python3; about 80 seconds on an M-series Mac
```

It regenerates `src/vectors.cairo` (one cairo-test per vector and verifier, about 1 MB, not
committed), runs it, fails unless every verifier agrees with the reference on every vector, and
rewrites `results.json`.

To regenerate the vectors (not needed to run; the committed file is the pinned artifact):

```sh
(cd signer && npm install --no-package-lock)
node bench/pf03/noble_vectors.mjs > /tmp/noble.json
python3 -I bench/pf03/gen_vectors.py --falcon-py /path/to/falcon.py \
  --reference /path/to/falcon512.py --noble /tmp/noble.json --seed 1
```

## Vectors (136)

| Category | Count | What |
| --- | ---: | --- |
| valid | 20 | 10 falcon.py signatures (tprest/falcon.py `5145a818`), 10 noble signatures (`@noble/post-quantum` 0.6.1 through `signer/falcon_adapter.mjs`) |
| tampered | 21 | per base signature (one falcon.py, one noble): message + 1, each salt half + 1, swapped s1, hint and key felts, s1[0] + 1 with and without re-hinting, hint[511] + 1, another key; plus a signature just over the norm bound |
| malformed | 35 | each half of a key, s1 and hint felt at q^9 (just out of range) and q^9 - 1 (in range), high half 2^123 - 1, felt p - 1, last felt at q^8 / q^8 - 1 / with a high half, salt halves 2^160 and p - 1, keys and signatures of the wrong length |
| random | 60 | seeded (`--seed 1`) mutations of valid vectors: +1, -1, a random bit, a random felt, an out-of-range half, zero |

Valid boundary cases: messages 0 and p - 1 (both signers), salt halves 0 and 2^160 - 1, salts
reading 565, 565, 568 and 574 SHAKE words (the most expensive of 30,000), and a signature with
norm 34,034,709, **17 under** the bound 34,034,726. Its rejected twin is **153 over**. Both are
built by adding x^k * (g, -f) to a sampled signature, which keeps the verification equation and
moves the norm in steps of a few thousand (see `gen_vectors.py`).

Reference verdicts: 20 VALID, 53 HINT, 41 ENCODING, 11 NORM, 7 LENGTH, 4 SALT_RANGE.

## Results

**All four verifiers agree with the reference on all 136 vectors** (680 tests pass).

Gas is cairo-test's estimate for `verify` alone (the vector's inputs-only test subtracted), not
Starknet L2 gas.

| Verifier | Worst valid | Worst invalid | Invalid / valid | Worst invalid input |
| --- | ---: | ---: | ---: | --- |
| baseline | 50,180,218 | 50,235,878 | 1.001 | salt_b + 1 |
| compact | 25,935,832 | 25,936,782 | 1.000 | 574-word vector, public key felt 24 random |
| record | 25,636,875 | 25,611,212 | 0.999 | 574-word vector, public key felt 24 random |
| small | 26,730,581 | 26,603,531 | 0.995 | 574-word vector, public key felt 24 random |

Most expensive rejection by reference reason:

| Verifier | ENCODING | HINT | LENGTH | NORM | SALT_RANGE |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 1,899,240 | 50,088,498 | 8,750 | 50,235,878 | 1,914,640 |
| compact | 25,936,782 | 25,905,086 | 18,820 | 25,155,146 | 15,820 |
| record | 25,611,212 | 25,591,886 | 16,140 | 24,840,389 | 12,740 |
| small | 26,603,531 | 26,372,571 | 18,610 | 25,033,768 | 15,610 |

## Findings

1. **No disagreement.** No candidate accepts anything the reference rejects or rejects
   anything it accepts, on these vectors. That is evidence, not proof: see coverage limits.
2. **Rejection cost stays under the challenge's 1.25x rule** for every verifier (worst invalid at
   most 1.001x the worst valid). It is a regression target, not a proof of account safety.
3. **The candidates check encodings late.** The baseline rejects a non-canonical key or signature
   within 1.9M gas; all three candidates first do the full SHAKE and NTT work (up to 26.6M) and reject
   at the end. They still reject all 41 such inputs. Rejections are cheap only for wrong lengths
   and out-of-range salts.
4. **The high-word slow path starts by 565 words.** Valid 565-word signatures cost about 790k more
   than a 545-word one on compact and record (small was not part of that measurement); the 574-word vector is the worst valid case. This
   refines PF-01's estimate of "about 560".

## Coverage limits

- 136 vectors and 60 random mutations from one seed are a small sample. The challenge's own
  screen uses about 600 inputs per record.
- The norm edge is approached from both sides (17 under, 153 over) but not hit exactly.
- SHAKE output and hash-to-point coefficients are checked only through the final verdict; there
  is no byte-level known-answer test of the candidates' SHAKE or of their unreduced internal
  coefficients (the functions are `pub(crate)` in the patched crates).
- Ten-block salts were not found (none in 200,000 random salts; PF-01), so the fallback past the
  ninth block is exercised only up to 574 words.
- No historical breaks: the board's `breaks` list was empty in the 2026-10-26 snapshot. Recheck
  before adoption.
- Python v0 and noble v0.1 keys are not compared with each other; each signer is checked against
  its own keys only.

## Open

For part 2 of PF-03:
- A readable account of each security-sensitive assumption in the candidates: bounded-int ranges,
  field wraparound, packed-lane interference, deferred NTT and reciprocal reductions, packed norm
  extraction, and the specialised `keccak_syscall` path. Both patches are largely minified.
- Byte-level SHAKE known-answer tests and hash-to-point coefficient comparisons.
- A larger fuzzing run, with seeds and coverage recorded.
