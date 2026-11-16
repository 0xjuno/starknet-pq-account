#!/usr/bin/env python3
"""Check a `scarb cairo-test` log of the PF-03 suite and write results.json.

Fails unless every (vector, verifier) test passed. Gas is cairo-test's estimate minus the
vector's inputs-only test, so it is the cost of `verify` alone (not Starknet L2 gas).

Usage: python3 -I bench/pf03/summarize.py LOG [bench/pf03/vectors.json] [bench/pf03/results.json]
"""

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).parent
VERIFIERS = ["baseline", "compact", "record", "small"]
LINE = re.compile(r"test \S+::v(\d+)_(\w+) \.\.\. (ok|fail)(?: \(gas usage est\.: (\d+)\))?")


def main() -> None:
    log = Path(sys.argv[1]).read_text()
    vectors = json.loads((Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "vectors.json").read_text())["vectors"]
    out = Path(sys.argv[3]) if len(sys.argv) > 3 else HERE / "results.json"

    status, gas = {}, {}
    for n, name, result, g in LINE.findall(log):
        status[(int(n), name)] = result
        if g:
            gas[(int(n), name)] = int(g)
    missing = [(v["id"], name) for v in vectors for name in VERIFIERS + ["inputs"]
               if status.get((v["id"], name)) != "ok"]
    if missing:
        raise SystemExit(f"{len(missing)} tests missing or failing, first: {missing[:5]}")

    per_verifier = {}
    for name in VERIFIERS:
        cost = {v["id"]: gas[(v["id"], name)] - gas[(v["id"], "inputs")] for v in vectors}
        valid = [v for v in vectors if v["expected"]]
        invalid = [v for v in vectors if not v["expected"]]
        worst_valid = max(valid, key=lambda v: cost[v["id"]])
        worst_invalid = max(invalid, key=lambda v: cost[v["id"]])
        per_verifier[name] = {
            "agrees_with_reference": len(vectors),
            "worst_valid": {"id": worst_valid["id"], "gas": cost[worst_valid["id"]],
                            "description": worst_valid["description"]},
            "worst_invalid": {"id": worst_invalid["id"], "gas": cost[worst_invalid["id"]],
                              "description": worst_invalid["description"]},
            "worst_invalid_over_worst_valid": round(cost[worst_invalid["id"]] / cost[worst_valid["id"]], 4),
            "by_reason_max": {r: max(cost[v["id"]] for v in vectors if v["reason"] == r)
                              for r in sorted({v["reason"] for v in vectors})},
            "per_vector": cost,
        }
    out.write_text(json.dumps({"vectors": len(vectors), "verifiers": per_verifier}, indent=1) + "\n")

    print(f"All {len(vectors)} vectors: {', '.join(VERIFIERS)} agree with the reference.")
    print("| Verifier | Worst valid | Worst invalid | Ratio | Worst invalid input |")
    print("| --- | ---: | ---: | ---: | --- |")
    for name, r in per_verifier.items():
        print(f"| {name} | {r['worst_valid']['gas']:,} | {r['worst_invalid']['gas']:,} | "
              f"{r['worst_invalid_over_worst_valid']:.3f} | {r['worst_invalid']['description']} |")
    reasons = sorted({v["reason"] for v in vectors})
    print("\n| Verifier | " + " | ".join(f"max {r}" for r in reasons) + " |")
    print("| --- |" + " ---: |" * len(reasons))
    for name, r in per_verifier.items():
        print(f"| {name} | " + " | ".join(f"{r['by_reason_max'][x]:,}" for x in reasons) + " |")


if __name__ == "__main__":
    main()
