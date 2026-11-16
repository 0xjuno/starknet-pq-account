#!/usr/bin/env python3
"""Turn the reproduce.sh logs into results.json and a Markdown table on stdout.

Usage: python3 -I bench/pf01/summarize.py WORK_DIR CORPUS RESULTS
"""

import json
import re
import statistics
import sys
from pathlib import Path

VARIANTS = ["baseline", "compact", "record"]
ACCOUNT = "pq_accounts_Falcon512ShakeAccount"
LINE = re.compile(r"\[(PASS|FAIL)\] \S+::(\w+) .*?l2_gas: ~(\d+)")
SUMMARY = re.compile(r"Tests: (\d+) passed, (\d+) failed")


def tests(log: Path) -> tuple[dict, dict]:
    gas, status = {}, {}
    text = log.read_text()
    for result, name, l2 in LINE.findall(text):
        status[name] = result
        gas[name] = int(l2)
    passed = failed = 0
    for p, f in SUMMARY.findall(text):
        passed, failed = passed + int(p), failed + int(f)
    return gas, {"passed": passed, "failed": failed, "failing": sorted(
        n for n, s in status.items() if s == "FAIL")}


def hybrid_sizes(target: Path) -> dict:
    sizes = {}
    for casm_path in sorted(target.glob("pq_hybrid_*.compiled_contract_class.json")):
        name = casm_path.name.split(".")[0].removeprefix("pq_hybrid_")
        sierra_path = casm_path.with_name(casm_path.name.replace("compiled_contract_class",
                                                                  "contract_class"))
        sizes[name] = {"casm_bytecode_felts": len(json.loads(casm_path.read_text())["bytecode"]),
                       "sierra_class_bytes": sierra_path.stat().st_size}
    return sizes


def main() -> None:
    work, corpus_path, out_path = (Path(a) for a in sys.argv[1:4])
    corpus = json.loads(corpus_path.read_text())
    env = dict(line.split("=", 1) for line in (work / "env.txt").read_text().splitlines())
    results = {"environment": env, "corpus_vectors": len(corpus["vectors"]), "variants": {}}

    for variant in VARIANTS:
        gas, falcon_status = tests(work / f"{variant}.falcon.log")
        _, ntt_status = tests(work / f"{variant}.ntt.log")
        per_vector = []
        for v in corpus["vectors"]:
            n = v["id"]
            if f"verify_{n}" not in gas or f"baseline_{n}" not in gas:
                raise SystemExit(f"{variant}: vector {n} did not run")
            per_vector.append({"id": n, "blocks": v["blocks"],
                               "l2_gas": gas[f"verify_{n}"] - gas[f"baseline_{n}"]})
        by_blocks = {b: [p["l2_gas"] for p in per_vector if p["blocks"] == b] for b in (8, 9)}
        target = work / f"ws-{variant}" / "target" / "dev"
        casm = json.loads((target / f"{ACCOUNT}.compiled_contract_class.json").read_text())
        build_log = (work / f"{variant}.build.log").read_text()
        results["variants"][variant] = {
            "mean_l2_gas": round(statistics.mean(p["l2_gas"] for p in per_vector)),
            "mean_l2_gas_by_blocks": {str(b): round(statistics.mean(g)) for b, g in by_blocks.items()},
            "worst_l2_gas": max(p["l2_gas"] for p in per_vector),
            "account_casm_bytecode_felts": len(casm["bytecode"]),
            "account_sierra_class_bytes": (target / f"{ACCOUNT}.contract_class.json").stat().st_size,
            "hybrid_classes": hybrid_sizes(work / f"hybrid-{variant}" / "contracts" / "target" / "dev"),
            "build_size_warnings": re.findall(r"contract `(\w+)`:\s*\n?\s*81920 felts allowed\. "
                                              r"Actual size: (\d+) felts", build_log),
            "falcon_512_tests": falcon_status,
            "ntt_tests": ntt_status,
            "per_vector": per_vector,
        }

    out_path.write_text(json.dumps(results, indent=1) + "\n")

    base = results["variants"]["baseline"]["mean_l2_gas"]
    print("| Variant | Mean L2 gas | 8-block | 9-block | Worst | vs baseline | Account CASM felts | Sierra bytes |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for variant, r in results["variants"].items():
        print(f"| {variant} | {r['mean_l2_gas']:,} | {r['mean_l2_gas_by_blocks']['8']:,} | "
              f"{r['mean_l2_gas_by_blocks']['9']:,} | {r['worst_l2_gas']:,} | "
              f"{base / r['mean_l2_gas']:.3f}x | {r['account_casm_bytecode_felts']:,} | "
              f"{r['account_sierra_class_bytes']:,} |")
    print()
    print("| Variant | HybridShakeAccount CASM felts | HybridPoseidonAccount | HybridMigratableAccount |")
    print("| --- | ---: | ---: | ---: |")
    for variant, r in results["variants"].items():
        h = r["hybrid_classes"]
        print(f"| {variant} | {h['HybridShakeAccount']['casm_bytecode_felts']:,} | "
              f"{h['HybridPoseidonAccount']['casm_bytecode_felts']:,} | "
              f"{h['HybridMigratableAccount']['casm_bytecode_felts']:,} |")
    for variant, r in results["variants"].items():
        print(f"{variant}: falcon_512 tests {r['falcon_512_tests']}, ntt tests {r['ntt_tests']}, "
              f"size warnings {r['build_size_warnings']}")


if __name__ == "__main__":
    main()
