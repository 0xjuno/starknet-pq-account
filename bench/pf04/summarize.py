#!/usr/bin/env python3
"""Turn a bench/pf04/run.sh work directory into results.json, and check limits and budgets.

L2 gas is snforge's figure (blockifier, Sierra-gas mode) of the measured test minus its `setup_`
twin. Fails if any network limit (network_limits below) or any budget in budgets.json is exceeded.

Usage: python3 -I bench/pf04/summarize.py WORK_DIR CONTRACTS_TARGET_DIR OUT.json
"""

import json
import re
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFIERS = ("baseline", "compact", "record", "small", "smallkr")
SELECTED = "small"
CLASSES = ("HybridShakeAccount", "HybridShakeVerifierPfCompact", "HybridShakeVerifierPfRecord",
           "HybridShakeVerifierPfSmall", "HybridShakeVerifierPfSmallKeyRead",
           "HybridMigratableAccount", "HybridPoseidonAccount", "VerifierSwitchGuard")
LINE = re.compile(r"\[(PASS|FAIL)\] \S+::(\w+) .*?l2_gas: ~(\d+)")
SUMMARY = re.compile(r"Tests: (\d+) passed, (\d+) failed")
REPORT_ROW = re.compile(r"\| (\w+)\s+\| (\d+)\s+\| (\d+)\s+\| (\d+)\s+\| (\d+)\s+\| (\d+)\s+\|")
REPORT_CONTRACT = re.compile(r"\| (\w+) Contract")
STEPS = re.compile(r"\[PASS\] \S+::(\w+) .*\n\s+steps: (\d+)")

# Starknet 0.14.4 (Sepolia and mainnet on 2026-10-27). Sources in README.md.
NETWORK_LIMITS = {
    "validate_max_sierra_gas": 100_000_000,
    "validate_max_n_steps": 1_000_000,
    "max_casm_bytecode_felts": 81_920,
    "max_sierra_program_felts": 81_920,
    "max_contract_class_object_bytes": 4_089_446,
    "max_compiled_class_object_bytes": 4_089_446,
    "max_signature_length": 4_000,
    # A declare must fit in one block: sequencer default max_receipt_l2_gas_in_block.
    "max_receipt_l2_gas_in_block": 5_800_000_000,
}
# Versioned constants 0.14.4 archival_data_gas_costs.gas_per_code_byte; code is 32 bytes per CASM
# and per Sierra felt, plus the ABI. Matches the network's declare estimates to within 0.01%.
GAS_PER_CODE_BYTE = 1280
# Measured candidates whose declare does not fit a block. Kept for comparison, never declarable;
# the check fails if one of them starts to fit (update the docs) or another class stops fitting.
NOT_DECLARABLE = ("HybridShakeVerifierPfCompact", "HybridShakeVerifierPfRecord")


def gas_pairs(log: str) -> dict:
    gas, failed = {}, []
    for status, name, g in LINE.findall(log):
        if status != "PASS":
            failed.append(name)
        gas[name] = int(g)
    m = SUMMARY.search(log)
    if failed or not m or int(m.group(2)):
        sys.exit(f"snforge failures: {failed or 'see log'}")
    return {name: gas[name] - gas[f"setup_{name}"]
            for name in gas if not name.startswith("setup_")}


def gas_report(log: str) -> dict:
    """snforge --gas-report prints one table per test: {test: {"Contract.fn": gas}}."""
    out, test, contract = {}, None, None
    for line in log.splitlines():
        if m := LINE.search(line):
            test = m.group(2)
            out[test] = {}
        elif m := REPORT_CONTRACT.search(line):
            contract = m.group(1)
        elif (m := REPORT_ROW.search(line)) and test and contract:
            out[test][f"{contract}.{m.group(1)}"] = int(m.group(4))
    return out


def entrypoint_cross_check(reports: dict, d: dict, verifier: str, blocks: dict) -> dict:
    """snforge's own figure for the validating entrypoint, against the paired figure."""
    contract = "HybridShakeAccount" if verifier == "direct" else "HybridMigratableAccount"
    report = reports[verifier]
    own = {n: report[f"validate_{verifier}_{n}"][f"{contract}.__validate__"] for n in blocks}
    gap = [d[f"validate_{verifier}_{n}"] - own[n] for n in blocks]
    return {"entrypoint_mean": round(statistics.mean(own.values())), "entrypoint_worst": max(own.values()),
            "paired_minus_entrypoint": {"min": min(gap), "max": max(gap)}}


def class_size(target: Path, name: str) -> dict:
    sierra = json.loads((target / f"pq_hybrid_{name}.contract_class.json").read_text())
    casm_path = target / f"pq_hybrid_{name}.compiled_contract_class.json"
    casm = json.loads(casm_path.read_text())
    # What the gateway measures: the declared class serialised as compact JSON, ABI as a string.
    declared = {"sierra_program": sierra["sierra_program"],
                "contract_class_version": sierra["contract_class_version"],
                "entry_points_by_type": sierra["entry_points_by_type"],
                "abi": json.dumps(sierra["abi"], separators=(",", ":"))}
    abi_bytes = len(declared["abi"])
    return {"casm_bytecode_felts": len(casm["bytecode"]),
            "sierra_program_felts": len(sierra["sierra_program"]),
            "declare_code_l2_gas": GAS_PER_CODE_BYTE * (32 * (len(casm["bytecode"]) + len(sierra["sierra_program"])) + abi_bytes),
            "contract_class_object_bytes": len(json.dumps(declared, separators=(",", ":"))),
            "compiled_class_object_bytes": len(json.dumps(casm, separators=(",", ":")))}


def stats(values: list[int]) -> dict:
    return {"mean": round(statistics.mean(values)), "worst": max(values), "best": min(values)}


def main() -> None:
    work, target, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    corpus = json.loads((HERE.parent / "pf01/corpus.json").read_text())["vectors"]
    blocks = {v["id"]: v["blocks"] for v in corpus}
    d = gas_pairs((work / "gas.log").read_text())

    validate = {}
    for v in VERIFIERS + ("direct",):
        per = {n: d[f"validate_{v}_{n}"] for n in blocks}
        validate[v] = {**stats(list(per.values())),
                       "mean_by_blocks": {str(b): round(statistics.mean(g for n, g in per.items() if blocks[n] == b))
                                          for b in (8, 9)},
                       "per_vector": per}
    selected = sorted({int(k.rsplit("_", 1)[1]) for k in d if k.startswith("declare_")})
    calls = {kind: {v: {str(n): d[f"{kind}_{v}_{n}"] for n in selected} for v in VERIFIERS}
             for kind in ("declare", "is_valid", "reject")}
    migrate = {v: d[f"migrate_{v}"] for v in VERIFIERS}

    reports = {v: gas_report((work / f"report-{v}.log").read_text()) for v in VERIFIERS + ("direct",)}
    cross_check = {v: entrypoint_cross_check(reports, d, v, blocks) for v in VERIFIERS + ("direct",)}
    steps_raw = dict(STEPS.findall((work / "steps.log").read_text()))
    steps = {v: int(steps_raw[f"validate_{v}_26"]) - int(steps_raw[f"setup_validate_{v}_26"]) for v in VERIFIERS}
    sizes = {c: class_size(target, c) for c in CLASSES}

    metrics = {}
    for v, s in validate.items():
        metrics[f"validate.{v}.mean"] = s["mean"]
        metrics[f"validate.{v}.worst"] = s["worst"]
    for kind, by_v in calls.items():
        for v, per in by_v.items():
            metrics[f"{kind}.{v}.worst"] = max(per.values())
    for v, g in migrate.items():
        metrics[f"migrate.{v}"] = g
    for c, s in sizes.items():
        for k, val in s.items():
            metrics[f"size.{c}.{k}"] = val

    limit_errors = []
    worst_validation = max(max(s["worst"] for s in validate.values()),
                           max(max(p.values()) for p in calls["declare"].values()))
    if worst_validation > NETWORK_LIMITS["validate_max_sierra_gas"]:
        limit_errors.append(f"validation {worst_validation:,} gas > cap")
    if max(steps.values()) > NETWORK_LIMITS["validate_max_n_steps"]:
        limit_errors.append(f"validation {max(steps.values()):,} steps > cap")
    for c, s in sizes.items():
        for k, cap in (("casm_bytecode_felts", "max_casm_bytecode_felts"),
                       ("sierra_program_felts", "max_sierra_program_felts"),
                       ("contract_class_object_bytes", "max_contract_class_object_bytes"),
                       ("compiled_class_object_bytes", "max_compiled_class_object_bytes")):
            if s[k] > NETWORK_LIMITS[cap]:
                limit_errors.append(f"{c} {k} {s[k]:,} > {NETWORK_LIMITS[cap]:,}")
        fits = s["declare_code_l2_gas"] <= NETWORK_LIMITS["max_receipt_l2_gas_in_block"]
        if fits == (c in NOT_DECLARABLE):
            limit_errors.append(f"{c} declare {s['declare_code_l2_gas']:,} L2 gas "
                                f"{'now fits' if fits else 'exceeds'} the block cap (NOT_DECLARABLE is stale)")

    budgets = json.loads((HERE / "budgets.json").read_text())["max"]
    budget_errors = [f"{k}: {metrics.get(k)} > budget {b}" for k, b in budgets.items()
                     if metrics.get(k) is None or metrics[k] > b]
    unbudgeted = sorted(set(metrics) - set(budgets))

    env = dict(line.split("=", 1) for line in (work / "env.txt").read_text().splitlines())
    results = {
        "description": "PF-04 account-level measurements; see bench/pf04/README.md",
        "env": env,
        "method": "snforge L2 gas (Sierra-gas mode): measured test minus its setup_ twin",
        "network_limits": NETWORK_LIMITS,
        "validate": validate,
        "selected_vectors": selected,
        **calls,
        "migrate": migrate,
        "entrypoint_cross_check": cross_check,
        "validate_steps_worst_vector": steps,
        "class_sizes": sizes,
        "not_declarable": list(NOT_DECLARABLE),
        "selected": SELECTED,
        "libfuncs": "every class builds with allowed-libfuncs-deny against network_libfuncs.json",
        "metrics": metrics,
    }
    out.write_text(json.dumps(results, indent=2) + "\n")

    b = validate["baseline"]["mean"]
    print(f"| Path | {' | '.join(VERIFIERS)} | {SELECTED} saving |")
    print("| --- |" + " ---: |" * (len(VERIFIERS) + 1))
    rows = [("`__validate__`, migrated account, mean", {v: validate[v]["mean"] for v in VERIFIERS}),
            ("`__validate__`, migrated account, worst", {v: validate[v]["worst"] for v in VERIFIERS})]
    for kind, label in (("declare", "`__validate_declare__`"), ("is_valid", "`is_valid_signature`"),
                        ("reject", "rejected signature")):
        rows.append((f"{label}, worst of selected", {v: max(calls[kind][v].values()) for v in VERIFIERS}))
    rows.append(("migration (`upgrade` + `migrate`)", migrate))
    for label, r in rows:
        print(f"| {label} | {' | '.join(f'{r[v]:,}' for v in VERIFIERS)} | "
              f"{1 - r[SELECTED] / r['baseline']:.1%} |")
    print(f"\ndirect HybridShakeAccount __validate__: mean {validate['direct']['mean']:,}, "
          f"worst {validate['direct']['worst']:,} (migrated baseline mean {b:,})")
    print(f"steps (worst vector): {steps}")
    print(f"entrypoint cross-check: {cross_check}")
    cap = NETWORK_LIMITS["max_receipt_l2_gas_in_block"]
    print("\n| Class | CASM felts | Sierra felts | Class object bytes | Compiled object bytes | Declare L2 gas | of block cap |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for c, s in sizes.items():
        print(f"| `{c}` | {s['casm_bytecode_felts']:,} | {s['sierra_program_felts']:,} | "
              f"{s['contract_class_object_bytes']:,} | {s['compiled_class_object_bytes']:,} | "
              f"{s['declare_code_l2_gas']:,} | {s['declare_code_l2_gas'] / cap:.1%} |")
    budget_errors += [f"{k}: {metrics[k]} has no budget" for k in unbudgeted]
    if limit_errors or budget_errors:
        sys.exit("\n".join(["NETWORK LIMIT EXCEEDED: " + e for e in limit_errors] +
                           ["BUDGET EXCEEDED: " + e for e in budget_errors]))
    print("\nwithin network limits and budgets")


if __name__ == "__main__":
    main()
