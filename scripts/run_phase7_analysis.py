#!/usr/bin/env python3
"""Phase 7 Full Campaign Analysis

Analyzes C1 × W1 × {D0, D1, D2, D3} × 3 trials.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analysis.decompose import decompose_cost, figure_a, figure_b, figure_c
from src.analysis.loader import load_raw, trial_valid

PROCESSED = Path("results/processed")
PHASE7_DATE = "2026-10-03"


def load_phase7_raw(path_glob: str) -> list[dict]:
    """Load raw result JSON files for Phase 7 campaign."""
    records = []
    for path in sorted(glob.glob(path_glob)):
        name = Path(path).name
        if not name.startswith(PHASE7_DATE + "-C"):
            continue
        if name.endswith("-observation.json"):
            continue
        with open(path, "r", encoding="utf-8") as f:
            records.append(json.load(f))
    return records


import glob


def render_png_figures(figures: dict) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # Figure A: CPU per attempt by defense
    fig_a = figures["figure_a"]
    defenses = sorted(fig_a["controlled_abort"].keys())
    workloads = ["controlled_abort"]
    x = range(len(defenses))
    width = 0.6
    plt.figure(figsize=(10, 5))
    for i, w in enumerate(workloads):
        means = [fig_a[w].get(d, {}).get("mean") or 0 for d in defenses]
        plt.bar([xi + i * width for xi in x], means, width, label=w)
    plt.xticks([xi + width / 2 for xi in x], defenses)
    plt.ylabel("CPU-seconds per attempted handshake")
    plt.title("Figure A — Server CPU cost per attempt, by defense (C1 × W1)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(PROCESSED / "phase7_figure_a.png", dpi=150)
    plt.close()

    # Figure B: CPU ratio vs D0
    fig_b = figures["figure_b"]
    plt.figure(figsize=(10, 5))
    for i, w in enumerate(workloads):
        ratios = [fig_b[w].get(d, {}).get("ratio_vs_D0") or 0 for d in defenses]
        plt.bar([xi + i * width for xi in x], ratios, width, label=w)
    plt.xticks([xi + width / 2 for xi in x], defenses)
    plt.ylabel("Ratio of CPU-seconds/attempt vs D0")
    plt.title("Figure B — Incremental cost relative to D0 (C1 × W1)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(PROCESSED / "phase7_figure_b.png", dpi=150)
    plt.close()

    # Figure: Legitimate client success rate
    # This would need legitimate client data from the records


def main() -> None:
    import glob
    records = load_phase7_raw("results/raw/*.json")
    valid, invalid = [], []
    for r in records:
        ok, reason = trial_valid(r)
        r["_valid"] = ok
        r["_validity_reason"] = reason
        (valid if ok else invalid).append(r)

    summary_rows = []
    for r in records:
        summary_rows.append({
            "experiment_id": r["experiment_id"],
            "configuration": r["configuration"],
            "defense": r["defense"],
            "workload_mode": r["workload_mode"],
            "attempts": r["attempts"],
            "valid": r["_valid"],
            "validity_reason": r["_validity_reason"],
            "server_cpu_seconds": r["server_cpu_seconds"],
            "server_cpu_seconds_per_attempt": r["server_cpu_seconds_per_attempt"],
            "bytes_received": r["bytes_received"],
            "bytes_sent": r["bytes_sent"],
            "bytes_received_per_attempt": r["bytes_received_per_attempt"],
            "bytes_sent_per_attempt": r["bytes_sent_per_attempt"],
            "handshake_outcomes": r["handshake_outcomes"],
            "measurement_status": r["measurement_status"],
            "measurement_errors": r["measurement_errors"],
            "legitimate_attempts": r.get("legitimate", {}).get("attempts"),
            "legitimate_successes": r.get("legitimate", {}).get("successes"),
            "legitimate_p50_latency_ms": r.get("legitimate", {}).get("p50_latency_ms"),
            "legitimate_p95_latency_ms": r.get("legitimate", {}).get("p95_latency_ms"),
            "admission_accepted": r.get("admission", {}).get("accepted"),
            "admission_rejected": r.get("admission", {}).get("rejected"),
            "d1_validation_hrr_observed": r.get("d1_validation", {}).get("hrr_observed") if r.get("d1_validation") else None,
            "d1_validation_cookie_observed": r.get("d1_validation", {}).get("cookie_observed") if r.get("d1_validation") else None,
            "d1_validation_negotiated_group": r.get("d1_validation", {}).get("negotiated_group") if r.get("d1_validation") else None,
        })

    # Compute figures for C1 W1 by defense
    c1_w1_records = [r for r in valid if r["configuration"] == "C1" and r["workload_mode"] == "controlled_abort"]
    
    # Figure A: CPU per attempt by defense
    fig_a_data = {}
    for w in ["controlled_abort"]:
        fig_a_data[w] = {}
        for defense in sorted({r["defense"] for r in c1_w1_records}):
            vals = [r["server_cpu_seconds_per_attempt"] for r in c1_w1_records if r["defense"] == defense]
            import statistics
            if vals:
                fig_a_data[w][defense] = {
                    "n": len(vals),
                    "median": round(statistics.median(vals), 6),
                    "mean": round(statistics.mean(vals), 6),
                    "std": round(statistics.pstdev(vals), 6) if len(vals) > 1 else 0.0,
                    "p95": round(sorted(vals)[int(0.95 * len(vals)) - 1] if len(vals) > 1 else vals[0], 6),
                }
            else:
                fig_a_data[w][defense] = {"n": 0, "median": None, "mean": None, "std": None, "p95": None}

    # Figure B: Ratio vs D0
    fig_b_data = {}
    for w in ["controlled_abort"]:
        fig_b_data[w] = {}
        d0_mean = fig_a_data[w].get("D0", {}).get("mean")
        for defense, stats in fig_a_data[w].items():
            if d0_mean and stats["mean"] and d0_mean != 0:
                fig_b_data[w][defense] = {
                    "delta_vs_D0": round(stats["mean"] - d0_mean, 6),
                    "ratio_vs_D0": round(stats["mean"] / d0_mean, 4),
                }
            else:
                fig_b_data[w][defense] = {"delta_vs_D0": None, "ratio_vs_D0": None}

    figures = {"figure_a": fig_a_data, "figure_b": fig_b_data}

    PROCESSED.mkdir(parents=True, exist_ok=True)
    (PROCESSED / "phase7_campaign_summary.json").write_text(
        json.dumps({"total_trials": len(records), "valid": len(valid),
                    "invalid": len(invalid), "trials": summary_rows}, indent=2),
        encoding="utf-8")
    (PROCESSED / "phase7_figures.json").write_text(json.dumps(figures, indent=2), encoding="utf-8")
    render_png_figures(figures)

    print(f"Phase 7 trials={len(records)} valid={len(valid)} invalid={len(invalid)}")
    for row in summary_rows:
        print(f"  {row['experiment_id']}: valid={row['valid']} "
              f"cpu/att={row['server_cpu_seconds_per_attempt']} "
              f"rx/att={row['bytes_received_per_attempt']} "
              f"tx/att={row['bytes_sent_per_attempt']} "
              f"outcomes={row['handshake_outcomes']}"
              f" legit={row['legitimate_successes']}/{row['legitimate_attempts']}"
              f" admission={row['admission_accepted']}/{row['admission_rejected']}"
              f" d1_hrr={row['d1_validation_hrr_observed']} d1_cookie={row['d1_validation_cookie_observed']}")


if __name__ == "__main__":
    main()