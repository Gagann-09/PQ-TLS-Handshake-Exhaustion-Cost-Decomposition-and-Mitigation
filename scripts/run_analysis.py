"""Phase 5-6 analysis: campaign summary + Figures A-D.

Reads results/raw/, validates trials, aggregates, writes
results/processed/{campaign_summary.json, figures.json, figure_*.png}.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analysis.decompose import decompose_cost, figure_a
from src.analysis.loader import load_raw, trial_valid

PROCESSED = Path("results/processed")


def render_png_figures(figures: dict) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig_a = figures["figure_a"]
    workloads = list(fig_a.keys())
    configs = sorted({c for w in fig_a.values() for c in w})
    x = range(len(configs))
    width = 0.38
    plt.figure(figsize=(10, 5))
    for i, w in enumerate(workloads):
        means = [fig_a[w].get(c, {}).get("mean") or 0 for c in configs]
        plt.bar([xi + i * width for xi in x], means, width, label=w)
    plt.xticks([xi + width / 2 for xi in x], configs)
    plt.ylabel("CPU-seconds per attempted handshake")
    plt.title("Figure A — Server CPU cost per attempt, by configuration")
    plt.legend()
    plt.tight_layout()
    plt.savefig(PROCESSED / "figure_a.png", dpi=150)
    plt.close()

    fig_b = figures["figure_b"]
    plt.figure(figsize=(10, 5))
    for i, w in enumerate(workloads):
        ratios = [fig_b[w].get(c, {}).get("ratio_vs_C0") or 0 for c in configs]
        plt.bar([xi + i * width for xi in x], ratios, width, label=w)
    plt.xticks([xi + width / 2 for xi in x], configs)
    plt.ylabel("Ratio of CPU-seconds/attempt vs C0")
    plt.title("Figure B — Incremental cost relative to C0")
    plt.legend()
    plt.tight_layout()
    plt.savefig(PROCESSED / "figure_b.png", dpi=150)
    plt.close()

    fig_c = figures["figure_c"]
    focus = ("C0", "C1", "C2", "C4")
    plt.figure(figsize=(9, 5))
    for i, w in enumerate(workloads):
        means = [fig_c[w].get(c, {}).get("mean") or 0 for c in focus]
        plt.bar([xi + i * width for xi in range(len(focus))], means, width, label=w)
    plt.xticks([xi + width / 2 for xi in range(len(focus))], focus)
    plt.ylabel("CPU-seconds per attempted handshake")
    plt.title("Figure C — Key-establishment vs authentication contribution")
    plt.legend()
    plt.tight_layout()
    plt.savefig(PROCESSED / "figure_c.png", dpi=150)
    plt.close()

    # Figure D: Fresh vs Reused client ML-KEM keypair (Phase 6)
    if "figure_d" in figures:
        fig_d = figures["figure_d"]
        labels = ["fresh_keypair", "reused_client_keypair"]
        means = [fig_d.get(k, {}).get("mean") or 0 for k in labels]
        medians = [fig_d.get(k, {}).get("median") or 0 for k in labels]

        plt.figure(figsize=(7, 5))
        x_pos = range(len(labels))
        plt.bar(x_pos, means, width=0.5, alpha=0.7, label="Mean", color="steelblue")
        plt.scatter(x_pos, medians, color="red", s=100, zorder=5, label="Median", marker="D")
        plt.xticks(x_pos, ["Fresh Keypair\n(per attempt)", "Reused Client\nML-KEM Keypair"])
        plt.ylabel("CPU-seconds per attempted handshake")
        plt.title("Figure D — RQ3: Fresh vs Reused Client ML-KEM Keypair (C1 × W1)")
        plt.legend()
        plt.tight_layout()
        plt.savefig(PROCESSED / "figure_d.png", dpi=150)
        plt.close()

        # Also render paired difference if available
        if "paired_delta_reused_minus_fresh" in fig_d:
            paired = fig_d["paired_delta_reused_minus_fresh"]
            if paired["n"] > 0:
                plt.figure(figsize=(7, 4))
                # Simple text summary for paired comparison
                plt.text(0.5, 0.5,
                         f"Paired Difference (Reused − Fresh)\n"
                         f"n={paired['n']} trials\n"
                         f"Mean Δ: {paired['mean']:.6f} CPU-s/att\n"
                         f"Median Δ: {paired['median']:.6f} CPU-s/att\n"
                         f"Std Δ: {paired['std']:.6f}\n"
                         f"Ratio (Reused/Fresh) mean: {fig_d['paired_ratio_reused_over_fresh']['mean']:.4f}",
                         ha="center", va="center", fontsize=12,
                         transform=plt.gca().transAxes,
                         bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.5))
                plt.axis("off")
                plt.title("Figure D (Paired) — Reused vs Fresh Keypair Difference")
                plt.tight_layout()
                plt.savefig(PROCESSED / "figure_d_paired.png", dpi=150)
                plt.close()


def main() -> None:
    records = load_raw("results/raw/*.json")
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
        })

    figures = decompose_cost(valid)

    PROCESSED.mkdir(parents=True, exist_ok=True)
    (PROCESSED / "campaign_summary.json").write_text(
        json.dumps({"total_trials": len(records), "valid": len(valid),
                    "invalid": len(invalid), "trials": summary_rows}, indent=2),
        encoding="utf-8")
    (PROCESSED / "figures.json").write_text(json.dumps(figures, indent=2),
                                            encoding="utf-8")
    render_png_figures(figures)

    print(f"trials={len(records)} valid={len(valid)} invalid={len(invalid)}")
    for row in summary_rows:
        print(f"  {row['experiment_id']}: valid={row['valid']} "
              f"cpu/att={row['server_cpu_seconds_per_attempt']} "
              f"rx/att={row['bytes_received_per_attempt']} "
              f"tx/att={row['bytes_sent_per_attempt']} "
              f"outcomes={row['handshake_outcomes']}")


if __name__ == "__main__":
    main()
