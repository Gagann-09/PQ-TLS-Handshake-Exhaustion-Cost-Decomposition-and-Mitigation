"""Cost decomposition: Figures A-D per architecture.md §6 / design.md §5.

Figure A - server CPU-seconds per attempted handshake, by configuration.
Figure B - incremental cost relative to C0, by configuration.
Figure C - key-establishment vs authentication contribution (C1 vs C2 vs C4).
Figure D - fresh vs reused client ML-KEM keypair cost comparison (RQ3).

Aggregates median, mean, std, p95 across trial repeats (design.md §5).
Pure functions over already-collected data.
"""
from __future__ import annotations

import statistics
from collections import defaultdict


def _percentiles(values: list[float]) -> dict:
    if not values:
        return {"n": 0, "median": None, "mean": None, "std": None, "p95": None}
    ordered = sorted(values)
    p95_index = max(0, int(0.95 * len(ordered)) - 1) if len(ordered) > 1 else 0
    return {
        "n": len(values),
        "median": round(statistics.median(values), 6),
        "mean": round(statistics.mean(values), 6),
        "std": round(statistics.pstdev(values), 6) if len(values) > 1 else 0.0,
        "p95": round(ordered[p95_index], 6),
    }


def group_by(records: list[dict], key: str) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        groups[r[key]].append(r)
    return dict(groups)


def figure_a(records: list[dict]) -> dict:
    """CPU-seconds per attempted handshake, by configuration, by workload."""
    out = {}
    for workload in ("normal_completion", "controlled_abort"):
        out[workload] = {}
        for cfg in sorted({r["configuration"] for r in records}):
            vals = [r["server_cpu_seconds_per_attempt"] for r in records
                    if r["configuration"] == cfg and r["workload_mode"] == workload
                    and r["server_cpu_seconds_per_attempt"] is not None]
            out[workload][cfg] = _percentiles(vals)
    return out


def figure_b(records: list[dict]) -> dict:
    """Incremental cost relative to C0 (delta and ratio of means), by workload."""
    a = figure_a(records)
    out = {}
    for workload, by_cfg in a.items():
        c0_mean = by_cfg.get("C0", {}).get("mean")
        out[workload] = {}
        for cfg, stats in by_cfg.items():
            if c0_mean in (None, 0) or stats["mean"] is None:
                out[workload][cfg] = {"delta_vs_C0": None, "ratio_vs_C0": None}
            else:
                out[workload][cfg] = {
                    "delta_vs_C0": round(stats["mean"] - c0_mean, 6),
                    "ratio_vs_C0": round(stats["mean"] / c0_mean, 4),
                }
    return out


def figure_c(records: list[dict]) -> dict:
    """C1 (PQ key-estab) vs C2 (PQ auth) vs C4 (both), by workload."""
    a = figure_a(records)
    out = {}
    for workload, by_cfg in a.items():
        out[workload] = {cfg: by_cfg.get(cfg) for cfg in ("C0", "C1", "C2", "C4")}
    return out


def figure_d(records: list[dict]) -> dict:
    """Figure D: Fresh vs reused client ML-KEM keypair cost comparison (RQ3).

    Compares C1 × W1 with fresh_keypair vs reused_client_keypair.
    Uses paired comparison by trial index where possible (design.md §5).
    """
    # Filter for C1 W1 trials
    c1_w1_records = [r for r in records
                     if r["configuration"] == "C1"
                     and r["workload_mode"] == "controlled_abort"
                     and r["server_cpu_seconds_per_attempt"] is not None]

    fresh = [r for r in c1_w1_records if r.get("key_reuse") == "fresh_keypair"]
    reused = [r for r in c1_w1_records if r.get("key_reuse") == "reused_client_keypair"]

    # Sort by experiment_id to enable paired comparison by trial index
    fresh.sort(key=lambda r: r["experiment_id"])
    reused.sort(key=lambda r: r["experiment_id"])

    fresh_vals = [r["server_cpu_seconds_per_attempt"] for r in fresh]
    reused_vals = [r["server_cpu_seconds_per_attempt"] for r in reused]

    # Paired differences (if same number of trials)
    paired_deltas = []
    paired_ratios = []
    if len(fresh_vals) == len(reused_vals) and len(fresh_vals) > 0:
        for f, r in zip(fresh_vals, reused_vals):
            if f is not None and r is not None and f != 0:
                paired_deltas.append(r - f)
                paired_ratios.append(r / f)

    return {
        "fresh_keypair": _percentiles(fresh_vals),
        "reused_client_keypair": _percentiles(reused_vals),
        "paired_delta_reused_minus_fresh": _percentiles(paired_deltas),
        "paired_ratio_reused_over_fresh": _percentiles(paired_ratios),
        "n_trials_fresh": len(fresh_vals),
        "n_trials_reused": len(reused_vals),
    }


def decompose_cost(records: list[dict]) -> dict:
    return {"figure_a": figure_a(records), "figure_b": figure_b(records),
            "figure_c": figure_c(records), "figure_d": figure_d(records)}
