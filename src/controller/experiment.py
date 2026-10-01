"""Experiment controller — orchestrates a bounded experiment run.

See architecture.md §3.1 and design.md §3.
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from .config import ExperimentConfig, load_config
from .safety import SafetyError, validate_config


def _get_openssl_version() -> str:
    """Get the OpenSSL version string."""
    try:
        result = subprocess.run(
            ["openssl", "version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def run_experiment(config: ExperimentConfig, results_dir: str | Path) -> dict:
    """Run a single bounded experiment.

    Validates safety, runs the workload, collects metrics, writes a result record.
    Returns the result record as a dict.
    """
    # Validate before any network activity — fail closed.
    validate_config(
        host=config.target_host,
        max_attempts=config.max_attempts,
        max_duration_seconds=config.max_duration_seconds,
        max_concurrency=config.max_concurrency,
    )

    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    start_time = time.monotonic()
    timestamp = datetime.now(timezone.utc).isoformat()

    # Run the workload (placeholder for Phase 2+ — Phase 1 only validates safety)
    # In later phases, this will start the workload client and legitimate client.
    attempts = 0
    handshake_outcomes = {"aborted_pre_finished": 0, "completed": 0}

    # Placeholder: Phase 1 does not run actual measurements.
    # The safety validation above is the Phase 1 deliverable.

    duration = time.monotonic() - start_time

    result = {
        "experiment_id": config.experiment_id,
        "configuration": config.configuration,
        "defense": config.defense,
        "workload_mode": config.workload_mode,
        "key_reuse": config.key_reuse,
        "attempts": attempts,
        "duration_seconds": round(duration, 3),
        "server_cpu_seconds": 0.0,
        "workload_client_cpu_seconds": 0.0,
        "bytes_received": 0,
        "bytes_sent": 0,
        "handshake_outcomes": handshake_outcomes,
        "legitimate": {
            "attempts": 0,
            "successes": 0,
            "p50_latency_ms": 0.0,
            "p95_latency_ms": 0.0,
            "timeouts": 0,
        },
        "environment": {
            "git_commit": _get_git_commit(),
            "os": platform.platform(),
            "cpu": platform.processor() or "unknown",
            "openssl_version": _get_openssl_version(),
            "timestamp_utc": timestamp,
        },
    }

    # Write result record (append-only).
    result_path = results_dir / f"{config.experiment_id}.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


def _get_git_commit() -> str:
    """Get the current git commit hash."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"
