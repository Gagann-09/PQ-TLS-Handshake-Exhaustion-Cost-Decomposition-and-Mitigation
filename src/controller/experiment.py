"""Experiment controller — orchestrates a bounded experiment run.

See architecture.md §3.1 and design.md §3.
"""
from __future__ import annotations

import json
import platform
import socket
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


def _start_lab(compose_file: str | Path) -> None:
    """Start the Docker lab using docker compose."""
    subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "up", "-d"],
        check=True,
        capture_output=True,
        text=True,
    )


def _stop_lab(compose_file: str | Path) -> None:
    """Stop the Docker lab."""
    subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "down"],
        check=True,
        capture_output=True,
        text=True,
    )


def _wait_for_server(host: str, port: int, timeout: float = 30.0) -> bool:
    """Wait for the TLS server to accept connections."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(0.5)
    return False


def _get_cpu_percent(container_name: str) -> float:
    """Get current CPU usage percentage for a container."""
    try:
        result = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}", container_name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            for line in lines:
                line = line.strip().rstrip("%")
                try:
                    return float(line)
                except ValueError:
                    continue
    except Exception:
        pass
    return 0.0


def _get_cpu_percent(container_name: str) -> float:
    """Get current CPU usage percentage for a container."""
    try:
        result = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}", container_name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            for line in lines:
                line = line.strip().rstrip("%")
                try:
                    return float(line)
                except ValueError:
                    continue
    except Exception:
        pass
    return 0.0


def _measure_server_cpu_during_run(container_name: str, duration: float) -> float:
    """Measure server CPU usage during the workload run.

    Measures CPU% at start and end, returns approximate CPU seconds.
    """
    cpu_start = _get_cpu_percent(container_name)
    time.sleep(duration)
    cpu_end = _get_cpu_percent(container_name)
    # docker stats shows cumulative CPU% since container start.
    # The difference is the CPU% used during this run.
    cpu_delta = abs(cpu_end - cpu_start)
    return (cpu_delta / 100.0) * duration


def run_experiment(
    config: ExperimentConfig,
    results_dir: str | Path,
    compose_file: str | Path | None = None,
) -> dict:
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

    timestamp = datetime.now(timezone.utc).isoformat()

    # Start the lab if compose file is provided
    if compose_file:
        _start_lab(compose_file)
        # Wait for server to be ready
        if not _wait_for_server("127.0.0.1", config.target_port):
            _stop_lab(compose_file)
            raise RuntimeError("TLS server did not start within timeout")

    try:
        start_time = time.monotonic()

        # Run the workload
        from src.workload.client import generate_attempts

        attempts = 0
        handshake_outcomes = {"aborted_pre_finished": 0, "completed": 0, "error": 0}
        bytes_received = 0
        bytes_sent = 0
        last_error = None

        for attempt in generate_attempts(
            host=config.target_host,
            port=config.target_port,
            mode=config.workload_mode,
            max_attempts=config.max_attempts,
            max_duration_seconds=config.max_duration_seconds,
        ):
            attempts += 1
            if attempt.outcome == "completed":
                handshake_outcomes["completed"] += 1
            elif attempt.outcome == "aborted_pre_finished":
                handshake_outcomes["aborted_pre_finished"] += 1
            else:
                handshake_outcomes["error"] += 1
                last_error = attempt.error

        duration = time.monotonic() - start_time

        # Server CPU measurement requires Phase 4 instrumentation (perf/pidstat).
        # Record as TBD until Phase 4 is implemented.
        server_cpu_seconds = None  # TBD — Phase 4 instrumentation

        # Run legitimate client
        from src.legitimate_client.client import run_legitimate_client

        legit_stats = run_legitimate_client(
            host=config.target_host,
            port=config.target_port,
            rate_per_sec=config.legitimate_rate_per_sec,
            duration_seconds=min(int(duration), config.max_duration_seconds),
        )

    finally:
        # Always stop the lab
        if compose_file:
            _stop_lab(compose_file)

    result = {
        "experiment_id": config.experiment_id,
        "configuration": config.configuration,
        "defense": config.defense,
        "workload_mode": config.workload_mode,
        "key_reuse": config.key_reuse,
        "attempts": attempts,
        "duration_seconds": round(duration, 3),
        "server_cpu_seconds": round(server_cpu_seconds, 3) if server_cpu_seconds is not None else "TBD",
        "workload_client_cpu_seconds": 0.0,  # TBD — Phase 4 instrumentation
        "bytes_received": bytes_received,
        "bytes_sent": bytes_sent,
        "handshake_outcomes": handshake_outcomes,
        "last_error": last_error,
        "legitimate": {
            "attempts": legit_stats.attempts,
            "successes": legit_stats.successes,
            "p50_latency_ms": round(legit_stats.p50_latency_ms, 3),
            "p95_latency_ms": round(legit_stats.p95_latency_ms, 3),
            "timeouts": legit_stats.timeouts,
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
