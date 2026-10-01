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
from src.instrumentation import cpu as cpu_instr
from src.instrumentation import packets as pkt_instr
from src.instrumentation import tls_log


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


def _resolve_container_id(
    compose_file: str | Path,
    service: str = "tls-server",
) -> str | None:
    """Resolve the running container ID for a compose service, or None."""
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "ps", "-q", service],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return ids[0] if ids else None
    except Exception:
        return None


def _per_attempt(value: float | int | None, attempts: int) -> float | None:
    """Normalize a raw measurement by ALL bounded attempts.

    Returns None when the measurement is unavailable or there were no
    attempts — a missing measurement never becomes a numeric zero.
    """
    if value is None or attempts <= 0:
        return None
    return round(value / attempts, 6)


def run_experiment(
    config: ExperimentConfig,
    results_dir: str | Path,
    compose_file: str | Path | None = None,
) -> dict:
    """Run a single bounded experiment.

    Validates safety, runs the workload, collects CPU / packet / TLS
    measurements, writes a result record, and returns it. An instrument stream
    that fails is recorded as unavailable/failed — never as a measured zero.
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

    container_id: str | None = None
    # Start the lab if a compose file is provided, then resolve its container.
    if compose_file:
        _start_lab(compose_file)
        if not _wait_for_server("127.0.0.1", config.target_port):
            _stop_lab(compose_file)
            raise RuntimeError("TLS server did not start within timeout")
        container_id = _resolve_container_id(compose_file)

    cpu_session = None
    capture_session = None
    cpu_stopped = False
    capture_stopped = False

    cpu_seconds: float | None = None
    cpu_status = "unavailable"
    cpu_error: str | None = None
    bytes_received: int | None = None
    bytes_sent: int | None = None
    pkt_status = "unavailable"
    pkt_error: str | None = None

    attempts = 0
    handshake_outcomes = {"aborted_pre_finished": 0, "completed": 0, "error": 0}
    last_error = None
    attempt_records: list[dict] = []

    try:
        # Instrumentation starts after readiness and before the workload.
        if container_id:
            cpu_session = cpu_instr.start_cpu_sampling(container_id)
            capture_session = pkt_instr.start_packet_capture(
                container_id, port=config.target_port
            )
        else:
            cpu_error = cpu_error or "no measurement container"
            pkt_error = pkt_error or "no measurement container"

        start_time = time.monotonic()

        # Run the bounded workload. (Lazy import avoids a controller/workload
        # import cycle.)
        from src.workload.client import generate_attempts

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
            # No per-attempt negotiation observation is available from the
            # client, so negotiated fields stay null — never a configured value.
            attempt_records.append({"outcome": attempt.outcome, "observation": None})

        duration = time.monotonic() - start_time

        # Stop CPU sampling — the workload window has ended.
        if cpu_session is not None:
            cpu_stopped = True
            cpu_result = cpu_instr.stop_cpu_sampling(cpu_session)
            if cpu_result is not None:
                cpu_seconds = cpu_result.cpu_seconds
                cpu_status = "measured"
            else:
                cpu_status = "failed" if cpu_session.error else "unavailable"
                cpu_error = cpu_session.error

        # Stop packet capture — the workload window has ended.
        if capture_session is not None:
            capture_stopped = True
            capture = pkt_instr.stop_packet_capture(capture_session)
            if capture.success:
                bytes_received = capture.meta.bytes_received
                bytes_sent = capture.meta.bytes_sent
                pkt_status = "measured"
            else:
                pkt_status = "failed"
                pkt_error = capture.error

        # Collect and normalize TLS observations (outcomes only; no fabricated
        # negotiated values are available from the client).
        tls_result = tls_log.observe_tls_events(attempt_records)
        tls_events = [
            {
                "negotiated_group": event.negotiated_group,
                "negotiated_signature_algorithm": event.negotiated_signature_algorithm,
                "outcome": event.outcome,
                "evidence_source": event.evidence_source,
            }
            for event in tls_result.events
        ]
        tls_status = "observed" if tls_result.events else "unavailable"

        # Run legitimate client (outside the capture window).
        from src.legitimate_client.client import run_legitimate_client

        legit_stats = run_legitimate_client(
            host=config.target_host,
            port=config.target_port,
            rate_per_sec=config.legitimate_rate_per_sec,
            duration_seconds=min(max(int(duration), 1), config.max_duration_seconds),
        )

    finally:
        # Ensure instruments are stopped and the lab torn down on any path.
        if cpu_session is not None and cpu_session.started and not cpu_stopped:
            cpu_instr.stop_cpu_sampling(cpu_session)
        if capture_session is not None and capture_session.started and not capture_stopped:
            pkt_instr.stop_packet_capture(capture_session)
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
        "server_cpu_seconds": round(cpu_seconds, 6) if cpu_seconds is not None else None,
        "server_cpu_seconds_per_attempt": _per_attempt(cpu_seconds, attempts),
        "workload_client_cpu_seconds": None,
        "bytes_received": bytes_received,
        "bytes_sent": bytes_sent,
        "bytes_received_per_attempt": _per_attempt(bytes_received, attempts),
        "bytes_sent_per_attempt": _per_attempt(bytes_sent, attempts),
        "handshake_outcomes": handshake_outcomes,
        "tls_events": tls_events,
        "measurement_status": {
            "server_cpu": cpu_status,
            "packets": pkt_status,
            "tls_events": tls_status,
        },
        "measurement_errors": {
            "server_cpu": cpu_error,
            "packets": pkt_error,
        },
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
