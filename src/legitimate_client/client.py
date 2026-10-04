"""Legitimate TLS client — issues requests at a fixed low rate.

See architecture.md §3.4. Runs independently of the workload client.
"""
from __future__ import annotations

import socket
import ssl
import subprocess
import time
from dataclasses import dataclass

from src.controller.safety import SafetyError, validate_target
from src.instrumentation import tls_log


@dataclass(frozen=True)
class LegitimateStats:
    """Statistics for the legitimate client run."""
    attempts: int
    successes: int
    p50_latency_ms: float
    p95_latency_ms: float
    timeouts: int


@dataclass(frozen=True)
class HandshakeObservationResult:
    """Result of one in-network full TLS handshake (observation only)."""

    attempts: int
    successes: int
    transcript: str


def run_in_network_handshake(
    container: str,
    host: str,
    port: int,
    groups: list[str] | None = None,
    sigalgs: list[str] | None = None,
    timeout: float = 10.0,
) -> HandshakeObservationResult:
    """Run ONE bounded full TLS 1.3 handshake inside the lab network.

    Executes `openssl s_client` (OpenSSL 3.5.x) inside the given container,
    which resolves the lab service name and supports ML-KEM-768 (C1). Success
    is TLS handshake COMPLETION; no application payload is awaited. Returns the
    observed OpenSSL `-msg`/`-state` transcript so callers can parse it
    independently.
    """
    group_args = f" -groups {':'.join(groups)}" if groups else ""
    sigalg_args = f" -sigalgs {':'.join(sigalgs)}" if sigalgs else ""
    command = (
        f"openssl s_client -connect {host}:{port} -tls1_3"
        f"{group_args}{sigalg_args} -msg -state -servername {host}"
        f" < /dev/null 2>&1"
    )
    transcript = ""
    try:
        proc = subprocess.run(
            ["docker", "exec", container, "sh", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        transcript = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        for stream in (exc.stdout, exc.stderr):
            if stream:
                transcript += (
                    stream if isinstance(stream, str)
                    else stream.decode(errors="replace")
                )
    except Exception as exc:  # pragma: no cover - defensive
        transcript = f"in-network handshake failed: {exc}"

    success = tls_log.d1_handshake_completed(transcript)
    return HandshakeObservationResult(
        attempts=1, successes=1 if success else 0, transcript=transcript
    )


def run_legitimate_client(
    host: str,
    port: int,
    rate_per_sec: float,
    duration_seconds: int,
    container: str | None = None,
    groups: list[str] | None = None,
    sigalgs: list[str] | None = None,
) -> LegitimateStats:
    """Run the legitimate client at a fixed rate for the given duration.

    Success is defined as TLS handshake COMPLETION, never as receipt of
    application payload. When `container` is provided the handshake runs
    in-network via OpenSSL 3.5.x (C1 capable); otherwise a host Python (SSL)
    fallback is used, which is NOT C1 capable. Fails closed if the target is
    not in the allowlist.
    """
    validate_target(host)

    latencies: list[float] = []
    successes = 0
    timeouts = 0
    attempts = 0

    interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 1.0
    start = time.monotonic()

    while time.monotonic() - start < duration_seconds:
        attempts += 1
        conn_start = time.monotonic()
        try:
            if container:
                obs = run_in_network_handshake(
                    container, host, port, groups=groups, sigalgs=sigalgs
                )
                if obs.successes:
                    latencies.append((time.monotonic() - conn_start) * 1000)
                    successes += 1
            else:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host):
                        # Handshake completed when wrap_socket returns; do NOT
                        # wait for application payload.
                        latencies.append((time.monotonic() - conn_start) * 1000)
                        successes += 1
        except socket.timeout:
            timeouts += 1
        except Exception:
            pass

        # Sleep to maintain the rate.
        elapsed = time.monotonic() - start
        target_time = attempts * interval
        if elapsed < target_time:
            time.sleep(target_time - elapsed)

    latencies.sort()
    p50 = latencies[len(latencies) // 2] if latencies else 0.0
    p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0.0

    return LegitimateStats(
        attempts=attempts,
        successes=successes,
        p50_latency_ms=p50,
        p95_latency_ms=p95,
        timeouts=timeouts,
    )
