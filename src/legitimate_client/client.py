"""Legitimate TLS client — issues requests at a fixed low rate.

See architecture.md §3.4. Runs independently of the workload client.
"""
from __future__ import annotations

import ssl
import time
from dataclasses import dataclass

from src.controller.safety import SafetyError, validate_target


@dataclass(frozen=True)
class LegitimateStats:
    """Statistics for the legitimate client run."""
    attempts: int
    successes: int
    p50_latency_ms: float
    p95_latency_ms: float
    timeouts: int


def run_legitimate_client(
    host: str,
    port: int,
    rate_per_sec: float,
    duration_seconds: int,
) -> LegitimateStats:
    """Run the legitimate client at a fixed rate for the given duration.

    Returns LegitimateStats. Fails closed if the target is not in the allowlist.
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
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            conn_start = time.monotonic()
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Send a simple HTTP request to simulate legitimate traffic.
                    ssock.sendall(b"GET / HTTP/1.1\r\nHost: tls-server\r\n\r\n")
                    response = ssock.recv(1024)
                    latency = (time.monotonic() - conn_start) * 1000
                    latencies.append(latency)
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
