"""Controlled workload client — opens TLS connections per the active workload mode.

See architecture.md §3.3. Does NOT support unbounded rate, IP spoofing,
or target discovery — these are structurally absent.
"""
from __future__ import annotations

import ssl
import time
from dataclasses import dataclass
from typing import Iterator

from src.controller.safety import SafetyError, validate_target


@dataclass(frozen=True)
class Attempt:
    """A single connection attempt."""
    timestamp: float
    outcome: str  # "completed", "aborted_pre_finished", "error"
    error: str | None = None


def generate_attempts(
    host: str,
    port: int,
    mode: str,
    max_attempts: int,
    max_duration_seconds: int,
) -> Iterator[Attempt]:
    """Generate bounded connection attempts.

    Yields Attempt objects. Stops when max_attempts or max_duration_seconds
    is reached. Fails closed if the target is not in the allowlist.
    """
    # Validate target before any network activity.
    validate_target(host)

    if mode not in ("normal_completion", "controlled_abort"):
        raise SafetyError(f"Unknown workload mode: {mode}")

    start = time.monotonic()
    for i in range(max_attempts):
        if time.monotonic() - start >= max_duration_seconds:
            break

        attempt_start = time.monotonic()
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    if mode == "normal_completion":
                        # Handshake completed.
                        yield Attempt(
                            timestamp=attempt_start,
                            outcome="completed",
                        )
                    elif mode == "controlled_abort":
                        # Handshake started but we abort before completion.
                        # Close the socket immediately after connection.
                        yield Attempt(
                            timestamp=attempt_start,
                            outcome="aborted_pre_finished",
                        )
        except Exception as e:
            yield Attempt(
                timestamp=attempt_start,
                outcome="error",
                error=str(e),
            )
