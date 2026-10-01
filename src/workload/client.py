"""Controlled workload client — opens TLS connections per the active workload mode.

See architecture.md §3.3 and PRD.md §7. W0 performs a full TLS 1.3 handshake to
completion. W1 transmits the ClientHello and then terminates the connection
BEFORE the handshake completes (pre-Finished); it never performs a completed
handshake. Does NOT support unbounded rate, IP spoofing, or target discovery —
these are structurally absent. No malformed, synthetic, or hand-rolled TLS
records are generated: both modes use the standard library SSL state machine.
"""
from __future__ import annotations

import socket
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


def _make_context() -> ssl.SSLContext:
    """Create a client context that does not verify the lab's self-signed cert."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _attempt_normal_completion(host: str, port: int, timeout: float = 5.0) -> None:
    """Perform a full TLS 1.3 handshake. Raises if the handshake fails."""
    context = _make_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        # wrap_socket performs the handshake (do_handshake_on_connect=True).
        with context.wrap_socket(sock, server_hostname=host):
            pass


def _attempt_controlled_abort(host: str, port: int, timeout: float = 5.0) -> None:
    """Send a ClientHello, then terminate before the handshake completes.

    The SSL state machine is driven in non-blocking mode: the first handshake
    step emits the ClientHello and then signals that it is awaiting the server,
    at which point the client closes the connection. Returning normally
    certifies that the intended pre-Finished termination occurred; if the
    handshake unexpectedly completed, a RuntimeError is raised so the caller
    cannot mislabel a completed handshake as an abort.
    """
    context = _make_context()
    sock = socket.create_connection((host, port), timeout=timeout)
    ssock: ssl.SSLSocket | None = None
    try:
        sock.setblocking(False)
        ssock = context.wrap_socket(
            sock, server_hostname=host, do_handshake_on_connect=False
        )
        pre_finished = False
        try:
            ssock.do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            # ClientHello has been transmitted; the handshake is incomplete and
            # the client now terminates. This is the intended abort point.
            pre_finished = True
        if not pre_finished:
            raise RuntimeError("controlled_abort handshake unexpectedly completed")
    finally:
        if ssock is not None:
            try:
                ssock.close()
            except OSError:
                pass
        try:
            sock.close()
        except OSError:
            pass


def generate_attempts(
    host: str,
    port: int,
    mode: str,
    max_attempts: int,
    max_duration_seconds: int,
) -> Iterator[Attempt]:
    """Generate bounded connection attempts.

    Yields Attempt objects. Stops when max_attempts or max_duration_seconds is
    reached. Fails closed if the target is not in the allowlist. An attempt's
    outcome reflects what actually happened; a W1 attempt whose handshake
    unexpectedly completes is reported as ``error``, never as an abort.
    """
    # Validate target before any network activity.
    validate_target(host)

    if mode not in ("normal_completion", "controlled_abort"):
        raise SafetyError(f"Unknown workload mode: {mode}")

    start = time.monotonic()
    for _ in range(max_attempts):
        if time.monotonic() - start >= max_duration_seconds:
            break

        attempt_start = time.monotonic()
        try:
            if mode == "normal_completion":
                _attempt_normal_completion(host, port)
                yield Attempt(timestamp=attempt_start, outcome="completed")
            else:  # controlled_abort
                _attempt_controlled_abort(host, port)
                yield Attempt(timestamp=attempt_start, outcome="aborted_pre_finished")
        except Exception as e:
            yield Attempt(timestamp=attempt_start, outcome="error", error=str(e))
