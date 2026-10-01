"""Safety validator — enforces allowlist and hard limits before any network activity.

See rules.md §2 and §10. Fails closed on any validation error.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Final

# Allowlist: localhost, 127.0.0.1, ::1, Docker service names resolvable only
# inside the lab network. Any destination outside this list must fail closed.
ALLOWED_HOSTS: Final[frozenset[str]] = frozenset({"localhost", "127.0.0.1", "::1"})
ALLOWED_DOCKER_SERVICES: Final[frozenset[str]] = frozenset({"tls-server"})

# Hard ceilings — these are project safety limits, NOT cryptographic bounds.
# An experiment config may only LOWER these, never raise them.
MAX_ATTEMPTS: Final[int] = 1000
MAX_DURATION_SECONDS: Final[int] = 30
MAX_CONCURRENCY: Final[int] = 1


class SafetyError(Exception):
    """Raised when a safety check fails. The run must not proceed."""


@dataclass(frozen=True)
class SafetyLimits:
    max_attempts: int = MAX_ATTEMPTS
    max_duration_seconds: int = MAX_DURATION_SECONDS
    max_concurrency: int = MAX_CONCURRENCY


def validate_target(host: str) -> None:
    """Validate that the target host is within the allowlist.

    Raises SafetyError if the host is not allowed.
    """
    if host in ALLOWED_HOSTS:
        return
    if host in ALLOWED_DOCKER_SERVICES:
        return
    # Reject everything else — fail closed.
    raise SafetyError(
        f"Target '{host}' is outside the allowed list. "
        f"Allowed: {sorted(ALLOWED_HOSTS | ALLOWED_DOCKER_SERVICES)}"
    )


def validate_attempts(attempts: int) -> None:
    """Validate that attempts does not exceed the hard ceiling."""
    if attempts > MAX_ATTEMPTS:
        raise SafetyError(
            f"max_attempts ({attempts}) exceeds hard ceiling ({MAX_ATTEMPTS})"
        )
    if attempts < 1:
        raise SafetyError(f"max_attempts ({attempts}) must be at least 1")


def validate_duration(seconds: int) -> None:
    """Validate that duration does not exceed the hard ceiling."""
    if seconds > MAX_DURATION_SECONDS:
        raise SafetyError(
            f"max_duration_seconds ({seconds}) exceeds hard ceiling ({MAX_DURATION_SECONDS})"
        )
    if seconds < 1:
        raise SafetyError(f"max_duration_seconds ({seconds}) must be at least 1")


def validate_concurrency(concurrency: int) -> None:
    """Validate that concurrency does not exceed the hard ceiling."""
    if concurrency > MAX_CONCURRENCY:
        raise SafetyError(
            f"max_concurrency ({concurrency}) exceeds hard ceiling ({MAX_CONCURRENCY})"
        )
    if concurrency < 1:
        raise SafetyError(f"max_concurrency ({concurrency}) must be at least 1")


def validate_config(
    host: str,
    max_attempts: int,
    max_duration_seconds: int,
    max_concurrency: int,
) -> None:
    """Run all safety validations. Raises SafetyError on first failure."""
    validate_target(host)
    validate_attempts(max_attempts)
    validate_duration(max_duration_seconds)
    validate_concurrency(max_concurrency)
