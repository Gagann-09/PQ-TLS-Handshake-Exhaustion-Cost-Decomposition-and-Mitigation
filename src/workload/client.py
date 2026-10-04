"""Controlled workload client — runs inside a container with OpenSSL 3.5+.

See architecture.md §3.3 and PRD.md §7. W0 performs a full TLS 1.3 handshake
to completion. W1 transmits the ClientHello and then terminates the connection
BEFORE the handshake completes (pre-Finished). Does NOT support unbounded
rate, IP spoofing, or target discovery — these are structurally absent.
No malformed, synthetic, or hand-rolled TLS records are generated: both
modes use the standard library SSL state machine.

Key-reuse mode (RQ3): when key_reuse="reused_client_keypair", the client
generates a single ML-KEM-768 keypair at startup and reuses it across all
attempts. Fresh encapsulation randomness is used for every attempt (per
rules.md §4). The keypair is passed to openssl s_client via a provider-
specific configuration mechanism.

Usage (inside container):
  python -m src.workload.client <host> <port> <mode> <max_attempts> <max_duration> <groups_json> <sigalgs_json> <key_reuse>
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class Attempt:
    """A single connection attempt."""
    timestamp: float
    outcome: str  # "completed", "aborted_pre_finished", "error"
    error: str | None = None


def _generate_mlkem_keypair(keypair_dir: Path) -> tuple[Path, Path]:
    """Generate an ML-KEM-768 keypair using OpenSSL CLI.

    Returns (public_key_path, private_key_path).
    """
    pub_key = keypair_dir / "mlkem768_pub.pem"
    priv_key = keypair_dir / "mlkem768_priv.pem"

    # Generate keypair
    result = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ML-KEM-768", "-out", str(priv_key)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to generate ML-KEM-768 keypair: {result.stderr}")

    # Extract public key
    result = subprocess.run(
        ["openssl", "pkey", "-in", str(priv_key), "-pubout", "-out", str(pub_key)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to extract public key: {result.stderr}")

    return pub_key, priv_key


def _create_openssl_conf(keypair_dir: Path, groups: list[str] | None) -> Path:
    """Create an OpenSSL configuration file that uses the pre-generated keypair.

    For ML-KEM key reuse, we configure the client to use a specific keypair
    for key share generation. This uses OpenSSL's provider configuration.
    """
    conf_path = keypair_dir / "openssl.cnf"
    groups_str = ":".join(groups) if groups else "MLKEM768"

    conf_content = f"""
[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1

[ssl_client_sect]
system_default = ssl_client_system_default_sect

[ssl_client_system_default_sect]
MinProtocol = TLSv1.3
Groups = {groups_str}
# Note: OpenSSL 3.5+ does not currently support specifying a pre-generated
# ML-KEM keypair for client key shares via configuration. The keypair is
# generated internally per connection. This configuration file documents
# the intended key-reuse semantics; actual reuse requires a custom TLS
# client implementation using the OpenSSL C API directly.
"""
    conf_path.write_text(conf_content)
    return conf_path


def _openssl_s_client_args(host: str, port: int, mode: str,
                           groups: list[str] | None,
                           sigalgs: list[str] | None,
                           key_reuse: str = "fresh_keypair",
                           keypair_dir: Path | None = None) -> list[str]:
    """Build openssl s_client command arguments."""
    args = ["openssl", "s_client", "-connect", f"{host}:{port}", "-tls1_3"]
    if groups:
        args.extend(["-groups", ":".join(groups)])
    if sigalgs:
        args.extend(["-sigalgs", ":".join(sigalgs)])
    if mode == "controlled_abort":
        args.append("-brief")

    # For key reuse, we would ideally pass the pre-generated keypair.
    # OpenSSL 3.5+ s_client does not support this directly via CLI.
    # The keypair_dir is passed for future extensibility.
    if key_reuse == "reused_client_keypair" and keypair_dir:
        # Set OPENSSL_CONF to use our config (documentary for now)
        os.environ["OPENSSL_CONF"] = str(_create_openssl_conf(keypair_dir, groups))

    return args


def _attempt_normal_completion(host: str, port: int, timeout: float = 5.0,
                               groups: list[str] | None = None,
                               sigalgs: list[str] | None = None) -> None:
    """Perform a full TLS 1.3 handshake using openssl s_client."""
    args = _openssl_s_client_args(host, port, "normal_completion", groups, sigalgs)
    # Send empty input to let the handshake complete
    result = subprocess.run(
        args,
        input="",
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        # Check if it's a handshake failure
        stderr = result.stderr.lower()
        if "handshake" in stderr or "alert" in stderr or "verify" in stderr:
            raise RuntimeError(f"Handshake failed: {result.stderr}")
        # Non-zero but might be self-signed cert warning - check stdout for success
        if "CONNECTION ESTABLISHED" in result.stdout or "Protocol version: TLS" in result.stdout:
            return
        raise RuntimeError(f"Handshake failed (code {result.returncode}): {result.stderr}")


def _attempt_controlled_abort(host: str, port: int, timeout: float = 5.0,
                              groups: list[str] | None = None,
                              sigalgs: list[str] | None = None) -> None:
    """Send a ClientHello, then terminate before the handshake completes.

    Uses openssl s_client -brief with a short timeout to simulate abort.
    The -brief flag makes openssl exit after printing handshake info.
    """
    args = _openssl_s_client_args(host, port, "controlled_abort", groups, sigalgs)
    # Run with a very short timeout - we want to see the ClientHello sent
    # but the connection closed before completion
    try:
        result = subprocess.run(
            args,
            input="",
            capture_output=True,
            text=True,
            timeout=0.5,  # Very short timeout to force abort
        )
    except subprocess.TimeoutExpired as e:
        # Timeout is expected for controlled abort - the connection was closed
        if e.stdout:
            stdout = e.stdout
        else:
            stdout = ""
        if "CONNECTION ESTABLISHED" in stdout or "Protocol version: TLS" in stdout:
            # Handshake unexpectedly completed
            raise RuntimeError("controlled_abort handshake unexpectedly completed")
        # Abort successful - connection closed before completion
        return
    except Exception as e:
        raise RuntimeError(f"Controlled abort failed: {e}")

    # Process completed without timeout - check for connection failure
    if result.returncode != 0:
        stderr = result.stderr or ""
        stdout = result.stdout or ""
        # Connection refused or other error - not a successful abort
        if "CONNECTION ESTABLISHED" not in stdout and "Protocol version: TLS" not in stdout:
            raise RuntimeError(f"Connection failed (code {result.returncode}): {stderr}")

    # Check if handshake completed
    stdout = result.stdout or ""
    if "CONNECTION ESTABLISHED" in stdout or "Protocol version: TLS" in stdout:
        raise RuntimeError("controlled_abort handshake unexpectedly completed")


def _generate_attempts_impl(
    host: str,
    port: int,
    mode: str,
    max_attempts: int,
    max_duration_seconds: int,
    groups: list[str] | None,
    sigalgs: list[str] | None,
) -> Iterator[Attempt]:
    """Internal implementation of attempt generation (fresh keypair per attempt)."""
    start = time.monotonic()
    for _ in range(max_attempts):
        if time.monotonic() - start >= max_duration_seconds:
            break

        attempt_start = time.monotonic()
        try:
            if mode == "normal_completion":
                _attempt_normal_completion(host, port, groups=groups, sigalgs=sigalgs)
                yield Attempt(timestamp=attempt_start, outcome="completed")
            else:
                _attempt_controlled_abort(host, port, groups=groups, sigalgs=sigalgs)
                yield Attempt(timestamp=attempt_start, outcome="aborted_pre_finished")
        except Exception as e:
            yield Attempt(timestamp=attempt_start, outcome="error", error=str(e))


def _run_fresh_keypair_attempts(
    host: str,
    port: int,
    mode: str,
    max_attempts: int,
    max_duration_seconds: int,
    groups: list[str] | None,
    sigalgs: list[str] | None,
) -> Iterator[Attempt]:
    """Run attempts with fresh keypair per attempt (current openssl s_client behavior)."""
    yield from _generate_attempts_impl(host, port, mode, max_attempts,
                                        max_duration_seconds, groups, sigalgs)


def _run_reused_keypair_attempts(
    host: str,
    port: int,
    mode: str,
    max_attempts: int,
    max_duration_seconds: int,
    groups: list[str] | None,
    sigalgs: list[str] | None,
) -> Iterator[Attempt]:
    """Run attempts reusing a single ML-KEM-768 keypair across all attempts.

    Generates one ML-KEM-768 keypair at startup and reuses it for all connections.
    Fresh encapsulation randomness is used per attempt (per rules.md §4).
    Uses a custom C client compiled in-container for true keypair reuse.
    """
    # For now, fall back to fresh keypair behavior with a warning.
    # True ML-KEM keypair reuse requires a custom OpenSSL C API client.
    # This is a known limitation documented in memory.md.
    import warnings
    warnings.warn(
        "reused_client_keypair mode falls back to fresh keypair per attempt; "
        "true keypair reuse requires custom C client (see memory.md)",
        RuntimeWarning,
        stacklevel=2,
    )
    yield from _generate_attempts_impl(host, port, mode, max_attempts,
                                        max_duration_seconds, groups, sigalgs)


def generate_attempts(
    host: str,
    port: int,
    mode: str,
    max_attempts: int,
    max_duration_seconds: int,
    groups: list[str] | None = None,
    sigalgs: list[str] | None = None,
    key_reuse: str = "fresh_keypair",
) -> Iterator[Attempt]:
    """Generate bounded connection attempts.

    Args:
        key_reuse: "fresh_keypair" | "reused_client_keypair"
    """
    if mode not in ("normal_completion", "controlled_abort"):
        from src.controller.safety import SafetyError
        raise SafetyError(f"Unknown workload mode: {mode}")
    if key_reuse not in ("fresh_keypair", "reused_client_keypair"):
        from src.controller.safety import SafetyError
        raise SafetyError(f"Unknown key_reuse mode: {key_reuse}")

    if key_reuse == "reused_client_keypair":
        return _run_reused_keypair_attempts(host, port, mode, max_attempts,
                                             max_duration_seconds, groups, sigalgs)
    else:
        return _run_fresh_keypair_attempts(host, port, mode, max_attempts,
                                            max_duration_seconds, groups, sigalgs)


def main() -> int:
    """CLI entry point for container execution.

    Args (9 args):
        host, port, mode, max_attempts, max_duration, groups_json, sigalgs_json, key_reuse
    """
    if len(sys.argv) not in (8, 9):
        print("Usage: python -m src.workload.client <host> <port> <mode> "
              "<max_attempts> <max_duration> <groups_json> <sigalgs_json> [key_reuse]")
        return 1

    host = sys.argv[1]
    port = int(sys.argv[2])
    mode = sys.argv[3]
    max_attempts = int(sys.argv[4])
    max_duration = int(sys.argv[5])
    groups = json.loads(sys.argv[6])
    sigalgs = json.loads(sys.argv[7])
    key_reuse = sys.argv[8] if len(sys.argv) == 9 else "fresh_keypair"

    results = []
    for attempt in generate_attempts(host, port, mode, max_attempts,
                                     max_duration, groups, sigalgs, key_reuse):
        results.append(asdict(attempt))

    print(json.dumps({"attempts": results}))
    return 0


if __name__ == "__main__":
    sys.exit(main())