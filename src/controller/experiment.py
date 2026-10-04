"""Experiment controller — orchestrates a bounded experiment run.

See architecture.md §3.1 and design.md §3.
"""
from __future__ import annotations

import json
import platform
import socket
import subprocess
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .config import ExperimentConfig, load_config
from .safety import SafetyError, validate_config
from src.defense import apply as apply_defense, ServerConfig
from src.instrumentation import cpu as cpu_instr
from src.instrumentation import packets as pkt_instr
from src.instrumentation import tls_log
from src.legitimate_client.client import run_in_network_handshake


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
    result = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "up", "-d"],
        capture_output=True,
        text=True,
    )
    # docker compose up -d may return non-zero in PowerShell even on success.
    # Verify containers are actually running.
    import time
    for _ in range(30):
        check = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "ps", "-q"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if check.returncode == 0 and check.stdout.strip():
            return
        time.sleep(0.5)
    # If we get here, containers didn't start
    raise RuntimeError(f"docker compose up failed: {result.stderr or result.stdout}")


def _stop_lab(compose_file: str | Path) -> None:
    """Stop the Docker lab."""
    subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "down"],
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


def _wait_for_service(compose_file: str | Path, service: str, timeout: float = 90.0) -> bool:
    """Wait for a compose service to be running."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        cid = _resolve_container_id(compose_file, service)
        if cid:
            return True
        time.sleep(0.5)
    return False


def _run_d1_validation_phase(
    server_container_id: str,
    client_container_id: str,
    config: ExperimentConfig,
    groups: list[str],
    sigalgs: list[str],
    capture_ports: list[int] | None = None,
) -> dict | None:
    """Run the D1 protocol validation phase.

    Performs a bounded number of full TLS 1.3 handshakes against the D1 server
    inside a dedicated packet-capture window. Returns a d1_validation result
    object per design.md §2 schema. Never contributes to W1 workload denominators.
    """
    import statistics
    from src.instrumentation import tls_log

    # Start dedicated validation packet capture
    validation_ports = capture_ports if capture_ports is not None else [config.target_port]
    validation_capture = pkt_instr.start_packet_capture(
        server_container_id, ports=validation_ports
    )
    if not validation_capture.started:
        return {
            "enabled": True,
            "handshakes_requested": config.validation_handshakes,
            "handshakes_completed": 0,
            "observed_sequence": [],
            "hrr_observed": False,
            "cookie_observed": False,
            "client_hello2_observed": False,
            "server_hello_observed": False,
            "negotiated_group": None,
            "rtt_count": None,
            "rtt_latency_p50_ms": None,
            "rtt_latency_p95_ms": None,
            "evidence_sources": [],
            "measurement_status": "failed",
            "measurement_error": validation_capture.error or "validation capture failed to start",
        }

    # Wait for DNS resolution of target host from client container
    # This ensures the client can resolve the server's Docker service name
    import time
    dns_deadline = time.monotonic() + 30.0
    while time.monotonic() < dns_deadline:
        try:
            result = subprocess.run(
                ["docker", "exec", client_container_id, "getent", "hosts", config.client_host],
                capture_output=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                break
        except Exception:
            pass
        time.sleep(0.5)
    else:
        return {
            "enabled": True,
            "handshakes_requested": config.validation_handshakes,
            "handshakes_completed": 0,
            "observed_sequence": [],
            "hrr_observed": False,
            "cookie_observed": False,
            "client_hello2_observed": False,
            "server_hello_observed": False,
            "negotiated_group": None,
            "rtt_count": None,
            "rtt_latency_p50_ms": None,
            "rtt_latency_p95_ms": None,
            "evidence_sources": [],
            "measurement_status": "failed",
            "measurement_error": f"DNS resolution failed for {config.client_host}",
        }

    # Run validation handshakes
    validation_transcripts: list[str] = []
    handshakes_completed = 0
    all_observed_sequence: list[str] = []
    hrr_observed = False
    cookie_observed = False
    client_hello2_observed = False
    server_hello_observed = False
    negotiated_groups: list[str] = []

    for _ in range(config.validation_handshakes):
        obs = run_in_network_handshake(
            container=client_container_id,
            host=config.client_host,
            port=config.target_port,
            groups=groups,
            sigalgs=sigalgs,
            timeout=config.validation_timeout_seconds,
        )
        validation_transcripts.append(obs.transcript)
        if obs.successes:
            handshakes_completed += 1
            # Parse transcript for D1 flow evidence
            d1_obs = tls_log.parse_d1_validation_transcript(obs.transcript)
            all_observed_sequence.extend(d1_obs.observed_sequence)
            if d1_obs.hrr_observed:
                hrr_observed = True
            if d1_obs.client_hello2_observed:
                client_hello2_observed = True
            if d1_obs.cookie_observed:
                cookie_observed = True
            if d1_obs.server_hello_observed:
                server_hello_observed = True
            if d1_obs.negotiated_group:
                negotiated_groups.append(d1_obs.negotiated_group)

    # Stop validation capture and parse pcap
    validation_capture_result = pkt_instr.stop_packet_capture(validation_capture)

    # Parse pcap for D1 flow and RTT
    d1_flow_obs = None
    rtt_count = None
    rtt_p50 = None
    rtt_p95 = None
    if validation_capture_result.success and validation_capture_result.pcap_path:
        try:
            d1_flow_obs = pkt_instr.parse_d1_handshake_flow(
                validation_capture_result.pcap_path, [config.target_port]
            )
        except Exception:
            d1_flow_obs = None

        # Use pcap-derived RTT if available
        if hasattr(validation_capture_result.meta, 'handshake_rtt_count'):
            rtt_count = validation_capture_result.meta.handshake_rtt_count
            rtt_p50 = validation_capture_result.meta.handshake_latency_p50_ms
            rtt_p95 = validation_capture_result.meta.handshake_latency_p95_ms

    # Merge transcript and pcap evidence
    evidence_sources = []
    if validation_transcripts:
        evidence_sources.append("openssl_handshake_transcript")
    if validation_capture_result.success:
        evidence_sources.append("pcap")

    # Determine negotiated_group (prefer most common from transcripts)
    negotiated_group = None
    if negotiated_groups:
        negotiated_group = max(set(negotiated_groups), key=negotiated_groups.count)

    # pcap can confirm flags even if transcript missed them
    if d1_flow_obs:
        hrr_observed = hrr_observed or d1_flow_obs.hrr_observed
        client_hello2_observed = client_hello2_observed or d1_flow_obs.client_hello2_observed
        cookie_observed = cookie_observed or d1_flow_obs.cookie_observed
        server_hello_observed = server_hello_observed or d1_flow_obs.server_hello_observed
        if rtt_count is None and d1_flow_obs.rtt_count is not None:
            rtt_count = d1_flow_obs.rtt_count

    # Build observed_sequence from transcript parser (more detailed)
    # Deduplicate while preserving order
    seen = set()
    dedup_sequence = []
    for msg in all_observed_sequence:
        if msg not in seen:
            seen.add(msg)
            dedup_sequence.append(msg)

    measurement_status = "observed" if handshakes_completed > 0 else "failed"
    measurement_error = None if handshakes_completed > 0 else "no validation handshakes completed"

    return {
        "enabled": True,
        "handshakes_requested": config.validation_handshakes,
        "handshakes_completed": handshakes_completed,
        "observed_sequence": dedup_sequence,
        "hrr_observed": hrr_observed,
        "cookie_observed": cookie_observed,
        "client_hello2_observed": client_hello2_observed,
        "server_hello_observed": server_hello_observed,
        "negotiated_group": negotiated_group,
        "rtt_count": rtt_count,
        "rtt_latency_p50_ms": round(rtt_p50, 3) if rtt_p50 is not None else None,
        "rtt_latency_p95_ms": round(rtt_p95, 3) if rtt_p95 is not None else None,
        "evidence_sources": evidence_sources,
        "measurement_status": measurement_status,
        "measurement_error": measurement_error,
    }


def _per_attempt(value: float | int | None, attempts: int) -> float | None:
    """Normalize a raw measurement by ALL bounded attempts.

    Returns None when the measurement is unavailable or there were no
    attempts — a missing measurement never becomes a numeric zero.
    """
    if value is None or attempts <= 0:
        return None
    return round(value / attempts, 6)


def _get_config_groups_sigalgs(configuration: str) -> tuple[list[str], list[str]]:
    """Return the pinned groups and signature algorithms for a configuration."""
    mapping = {
        "C0": (["X25519"], ["ecdsa_secp256r1_sha256"]),
        "C1": (["MLKEM768"], ["ecdsa_secp256r1_sha256"]),
        "C2": (["X25519"], ["mldsa65"]),
        "C3": (["X25519MLKEM768"], ["ecdsa_secp256r1_sha256"]),
        "C4": (["MLKEM768"], ["mldsa65"]),
    }
    return mapping.get(configuration, ([], []))


def _get_d1_validation_groups_sigalgs() -> tuple[list[str], list[str]]:
    """Return groups and sigalgs for D1 validation client.

    The D1 server (openssl s_server -stateless) is configured with MLKEM768
    as the preferred group. To trigger HRR + stateless cookie, the validation
    client MUST advertise both X25519 and MLKEM768 in supported_groups,
    with X25519 as the initial key share. OpenSSL's s_client uses the first
    group in -groups as the initial key share.
    """
    return (["X25519", "MLKEM768"], ["ecdsa_secp256r1_sha256"])


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

    # Resolve defense-specific server configuration
    server_config: ServerConfig = apply_defense(config.defense, config.configuration)

    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).isoformat()

    server_container_id: str | None = None
    client_container_id: str | None = None
    # Start the lab if a compose file is provided, then resolve its containers.
    if compose_file:
        _start_lab(compose_file)
        # For D2/D3, the target port is the proxy port (4433), but the TLS server is on 4434.
        # Wait for the proxy (or server) to be ready on the target port.
        if not _wait_for_server("127.0.0.1", config.target_port):
            _stop_lab(compose_file)
            raise RuntimeError("TLS server/proxy did not start within timeout")
        if not _wait_for_service(compose_file, "workload-client"):
            _stop_lab(compose_file)
            raise RuntimeError("Workload client container did not start within timeout")
        server_container_id = _resolve_container_id(compose_file, "tls-server")
        client_container_id = _resolve_container_id(compose_file, "workload-client")
        if not server_container_id or not client_container_id:
            _stop_lab(compose_file)
            raise RuntimeError("Failed to resolve server or client container IDs")
        # Wait for python3 and openssl to be installed in workload client container (apk add runs in foreground)
        for _ in range(60):
            check = subprocess.run(
                ["docker", "exec", client_container_id, "test", "-f", "/usr/bin/python3"],
                capture_output=True, timeout=5
            )
            if check.returncode == 0:
                break
            time.sleep(2)
        else:
            _stop_lab(compose_file)
            raise RuntimeError("python3 not installed in workload client container within timeout")

        # Also wait for openssl (installed by the same apk add command)
        for _ in range(60):
            check = subprocess.run(
                ["docker", "exec", client_container_id, "test", "-f", "/usr/bin/openssl"],
                capture_output=True, timeout=5
            )
            if check.returncode == 0:
                break
            time.sleep(2)
        else:
            _stop_lab(compose_file)
            raise RuntimeError("openssl not installed in workload client container within timeout")

    # Get pinned groups and sigalgs for this configuration (needed for workload)
    groups, sigalgs = _get_config_groups_sigalgs(config.configuration)

    # D1 validation uses special groups to trigger HRR: client offers X25519:MLKEM768
    # with X25519 key_share, server prefers MLKEM768 -> HRR requesting MLKEM768
    d1_validation_groups, d1_validation_sigalgs = _get_d1_validation_groups_sigalgs()

    # --- PHASE B: D1 Protocol Validation (separate from W1 measurement) ---
    # Runs for D1 and D3 defenses with validation_handshakes > 0.
    # Uses a dedicated packet-capture window and in-network OpenSSL 3.5.x client.
    # Results are recorded in d1_validation object; NEVER contributes to W1 denominators.
    d1_validation_result: dict | None = None
    if config.defense in ("D1", "D3") and config.validation_handshakes > 0 and server_container_id and client_container_id:
        # For D3, the D1 server is on port 4434 (behind proxy on 4433).
        # Validation should connect directly to the D1 server to test the mechanism.
        if config.defense == "D3":
            val_config = replace(config, target_port=4434, client_host="tls-server")
            val_capture_ports = [4434]
        else:
            val_config = config
            val_capture_ports = [config.target_port]
        d1_validation_result = _run_d1_validation_phase(
            server_container_id=server_container_id,
            client_container_id=client_container_id,
            config=val_config,
            groups=d1_validation_groups,
            sigalgs=d1_validation_sigalgs,
            capture_ports=val_capture_ports,
        )

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
        if server_container_id:
            cpu_session = cpu_instr.start_cpu_sampling(
                server_container_id,
                server_process_name=server_config.server_process_name,
            )
            # For D2/D3, packet capture should monitor both proxy (4433) and TLS server (4434) ports.
            # The controller's target_port is the proxy port (4433); we also capture on 4434 if D2/D3.
            capture_ports = [config.target_port]
            if config.defense in ("D2", "D3"):
                capture_ports.append(4434)  # TLS server port behind proxy
            capture_session = pkt_instr.start_packet_capture(
                server_container_id, ports=capture_ports
            )
        else:
            cpu_error = cpu_error or "no measurement container"
            pkt_error = pkt_error or "no measurement container"

        start_time = time.monotonic()

        # Run the bounded workload inside the workload-client container.
        groups_json = json.dumps(groups)
        sigalgs_json = json.dumps(sigalgs)

        if client_container_id:
            # Run workload client inside container.
            # For D0/D1: TLS server listens on 4433 at service "tls-server"
            # For D2/D3: Proxy listens on 4433 at service "admission-proxy", TLS server on 4434 at "tls-server"
            if config.defense in ("D2", "D3"):
                workload_host = "admission-proxy"
            else:
                workload_host = "tls-server"
            result = subprocess.run(
                [
                    "docker", "exec", client_container_id,
                    "/usr/bin/python3", "-m", "src.workload.client",
                    workload_host, str(config.target_port),
                    config.workload_mode,
                    str(config.max_attempts), str(config.max_duration_seconds),
                    groups_json, sigalgs_json,
                    config.key_reuse,
                ],
                capture_output=True,
                text=True,
                timeout=config.max_duration_seconds + 30,
            )
            if result.returncode != 0:
                raise RuntimeError(f"Workload client failed (code {result.returncode}): {result.stderr}")
            try:
                workload_result = json.loads(result.stdout.strip())
                workload_attempts = workload_result.get("attempts", [])
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Failed to parse workload client output: {e}")
        else:
            # Fallback to local execution (should not happen in Phase 5/6)
            from src.workload.client import generate_attempts
            workload_attempts = list(generate_attempts(
                host=config.target_host,
                port=config.target_port,
                mode=config.workload_mode,
                max_attempts=config.max_attempts,
                max_duration_seconds=config.max_duration_seconds,
                key_reuse=config.key_reuse,
            ))

        for attempt in workload_attempts:
            attempts += 1
            outcome = attempt.get("outcome", "error")
            error_msg = attempt.get("error")
            if outcome == "completed":
                handshake_outcomes["completed"] += 1
            elif outcome == "aborted_pre_finished":
                handshake_outcomes["aborted_pre_finished"] += 1
            else:
                handshake_outcomes["error"] += 1
                last_error = error_msg
            attempt_records.append({"outcome": outcome, "observation": None, "error": error_msg})

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
                if attempts > 0 and bytes_received == 0 and bytes_sent == 0:
                    pkt_status = "failed"
                    pkt_error = pkt_error or "pcap contained no IP bytes for the server port"
                    bytes_received = None
                    bytes_sent = None
                else:
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

        # For D1 and D3, the legitimate client must use validation groups (X25519:MLKEM768)
        # to trigger HRR and complete the handshake through the stateless cookie path.
        if config.defense in ("D1", "D3"):
            legit_groups, legit_sigalgs = _get_d1_validation_groups_sigalgs()
        else:
            legit_groups, legit_sigalgs = groups, sigalgs

        # For D2/D3, legitimate client must connect through proxy (admission-proxy:4433)
        # For D0/D1, legitimate client connects directly to tls-server:4433
        if config.defense in ("D2", "D3"):
            legit_host = "admission-proxy"
        else:
            legit_host = config.target_host

        legit_stats = run_legitimate_client(
            host=legit_host,
            port=config.target_port,
            rate_per_sec=config.legitimate_rate_per_sec,
            duration_seconds=min(max(int(duration), 1), config.max_duration_seconds),
            container=client_container_id,
            groups=legit_groups,
            sigalgs=legit_sigalgs,
        )

    finally:
        # Ensure instruments are stopped and the lab torn down on any path.
        if cpu_session is not None and cpu_session.started and not cpu_stopped:
            cpu_instr.stop_cpu_sampling(cpu_session)
        if capture_session is not None and capture_session.started and not capture_stopped:
            pkt_instr.stop_packet_capture(capture_session)
        if compose_file:
            _stop_lab(compose_file)

    # Get packet-level RTT and handshake latency from capture (if available)
    handshake_rtt_count: int | None = None
    handshake_latency_p50_ms: float | None = None
    handshake_latency_p95_ms: float | None = None
    if capture_session is not None and capture_session.started:
        capture = pkt_instr.stop_packet_capture(capture_session)
        if capture.success and hasattr(capture.meta, 'handshake_rtt_count'):
            handshake_rtt_count = capture.meta.handshake_rtt_count
            handshake_latency_p50_ms = capture.meta.handshake_latency_p50_ms
            handshake_latency_p95_ms = capture.meta.handshake_latency_p95_ms

    # Admission accounting for D2/D3
    admission_accepted: int | None = None
    admission_rejected: int | None = None
    if config.defense in ("D2", "D3"):
        # Count admission rejections from error messages (connection refused)
        # admission_accepted = attempts that reached TLS (aborted_pre_finished + completed)
        # admission_rejected = errors indicating connection refused
        admission_accepted = handshake_outcomes["aborted_pre_finished"] + handshake_outcomes["completed"]
        admission_rejected = 0
        for attempt in attempt_records:
            error = attempt.get("error", "")
            if error and ("connection refused" in error.lower() or "connection reset" in error.lower() or "connection failed" in error.lower()):
                admission_rejected += 1
        # Sanity check
        total_accounted = admission_accepted + admission_rejected + handshake_outcomes["error"]
        # Remaining errors (not connection refused) are other TLS errors
        other_errors = handshake_outcomes["error"] - admission_rejected
        if other_errors < 0:
            other_errors = 0

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
        "d1_validation": d1_validation_result,
        "legitimate": {
            "attempts": legit_stats.attempts,
            "successes": legit_stats.successes,
            "p50_latency_ms": round(legit_stats.p50_latency_ms, 3),
            "p95_latency_ms": round(legit_stats.p95_latency_ms, 3),
            "timeouts": legit_stats.timeouts,
            "handshake_rtt_count": handshake_rtt_count,
            "handshake_latency_p50_ms": round(handshake_latency_p50_ms, 3) if handshake_latency_p50_ms is not None else None,
            "handshake_latency_p95_ms": round(handshake_latency_p95_ms, 3) if handshake_latency_p95_ms is not None else None,
        },
        "environment": {
            "git_commit": _get_git_commit(),
            "os": platform.platform(),
            "cpu": platform.processor() or "unknown",
            "openssl_version": _get_openssl_version(),
            "timestamp_utc": timestamp,
        },
    }

    # Add admission accounting for D2/D3
    if config.defense in ("D2", "D3") and admission_accepted is not None:
        result["admission"] = {
            "accepted": admission_accepted,
            "rejected": admission_rejected,
        }

    # Write result record (append-only).
    result_path = results_dir / f"{config.experiment_id}.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result
