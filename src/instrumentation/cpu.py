"""CPU and process instrumentation.

See architecture.md §3.5. Uses pidstat inside the TLS-server container
for CPU sampling of the openssl s_server process at 1 Hz.

Host-side psutil is NOT an experimental fallback. Docker cumulative stats
are NOT the primary CPU measurement.
"""
from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field


@dataclass
class CpuSamples:
    """CPU samples collected during a run."""
    timestamps: list[float] = field(default_factory=list)
    cpu_percent: list[float] = field(default_factory=list)


@dataclass
class PidstatResult:
    """Result from running pidstat inside a container."""
    samples: CpuSamples
    cpu_seconds: float
    pid: int
    process_name: str


@dataclass
class CpuSamplingSession:
    """A running, bounded CPU-sampling session (non-blocking).

    `started` is True only after pidstat has been launched for a verified PID.
    `error` records why a session could not start.
    """

    container_name: str
    interval: float
    pid: int = -1
    proc: "subprocess.Popen | None" = None
    started: bool = False
    start_time: float = 0.0
    error: str | None = None


def _cmdline_is_openssl_s_server(cmdline: bytes) -> bool:
    """True when cmdline is the actual openssl s_server process, not a shell wrapper."""
    if not cmdline:
        return False
    parts = cmdline.split(b"\x00")
    if parts and parts[-1] == b"":
        parts = parts[:-1]
    if not parts:
        return False
    exe = parts[0].decode("utf-8", errors="replace")
    if not (exe == "openssl" or exe.endswith("/openssl")):
        return False
    return b"s_server" in parts[1:]


def _list_proc_pids(container_name: str, timeout: float) -> list[int]:
    """List numeric PIDs visible inside the container."""
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "sh", "-c", "ls -1 /proc"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            return []
        pids: list[int] = []
        for name in result.stdout.split():
            if name.isdigit():
                pids.append(int(name))
        return pids
    except Exception:
        return []


def _read_proc_cmdline(container_name: str, pid: int, timeout: float) -> bytes | None:
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "cat", f"/proc/{pid}/cmdline"],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            return None
        return result.stdout
    except Exception:
        return None


def find_server_pid(container_name: str, timeout: float = 10.0) -> int | None:
    """Find the openssl s_server process PID inside the container.

    Inspects /proc cmdlines so a shell wrapper that merely mentions
    ``openssl s_server`` in its ``-c`` string is not mistaken for the server.
    Returns None if the process cannot be unambiguously identified.
    """
    try:
        matches: list[int] = []
        for pid in _list_proc_pids(container_name, timeout):
            cmdline = _read_proc_cmdline(container_name, pid, timeout)
            if cmdline is not None and _cmdline_is_openssl_s_server(cmdline):
                matches.append(pid)
        if len(matches) != 1:
            return None
        return matches[0]
    except Exception:
        return None


def verify_server_pid(container_name: str, pid: int, timeout: float = 10.0) -> bool:
    """Verify that the given PID is actually the openssl s_server process."""
    cmdline = _read_proc_cmdline(container_name, pid, timeout)
    return cmdline is not None and _cmdline_is_openssl_s_server(cmdline)


def _parse_pidstat_output(output: str, interval: float) -> CpuSamples:
    """Parse pidstat output and return CpuSamples.

    Two real pidstat output forms are handled.

    Timestamped (an interval is used — the form this project consumes):
    ```
    Linux 6.6.87.2-microsoft-standard-WSL2 (host)   10/01/26   _x86_64_  (16 CPU)

    17:12:10      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command
    17:12:11        0         1    1.23   4.56    0.00    0.00   5.79     8  openssl
    Average:        0         1    0.61   2.28    0.00    0.00   2.89     -  openssl
    ```

    Since-boot (no interval):
    ```
    #      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command
             0         1    1.23   4.56    0.00    0.00   5.79     -  openssl
    ```

    In the timestamped form the leading HH:MM:SS column is stripped before the
    UID/PID/%CPU columns are read.
    """
    samples = CpuSamples()
    for line in output.split("\n"):
        line = line.strip()
        if (
            not line
            or line.startswith("Linux")
            or line.startswith("#")
            or line.startswith("Average")
        ):
            continue
        parts = line.split()
        # Strip the leading timestamp column (present when an interval is used).
        if parts and ":" in parts[0]:
            parts = parts[1:]
        # Columns: UID PID %usr %system %guest %wait %CPU CPU Command
        if len(parts) < 8:
            continue
        try:
            int(parts[1])          # PID column must be a valid integer
            cpu_percent = float(parts[6])
        except (ValueError, IndexError):
            continue
        samples.timestamps.append(len(samples.timestamps) * interval)
        samples.cpu_percent.append(cpu_percent)
    return samples


def derive_cpu_seconds(samples: CpuSamples, interval: float) -> float:
    """Derive CPU-seconds from sampled CPU percentages.

    CPU-seconds = sum of (CPU% / 100 * interval) for each sample.

    This gives the total CPU time consumed by the process during the
    measurement window, accounting for multi-core usage (CPU% can exceed
    100% on multi-core systems).
    """
    if not samples.cpu_percent:
        return 0.0
    total = 0.0
    for cpu_pct in samples.cpu_percent:
        total += (cpu_pct / 100.0) * interval
    return total


def start_cpu_sampling(
    container_name: str,
    interval: float = 1.0,
) -> CpuSamplingSession:
    """Start background pidstat sampling of the openssl s_server process.

    Non-blocking: pidstat runs continuously until `stop_cpu_sampling` is
    called, so the workload executes within the sampling window. Returns a
    session whose `started` flag is True only if sampling actually began; if
    the server PID cannot be identified (see find_server_pid) or pidstat cannot
    be launched, `started` is False and `error` explains why.
    """
    session = CpuSamplingSession(container_name=container_name, interval=interval)

    pid: int | None = None
    pid_lookup_timeout = 10.0
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        pid = find_server_pid(container_name, timeout=pid_lookup_timeout)
        if pid is not None:
            break
        time.sleep(0.5)
    if pid is None:
        session.error = "openssl s_server PID could not be identified"
        return session
    if not verify_server_pid(container_name, pid):
        session.error = "server PID verification failed"
        return session

    # Ensure sysstat is installed (it provides pidstat; procps does NOT).
    from src.instrumentation.container import ensure_container_tool

    if not ensure_container_tool(container_name, "pidstat", "sysstat"):
        session.error = "pidstat is not available (sysstat install failed)"
        return session

    try:
        session.proc = subprocess.Popen(
            ["docker", "exec", container_name, "pidstat", "-p", str(pid),
             str(int(interval))],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as e:
        session.error = f"failed to start pidstat: {e}"
        return session

    session.pid = pid
    session.started = True
    session.start_time = time.monotonic()
    return session


def stop_cpu_sampling(
    session: CpuSamplingSession,
    stop_timeout: float = 15.0,
) -> PidstatResult | None:
    """Stop pidstat explicitly and derive CPU-seconds from its output.

    Returns None when sampling did not start or produced no samples, so the
    caller reports CPU as unavailable rather than as a measured zero.
    """
    if not session.started or session.proc is None:
        return None

    proc = session.proc
    # Explicit stop: SIGINT lets pidstat flush and exit cleanly.
    try:
        subprocess.run(
            ["docker", "exec", session.container_name, "pkill", "-INT", "pidstat"],
            capture_output=True,
            text=True,
            timeout=stop_timeout,
            check=False,
        )
    except Exception:
        pass

    try:
        stdout, _ = proc.communicate(timeout=stop_timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, _ = proc.communicate()
        session.error = session.error or "pidstat did not terminate cleanly"

    samples = _parse_pidstat_output(stdout or "", session.interval)
    if not samples.cpu_percent:
        session.error = session.error or "no pidstat samples captured"
        return None

    return PidstatResult(
        samples=samples,
        cpu_seconds=derive_cpu_seconds(samples, session.interval),
        pid=session.pid,
        process_name="openssl s_server",
    )


def sample_cpu(pid: int, interval: float, duration: float) -> CpuSamples:
    """Sample CPU usage for the given process at the specified interval.

    Returns CpuSamples. Uses psutil if available, otherwise returns empty.

    NOTE: This is the legacy host-side approach. The primary Phase 4
    methodology uses start_cpu_sampling()/stop_cpu_sampling() with pidstat
    inside the TLS-server container. This function is retained for
    non-container use only and is NOT an experimental fallback.
    """
    samples = CpuSamples()
    try:
        import psutil
    except ImportError:
        return samples

    try:
        proc = psutil.Process(pid)
    except Exception:
        return samples

    start = time.monotonic()
    while time.monotonic() - start < duration:
        try:
            samples.timestamps.append(time.monotonic() - start)
            samples.cpu_percent.append(proc.cpu_percent(interval=None))
        except Exception:
            break
        time.sleep(interval)

    return samples
