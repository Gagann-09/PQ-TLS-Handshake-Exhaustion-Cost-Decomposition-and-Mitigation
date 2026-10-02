"""Regression tests for the CPU sampling path (pidstat).

Covers the fixes required to make the locked CPU methodology executable in the
Docker lab: pidstat ships in the ``sysstat`` package (NOT ``procps``), and the
timestamped pidstat output form (produced when an interval is used) must be
parsed. Also locks the PID-resolution requirement: exactly one actual
``openssl s_server`` process must be identified.
"""
from unittest import mock

import pytest

from src.instrumentation import cpu

TIMESTAMPED = (
    "Linux 6.6.87.2-microsoft-standard-WSL2 (abc)   10/01/26   _x86_64_  (16 CPU)\n"
    "\n"
    "17:12:10      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command\n"
    "17:12:11        0         1    1.23   4.56    0.00    0.00   5.79     8  openssl\n"
    "17:12:12        0         1    2.00   1.00    0.00    0.00   3.00     3  openssl\n"
    "\n"
    "Average:        0         1    1.61   2.78    0.00    0.00   4.39     -  openssl\n"
)

SINCE_BOOT = (
    "Linux 6.6 (abc)   10/01/26   _x86_64_  (16 CPU)\n"
    "\n"
    "#      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command\n"
    "         0         1    5.00   5.00    0.00    0.00  10.00     -  openssl\n"
)


def test_parse_timestamped_output():
    samples = cpu._parse_pidstat_output(TIMESTAMPED, interval=1.0)
    assert samples.cpu_percent == [5.79, 3.00]
    assert len(samples.timestamps) == 2


def test_parse_since_boot_output():
    samples = cpu._parse_pidstat_output(SINCE_BOOT, interval=1.0)
    assert samples.cpu_percent == [10.00]


def test_parse_ignores_header_and_average():
    samples = cpu._parse_pidstat_output(TIMESTAMPED, interval=1.0)
    # Header + Average lines must not be counted as samples.
    assert len(samples.cpu_percent) == 2


def test_derive_cpu_seconds_from_timestamped_samples():
    samples = cpu._parse_pidstat_output(TIMESTAMPED, interval=1.0)
    # 5.79% * 1s + 3.00% * 1s = 0.0879 CPU-seconds
    assert cpu.derive_cpu_seconds(samples, 1.0) == pytest.approx(0.0879)


def test_start_cpu_sampling_installs_sysstat(monkeypatch):
    ensure_calls: list[tuple] = []

    def fake_ensure(container_name, tool, package, **kwargs):
        ensure_calls.append((container_name, tool, package))
        return True

    monkeypatch.setattr(cpu, "find_server_pid", lambda c, timeout=10.0: 1)
    monkeypatch.setattr(cpu, "verify_server_pid", lambda c, p, timeout=10.0: True)
    monkeypatch.setattr(
        "src.instrumentation.container.ensure_container_tool", fake_ensure
    )
    monkeypatch.setattr(cpu.subprocess, "Popen", lambda *a, **k: mock.Mock())

    session = cpu.start_cpu_sampling("cid")
    assert session.started is True
    assert ensure_calls == [("cid", "pidstat", "sysstat")]


def test_cmdline_is_openssl_s_server_accepts_real_process():
    cmdline = b"openssl\x00s_server\x00-accept\x004433\x00"
    assert cpu._cmdline_is_openssl_s_server(cmdline) is True


def test_cmdline_is_openssl_s_server_rejects_shell_wrapper():
    cmdline = (
        b"sh\x00-c\x00apk add --no-cache openssl && "
        b"openssl s_server -accept 4433\x00"
    )
    assert cpu._cmdline_is_openssl_s_server(cmdline) is False


def test_find_server_pid_requires_exactly_one(monkeypatch):
    openssl_cmdline = b"openssl\x00s_server\x00-accept\x004433\x00"
    shell_cmdline = b"sh\x00-c\x00openssl s_server\x00"

    def fake_list(container_name, timeout=10.0):
        return [1, 42]

    def fake_read(container_name, pid, timeout=10.0):
        if pid == 42:
            return openssl_cmdline
        return shell_cmdline

    monkeypatch.setattr(cpu, "_list_proc_pids", fake_list)
    monkeypatch.setattr(cpu, "_read_proc_cmdline", fake_read)
    assert cpu.find_server_pid("cid") == 42

    def fake_list_two_openssl(container_name, timeout=10.0):
        return [10, 11]

    def fake_read_two(container_name, pid, timeout=10.0):
        return openssl_cmdline

    monkeypatch.setattr(cpu, "_list_proc_pids", fake_list_two_openssl)
    monkeypatch.setattr(cpu, "_read_proc_cmdline", fake_read_two)
    assert cpu.find_server_pid("cid") is None

    monkeypatch.setattr(cpu, "_list_proc_pids", lambda *a, **k: [])
    assert cpu.find_server_pid("cid") is None


def test_stop_cpu_sampling_returns_none_without_samples(monkeypatch):
    monkeypatch.setattr(cpu.subprocess, "run", lambda *a, **k: mock.Mock(returncode=0))
    session = cpu.CpuSamplingSession(container_name="cid", interval=1.0, pid=1)
    session.started = True
    session.proc = mock.Mock()
    session.proc.communicate.return_value = ("", "")
    assert cpu.stop_cpu_sampling(session) is None
