"""F-03 — bounded packet-capture lifecycle tests (subprocess mocked)."""
import subprocess as _sp
from unittest import mock

from src.instrumentation import packets


class FakeProc:
    def __init__(self, poll_value=None, stdout="", stderr=""):
        self._poll = poll_value
        self.stdout = stdout
        self.stderr = stderr
        self.terminated = False
        self.killed = False
        self.waited = False

    def poll(self):
        return self._poll

    def wait(self, timeout=None):
        self.waited = True
        self._poll = 0
        return 0

    def communicate(self, timeout=None):
        return self.stdout, self.stderr

    def terminate(self):
        self.terminated = True
        self._poll = 0

    def kill(self):
        self.killed = True
        self._poll = 0


def _session(proc, started=True):
    return packets.CaptureSession(
        container_name="cid",
        pcap_path="/tmp/pq_capture_x.pcap",
        interface="eth0",
        port=4433,
        ports=[4433],
        proc=proc,
        started=started,
        start_time=0.0,
    )


def _ok_run(args, **kwargs):
    return mock.Mock(returncode=0, stdout="", stderr="")


def test_capture_starts_and_confirms_process(monkeypatch):
    monkeypatch.setattr(packets, "_ensure_tcpdump", lambda c: True)
    monkeypatch.setattr(packets.time, "sleep", lambda s: None)
    fake = FakeProc(poll_value=None)
    monkeypatch.setattr(packets.subprocess, "Popen", lambda *a, **k: fake)

    session = packets.start_packet_capture("cid", 4433, "eth0")
    assert session.started is True
    assert session.proc is fake


def test_capture_start_detects_immediate_exit(monkeypatch):
    monkeypatch.setattr(packets, "_ensure_tcpdump", lambda c: True)
    monkeypatch.setattr(packets.time, "sleep", lambda s: None)
    fake = FakeProc(poll_value=1, stderr="boom")
    monkeypatch.setattr(packets.subprocess, "Popen", lambda *a, **k: fake)

    session = packets.start_packet_capture("cid")
    assert session.started is False
    assert session.error


def test_stop_sends_sigint_waits_and_parses(monkeypatch):
    run_calls = []

    def fake_run(args, **kwargs):
        run_calls.append(args)
        return _ok_run(args)

    monkeypatch.setattr(packets.subprocess, "run", fake_run)
    monkeypatch.setattr(packets, "_parse_pcap_file", lambda path, port: (123, 45, 3, 2))
    monkeypatch.setattr(packets.os.path, "exists", lambda p: False)

    fake = FakeProc(poll_value=None)
    result = packets.stop_packet_capture(_session(fake))

    assert result.success is True
    assert result.meta.bytes_received == 123
    assert result.meta.bytes_sent == 45
    assert fake.waited is True
    # Explicit SIGINT stop was issued (not a timeout).
    assert any("pkill" in c for c in run_calls)


def test_timeout_is_only_a_backstop(monkeypatch):
    monkeypatch.setattr(packets.subprocess, "run", _ok_run)
    monkeypatch.setattr(packets, "_parse_pcap_file", lambda path, port: (1, 1, 1, 1))
    monkeypatch.setattr(packets.os.path, "exists", lambda p: False)

    class HangingProc(FakeProc):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._wait_calls = 0

        def wait(self, timeout=None):
            self.waited = True
            self._wait_calls += 1
            if self._wait_calls == 1:
                raise _sp.TimeoutExpired(cmd="tcpdump", timeout=timeout)
            self._poll = 0
            return 0

    fake = HangingProc(poll_value=None)
    result = packets.stop_packet_capture(_session(fake), stop_timeout=0.0)
    # A timeout only triggers the emergency terminate path; capture still ends.
    assert fake.terminated is True
    assert result.success is True


def test_failed_capture_is_not_a_measured_zero(monkeypatch):
    def fake_run(args, **kwargs):
        if "cp" in args:
            return mock.Mock(returncode=1, stdout="", stderr="copy failed")
        return _ok_run(args)

    monkeypatch.setattr(packets.subprocess, "run", fake_run)
    monkeypatch.setattr(packets.os.path, "exists", lambda p: False)

    fake = FakeProc(poll_value=0)
    result = packets.stop_packet_capture(_session(fake))
    assert result.success is False
    assert result.error
    # A failed capture must never masquerade as a successful measurement.
    assert result.success is False


def test_cleanup_runs_on_success(monkeypatch):
    run_calls = []
    removed = []

    def fake_run(args, **kwargs):
        run_calls.append(args)
        return _ok_run(args)

    monkeypatch.setattr(packets.subprocess, "run", fake_run)
    monkeypatch.setattr(packets, "_parse_pcap_file", lambda path, port: (0, 0, 0, 0))
    monkeypatch.setattr(packets.os.path, "exists", lambda p: True)
    monkeypatch.setattr(packets.os, "remove", lambda p: removed.append(p))

    packets.stop_packet_capture(_session(FakeProc(poll_value=0)))
    assert any("rm" in c for c in run_calls)  # container cleanup
    assert removed                            # host cleanup


def test_cleanup_runs_on_failure(monkeypatch):
    removed = []

    def fake_run(args, **kwargs):
        if "cp" in args:
            return mock.Mock(returncode=1, stdout="", stderr="copy failed")
        return _ok_run(args)

    monkeypatch.setattr(packets.subprocess, "run", fake_run)
    monkeypatch.setattr(packets.os.path, "exists", lambda p: True)
    monkeypatch.setattr(packets.os, "remove", lambda p: removed.append(p))

    packets.stop_packet_capture(_session(FakeProc(poll_value=0)))
    assert removed  # host cleanup still runs on the failure path
