"""F-02 — controlled-abort (W1) semantics tests.

Structural + unit verification (runtime follows separately in the report).
These prove W1 does not perform a completed handshake before its abort, and
that a completed handshake cannot be mislabeled `aborted_pre_finished`.
"""
import inspect
import subprocess

import pytest

from src.workload import client as wl


def test_normal_completion_uses_openssl_s_client():
    """W0 uses openssl s_client to perform a full handshake."""
    src = inspect.getsource(wl._attempt_normal_completion)
    assert "openssl" in src
    assert "s_client" in src
    assert "CONNECTION ESTABLISHED" in src
    assert "Protocol version: TLS" in src
    # W0 must NOT use -brief flag (that would exit early)
    assert "-brief" not in src


def test_controlled_abort_uses_openssl_s_client_brief():
    """W1 uses openssl s_client -brief with short timeout to abort pre-Finished."""
    src = inspect.getsource(wl._attempt_controlled_abort)
    assert "openssl" in src
    assert "s_client" in src
    assert "-brief" in src
    assert "TimeoutExpired" in src or "timeout" in src
    # Must refuse to report an abort if the handshake completed
    assert "unexpectedly completed" in src
    assert "CONNECTION ESTABLISHED" in src
    assert "Protocol version: TLS" in src


def test_w1_abort_raises_if_handshake_completes(monkeypatch):
    """If the handshake completes, the abort helper must raise (=> error)."""

    class _CompletedProc:
        returncode = 0
        stdout = "CONNECTION ESTABLISHED\nProtocol version: TLSv1.3"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _CompletedProc())

    with pytest.raises(RuntimeError, match="unexpectedly completed"):
        wl._attempt_controlled_abort("localhost", 4433)


def test_w1_returns_normally_on_abort(monkeypatch):
    """Short timeout / abort should return normally (=> genuine pre-Finished abort)."""

    class _AbortProc:
        """Simulates openssl s_client -brief timing out (abort)."""
        def __init__(self):
            raise subprocess.TimeoutExpired("openssl", 0.5)

    def mock_run(*a, **k):
        raise subprocess.TimeoutExpired("openssl", 0.5)

    monkeypatch.setattr(subprocess, "run", mock_run)

    # Should return normally (no exception) => genuine pre-Finished abort.
    wl._attempt_controlled_abort("localhost", 4433)


def test_outcome_mapping(monkeypatch):
    monkeypatch.setattr(wl, "_attempt_normal_completion", lambda *a, **k: None)
    monkeypatch.setattr(wl, "_attempt_controlled_abort", lambda *a, **k: None)

    normal = list(wl.generate_attempts("localhost", 4433, "normal_completion", 1, 5, [], []))
    assert normal[0].outcome == "completed"

    abort = list(wl.generate_attempts("localhost", 4433, "controlled_abort", 1, 5, [], []))
    assert abort[0].outcome == "aborted_pre_finished"


def test_completed_handshake_cannot_be_mislabeled_aborted(monkeypatch):
    def boom(host, port):
        raise RuntimeError("controlled_abort handshake unexpectedly completed")

    monkeypatch.setattr(wl, "_attempt_controlled_abort", boom)
    attempts = list(wl.generate_attempts("localhost", 4433, "controlled_abort", 1, 5, [], []))
    assert attempts[0].outcome == "error"
    assert attempts[0].outcome != "aborted_pre_finished"