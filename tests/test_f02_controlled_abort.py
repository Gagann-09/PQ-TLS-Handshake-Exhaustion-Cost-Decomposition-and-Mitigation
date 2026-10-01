"""F-02 — controlled-abort (W1) semantics tests.

Structural + unit verification (runtime follows separately in the report).
These prove W1 does not perform a completed handshake before its abort, and
that a completed handshake cannot be mislabeled `aborted_pre_finished`.
"""
import inspect

import pytest

from src.workload import client as wl


def test_normal_completion_performs_a_handshake():
    src = inspect.getsource(wl._attempt_normal_completion)
    assert "wrap_socket" in src
    # W0 must NOT disable the handshake.
    assert "do_handshake_on_connect=False" not in src


def test_controlled_abort_drives_handshake_manually():
    src = inspect.getsource(wl._attempt_controlled_abort)
    # The abort path must disable the automatic (blocking) handshake ...
    assert "do_handshake_on_connect=False" in src
    # ... drive one handshake step, then stop.
    assert "do_handshake()" in src
    assert "SSLWantReadError" in src or "SSLWantWriteError" in src
    # ... and must refuse to report an abort if the handshake completed.
    assert "unexpectedly completed" in src


def test_w1_abort_raises_if_handshake_completes(monkeypatch):
    """If the handshake completes, the abort helper must raise (=> error)."""

    class _Completed:
        def do_handshake(self):
            return None  # completed, not WantRead/WantWrite

        def close(self):
            pass

    class _Ctx:
        def wrap_socket(self, sock, **kwargs):
            return _Completed()

    class _Sock:
        def setblocking(self, flag):
            pass

        def close(self):
            pass

    monkeypatch.setattr(wl, "_make_context", lambda: _Ctx())
    monkeypatch.setattr(wl.socket, "create_connection", lambda *a, **k: _Sock())

    with pytest.raises(RuntimeError):
        wl._attempt_controlled_abort("localhost", 4433)


def test_w1_returns_normally_on_want_read(monkeypatch):
    class _Pending:
        def do_handshake(self):
            raise wl.ssl.SSLWantReadError("would block")

        def close(self):
            pass

    class _Ctx:
        def wrap_socket(self, sock, **kwargs):
            return _Pending()

    class _Sock:
        def setblocking(self, flag):
            pass

        def close(self):
            pass

    monkeypatch.setattr(wl, "_make_context", lambda: _Ctx())
    monkeypatch.setattr(wl.socket, "create_connection", lambda *a, **k: _Sock())

    # Should return normally (no exception) => genuine pre-Finished abort.
    wl._attempt_controlled_abort("localhost", 4433)


def test_outcome_mapping(monkeypatch):
    monkeypatch.setattr(wl, "_attempt_normal_completion", lambda h, p: None)
    monkeypatch.setattr(wl, "_attempt_controlled_abort", lambda h, p: None)

    normal = list(wl.generate_attempts("localhost", 4433, "normal_completion", 1, 5))
    assert normal[0].outcome == "completed"

    abort = list(wl.generate_attempts("localhost", 4433, "controlled_abort", 1, 5))
    assert abort[0].outcome == "aborted_pre_finished"


def test_completed_handshake_cannot_be_mislabeled_aborted(monkeypatch):
    def boom(host, port):
        raise RuntimeError("controlled_abort handshake unexpectedly completed")

    monkeypatch.setattr(wl, "_attempt_controlled_abort", boom)
    attempts = list(wl.generate_attempts("localhost", 4433, "controlled_abort", 1, 5))
    assert attempts[0].outcome == "error"
    assert attempts[0].outcome != "aborted_pre_finished"
