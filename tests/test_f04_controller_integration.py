"""F-04 — controller integration tests (instrumentation and lab mocked).

Verifies the result carries every required field, that values come from the
instrumentation (not fabricated constants), and that unavailable/failed
streams are represented as null + status rather than as zero.
"""
from dataclasses import replace

import pytest

from src.controller import experiment
from src.controller.config import load_config
from src.legitimate_client import client as legit_client
from src.workload import client as workload_client


class _Attempt:
    def __init__(self, outcome, error=None):
        self.timestamp = 0.0
        self.outcome = outcome
        self.error = error


class _CpuSession:
    def __init__(self, started=True, error=None):
        self.started = started
        self.error = error


class _CpuResult:
    def __init__(self, cpu_seconds):
        self.cpu_seconds = cpu_seconds
        self.pid = 10
        self.samples = None


class _CapSession:
    def __init__(self):
        self.started = True
        self.error = None


class _Meta:
    def __init__(self, br, bs):
        self.bytes_received = br
        self.bytes_sent = bs


class _CapResult:
    def __init__(self, success, br=0, bs=0, error=None):
        self.success = success
        self.meta = _Meta(br, bs)
        self.error = error


class _Legit:
    attempts = 3
    successes = 3
    p50_latency_ms = 1.0
    p95_latency_ms = 2.0
    timeouts = 0


def _patch_common(monkeypatch):
    monkeypatch.setattr(experiment, "_start_lab", lambda f: None)
    monkeypatch.setattr(experiment, "_stop_lab", lambda f: None)
    monkeypatch.setattr(experiment, "_wait_for_server", lambda h, p, *a, **k: True)
    monkeypatch.setattr(
        experiment, "_resolve_container_id", lambda f, service="tls-server": "cid"
    )
    monkeypatch.setattr(legit_client, "run_legitimate_client", lambda **k: _Legit())


def test_result_has_required_fields_and_genuine_values(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    monkeypatch.setattr(
        workload_client,
        "generate_attempts",
        lambda **k: iter(
            [
                _Attempt("completed"),
                _Attempt("aborted_pre_finished"),
                _Attempt("error", "boom"),
            ]
        ),
    )
    monkeypatch.setattr(
        experiment.cpu_instr, "start_cpu_sampling", lambda c, interval=1.0: _CpuSession()
    )
    monkeypatch.setattr(
        experiment.cpu_instr, "stop_cpu_sampling", lambda s: _CpuResult(1.5)
    )
    monkeypatch.setattr(
        experiment.pkt_instr,
        "start_packet_capture",
        lambda c, port=4433, interface="eth0": _CapSession(),
    )
    monkeypatch.setattr(
        experiment.pkt_instr, "stop_packet_capture", lambda s: _CapResult(True, 300, 90)
    )

    cfg = replace(load_config("config/c0_experiment.yaml"), experiment_id="TEST-C0-W0-R01")
    result = experiment.run_experiment(cfg, tmp_path, "lab/network/docker-compose-c0.yml")

    for field in (
        "attempts",
        "server_cpu_seconds",
        "server_cpu_seconds_per_attempt",
        "bytes_received",
        "bytes_sent",
        "bytes_received_per_attempt",
        "bytes_sent_per_attempt",
        "tls_events",
    ):
        assert field in result

    assert result["attempts"] == 3
    assert result["server_cpu_seconds"] == 1.5
    assert result["server_cpu_seconds_per_attempt"] == pytest.approx(0.5)
    assert result["bytes_received"] == 300
    assert result["bytes_sent"] == 90
    assert result["bytes_received_per_attempt"] == pytest.approx(100.0)
    assert result["bytes_sent_per_attempt"] == pytest.approx(30.0)
    assert len(result["tls_events"]) == 3
    assert result["measurement_status"] == {
        "server_cpu": "measured",
        "packets": "measured",
        "tls_events": "observed",
    }
    # Genuine values, not fabricated constants.
    assert result["server_cpu_seconds"] != 0
    assert result["bytes_received"] != 0
    assert result["workload_client_cpu_seconds"] is None
    # Persisted.
    assert (tmp_path / "TEST-C0-W0-R01.json").exists()


def test_tls_events_are_null_not_config_derived(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    monkeypatch.setattr(
        workload_client,
        "generate_attempts",
        lambda **k: iter([_Attempt("completed"), _Attempt("aborted_pre_finished")]),
    )
    monkeypatch.setattr(
        experiment.cpu_instr, "start_cpu_sampling", lambda c, interval=1.0: _CpuSession()
    )
    monkeypatch.setattr(experiment.cpu_instr, "stop_cpu_sampling", lambda s: _CpuResult(2.0))
    monkeypatch.setattr(
        experiment.pkt_instr,
        "start_packet_capture",
        lambda c, port=4433, interface="eth0": _CapSession(),
    )
    monkeypatch.setattr(
        experiment.pkt_instr, "stop_packet_capture", lambda s: _CapResult(True, 10, 20)
    )

    cfg = replace(load_config("config/c1_experiment.yaml"), experiment_id="TEST-C1-W0-R01")
    result = experiment.run_experiment(cfg, tmp_path, "lab/network/docker-compose-c1.yml")

    # C1 would "expect" MLKEM768 / ecdsa_secp256r1_sha256 — none may appear.
    for event in result["tls_events"]:
        assert event["negotiated_group"] is None
        assert event["negotiated_signature_algorithm"] is None
        assert event["negotiated_group"] not in {"MLKEM768", "X25519", "X25519MLKEM768"}


def test_partial_measurement_is_visible_not_zero(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    monkeypatch.setattr(
        workload_client, "generate_attempts", lambda **k: iter([_Attempt("completed")])
    )
    failed_cpu = _CpuSession(
        started=False, error="openssl s_server PID could not be identified"
    )
    monkeypatch.setattr(
        experiment.cpu_instr, "start_cpu_sampling", lambda c, interval=1.0: failed_cpu
    )
    monkeypatch.setattr(experiment.cpu_instr, "stop_cpu_sampling", lambda s: None)
    monkeypatch.setattr(
        experiment.pkt_instr,
        "start_packet_capture",
        lambda c, port=4433, interface="eth0": _CapSession(),
    )
    monkeypatch.setattr(
        experiment.pkt_instr,
        "stop_packet_capture",
        lambda s: _CapResult(False, error="tcpdump unavailable"),
    )

    cfg = replace(load_config("config/c0_experiment.yaml"), experiment_id="TEST-C0-W0-R02")
    result = experiment.run_experiment(cfg, tmp_path, "lab/network/docker-compose-c0.yml")

    assert result["server_cpu_seconds"] is None
    assert result["server_cpu_seconds_per_attempt"] is None
    assert result["bytes_received"] is None
    assert result["bytes_sent"] is None
    assert result["bytes_received_per_attempt"] is None
    assert result["measurement_status"]["packets"] == "failed"
    assert result["measurement_status"]["server_cpu"] in ("failed", "unavailable")
    assert result["measurement_errors"]["packets"]


def test_zero_attempts_do_not_divide(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    monkeypatch.setattr(workload_client, "generate_attempts", lambda **k: iter([]))
    monkeypatch.setattr(
        experiment.cpu_instr, "start_cpu_sampling", lambda c, interval=1.0: _CpuSession()
    )
    monkeypatch.setattr(experiment.cpu_instr, "stop_cpu_sampling", lambda s: _CpuResult(0.0))
    monkeypatch.setattr(
        experiment.pkt_instr,
        "start_packet_capture",
        lambda c, port=4433, interface="eth0": _CapSession(),
    )
    monkeypatch.setattr(
        experiment.pkt_instr, "stop_packet_capture", lambda s: _CapResult(True, 0, 0)
    )

    cfg = replace(load_config("config/c0_experiment.yaml"), experiment_id="TEST-C0-W0-R03")
    result = experiment.run_experiment(cfg, tmp_path, "lab/network/docker-compose-c0.yml")

    assert result["attempts"] == 0
    assert result["server_cpu_seconds_per_attempt"] is None
    assert result["bytes_received_per_attempt"] is None

