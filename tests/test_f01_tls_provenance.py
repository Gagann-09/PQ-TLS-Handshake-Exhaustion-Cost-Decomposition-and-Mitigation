"""F-01 — TLS negotiation provenance tests.

These prove observed negotiated values can only come from a real observation
source, never from the experiment configuration.
"""
from src.instrumentation import tls_log


def test_completed_handshake_does_not_populate_from_configuration():
    """A completed handshake alone must not yield configuration values."""
    event = tls_log.normalize_tls_event("completed")
    assert event.negotiated_group is None
    assert event.negotiated_signature_algorithm is None
    # The C0-C4 expectation values must not appear as observations.
    assert event.negotiated_group not in {"X25519", "MLKEM768", "X25519MLKEM768"}
    assert event.negotiated_signature_algorithm not in {
        "ecdsa_secp256r1_sha256",
        "mldsa65",
    }


def test_actual_observation_produces_observed_values():
    """A genuine OpenSSL transcript yields its key-exchange/signature values."""
    transcript = (
        "Peer signature type: ecdsa_secp256r1_sha256\n"
        "Negotiated TLS1.3 group: X25519\n"
    )
    observation = tls_log.parse_openssl_handshake_observation(transcript)
    event = tls_log.normalize_tls_event("completed", observation)
    assert event.negotiated_group == "X25519"
    assert event.negotiated_signature_algorithm == "ecdsa_secp256r1_sha256"
    assert event.evidence_source == tls_log.SOURCE_OPENSSL_TRANSCRIPT


def test_missing_observation_produces_null():
    """With no observation, both negotiated fields are null."""
    event = tls_log.normalize_tls_event("aborted_pre_finished")
    assert event.negotiated_group is None
    assert event.negotiated_signature_algorithm is None


def test_partial_observation_leaves_missing_field_null():
    """Only the observed field is populated; the other stays null."""
    observation = tls_log.parse_openssl_handshake_observation(
        "Negotiated TLS1.3 group: X25519\n"
    )
    event = tls_log.normalize_tls_event("completed", observation)
    assert event.negotiated_group == "X25519"
    assert event.negotiated_signature_algorithm is None


def test_brief_transcript_format_is_parsed():
    """The `s_client -brief` transcript format is also genuine evidence."""
    transcript = (
        "Peer Temp Key: X25519, 253 bits\n"
        "Signature type: ecdsa_secp256r1_sha256\n"
    )
    observation = tls_log.parse_openssl_handshake_observation(transcript)
    assert observation.negotiated_group == "X25519"
    assert observation.negotiated_signature_algorithm == "ecdsa_secp256r1_sha256"


def test_configuration_alone_cannot_manufacture_an_observation():
    """The module exposes no configuration->observation mapping at all."""
    assert not hasattr(tls_log, "CONFIG_EXPECTED_GROUP")
    assert not hasattr(tls_log, "CONFIG_EXPECTED_SIGNATURE")

    # normalize_tls_event has no configuration parameter, so an outcome that a
    # pinned config would "expect" to complete still yields null.
    for outcome in ("completed", "aborted_pre_finished", "error"):
        event = tls_log.normalize_tls_event(outcome)
        assert event.negotiated_group is None
        assert event.negotiated_signature_algorithm is None


def test_observe_tls_events_uses_records_not_configuration():
    records = [
        {"outcome": "completed", "observation": None},
        {
            "outcome": "completed",
            "observation": tls_log.parse_openssl_handshake_observation(
                "Negotiated TLS1.3 group: X25519MLKEM768\n"
                "Peer signature type: ecdsa_secp256r1_sha256\n"
            ),
        },
        {"outcome": "aborted_pre_finished"},
        {"outcome": "error"},
    ]
    result = tls_log.observe_tls_events(records)
    assert result.total_events == 4
    assert result.completed_count == 2
    assert result.aborted_count == 1
    assert result.error_count == 1
    assert result.events[0].negotiated_group is None
    assert result.events[1].negotiated_group == "X25519MLKEM768"
