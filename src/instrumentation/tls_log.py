"""TLS event observation and normalization.

See architecture.md §3.5 and design.md §3. Produces normalized TLS events with
fields: negotiated_group, negotiated_signature_algorithm, outcome.

Provenance requirement (PRD.md §8, architecture.md §3.5, memory.md P4-001):
every normalized TLS event must be traceable to an underlying observation
source. The implementation MUST NOT manufacture negotiated values from the
experiment configuration alone. A configured expectation (e.g. C3 =
X25519MLKEM768 + ECDSA-P256) is NOT evidence that a given attempt negotiated
those values. Where the observation source does not expose the negotiated
group / signature algorithm, the field is `null` — never a configuration value.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

# Outcome vocabulary (locked, PRD.md §8.1).
Outcome = Literal["completed", "aborted_pre_finished", "error"]

# Evidence-source labels naming the actual observation that produced an event.
SOURCE_CLIENT_OUTCOME = "client_handshake_outcome"
SOURCE_OPENSSL_TRANSCRIPT = "openssl_handshake_transcript"
SOURCE_NONE = "no_negotiation_observation"


@dataclass(frozen=True)
class NegotiationObservation:
    """The negotiated algorithms actually *observed* for a handshake.

    A field is None when the underlying observation did not expose it. This is
    meaningful and MUST NOT be replaced by a configured expectation.
    """

    negotiated_group: str | None = None
    negotiated_signature_algorithm: str | None = None
    source: str = SOURCE_NONE


@dataclass
class HandshakeEvent:
    """Normalized TLS observation for a handshake attempt.

    - negotiated_group: observed negotiated key-exchange group, or null if the
      observation did not expose it.
    - negotiated_signature_algorithm: observed negotiated signature algorithm,
      or null if the observation did not expose it.
    - outcome: completed | aborted_pre_finished | error.
    - evidence_source: the underlying observation source for this event.
    """

    negotiated_group: str | None = None
    negotiated_signature_algorithm: str | None = None
    outcome: Outcome = "error"
    evidence_source: str = ""


@dataclass
class TlsObservationResult:
    """Result from TLS event observation."""

    events: list[HandshakeEvent] = field(default_factory=list)
    total_events: int = 0
    completed_count: int = 0
    aborted_count: int = 0
    error_count: int = 0


# OpenSSL handshake-transcript fields (verified against OpenSSL 3.5.5):
#   full  `openssl s_client` : "Negotiated TLS1.3 group: X25519MLKEM768"
#                              "Peer signature type: ecdsa_secp256r1_sha256"
#   brief `openssl s_client -brief` : "Peer Temp Key: X25519, 253 bits"
#                                     "Signature type: ecdsa_secp256r1_sha256"
_GROUP_PATTERNS = (
    re.compile(r"Negotiated TLS1\.?3 group:\s*([A-Za-z0-9_\-]+)"),
    re.compile(r"Peer Temp Key:\s*([A-Za-z0-9_\-]+)"),
)
_SIGNATURE_PATTERNS = (
    re.compile(r"Peer signature type:\s*([A-Za-z0-9_\-]+)"),
    re.compile(r"Signature type:\s*([A-Za-z0-9_\-]+)"),
)


def parse_openssl_handshake_observation(transcript: str) -> NegotiationObservation:
    """Extract the *observed* negotiated group/signature from a transcript.

    The transcript is the diagnostic output of an existing OpenSSL handshake
    (e.g. `openssl s_client`). Fields absent from the transcript remain None;
    no configuration value is ever substituted.
    """
    group = None
    for pattern in _GROUP_PATTERNS:
        match = pattern.search(transcript)
        if match:
            group = match.group(1)
            break

    signature = None
    for pattern in _SIGNATURE_PATTERNS:
        match = pattern.search(transcript)
        if match:
            signature = match.group(1)
            break

    source = SOURCE_OPENSSL_TRANSCRIPT if (group or signature) else SOURCE_NONE
    return NegotiationObservation(
        negotiated_group=group,
        negotiated_signature_algorithm=signature,
        source=source,
    )


def normalize_tls_event(
    outcome: str,
    observation: NegotiationObservation | None = None,
) -> HandshakeEvent:
    """Build one normalized event from the actual observation of an attempt.

    The negotiated fields are taken ONLY from `observation`. The experiment
    configuration is never consulted, so a completed handshake alone does not
    populate them (a completed handshake is evidence that *a* handshake
    completed, not which group/signature it negotiated). Absent an observation
    that exposes them, the fields are null.
    """
    obs = observation if observation is not None else NegotiationObservation()
    if obs.source and obs.source != SOURCE_NONE:
        evidence_source = obs.source
    else:
        evidence_source = SOURCE_CLIENT_OUTCOME
    return HandshakeEvent(
        negotiated_group=obs.negotiated_group,
        negotiated_signature_algorithm=obs.negotiated_signature_algorithm,
        outcome=outcome,  # type: ignore[arg-type]
        evidence_source=evidence_source,
    )


def observe_tls_events(records: list[dict]) -> TlsObservationResult:
    """Normalize a sequence of observed attempts.

    Each record is a mapping with `outcome` and an optional `observation`
    (NegotiationObservation). Records carry no configuration-derived values.
    """
    result = TlsObservationResult()

    for record in records:
        outcome = record.get("outcome", "error")
        event = normalize_tls_event(
            outcome=outcome,
            observation=record.get("observation"),
        )
        result.events.append(event)
        result.total_events += 1

        if outcome == "completed":
            result.completed_count += 1
        elif outcome == "aborted_pre_finished":
            result.aborted_count += 1
        else:
            result.error_count += 1

    return result


def read_tls_log(path: str) -> list[HandshakeEvent]:
    """Read TLS events from a JSON-lines observation log.

    Each line is a JSON object with `outcome` and optionally `transcript`
    (an OpenSSL handshake transcript that genuinely contains the negotiated
    values). No configuration-based values are used to populate the events.
    """
    import json

    events: list[HandshakeEvent] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                observation = None
                if record.get("transcript"):
                    observation = parse_openssl_handshake_observation(
                        str(record["transcript"])
                    )
                events.append(
                    normalize_tls_event(
                        outcome=record.get("outcome", "error"),
                        observation=observation,
                    )
                )
    except FileNotFoundError:
        pass

    return events
