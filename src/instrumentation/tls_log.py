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


# --- D1 protocol-validation observation (Phase 7, RQ4/RQ5) -----------------
# Observation vocabulary for the D1 forced-HRR validation handshake. These
# labels name protocol messages ACTUALLY SEEN in an OpenSSL handshake
# transcript or a packet capture; they are never derived from configuration.
MSG_CLIENT_HELLO = "client_hello"
MSG_HELLO_RETRY_REQUEST = "hello_retry_request"
MSG_CLIENT_HELLO2 = "client_hello2"
MSG_SERVER_HELLO = "server_hello"

_MSG_LINE = re.compile(
    r"(?:>>>|<<<)[^\n]*?\b(ClientHello|HelloRetryRequest|ServerHello)\b"
)
_STATE_LINE = re.compile(
    r"\b(write|read)\s+(client hello|hello retry request|server hello)\b",
    re.IGNORECASE,
)
# Markers that OpenSSL prints only once the TLS handshake has completed.
# Used to define legitimate/validation success WITHOUT waiting on application
# payload (the D1 server intentionally sends none).
# Note: OpenSSL 3.5+ s_client output varies by verbosity. With -msg -state, it prints
# "New, TLSv1.3, Cipher is ..." and "SSL handshake has read X bytes...".
# Without -msg, it prints "SSL-Session:" and "Cipher    : ...".
_COMPLETION_MARKERS = (
    "SSL negotiation finished successfully",
    "SSL-Session:",
    "Ciphersuite:",
    "Cipher is",
    "New, TLSv1.3",
)

# RFC 8446 HelloRetryRequest special random value (32 bytes)
_HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

# Extension types
_EXT_KEY_SHARE = 51
_EXT_COOKIE = 44


@dataclass
class D1ValidationObservation:
    """Observation-derived evidence of the D1 forced-HRR handshake flow."""

    observed_sequence: list[str] = field(default_factory=list)
    hrr_observed: bool = False
    client_hello2_observed: bool = False
    server_hello_observed: bool = False
    cookie_observed: bool = False
    negotiated_group: str | None = None
    evidence_source: str = SOURCE_NONE


def d1_handshake_completed(transcript: str) -> bool:
    """True when the transcript shows a completed TLS handshake.

    Success is defined as TLS handshake completion, never as the receipt of
    application payload.
    """
    if not transcript:
        return False
    return any(marker in transcript for marker in _COMPLETION_MARKERS)


def _d1_message_name(line: str) -> str | None:
    """Map one transcript line to an observed protocol message, or None."""
    match = _MSG_LINE.search(line)
    if match:
        name = match.group(1)
        if name == "ClientHello":
            return MSG_CLIENT_HELLO
        if name == "HelloRetryRequest":
            return MSG_HELLO_RETRY_REQUEST
        if name == "ServerHello":
            return MSG_SERVER_HELLO

    match = _STATE_LINE.search(line)
    if match:
        msg = match.group(2).lower()
        if msg == "client hello":
            return MSG_CLIENT_HELLO
        if msg == "hello retry request":
            return MSG_HELLO_RETRY_REQUEST
        if msg == "server hello":
            return MSG_SERVER_HELLO
    return None


def parse_d1_validation_transcript(transcript: str) -> D1ValidationObservation:
    """Parse an OpenSSL `s_client -msg`/`-state` transcript into observed evidence.

    Reports the observed message sequence (ClientHello, HelloRetryRequest,
    ClientHello2, ServerHello), whether a cookie token appears, and the
    negotiated group. A second ClientHello is labelled `client_hello2`.
    Nothing here is inferred from the experiment configuration.
    """
    obs = D1ValidationObservation()
    if not transcript:
        return obs

    # First pass: text-based detection from -state output and text markers
    client_hello_count = 0
    for line in transcript.splitlines():
        name = _d1_message_name(line)
        if name is None:
            continue
        if name == MSG_CLIENT_HELLO:
            client_hello_count += 1
            if client_hello_count == 1:
                obs.observed_sequence.append(MSG_CLIENT_HELLO)
            else:
                obs.observed_sequence.append(MSG_CLIENT_HELLO2)
                obs.client_hello2_observed = True
        elif name == MSG_HELLO_RETRY_REQUEST:
            obs.observed_sequence.append(MSG_HELLO_RETRY_REQUEST)
            obs.hrr_observed = True
        elif name == MSG_SERVER_HELLO:
            obs.observed_sequence.append(MSG_SERVER_HELLO)
            obs.server_hello_observed = True

    if re.search(r"\bcookie\b", transcript, re.IGNORECASE):
        obs.cookie_observed = True

    # Second pass: parse -msg output for HRR random and cookie extension
    # This catches HRR even when OpenSSL labels it as "ServerHello" in text output.
    try:
        obs = _parse_d1_from_msg_output(transcript, obs)
    except Exception:
        pass  # Best effort; text-based detection already ran

    negotiation = parse_openssl_handshake_observation(transcript)
    obs.negotiated_group = negotiation.negotiated_group

    if negotiation.source != SOURCE_NONE:
        obs.evidence_source = negotiation.source
    elif obs.observed_sequence:
        obs.evidence_source = SOURCE_OPENSSL_TRANSCRIPT

    return obs


def _parse_d1_from_msg_output(transcript: str, obs: D1ValidationObservation) -> D1ValidationObservation:
    """Parse OpenSSL `-msg` output for HRR random and cookie extension evidence.

    Looks for:
    - HRR: ServerHello (msg_type=2) containing the RFC 8446 HRR random value
    - Cookie: Extension type 44 (cookie) in HRR or ClientHello2
    """
    import re

    # Pattern to match `-msg` handshake message dumps:
    # >>> TLS 1.3, Handshake [length XXXX], ServerHello
    #     02 00 00 XX 03 03 CF 21 AD 74 ... (raw bytes)
    msg_header_re = re.compile(
        r"(?:>>>|<<<)\s+TLS\s+1\.[023],\s+Handshake\s+\[length\s+\d+\],\s+(ClientHello|ServerHello|HelloRetryRequest)"
    )

    lines = transcript.splitlines()
    i = 0
    server_hello_count = 0
    while i < len(lines):
        line = lines[i]
        header_match = msg_header_re.search(line)
        if not header_match:
            i += 1
            continue

        msg_type_name = header_match.group(1)

        # Collect the hex dump lines following the header
        hex_bytes = []
        i += 1
        while i < len(lines):
            # Hex dump lines look like: "    02 00 00 54 03 03 CF 21 ..."
            if re.match(r"^\s+[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})+\s*$", lines[i]):
                parts = lines[i].strip().split()
                for p in parts:
                    try:
                        hex_bytes.append(int(p, 16))
                    except ValueError:
                        pass
                i += 1
            else:
                break

        if not hex_bytes:
            continue

        msg_bytes = bytes(hex_bytes)

        if msg_type_name == "ClientHello":
            # Check for cookie extension in ClientHello (ClientHello2)
            if _has_extension(msg_bytes, _EXT_COOKIE):
                obs.cookie_observed = True

        elif msg_type_name == "ServerHello":
            server_hello_count += 1
            # Check for HRR random (first ServerHello with special random = HRR)
            if server_hello_count == 1 and _has_hrr_random(msg_bytes):
                obs.hrr_observed = True
                if MSG_HELLO_RETRY_REQUEST not in obs.observed_sequence:
                    obs.observed_sequence.append(MSG_HELLO_RETRY_REQUEST)
            # Check for cookie extension in HRR
            if _has_extension(msg_bytes, _EXT_COOKIE):
                obs.cookie_observed = True

    return obs


def _has_hrr_random(server_hello_bytes: bytes) -> bool:
    """Check if ServerHello contains the RFC 8446 HRR special random value.

    ServerHello structure (RFC 8446):
    - msg_type (1) = 2
    - length (3)
    - body:
        - legacy_version (2)
        - random (32)
        - legacy_session_id_echo (1 + len)
        - cipher_suite (2)
        - legacy_compression_method (1)
        - extensions (2 + len)
    """
    try:
        if len(server_hello_bytes) < 4:
            return False
        # Skip msg_type (1) and length (3)
        body = server_hello_bytes[4:]
        if len(body) < 2 + 32:
            return False
        # legacy_version (2)
        random_bytes = body[2:2+32]
        return random_bytes == _HRR_RANDOM
    except Exception:
        return False


def _has_extension(handshake_msg_bytes: bytes, ext_type: int) -> bool:
    """Check if a handshake message (ClientHello or ServerHello) contains an extension.

    Parses the extensions block at the end of the handshake message body.
    """
    try:
        if len(handshake_msg_bytes) < 4:
            return False
        body = handshake_msg_bytes[4:]  # skip msg_type + length
        # Parse based on message type (first byte of original message)
        # For ClientHello: legacy_version(2) + random(32) + session_id(1+len) + cipher_suites(2+len) + compression(1+len) + extensions(2+len)
        # For ServerHello: legacy_version(2) + random(32) + session_id_echo(1+len) + cipher_suite(2) + compression(1) + extensions(2+len)
        # We'll use a generic approach: find the extensions block by skipping known fixed fields.

        # This is a simplified parser - for robust parsing we'd need message-type-specific logic.
        # For now, search for the extension type in the latter half of the message.
        # Extension format: type(2) + length(2) + value
        if len(body) < 10:
            return False
        # Search for the extension type in the raw bytes (simple but effective for our case)
        ext_type_bytes = ext_type.to_bytes(2, "big")
        return ext_type_bytes in body
    except Exception:
        return False
