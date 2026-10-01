# PRD — PQ-TLS Handshake Cost Decomposition and Admission-Control Evaluation

## 1. Objective
Determine which TLS 1.3 / PQC components (key establishment vs. authentication,
classical vs. post-quantum) account for the incremental server-side resource
cost observed under controlled handshake-exhaustion workloads, and evaluate
whether inexpensive, already-standardized admission controls reduce that cost
without unacceptable legitimate-client impact.

This is an empirical measurement project. It introduces no new cryptographic
primitive and no new protocol.

## 2. Research Context
Lee et al. ([arXiv:2607.12504](https://arxiv.org/abs/2607.12504), 2026)
report that switching a TLS 1.3 server from classical (ECDSA P-256 + X25519)
to post-quantum (ML-KEM-768 + ML-DSA-65) cipher suites greatly prolongs the
period of high CPU utilization under a handshake-flood workload, and release
an open testbed/dataset. That paper does not report a per-component,
normalized cost breakdown, and it does not evaluate any defense.

This project therefore **does not claim** that PQ-TLS handshake exhaustion is
newly discovered. The claim being tested is narrower and stated in Section 4.

## 3. Research Gap
The aggregate amplification result does not by itself identify which
cryptographic component drives the incremental cost, nor whether that cost
is reducible with mechanisms TLS 1.3 already defines. This project separates:
- classical vs. PQ key establishment,
- classical vs. PQ authentication,
- hybrid key establishment,
- handshake completion vs. controlled early termination,
- fresh vs. reused ML-KEM client keypair (public-key reuse, not ciphertext
  reuse — see `rules.md` §4),
- admission control on vs. off.

## 4. Research Questions
- **RQ1 (Component cost):** How does normalized server CPU cost per
  attempted handshake change when ML-KEM and ML-DSA are introduced
  independently and jointly?
- **RQ2 (Processing stage):** Which handshake stage accounts for the
  largest incremental PQ-related server cost?
- **RQ3 (Key reuse):** Does reusing the client's ML-KEM keypair across
  attempts materially change attacker-side preparation cost or server-side
  processing cost per attempt?
- **RQ4 (Admission control):** Does a stateless TLS 1.3 HelloRetryRequest
  cookie reduce expensive handshake processing under controlled
  PQ-TLS exhaustion workloads?
- **RQ5 (Availability trade-off):** What is the cost, in legitimate-client
  success rate, latency, and added round trips, of each defense evaluated?

## 5. Hypotheses
- **H1:** PQ key establishment and PQ authentication contribute different,
  separable amounts of incremental server cost.
- **H2:** The aggregate overhead reported for full-PQ configurations is not
  explained by a single primitive alone.
- **H3:** Reusing a client ML-KEM keypair reduces client-side key-generation
  cost without requiring reuse of encapsulation randomness.
- **H4:** A stateless cookie reduces server-side cost under flood but adds
  one round trip for legitimate clients.

These are hypotheses to test, not results to manufacture. A null result on
any of H1–H4 is a valid, reportable outcome (see `tasks.md` decision gates).

## 6. TLS Configuration Matrix
| ID | Key Establishment | Authentication | Purpose |
|---|---|---|---|
| C0 | X25519 | ECDSA-P256 | Classical baseline |
| C1 | ML-KEM-768 | ECDSA-P256 | Isolates PQ key-establishment cost |
| C2 | X25519 | ML-DSA-65 | Isolates PQ authentication cost |
| C3 | X25519 + ML-KEM-768 | ECDSA-P256 | Hybrid key establishment ([draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)) |
| C4 | ML-KEM-768 | ML-DSA-65 | Combined PQ configuration |

Every key-establishment row above uses [draft-ietf-tls-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/)'s
NamedGroup registration for standalone ML-KEM where applicable. A
configuration the chosen TLS stack cannot negotiate is recorded as
`UNSUPPORTED`, never silently substituted.

## 7. Workload Modes
- **W0 — Completed handshake:** full TLS 1.3 handshake to completion.
- **W1 — Controlled termination:** client sends ClientHello (and, where the
  mode requires it, proceeds to a fixed later point) and then disconnects
  before completion, to isolate pre-completion server cost.
- **W2 — Repeated bounded attempts:** W0/W1 repeated under the hard limits
  in `rules.md` to obtain a distribution, not a single sample.

## 8. Metrics
**Primary:** server CPU-seconds per attempted handshake.
**Secondary:** handshake processing time, handshakes/second, bytes
received/sent per attempt, CPU cycles where available, legitimate-client
success rate, legitimate-client p50/p95 latency, retransmissions.
**Derived:** attacker CPU-seconds ÷ server CPU-seconds (cost ratio);
legitimate-client goodput under load.

### 8.1 Measurement Definitions (locked 2026-10-01)

**CPU metric:** Server CPU-seconds consumed by the `openssl s_server`
process during the workload execution window, measured via `pidstat` inside
the TLS-server container at 1 Hz. Normalized by total handshake attempts
(including completed, aborted, and failed). Host-side `psutil` is NOT an
experimental fallback. Docker cumulative stats are NOT the primary CPU
measurement. `perf` may remain useful as a future supplementary diagnostic
but must NOT create ambiguity about the primary Phase 4 metric.

**Byte metric:** `bytes_received` and `bytes_sent` are wire-level IP-packet
bytes — total bytes represented by IP packets received/sent by the TLS
server during the experiment window. Measured via packet capture restricted
to the controlled lab traffic/interface/port. Excludes Ethernet
framing/physical-layer overhead. Excludes unrelated traffic and traffic
outside the experiment window. Does NOT represent application payload bytes.
Normalized reporting: bytes received/attempt and bytes sent/attempt, while
preserving raw totals.

**TLS event schema:** Each observed handshake attempt produces a normalized
TLS event with fields: `negotiated_group`, `negotiated_signature_algorithm`,
`outcome`. The two negotiated algorithm fields MUST be nullable — a controlled
abort may terminate before the server has enough protocol evidence to
determine the negotiated group or signature algorithm. Do not force invented
values such as `"unknown"`, `"none"`, `"failed"`, or `"N/A"`. Prefer semantic
null. Outcome values: `completed`, `aborted_pre_finished`, `error`.

**Provenance requirement:** Every normalized TLS event must be traceable to
an underlying observation source (TLS/server log, client-side handshake
observation, or packet-derived evidence). The implementation MUST NOT
manufacture negotiated values from the experiment configuration alone. A
configured expectation (e.g., C3 = X25519MLKEM768 + ECDSA-P256) is NOT by
itself evidence that every attempt actually negotiated those values. The
implementation must distinguish configured expectation from observed
negotiated result.

## 9. Defense Experiments
- **D0 — Baseline:** no admission control.
- **D1 — Stateless cookie:** TLS 1.3 HelloRetryRequest cookie, as already
  specified by RFC 8446 and discussed in the DoS-resistance context by
  [RFC 9954](https://www.rfc-editor.org/rfc/rfc9954.html).
- **D2 — Source admission budget:** a bounded per-source connection-rate
  cap, implemented outside the TLS library.
- **D3 — Combined:** D1 + D2.

The contribution is measuring D1–D3's effect on PQ-specific cost, not
inventing a new mechanism.

## 10. Novelty Boundary
**Existing work** (Lee et al., 2607.12504) establishes that PQ-TLS can
amplify handshake-exhaustion resource consumption in aggregate.
**This project** investigates where that cost originates (RQ1–RQ2), whether
a specification-permitted key-reuse pattern changes the attack economics
(RQ3), and whether existing, standardized admission controls measurably
reduce it (RQ4–RQ5). Novelty confidence is **medium** for the decomposition
and key-reuse results, **low–medium** for the cookie evaluation, since the
mechanism itself is not new — only its measured behavior under PQ cost is.
This confidence assessment must be re-checked against the literature
immediately before any paper submission, not assumed to remain stable.

## 11. Safety Boundary (summary — authoritative version in `rules.md`)
All experiments run only against infrastructure the researcher owns, by
default `localhost` / `127.0.0.1` / a Docker service name. No IP spoofing,
no public-target scanning, no unbounded workload mode. Full detail and
enforcement mechanics live in `rules.md`.

## 12. Success Criteria
The project is complete when:
1. C0–C4 produce reproducible measurements where the stack supports them;
2. component-level cost differences are quantified with variance;
3. the key-reuse experiment (RQ3) is run under the boundary in `rules.md` §4;
4. at least one defense (minimum: D1) is evaluated end to end;
5. legitimate-client impact is measured for every condition above;
6. raw data, analysis code, and figures are reproducible from a documented
   entrypoint;
7. limitations are stated explicitly in the final report.

A newly discovered cryptographic vulnerability is **not** a requirement.

## 13. Technologies
OpenSSL 3.5+ (or `oqs-provider` where a parameter set is missing), nginx or
a minimal C/OpenSSL TLS test server, Python 3.11+ for orchestration and
analysis, `perf`/`pidstat`/`tcpdump`, Docker for the lab network, `tc`/`netem`
for optional network-condition sweeps. No homemade cryptographic code
(enforced in `rules.md`).

## 14. Literature Anchors
- Lee et al., *On the Security Implications of PQC in TLS: Handshake
  Exhaustion and IDS Degradation*, [arXiv:2607.12504](https://arxiv.org/abs/2607.12504), 2026.
- [RFC 9954 — Hybrid Key Exchange in TLS 1.3](https://www.rfc-editor.org/rfc/rfc9954.html).
- [draft-ietf-tls-mlkem — ML-KEM Post-Quantum Key Agreement for TLS 1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/).
- [draft-ietf-tls-ecdhe-mlkem — Post-quantum hybrid ECDHE-MLKEM Key Agreement for TLS 1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/).

Verify current draft revision numbers before citing in the final paper —
IETF drafts referenced above are living documents and may have advanced.
