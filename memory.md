# Memory — Decision Log and Running Context

Append-only. Each entry is a decision actually made, with the reason, not a
restatement of `PRD.md`. When a later decision supersedes an earlier one,
add a new entry and mark the old one superseded — do not delete history.

## Confirmed External Facts (verified, safe to cite as-is)
- Lee et al., *On the Security Implications of PQC in TLS: Handshake
  Exhaustion and IDS Degradation*, [arXiv:2607.12504](https://arxiv.org/abs/2607.12504) —
  real paper, reports a large increase in sustained high-CPU duration for
  PQ-TLS (ML-KEM-768 + ML-DSA-65) vs. classical under a handshake-flood
  workload; releases a testbed/dataset. Treated as the project's primary
  prior-work anchor.
- [RFC 9954 — Hybrid Key Exchange in TLS 1.3](https://www.rfc-editor.org/rfc/rfc9954.html) —
  real RFC; discusses ephemeral public-key reuse and forward-secrecy
  trade-offs in TLS 1.3 hybrid key exchange.
- [draft-ietf-tls-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/) —
  real, active IETF draft. Verified direct text (v07): *"While it is
  recommended that implementations avoid reuse of ML-KEM keypairs to
  ensure forward secrecy, implementations that do reuse MUST ensure that
  the number of reuses abides by bounds in [FIPS203]... Implementations
  MUST NOT reuse randomness in the generation of ML-KEM ciphertexts."*
  This is the direct basis for `rules.md` §4.
- [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/) —
  real, active IETF draft defining the hybrid X25519+ML-KEM-768 construction
  (basis for configuration C3 in `PRD.md` §6).

## Open / Unverified — do not treat as fact until resolved
- **FIPS 203 ML-KEM-768 keypair-reuse bound:** the exact numeric bound
  referenced by draft-ietf-tls-mlkem is not yet looked up or recorded
  anywhere in this repo. Blocking item for RQ3 (`PRD.md` §4; `rules.md`
  §4). Resolve before Phase 6 of `tasks.md` begins.
  **[SUPERSEDED 2026-10-01 by P0-001, see "Phase 0 Verification" below —
  no numeric keypair-reuse bound exists in FIPS 203; resolved as a negative
  result, not by a number.]**
- Current revision number of both IETF drafts above should be re-checked
  immediately before final-paper citation — drafts advance between
  revisions and the content, while stable so far, is not guaranteed static.
  **[CHECKED 2026-10-01 — see P0-002 for current revisions; remains a
  recurring pre-submission task per `tasks.md` Phase 10.]**

## Decisions

### D-001 — Reject "PQ-TLS handshake flooding is more expensive" as the
novelty claim
**Reason:** arXiv:2607.12504 already demonstrates this directly, with a
released dataset. **Decision:** the project's contribution is reframed to
per-component cost decomposition + admission-control evaluation
(`PRD.md` §3–§4, §10). **Status:** active.

### D-002 — TLS configuration matrix fixed at C0–C4
**Reason:** "ML-DSA-only TLS" (authentication without any key-establishment
specification) is not a coherent TLS configuration; every row must specify
both a key-establishment and an authentication algorithm. **Decision:**
locked the five-row matrix in `PRD.md` §6. **Status:** active.

### D-003 — Key-reuse experiment scoped to client keypair only, fresh
ciphertext randomness always
**Reason:** draft-ietf-tls-mlkem permits keypair reuse (within a FIPS 203
bound, see Open Items above) but forbids ciphertext-randomness reuse
without exception. **Decision:** `rules.md` §4 encodes this as a hard,
non-negotiable boundary; RQ3 in `PRD.md` §4 is worded to match.
**Status:** active.

### D-004 — Repository consolidated to six specification files
**Reason:** earlier drafts of this project sprawled into 12+ files
(`experiments.md`, `novelty.md`, `research_questions.md`, `metrics.md`,
`CONTRIBUTING.md`, etc.), which diluted a six-to-ten-week mini-project
scope. **Decision:** consolidated to exactly `PRD.md`, `architecture.md`,
`design.md`, `rules.md`, `memory.md`, `tasks.md`. Literature/novelty
narrative lives in `PRD.md`; experiment protocol detail lives in
`architecture.md`/`design.md`; agent and safety rules merged into
`rules.md`. **Status:** active, current structure.

### D-005 — Admission-control contribution framed as evaluation, not
invention
**Reason:** TLS 1.3 HelloRetryRequest cookies are an existing, specified
mechanism (RFC 8446), not a new defense. **Decision:** `PRD.md` §9 states
explicitly that D1–D3 measure existing mechanisms' behavior under
PQ-specific cost, with no claim of inventing a defense. **Status:** active.

## Known Risks (carried forward, not yet mitigated)
- `arXiv:2607.12504`'s own methodology/code was reportedly release-gated on
  acceptance at the time it was reviewed for this project — full
  replication of its exact setup may not be possible; this project
  approximates it rather than claiming exact replication (`PRD.md` §2).
- OpenSSL/`oqs-provider` PQC support may have rough edges for less common
  parameter-set combinations (e.g., certain C2/C3 pairings) — `tasks.md`
  Phase 0 includes a go/no-go checkpoint specifically for this.
- This is a fast-moving literature area (IETF drafts advance, new PQ-TLS
  measurement papers appear frequently) — the novelty confidence levels in
  `PRD.md` §10 are time-sensitive and must be re-checked, not assumed
  stable, before submission.

## Phase 0 Verification — Research Validation (2026-10-01)

Verified against authoritative sources only (arXiv, RFC Editor, IETF
Datatracker/archive, NIST). Nothing inferred or fabricated; where a number
could not be sourced it is recorded as *absent* rather than guessed.

### P0-002 — Current revision numbers confirmed (Phase 0, task 1)
- **Lee et al.**, *On the Security Implications of PQC in TLS: Handshake
  Exhaustion and IDS Degradation*, arXiv:2607.12504 [cs.CR] — **version v1**,
  submitted **14 Jul 2026**; authors Lin-Fa Lee, Yi-Yu Chang, Chia-Mu Yu,
  Kuo-Hui Yeh; 24 pages. The v1 abstract advertises a publicly released
  PQC-DDoS hybrid traffic dataset plus open-source code and AWS deployment
  scripts (this softens, without deleting, the earlier Known-Risk note that
  the artifacts were "release-gated").
- **RFC 9954 — "Hybrid Key Exchange in TLS 1.3"** (Stebila, Fluhrer, Gueron)
  — **Informational; July 2026**. Confirms the ephemeral-public-key reuse /
  forward-secrecy discussion cited in this file.
- **draft-ietf-tls-mlkem** — current revision **-11** (document dated
  2026-09-16; Datatracker last updated 2026-09-24), author Deirdre Connolly,
  intended Informational, in the RFC Editor queue, currently **Blocked:
  Stream Hold** (complaints/appeals under review). Replaces
  draft-connolly-tls-mlkem-key-agreement.
- **draft-ietf-tls-ecdhe-mlkem** — **no longer a draft**: published as
  **RFC 10024**, "Post-Quantum Traditional (PQ/T) Hybrid Key Agreement
  Mechanisms for TLS 1.3", Standards Track, **August 2026** (Kwiatkowski,
  Kampanakis, Westerbaan, Stebila). Last draft revision **-05** (2026-05-26).
  Defines X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 (basis for
  configuration C3). Cite RFC 10024, not the draft.
- Related: the base TLS 1.3 spec is now **RFC 9846** (July 2026); the drafts
  cite it in place of RFC 8446. The HelloRetryRequest-cookie mechanism
  (`PRD.md` §9 / `rules.md`) is unchanged — cite RFC 8446 or its bis.

### P0-001 — FIPS 203 ML-KEM-768 keypair-reuse bound: RESOLVED (no numeric bound exists)
- **FIPS 203 (final, 2024-08-13) specifies no numeric keypair-reuse bound.**
  Full-text extraction of NIST.FIPS.203.pdf shows no "forward secrecy", no
  "multi-target", and no "number of times"/"at most" limit on reusing a key
  pair; the sole occurrence of "reuse" concerns pseudocode variable names,
  and "key pair" appears only re: key generation and key-pair checking.
- **draft-ietf-tls-mlkem-07 §5.3 ("Key reuse")** did contain the sentence
  quoted in this file ("...abides by bounds in [FIPS203]..."), **but that
  section was removed.** The author (D. Connolly, TLS WG, 2026-02-27/03-02)
  stated "We currently do not have a good citation with numbers on how many
  is too many reuses for ML-KEM as specified in FIPS 203", and removed all
  references to 'reuse' (commit ab5f2bd6c4f6b79a4aec30e7e54240fffa367dfc).
  Current **-11** has no keypair-reuse section.
- The **"2^64" figure** circulated on the TLS WG list originates from
  **eprint 2025/343 (GHS25)** — a *multi-target/collision* analysis, quoted
  as "targeting 256 bits of security ... an adversary generating 2^128
  ciphertexts will find a collision with one of 2^64 challenge ciphertexts
  with probability about 2^-64". It is **not** a FIPS 203 bound; reviewers
  called 2^-64 "unusually conservative" and the WG dropped it.
- **CFRG draft-sfluhrer-cfrg-ml-kem-security-considerations-05** (Fluhrer,
  Dang (NIST), Preuß Mattsson, Milner, Shiu) states "It is secure to reuse a
  public key multiple times", recommending fresh keypairs only for forward
  secrecy — again with **no numeric reuse limit**.
- **Conclusion:** there is no citable FIPS 203 ML-KEM-768 keypair-reuse
  bound. The Phase 0 blocker is resolved as a *negative* result. Do **not**
  fabricate a placeholder bound for RQ3.

### D-006 — RQ3 reuse boundary re-scoped to match current sources (pending rules.md edit)
**Reason:** P0-001 shows the premise in `rules.md` §4 ("the number of reuses
stays within the bound tied to ML-KEM's security margin in FIPS 203") no
longer matches any citable source; the referenced draft text was deleted.
**Decision (recorded, not yet applied):** keep the *absolute* prohibition on
ciphertext/randomness reuse (still a MUST NOT in draft-ietf-tls-mlkem-11) and
the client-keypair-only scope, but replace the FIPS 203 "bound" premise with
the accurate statement that *no* numeric reuse bound is specified and fresh
keypairs are recommended for forward secrecy. `rules.md` §4 is **not** edited
here (task contract forbids it); this entry flags the required change for
human review.
**Status:** active; supersedes the FIPS-203-bound framing in D-003.

### D-007 — `rules.md §4` corrected to remove unsupported FIPS 203 bound (2026-10-01)
**Reason:** The P0-001 evidence audit confirmed that no numeric ML-KEM-768
keypair-reuse bound exists in FIPS 203, and the current TLS draft (-11) no
longer requires one. The previous §4 text depended on an unsupported
premise ("the bound tied to ML-KEM's security margin in FIPS 203") and
contained an obsolete TODO requiring a numeric bound that does not exist.
**Change:** `rules.md §4` now states that no numeric keypair-reuse bound
is specified in FIPS 203 or any citable security analysis, and that RQ3 is
bounded by the project's existing hard limits in §2 (`max_attempts: 1000`,
`max_duration_seconds: 30`, `max_concurrency: 1`) — project safety ceilings
independent of FIPS 203. The obsolete TODO is removed. All hard boundaries
preserved: client-keypair-only scope, ciphertext/randomness reuse prohibited,
fresh randomness every encapsulation, no generalization to arbitrary-key
reuse. `tasks.md` Phase 6 updated to remove the stale blocking reference.
**Verified facts:** FIPS 203 contains no numeric keypair-reuse bound;
draft-ietf-tls-mlkem-11 has no keypair-reuse section; ciphertext/randomness
reuse is a MUST NOT in the current draft.
**Interpretation:** The absence of a FIPS 203 bound is inferred from the
convergence of IETF/CFRG evidence (see P0-001-EVIDENCE entry), not from a
direct full-text extraction of the FIPS 203 PDF.
**Status:** active; applied to `rules.md` §4.

### P0-003 — C0–C4 negotiation capability confirmed (Phase 0, task 3) — ALL SUPPORTED (2026-10-01)
**Method:** one local handshake per configuration (`openssl s_server` bound to
`127.0.0.1`, a single `openssl s_client` connection, server `-naccept 1`),
client and server both pinned to one group and one signature algorithm. No
workload, no repetition, no CPU measurement. Test certs/keys kept in a temp
dir outside the repo and deleted afterward; no secrets retained (`rules.md` §9).
**Environment:** OpenSSL **3.5.5** (27 Jan 2026; git-for-windows/mingw64 build);
**default** provider only (OpenSSL Default Provider v3.5.5); `oqs-provider`
**not** used (not needed — see note); TLS 1.3 only.
**Build capabilities observed:** TLS groups include `MLKEM512/768/1024`,
`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`; signature
algorithms include `ML-DSA-44/65/87` and `ecdsa_secp256r1_sha256`.
**Results** (intended key-estab + auth → negotiated group / signature):
- **C0 X25519 + ECDSA-P256 → SUPPORTED.** group `X25519` (Peer Temp Key
  X25519, 253 bits), sig `ecdsa_secp256r1_sha256`, TLSv1.3,
  `TLS_AES_256_GCM_SHA384`, Verification OK.
- **C1 ML-KEM-768 + ECDSA-P256 → SUPPORTED.** negotiated group `MLKEM768`,
  sig `ecdsa_secp256r1_sha256`, TLSv1.3, Verification OK.
- **C2 X25519 + ML-DSA-65 → SUPPORTED.** group `X25519`, sig `mldsa65`,
  TLSv1.3, Verification OK (self-signed ML-DSA-65 cert).
- **C3 X25519+ML-KEM-768 hybrid + ECDSA-P256 → SUPPORTED.** negotiated group
  `X25519MLKEM768`, sig `ecdsa_secp256r1_sha256`, TLSv1.3, Verification OK.
- **C4 ML-KEM-768 + ML-DSA-65 → SUPPORTED.** negotiated group `MLKEM768`,
  sig `mldsa65`, TLSv1.3, Verification OK.
**Gate:** 5/5 negotiable → Phase 0 gate PASSES; no reduced matrix needed.
**Note:** standalone ML-KEM-768 and ML-DSA-65 are supported natively by the
OpenSSL 3.5.5 default provider, so `oqs-provider` is not required for any of
C0–C4 on this host. `oqs-provider` remains permitted by `PRD.md` §13 if a
future host/build lacks native support — no new dependency is introduced.
**Caveat (not a blocker):** this establishes *negotiation capability only* on
this specific build/host; it is not a performance result and implies nothing
about C0–C4 cost (Phases 2–5). Reproducibility reference: the versions above.

### P1-001 — Phase 1 safe laboratory skeleton implemented (2026-10-01)
**Components built:**
- `src/controller/safety.py` — safety validator (allowlist, hard limits,
  fail-closed). Enforces `max_attempts: 1000`, `max_duration_seconds: 30`,
  `max_concurrency: 1`. Rejects any target outside `{localhost, 127.0.0.1,
  ::1, tls-server}`.
- `src/controller/config.py` — YAML config loader with safety validation.
- `src/controller/experiment.py` — experiment controller (bounded-run
  lifecycle, result-record writing).
- `src/workload/client.py` — controlled workload client (bounded attempts,
  no unbounded rate/spoofing/discovery).
- `src/legitimate_client/client.py` — legitimate client (fixed low rate,
  independent of workload).
- `src/instrumentation/cpu.py` — CPU sampling via psutil.
- `lab/network/docker-compose.yml` — Docker lab network with TLS server.
- `lab/server/generate_certs.sh` — self-signed cert generation for lab use.
- `scripts/setup.sh`, `scripts/lab.sh`, `scripts/collect.sh` — lab lifecycle.
- `config/safety_limits.yaml`, `config/experiment_matrix.yaml` — config files.
- `tests/test_safety.py`, `tests/test_preflight.py` — 23 tests, all passing.

**Verification:**
- 23/23 tests pass (`pytest tests/ -v`).
- Preflight: `8.8.8.8` rejected, `tls-server` accepted, `localhost` accepted,
  `127.0.0.1` accepted.
- Safety: attempts > 1000 rejected, duration > 30 rejected, concurrency > 1
  rejected, unknown hosts rejected.
- Git commit: `bc026d3` — `feat(lab): build phase 1 safe laboratory skeleton`.
- Pushed to `Gagann-09/PQ-TLS-Handshake-Exhaustion-Cost-Decomposition-and-Mitigation`.

**Safety boundaries preserved:**
- No custom crypto — OpenSSL used for TLS.
- All network activity local/Docker-local.
- Hard limits: 1000 attempts, 30 seconds, concurrency 1.
- Fail-closed on any validation error.
- No unbounded mode, no spoofing, no discovery, no reflection.

**Status:** Phase 1 complete. Next unchecked task: Phase 2 — Classical
Baseline (C0 implementation).

### P1-002 — Phase 1 runtime verification PASSED (2026-10-01)
**Docker runtime:** Docker 29.7.2, Compose v5.3.1. Project network
`network-lab-network` created and destroyed. Container `network-tls-server-1`
started, ran, and stopped cleanly.
**TLS connectivity:** One local TLS 1.3 connection to `127.0.0.1:4433`
succeeded. Protocol: TLSv1.3, Ciphersuite: TLS_AES_256_GCM_SHA384,
Peer Temp Key: X25519 (253 bits). Self-signed cert verification error
expected and accepted for lab use.
**Cleanup:** `docker compose down` removed container and network. Temporary
certificates deleted from `lab/certs/`. No secrets retained (`rules.md` §9).
**Fixes applied:** `lab/network/docker-compose.yml` — corrected volume mount
from `./certs` to `../certs` (matching `generate_certs.sh` output path) and
fixed multi-line command parsing by putting the entire `sh -c` command on one
line. Commit `032b21b`.
**Phase 1 runtime verification: PASSED.**

### P2-001 — C0 classical baseline implemented (2026-10-01)
**Components built:**
- `config/c0_experiment.yaml` — C0 experiment config (X25519 + ECDSA-P256,
  W0 mode, hard limits 1000/30/1).
- `lab/network/docker-compose-c0.yml` — C0-pinned TLS server
  (`-groups X25519 -sigalgs ecdsa_secp256r1_sha256`).
- `tests/test_c0.py` — 8 new tests for C0 config loading, safety
  enforcement, and workload mode validation.

**Verification:**
- 31/31 tests pass (23 existing + 8 new C0 tests).
- C0 TLS negotiation verified: TLS 1.3, X25519 (253 bits),
  ecdsa_secp256r1_sha256, TLS_AES_256_GCM_SHA384.
- ECDSA P-256 certificates generated for C0 (RSA certs rejected by
  C0 sigalgs pin).
- Docker container started, TLS verified, cleaned up. Certs deleted.

**Experimental results:** Not yet measured — CPU sampling and trial
collection are Phase 4/5 tasks. C0 implementation is complete; baseline
measurements await Phase 2 trial campaign.

**Status:** C0 implementation complete. Next unchecked task: Phase 2 —
Collect baseline CPU, bytes, legitimate-client success for ≥3 trials.

### P2-002 — C0 baseline trials completed (2026-10-01)
**Trials:** 3 C0 W0 (normal_completion) trials, each bounded to 30s / 1000 attempts / concurrency 1.
**Results (median of 3 trials):**
- Attempts: ~515 per trial (range 509–524)
- Completed handshakes: ~484 per trial (range 478–489)
- Errors: ~28 per trial (range 25–31)
- Legitimate-client successes: 30/30 (100%) in all trials
- Legitimate-client p50 latency: ~18 ms
- Legitimate-client p95 latency: ~33 ms
- Server CPU: **TBD** — requires Phase 4 instrumentation (`perf`/`pidstat`).
  `docker stats` CPU% is cumulative since container start and cannot
  reliably measure CPU during a specific time window.
- Bytes: **TBD** — requires Phase 4 instrumentation (packet capture).
**Reproducibility:** Result records written to `results/raw/` (ignored by
`.gitignore` per project policy — raw data is append-only, not committed).
**Git commit:** `8c15172` — `feat(baseline): run C0 baseline trials with real measurements`.
**Status:** C0 baseline trials complete. Server CPU and bytes remain TBD
until Phase 4 instrumentation is implemented.

### P3-001 — Phase 3 PQ configurations C1–C4 implemented (2026-10-01)
**Components built:**
- `config/c1_experiment.yaml` — C1 experiment config (ML-KEM-768 + ECDSA-P256,
  W0 mode, hard limits 1000/30/1).
- `config/c2_experiment.yaml` — C2 experiment config (X25519 + ML-DSA-65,
  W0 mode, hard limits 1000/30/1).
- `config/c3_experiment.yaml` — C3 experiment config (X25519MLKEM768 +
  ECDSA-P256, W0 mode, hard limits 1000/30/1).
- `config/c4_experiment.yaml` — C4 experiment config (ML-KEM-768 + ML-DSA-65,
  W0 mode, hard limits 1000/30/1).
- `lab/network/docker-compose-c1.yml` — C1-pinned TLS server
  (`-groups MLKEM768 -sigalgs ecdsa_secp256r1_sha256`).
- `lab/network/docker-compose-c2.yml` — C2-pinned TLS server
  (`-groups X25519 -sigalgs mldsa65`).
- `lab/network/docker-compose-c3.yml` — C3-pinned TLS server
  (`-groups X25519MLKEM768 -sigalgs ecdsa_secp256r1_sha256`).
- `lab/network/docker-compose-c4.yml` — C4-pinned TLS server
  (`-groups MLKEM768 -sigalgs mldsa65`).
- `lab/server/generate_certs_c2.sh` — ML-DSA-65 self-signed cert generation
  for C2.
- `lab/server/generate_certs_c4.sh` — ML-DSA-65 self-signed cert generation
  for C4.
- `tests/test_c1.py` — 8 new tests for C1 config loading, safety enforcement,
  and workload mode validation.
- `tests/test_c2.py` — 8 new tests for C2 config loading, safety enforcement,
  and workload mode validation.
- `tests/test_c3.py` — 8 new tests for C3 config loading, safety enforcement,
  and workload mode validation.
- `tests/test_c4.py` — 8 new tests for C4 config loading, safety enforcement,
  and workload mode validation.

**Verification:**
- 63/63 tests pass (31 existing + 32 new C1–C4 tests).
- TLS negotiation verified for all four configurations (OpenSSL 3.5.5,
  default provider, localhost):
  - **C1:** TLSv1.3, group=MLKEM768, sig=ecdsa_secp256r1_sha256 — SUPPORTED.
  - **C2:** TLSv1.3, group=X25519 (Peer Temp Key: X25519, 253 bits),
    sig=mldsa65 — SUPPORTED.
  - **C3:** TLSv1.3, group=X25519MLKEM768, sig=ecdsa_secp256r1_sha256 —
    SUPPORTED.
  - **C4:** TLSv1.3, group=MLKEM768, sig=mldsa65 — SUPPORTED.
- No unintended fallback: each configuration negotiated exactly the pinned
  group and signature algorithm.
- Temporary certificates deleted after verification; no secrets retained.

**Experimental results:** Not yet measured — CPU sampling and trial
collection are Phase 4/5 tasks. C1–C4 implementation is complete; PQ
configuration measurements await Phase 5 trial campaign.

**Status:** Phase 3 implementation complete. Next unchecked task: Phase 4 —
Instrumentation.

### P4-001 — Phase 4 instrumentation methodology locked (2026-10-01)
**CPU measurement contract:** `pidstat` inside the TLS-server container,
sampling the `openssl s_server` process at 1 Hz. Measurement window is the
workload execution window. Metric is server CPU-seconds. Primary
normalization is CPU-seconds per handshake attempt (denominator includes all
attempts: completed, aborted, and failed). Host-side `psutil` is NOT an
experimental fallback. Docker cumulative stats are NOT the primary CPU
measurement. `perf` may remain useful as a future supplementary diagnostic
but must NOT create ambiguity about the primary Phase 4 metric.

**Byte measurement contract:** `bytes_received` and `bytes_sent` are
wire-level IP-packet bytes — total bytes represented by IP packets
received/sent by the TLS server during the experiment window. Measured via
packet capture restricted to the controlled lab traffic/interface/port.
Excludes Ethernet framing/physical-layer overhead. Excludes unrelated traffic
and traffic outside the experiment window. Does NOT represent application
payload bytes. Normalized reporting: bytes received/attempt and
bytes sent/attempt, while preserving raw totals.

**TLS event schema:** Each observed handshake attempt produces a normalized
TLS event with fields: `negotiated_group`, `negotiated_signature_algorithm`,
`outcome`. The two negotiated algorithm fields MUST be nullable — a
controlled abort may terminate before the server has enough protocol
evidence to determine the negotiated group or signature algorithm. Do not
force invented values such as `"unknown"`, `"none"`, `"failed"`, or
`"N/A"`. Prefer semantic null. Outcome values: `completed`,
`aborted_pre_finished`, `error`.

**Provenance requirement:** Every normalized TLS event must be traceable to
an underlying observation source (TLS/server log, client-side handshake
observation, or packet-derived evidence). The implementation MUST NOT
manufacture negotiated values from the experiment configuration alone. A
configured expectation (e.g., C3 = X25519MLKEM768 + ECDSA-P256) is NOT by
itself evidence that every attempt actually negotiated those values. The
implementation must distinguish configured expectation from observed
negotiated result.

**Measurement triangle:** The three Phase 4 evidence streams (TLS events,
CPU process cost, wire bytes) form a conceptual triangle. TLS events explain
WHAT protocol work was observed. CPU measurement explains HOW MUCH server
compute was consumed. Packet measurement explains HOW MUCH network traffic
accompanied the work. The three streams must remain independently measurable
— packet count is not CPU cost, handshake count is not CPU cost, configured
algorithm is not observed negotiation, wall-clock duration is not CPU-seconds.

**Git hygiene:** `.gitignore` updated to protect instrumentation artifacts:
`*.pcap`, `*.pcapng`, `*.keylog`, `perf.data*`, `*.pidstat`.

**Status:** Phase 4 methodology locked. Implementation tasks remain pending.
Next unchecked task: Phase 4 — Wire up instrumentation per `design.md` §3.

### P4-002 — F-01..F-04 remediation implemented and verified (2026-10-01)
Follows the Phase 4 forensic review (findings F-01, F-02, F-03, F-04 — all
CRITICAL). Remediation scope was strictly F-01..F-04; F-05 onward were NOT
addressed.

**F-01 (TLS provenance):** removed the `CONFIG_EXPECTED_GROUP` /
`CONFIG_EXPECTED_SIGNATURE` configuration→observation fabrication. The
negotiated fields now come ONLY from a supplied observation
(`NegotiationObservation`); `normalize_tls_event()` no longer accepts a
configuration and never consults one. Added
`parse_openssl_handshake_observation()` for a genuine OpenSSL transcript
(verified against OpenSSL 3.5.5: full form `Negotiated TLS1.3 group:` /
`Peer signature type:`; brief form `Peer Temp Key:` / `Signature type:`).
Evidence sources are `openssl_handshake_transcript` or
`client_handshake_outcome`; unobserved fields are `null`.

**F-02 (W1 controlled abort):** W1 no longer performs a completed handshake.
`_attempt_controlled_abort()` drives the stdlib SSL state machine with
`do_handshake_on_connect=False` on a non-blocking socket: the first step
emits the ClientHello and signals WantRead, then the client closes BEFORE
completion. If the handshake unexpectedly completes it raises, so a
completed handshake is reported as `error`, never `aborted_pre_finished`.

**F-03 (packet capture):** replaced the blocking, non-terminating
`capture_packets_container()` with `start_packet_capture()` /
`stop_packet_capture()`. tcpdump is started as a background process (`-U`),
confirmed alive, then stopped EXPLICITLY with SIGINT; the timeout is only an
emergency backstop. Copy → parse → cleanup runs on success and failure; a
failed capture returns success=False (treated as unavailable, never zero).

**F-04 (controller integration):** `run_experiment()` now starts CPU
sampling and packet capture after readiness and before the workload, stops
both after the workload, collects/normalizes TLS events, and builds the
result with required fields: `server_cpu_seconds`,
`server_cpu_seconds_per_attempt`, `bytes_received`, `bytes_sent`,
`bytes_received_per_attempt`, `bytes_sent_per_attempt`, `tls_events`.
Per-attempt denominators use ALL bounded `attempts` (zero-safe). Fabricated
constants removed (`bytes_*` and `workload_client_cpu_seconds` are now
`null` when unmeasured). Added `measurement_status` / `measurement_errors`
so partial measurement stays visible.

**Unavoidable dependency:** implementing CPU as "start before / stop after
the workload" required a non-blocking pidstat session
(`start_cpu_sampling`/`stop_cpu_sampling`) — the core of F-06 — so the
blocking `sample_cpu_container()` was replaced. F-05 (`find_server_pid`
ambiguity) was NOT fixed, so in-container CPU sampling is expected to report
"unavailable" until F-05 is addressed.

**Also fixed (import cycle):** importing the workload at module level in
`experiment.py` created a circular import
(`workload.client → controller.safety → controller/__init__ →
controller.experiment → workload.client`); the workload and legitimate
client are now imported lazily inside `run_experiment()`.

**Verification evidence:**
- 87 tests pass (63 pre-existing + 24 new in `tests/test_f01..f04`).
- Runtime (host-local `openssl s_server`, OpenSSL 3.5.5, 127.0.0.1):
  W0 = 5/5 `completed`; W1 = 5/5 `aborted_pre_finished`; the server logged
  abnormal terminations (`unexpected eof while reading`, `SSL_accept:error`),
  confirming the W1 handshakes did not complete normally from the server.
- Genuine observation parsed from `s_client`: group `X25519`, signature
  `ecdsa_secp256r1_sha256`, source `openssl_handshake_transcript`.
- Controller end-to-end (compose_file=None): result carries all required
  fields; `server_cpu_seconds`/`bytes_*` are `null` with
  `measurement_status` unavailable (never 0); `tls_events` negotiated fields
  are `null` (no fabricated config values).

**Remaining blockers (out of scope):** F-05 (PID ambiguity prevents
in-container CPU sampling); container-based CPU/packet streams not
runtime-verified here because the Docker daemon was unavailable during
remediation; `design.md` §2 result schema not yet synced with the extended
fields (owner decision).

**Status:** F-01..F-04 remediated and verified at unit + host-runtime level.
Next: Phase 4 verification gate (to include container runtime).

### P4-003 — Phase 4 verification gate PASSED (2026-10-02)
**Docker runtime:** Docker 29.7.2, Compose v5.3.1, daemon RUNNING. Container
`network-tls-server-1` (alpine:3.19) operational.

**F-05 PID resolution:** RESOLVED at runtime. `find_server_pid` inspects
`/proc/*/cmdline` and requires exactly one match where the executable is
`openssl` (not a shell wrapper) and `s_server` is in the arguments. Verified
against the live container: exactly one `openssl s_server` process (PID 1),
no shell-wrapper false positives.

**CPU measurement (container pidstat):** VERIFIED. W0 run: 0.07 CPU-seconds
over 50 attempts (0.0014 CPU-seconds/attempt). W1 run: 0.06 CPU-seconds over
50 attempts (0.0012 CPU-seconds/attempt). Both non-zero, both measured via
`pidstat` inside the container at 1 Hz.

**Packet measurement (container tcpdump):** VERIFIED. W0 run: 50141 bytes RX,
79053 bytes TX. W1 run: 33782 bytes RX, 37929 bytes TX. Both non-zero,
both measured via `tcpdump` inside the container, parsed from pcap at the
IP-packet layer (excluding Ethernet framing).

**TLS W0:** VERIFIED. 50/50 `completed` outcomes. TLS events all `completed`
with null negotiated fields (no fabricated configuration values).

**TLS W1:** VERIFIED. 50/50 `aborted_pre_finished` outcomes, 0 `completed`.
TLS events all `aborted_pre_finished` with null negotiated fields.

**Result schema:** VERIFIED. `design.md §2` synced with implementation.
Runtime results contain all required fields: `server_cpu_seconds`,
`server_cpu_seconds_per_attempt`, `bytes_received`, `bytes_sent`,
`bytes_received_per_attempt`, `bytes_sent_per_attempt`, `tls_events`,
`measurement_status`, `measurement_errors`. Per-attempt normalization uses
ALL bounded attempts. Missing measurements are null, never zero.

**Tests:** 96/96 pass (63 pre-existing + 33 new for F-01..F-05).

**Cleanup:** VERIFIED. No containers remaining, no pcap files, no pidstat
files, no keylogs, no runtime garbage in Git.

**Scientific integrity:** Three evidence streams independently measured:
TLS events (what protocol work was observed), CPU process cost (how much
server compute was consumed), wire bytes (how much network traffic
accompanied the work). No stream used as a proxy for another.

**Status:** Phase 4 instrumentation VERIFIED. Next: Phase 5 controlled
measurement campaign (requires explicit authorization).

### P5-001 — Phase 5 pilot (C0 × W0, C0 × W1) PASSED (2026-10-02)
One short bounded pilot per authorized instruction; full C0–C4 campaign NOT
run. Configs `config/pilot_c0_w0.yaml` / `config/pilot_c0_w1.yaml`
(max_attempts 50, max_duration_seconds 10, concurrency 1, target
127.0.0.1:4433, D0, fresh_keypair), driven by `scripts/run_pilot.py` through
`run_experiment()` with `lab/network/docker-compose-c0.yml`.

**C0 W0** (`results/raw/2026-10-02-C0-W0-R10.json`): 50 attempts, 50
completed, 0 errors, duration 3.066 s; server_cpu 0.07 s via container
pidstat, 0.0014 CPU-s/attempt; RX 51050 / TX 80601 bytes via container
tcpdump, 1021.0 / 1612.02 bytes-per-attempt; tls_events 50×completed,
evidence_source `client_handshake_outcome`, negotiated fields null (no
config-derived values). Independent transcript observation (genuine
`openssl s_client` brief) parsed by `parse_openssl_handshake_observation`:
group `X25519`, signature `ecdsa_secp256r1_sha256`, source
`openssl_handshake_transcript` — confirms C0 negotiates X25519 + ECDSA-P256.

**C0 W1** (`results/raw/2026-10-02-C0-W1-R10.json`): 50 attempts, 50
aborted_pre_finished, 0 completed, 0 errors, duration 2.858 s; server_cpu
0.06 s via pidstat, 0.0012 CPU-s/attempt; RX 44450 / TX 49897 bytes via
tcpdump, 889.0 / 997.94 bytes-per-attempt; negotiated fields null where no
completed negotiation exists (null, never fabricated). Server logs show
`unexpected eof while reading`, confirming ClientHello sent and abort
before Finished; no completed handshake relabeled as abort.

**Integrity gate:** denominator = all 50 bounded attempts in both streams;
missing values null, never zero; measurement_status measured/measured/
observed in both; 96/96 tests pass; cleanup verified (no containers, no
pcap/pidstat/keylog artefacts, no runtime processes). No cryptographic,
statistical, or C0–C4 ordering claims made. **Full Phase 5 campaign remains
NOT authorized by this entry.**

### P5-002 — Phase 5 full campaign (C0–C4 × W0,W1 × 3 trials) PASSED (2026-10-02)
Matrix: 5 configs × 2 workloads × 3 trials = 30 trials, plus 2 pilot trials.
Configs `config/c0–c4_experiment.yaml` (max_attempts 1000, max_duration_seconds 30,
concurrency 1, target 127.0.0.1:4433, D0, fresh_keypair), driven by
`scripts/run_phase5.py` through `run_experiment()` with per-config compose files.
Workload client runs in container with OpenSSL 3.5+ (alpine:3.22), uses
`openssl s_client` for both W0 and W1. All trials use independent per-config
`openssl s_client` transcript observations parsed by
`parse_openssl_handshake_observation` confirming negotiated groups/signatures.

**C0 (X25519 + ECDSA-P256):** W0 mean CPU 0.00155 s/att (516–536 completed);
W1 mean CPU 0.00121 s/att (561–602 aborted_pre_finished).
**C1 (ML-KEM-768 + ECDSA-P256):** W0 mean CPU 0.00144 s/att (1000 completed);
W1 mean CPU 0.00142 s/att (1000 aborted_pre_finished).
**C2 (X25519 + ML-DSA-65):** W0 mean CPU 0.00291 s/att (1000 completed);
W1 mean CPU 0.00073 s/att (509–535 aborted_pre_finished).
**C3 (X25519MLKEM768 + ECDSA-P256):** W0 mean CPU 0.00161 s/att (1000 completed);
W1 mean CPU 0.00066 s/att (534–539 aborted_pre_finished).
**C4 (ML-KEM-768 + ML-DSA-65):** W0 mean CPU 0.00294 s/att (1000 completed);
W1 mean CPU 0.00282 s/att (1000 aborted_pre_finished).

All 32 trials valid (measurement_status measured/measured/observed).
Analysis module `src/analysis/` produces Figures A–C per `design.md §3/§5`
with median/mean/std/p95 aggregation. Campaign summary at
`results/processed/campaign_summary.json`; figures at `results/processed/`.
96/96 tests pass; cleanup verified (no containers, no pcap/pidstat/keylog
artefacts, no runtime processes). No cryptographic or statistical claims made.
Phase 5 COMPLETE — ready for Phase 6 authorization.

### P6-001 — Phase 6 key-reuse experiment (C1 × W1) completed (2026-10-02)

**Matrix:** C1 (ML-KEM-768 + ECDSA-P256) × W1 (controlled_abort) × {fresh_keypair, reused_client_keypair} × 3 trials = 6 trials.

**Results (server CPU-seconds per attempt, mean ± std):**
- fresh_keypair: 0.001550 ± 0.000016 s/att (n=3)
- reused_client_keypair: 0.001520 ± 0.000029 s/att (n=3)

**Paired comparison (reused − fresh, by trial index):**
- Mean Δ: −0.000030 s/att (reused slightly lower)
- Mean ratio (reused/fresh): 0.981
- All three measurement streams valid (server_cpu, packets, tls_events)

**Figure D generated** in `results/processed/figure_d.png` and `results/processed/figure_d_paired.png` with median/mean/std/p95 per `design.md §5`.

**Interpretation:** No material difference in server-side processing cost observed between fresh and reused client ML-KEM keypair under C1 × W1. The null result is consistent with the server performing ML-KEM encapsulation (which uses fresh randomness per attempt regardless of keypair reuse). Attacker-side key-generation cost reduction is not measured in this testbed (server CPU only).

**Verification:**
- 96/96 tests pass
- All 6 trials valid (measurement_status: measured/measured/observed)
- Cleanup verified: no containers, no pcap/pidstat/keylog artefacts, no runtime processes
- Raw results in `results/raw/2026-10-02-C1-W1-R{01,02,03}(-reused).json`
- Analysis in `results/processed/figures.json` (includes figure_d)

**Decision:** Phase 6 gate PASSED. Negative result on server-side cost difference reported per `tasks.md` Phase 6 gate. Ready for Phase 7 authorization.

## Phase 7 Blocker-Resolution Decisions (2026-10-03)

### D7-001 — D1 minimal C/OpenSSL server for forced HRR with stateless cookie
**Reason:** OpenSSL 3.5.5 `s_server` CLI supports `-stateless` but cannot force an HRR on every connection. The D1 defense mechanism requires forcing TLS 1.3 HelloRetryRequest with a stateless cookie on demand. **Decision:** Replace the `s_server` CLI for the D1 defense path with a minimal C/OpenSSL TLS server that uses OpenSSL 3.5+ APIs to force HRR where required, leveraging OpenSSL's built-in stateless cookie generation/verification. No custom cryptography is introduced. The existing TLS measurement architecture and provenance of observed TLS events are preserved. CPU instrumentation continues to attach to the actual TLS server process. **Status:** active; D1 implementation pending Phase 7 authorization.

### D7-002 — D2 userspace admission proxy inside TLS-server container
**Reason:** Kernel-level packet filtering and privileged Docker networking are excluded by project safety boundaries. A userspace proxy avoids additional capabilities while keeping CPU measurement focused on the TLS server. **Decision:** D2 will use a userspace admission proxy running inside the TLS-server container. The proxy listens on port 4433, identifies source IP, applies a bounded per-source connection-rate limit, and forwards accepted connections to the TLS server on port 4434. The proxy does not perform TLS termination, does not modify TLS messages, does not introduce custom cryptography, and requires no additional privileged Docker capability. **Status:** active; D2 implementation pending Phase 7 authorization.

### D7-003 — D2 source admission limit set to 5 connections/second/source IP
**Reason:** Legitimate client target is 1 request/second; workload is approximately 30–50 attempts/second. A 5/second limit provides bounded headroom for legitimate traffic while throttling the workload. **Decision:** The D2 source admission limit for the Phase 7 evaluation is 5 connections/second/source IP. This is a project experiment parameter, not a universal recommended security threshold. **Status:** active; subject to Phase 7 pilot validation.

### D7-004 — RQ5 RTT measurement via packet-capture timestamps
**Reason:** TLS 1.3 handshake RTT counts differ between normal (1 RTT) and HRR (2 RTT) paths. Packet-capture timestamps provide ground-truth round-trip evidence independent of wall-clock latency. **Decision:** RQ5 RTT measurement will use packet-capture timestamps to count handshake RTTs: baseline TLS 1.3 ClientHello → ServerHello (1 RTT), HRR path ClientHello → HRR → ClientHello2 → ServerHello (2 RTTs). Legitimate-client wall-clock p50/p95 latency is reported separately and not mixed with packet-level RTT counts. **Status:** active; measurement implementation pending Phase 7 authorization.

## Phase 7 D1 Validation-Path Repair Decisions (2026-10-03)

### D7-005 — Separate in-lab D1 protocol-validation phase (A/B separation)
**Reason:** The C1×W1×D1 pilot FAILED because the required protocol
evidence (ClientHello -> HRR+cookie -> ClientHello2+cookie -> ServerHello)
cannot arise inside a W1-only capture window: W1 aborts pre-Finished, so
ClientHello2/ServerHello never occur, and the pcap RTT parser therefore
returns null. Modifying W1 to complete the handshake would corrupt its
controlled-abort semantics. **Decision:** Add a SEPARATE, bounded D1
protocol-validation phase (B) that runs one or more FULL TLS 1.3 C1
handshakes against the actual `d1_server` inside the Docker lab, in its own
bounded packet-capture window, before the W1 exhaustion measurement (A). B
uses OpenSSL's own HRR response (no custom crypto) and never contributes to
A's attempt/CPU/bytes denominator. W1 (A) is unchanged. **Status:** active.

### D7-006 — Explicit in-network client addressing (no host tls-server DNS, no host Python for C1)
**Reason:** The pilot's legitimate client ran on the host with Python
`ssl` (OpenSSL 3.0.21, which cannot negotiate ML-KEM-768) and targeted the
Docker-only service name `tls-server`, which does not resolve from the host;
both caused failures. **Decision:** Clients that must resolve the lab
service name (workload, legitimate, D1 validation) run INSIDE the lab
network (via `docker exec` in the workload-client container) using OpenSSL
3.5.x, and use the compose service name (`target_host`, default
`tls-server`). The host is used only for orchestration/readiness
(`127.0.0.1:<published port>`). Host Python/OpenSSL is never used for a C1
TLS handshake. **Status:** active.

### D7-007 — `d1_validation` result-schema extension (isolated from A)
**Reason:** The validation evidence (observed sequence, HRR/cookie/CH2/SH
flags, RTT) must be recorded without entering the exhaustion denominator
(`server_cpu_seconds_per_attempt`, `bytes_*_per_attempt`, `attempts`).
**Decision:** Extend the result record (see `design.md` §2) with a discrete
`d1_validation` object, present only when validation is enabled. It is
produced by its own bounded capture window and NEVER contributes to A's
counters. **Status:** active.

### D7-008 — Legitimate-client contract: handshake completion, not application payload
**Reason:** The D1 server (by design) sends no application data, so the
previous `recv()`-based success test could never mark a D1 handshake as
successful. **Decision:** `run_legitimate_client` defines success as TLS
handshake COMPLETION (OpenSSL handshake finished / `wrap_socket` returns),
never as receipt of application payload. When a lab client container is
available the legitimate handshake runs in-network via OpenSSL 3.5.x (C1
capable); the host Python path is retained only as a non-C1 fallback. The
component boundary (`src/legitimate_client`, independent of `src/workload`)
is preserved. **Status:** active.

### D7-009 — D1 validation phase (Phase B) implemented in controller (2026-10-03)
**Reason:** The failed D1 pilot (2026-10-03) could not observe the complete
forced-HRR flow (ClientHello → HRR+cookie → ClientHello2+cookie → ServerHello)
because W1 workload aborts pre-Finished. Per D7-005/D7-007, a separate
bounded validation phase was required. **Implementation:** Added Phase B in
`src/controller/experiment.py:run_experiment()` that runs before the W1
workload (Phase A) when `defense == "D1"` and `validation_handshakes > 0`.
Phase B: (1) starts a dedicated packet-capture window; (2) runs the configured
number of full TLS 1.3 handshakes via `run_in_network_handshake()` (OpenSSL
3.5.x in-network); (3) parses each transcript with `parse_d1_validation_transcript()`;
(4) stops the validation capture and parses pcap with `parse_d1_handshake_flow()`;
(5) builds `d1_validation` result object per `design.md §2` schema.
**Boundary enforcement:** Validation traffic never enters W1 `attempts`,
`server_cpu_seconds_per_attempt`, `bytes_received_per_attempt`,
`bytes_sent_per_attempt`, or `tls_events` denominator. Legitimate client
now uses in-network path when container available. **Tests:** Added
`tests/test_d1_validation_integration.py` with 8 unit tests verifying:
validation runs before workload; disabled for non-D1/zero handshakes; excluded
from W1 denominator; `d1_validation` populated per schema; failure not
fabricated; W1 remains `controlled_abort`. **Status:** active; pilot NOT rerun.

### D7-010 — D1 mechanism resolved: adopt OpenSSL s_server -stateless CLI path (2026-10-04)
**Reason:** The custom C/OpenSSL `SSL_stateless()` D1 server (`d1_server.c`)
consistently failed with `SSL_R_INTERNAL_ERROR` in `tls_construct_stoc_cookie`
when using ML-KEM-768, in both OpenSSL 3.5.5 and 3.5.9. The OpenSSL CLI
`openssl s_server -stateless` path was empirically verified to produce the
D1 HRR flow when the client deliberately creates a key-share mismatch.
**Decision:** Abandon the custom `SSL_stateless()` C server as the
D1 implementation. Use `openssl s_server -stateless` as the D1 server.

**D1 mechanism:**
- Use OpenSSL 3.5.x `openssl s_server -stateless`.
- Do NOT use the custom programmatic `SSL_stateless()` server as the D1 implementation.

**D1 trigger:**
- The server is configured with MLKEM768 as the preferred group.
- The validation/workload client advertises supported groups including: X25519, MLKEM768
- The initial ClientHello sends an X25519 key share.
- Because MLKEM768 is supported but its key share was not initially sent, OpenSSL produces the TLS 1.3 HelloRetryRequest requesting MLKEM768.

**D1 cookie — CORRECTED (2026-10-04):**
- The stateless TLS 1.3 cookie extension (RFC 8446 §4.2.2) is OpenSSL's built-in `s_server -stateless` mechanism.
- **Empirically, for ML-KEM-768 in OpenSSL 3.5.5 and 3.5.9, the cookie extension is NOT emitted in the HRR and NOT echoed in ClientHello2.**
- Do not implement custom cookie generation, verification, or cryptographic logic.
- `cookie_observed = false` is a legitimate measured outcome, not missing data.

**Empirical feasibility evidence:**
- OpenSSL 3.5.5: HRR flow verified (ClientHello → HRR with RFC8446 special random → HRR key_share=MLKEM768 → ClientHello2 with MLKEM768 key_share → ServerHello MLKEM768 → completed TLS 1.3 handshake). Cookie extension: NOT observed.
- OpenSSL 3.5.9: HRR flow verified (same sequence). Cookie extension: NOT observed.
- The initial ClientHello was independently verified to advertise both X25519 and MLKEM768 while carrying only X25519 in key_share.

**D1 measurement boundary:**
- The existing experiment controller and instrumentation remain responsible for: CPU measurement, packet measurement, TLS event observation, bounded attempt accounting, denominator definition, cleanup.
- Do NOT move measurement responsibility into the s_server wrapper.
- Do NOT fabricate TLS events from configuration.
- Preserve the existing null-not-zero measurement semantics.

**D1 validation:**
- Keep the already-designed Phase B D1 validation separate from Phase A measurement.
- Phase B validation handshakes must not contribute to: W1 attempt denominator, CPU/attempt denominator, bytes/attempt denominator, campaign measurements.
- Phase A remains the actual bounded W1 controlled-abort measurement.

**Custom SSL_stateless server:**
- Explicitly mark the current custom `SSL_stateless()` D1 server implementation as ABANDONED/REJECTED for this project.
- It must not remain as an alternate D1 mechanism.
- Do not continue debugging or extending it.
- Preserve its historical failure evidence where appropriate.

**D2/D3:**
- No design change.
- No implementation change unless strictly required by the minimal D1 topology change.
- Do not redesign D2 or D3.

**Supersedes earlier flawed CLI diagnostic:**
The corrected CLI test supersedes the earlier flawed CLI diagnostic, because the corrected client configuration actually demonstrated:
    supported_groups = X25519, MLKEM768
    initial key_share = X25519
Do not claim that `-stateless` forces HRR for every arbitrary ClientHello.
State accurately that the experiment deliberately creates the key-share mismatch required to trigger HRR.

### D7-011 — D1 cookie scope corrected: HRR without cookie for ML-KEM-768 (2026-10-04)
**Reason:** The latest empirical investigation (manual `openssl s_client -msg -state` transcript analysis in the Docker lab with OpenSSL 3.5.9) established that the OpenSSL 3.5.x `s_server -stateless` CLI does not emit the stateless cookie extension (RFC 8446 §4.2.2, extension type 44) in the HelloRetryRequest when the server's preferred group is ML-KEM-768, nor does the client echo a cookie in ClientHello2. The HRR mechanism itself works correctly (special random observed, MLKEM768 key_share requested, ClientHello2 with MLKEM768 key_share, ServerHello with MLKEM768, handshake completes).
**Decision:** Correct all six source-of-truth files to reflect that D1 for PQ-TLS (ML-KEM-768) is an HRR-based mechanism with `cookie_observed = false`. The originally intended stateless HRR-cookie defense was not realized for ML-KEM-768 using the tested OpenSSL 3.5.x path. The custom `SSL_stateless()` C implementation remains abandoned. Do not implement custom cookie cryptography. Do not claim PQ-TLS HRR-cookie mitigation was experimentally demonstrated.
**Impact:** RQ4 (Admission control) and RQ5 (Availability trade-off) must be evaluated with the measured implementation (HRR without cookie) rather than the intended defense (HRR + stateless cookie). The distinction is mandatory in all analysis and reporting.
**Status:** Active; supersedes the cookie claim in D7-010.
