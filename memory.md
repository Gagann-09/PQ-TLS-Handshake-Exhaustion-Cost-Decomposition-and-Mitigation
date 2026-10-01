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
