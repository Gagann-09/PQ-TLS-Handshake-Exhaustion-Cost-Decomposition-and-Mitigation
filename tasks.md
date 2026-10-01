# Tasks — Phased Roadmap

Each phase lists a deliverable and, where relevant, a decision gate. Do not
proceed past a gate whose condition has failed without recording the
decision in `memory.md`.

## Phase 0 — Research Validation (Days 1–3)
- [ ] Re-read arXiv:2607.12504, RFC 9954, draft-ietf-tls-mlkem,
      draft-ietf-tls-ecdhe-mlkem; confirm current revision numbers.
- [ ] Resolve the FIPS 203 ML-KEM-768 reuse-bound open item in `memory.md`.
- [x] Confirm which of C0–C4 the chosen OpenSSL/`oqs-provider` build
      actually negotiates end to end (`openssl s_client -groups ...
      -sigalgs ...`).
      **DONE 2026-10-01 — 5/5 SUPPORTED** (OpenSSL 3.5.5, default provider;
      local `127.0.0.1` handshakes; full evidence in `memory.md` P0-003).
- **Gate:** if fewer than four of the five configurations are negotiable by
  end of Phase 0, record the reduced matrix as a decision in `memory.md`
  before continuing — do not silently drop a row.
- **Gate status (2026-10-01): PASSED** — 5/5 (C0–C4) negotiable on the
  Phase 0 build; no reduced-matrix decision required.

## Phase 1 — Safe Laboratory Skeleton (Days 4–5)
- [x] Stand up the Docker lab network, TLS server, legitimate client,
      experiment controller, and safety validator from `architecture.md`
      and `design.md`.
      **DONE 2026-10-01** — 23 tests pass; preflight verified; committed
      and pushed (`bc026d3`). See `memory.md` P1-001.
- **Acceptance test:** target allowlist rejects `8.8.8.8` and accepts
  `tls-server`; max-attempts and max-duration are enforced; automatic
  cleanup runs after every experiment (`rules.md` §10).
  **PASSED 2026-10-01** — `tests/test_preflight.py` and
  `tests/test_safety.py` both green.

## Phase 2 — Classical Baseline (Days 6–8)
- [x] Implement C0 (X25519 + ECDSA-P256), workload modes W0 and W1.
      **DONE 2026-10-01** — C0 config, Docker compose, W0/W1 modes,
      8 new tests (31 total pass). TLS negotiation verified: X25519 +
      ecdsa_secp256r1_sha256. See `memory.md` P2-001.
- [x] Collect baseline CPU, bytes, legitimate-client success for ≥3 trials.
      **DONE 2026-10-01** — 3 C0 W0 trials completed. ~515 attempts/trial,
      ~484 completed handshakes/trial, 30/30 legitimate-client successes.
      Server CPU: TBD (requires Phase 4 instrumentation). See `memory.md` P2-002.
- **Gate:** do not start Phase 3 until C0 measurements are reproducible
  across trials within a reasonable variance band.

## Phase 3 — PQ Configurations (Week 2)
- [x] Implement C1, C2, C3, C4 per `PRD.md` §6.
      **DONE 2026-10-01** — C1–C4 configs, Docker compose files, ML-DSA-65
      cert generation scripts, 32 new tests (63 total pass). TLS negotiation
      verified for all four: C1 MLKEM768+ecdsa_secp256r1_sha256, C2
      X25519+mldsa65, C3 X25519MLKEM768+ecdsa_secp256r1_sha256, C4
      MLKEM768+mldsa65. All SUPPORTED. See `memory.md` P3-001.
- [x] Record any `UNSUPPORTED` configuration rather than substituting one.
      **DONE 2026-10-01** — All four configurations SUPPORTED on OpenSSL
      3.5.5 default provider; no UNSUPPORTED entries needed.

## Phase 4 — Instrumentation (Week 3)
- [ ] Wire up `perf`/`pidstat`/`tcpdump`/TLS logging per `design.md` §3.
      **Methodology locked 2026-10-01** — CPU via `pidstat` inside
      container, bytes via IP-packet capture, TLS events with nullable
      negotiated fields. Implementation still pending.
      **Remediation 2026-10-01 (memory.md P4-002)** — F-01..F-04 implemented:
      TLS provenance no longer config-derived; W1 genuinely aborts
      pre-Finished; tcpdump has an explicit start/stop lifecycle; controller
      integrates the three streams with a null-not-zero result schema.
      Unit-verified (87 tests) and host-runtime verified (C0 W0/W1). Container
      (CPU/pidstat + tcpdump) runtime verification still pending.
- [ ] Confirm the result-record schema (`design.md` §2) is produced
      correctly for one full run of each configuration.
      **Partial 2026-10-01** — schema produced and inspected for C0 W0 and W1
      (host runtime). C1–C4 runs and `design.md` §2 sync still pending.

## Phase 5 — RQ1/RQ2 Decomposition (Week 4)
- [ ] Run the full `{C0..C4} × {W0,W1}` matrix, ≥3 trials each.
- [ ] Produce Figures A–C (`architecture.md` §6).
- **Gate:** if no meaningful component-level difference appears, do not add
  complexity to manufacture one — narrow the paper to a measurement study
  and record that decision in `memory.md`.

## Phase 6 — RQ3 Key Reuse (Week 5)
- [ ] Confirm the FIPS 203 bound item from Phase 0 is resolved (resolved
      as a negative result per P0-001; no longer blocking per `rules.md` §4).
- [ ] Run C1 × W1 under `fresh_keypair` and `reused_client_keypair`, fresh
      encapsulation randomness in both cases, always.
- [ ] Produce Figure D.
- **Gate:** if reuse does not materially change measured cost, report the
  negative result; do not expand this branch further.

## Phase 7 — RQ4/RQ5 Defense (Week 6)
- [ ] Implement D0–D3 per `PRD.md` §9 / `architecture.md` §3.7.
- [ ] Run C1 × W1 (minimum) across D0–D3, ≥3 trials each.
- [ ] Produce Figures E and F.
- **Minimum bar:** D1 alone is sufficient for project completion if time is
  short (see Scope Cut Order below); D2/D3 are additive.

## Phase 8 — Network Conditions (Week 7, optional)
- [ ] Only if Phases 5–7 are stable: sweep latency (0/20/50/100 ms) and
      loss (0/1/5%) via `tc netem` on the C1 × W1 condition.
- Do not start this phase while any earlier gate is unresolved.

## Phase 9 — Analysis (Week 8)
- [ ] Consolidate Figures A–F with medians, means, standard deviations, and
      p95s per `design.md` §5.
- [ ] Recompute the headline "how much extra cost" number in this testbed's
      own terms, and explicitly state how it relates to — not necessarily
      reproduces — arXiv:2607.12504's duration-based figure.

## Phase 10 — Paper (Weeks 9–10)
- [ ] Draft sections: Introduction, Background, Related Work, Research
      Questions, Threat Model, Architecture, Component Decomposition,
      Key-Reuse Experiment, Defense Evaluation, Limitations,
      Reproducibility, Conclusion.
- [ ] Re-verify every literature citation and draft revision number
      immediately before submission (`memory.md` Open Items).
- [ ] Final pass against `rules.md` §9 (data scrubbing) and §5 (no
      fabricated/unsupported claims).

## Scope Cut Order (if time runs short)
Cut in this order — last listed is cut first:
1. Phase 8 (network-condition sweep).
2. D2/D3 combined-defense runs (keep D1 alone).
3. C3 hybrid configuration (keep C0, C1, C2, C4).
4. Any secondary-hardware generalization check not already in scope.

**Never cut:** safety boundaries (`rules.md`), the C0 baseline, the C1
(ML-KEM) comparison, normalized CPU-per-attempt reporting, legitimate-client
measurement for every tested condition, or reproducibility documentation.
These constitute the minimum viable paper per `PRD.md` §12.

## Minimum Viable Deliverable
```
C0 baseline + C1 (ML-KEM) comparison
  + controlled-termination workload (W1)
  + normalized CPU-seconds/attempt
  + legitimate-client availability measurement
  + ML-KEM client-keypair reuse experiment (RQ3)
  + one defense evaluated end to end (D1 minimum)
```
Everything else in this roadmap is additive, not required.
