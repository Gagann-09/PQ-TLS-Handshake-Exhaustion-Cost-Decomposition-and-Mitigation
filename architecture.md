# Architecture — PQ-TLS Handshake Research Testbed

## 1. Design Principle
A bounded measurement testbed, not a general-purpose flood framework. Six
responsibilities are kept in separate components so that no single piece of
code both generates load and decides how much load is safe to generate.

## 2. High-Level Topology
```
                         ┌──────────────────────────┐
                         │   Experiment Controller   │
                         │ matrix · safety limits ·  │
                         │ repetitions · logging     │
                         └─────────────┬─────────────┘
                                       │
                 ┌──────────────────── ┴ ──────────────────┐
                 │                                         │
                 ▼                                         ▼
      ┌────────────────────────┐              ┌────────────────────────┐
      │ Controlled TLS Workload│              │ Legitimate TLS Client  │
      │ bounded attempts only  │              │ steady background rate │
      └────────────┬────────────┘              └────────────┬────────────┘
                   │                                         │
                   └──────────────────┬──────────────────────┘
                                      ▼
                          ┌─────────────────────┐
                          │  Laboratory Network  │
                          │  optional tc/netem   │
                          └──────────┬───────────┘
                                     ▼
                          ┌─────────────────────┐
                          │   TLS 1.3 Server     │
                          │ nginx/OpenSSL, C0–C4 │
                          │ defense layer (D0–D3)│
                          └──────────┬───────────┘
                                     ▼
                          ┌─────────────────────┐
                          │   Instrumentation    │
                          │ perf · pidstat ·     │
                          │ tcpdump · TLS logs   │
                          └─────────────────────┘
```

## 3. Components

### 3.1 Experiment Controller
Loads an experiment config, checks it against the allowlist and hard limits
defined in `rules.md`, selects the TLS configuration (C0–C4), starts
telemetry, starts the legitimate client, starts the bounded workload, stops
everything at the configured limit, and writes one structured result record
per run. Every run gets an experiment ID of the form `<date>-<Cn>-<Wn>-R<nn>`.

### 3.2 TLS Server
nginx fronting OpenSSL 3.5+, or a minimal C/OpenSSL test server if nginx's
build makes phase-level instrumentation impractical. Exposes only the
laboratory port. Runs exactly one of C0–C4 per experiment run (never mixed
mid-run) and, when a defense is under test, exactly one of D0–D3.

### 3.3 Controlled Workload Client
Opens TLS connections per the active workload mode (W0/W1/W2) and the active
key-reuse condition. Supports: `normal_completion`, `controlled_abort`,
`reused_client_mlkem_keypair`. Does **not** support unbounded rate, IP
spoofing, or target discovery — these are structurally absent, not merely
disabled by default (see `rules.md` §2).

### 3.4 Legitimate TLS Client
An independent process issuing requests at a fixed low rate throughout every
experiment, regardless of workload or defense condition, to provide the
availability baseline (RQ5). Runs on separate CPU affinity from the workload
client so its own resource use doesn't contaminate attacker-side cost
measurements.

### 3.5 Instrumentation
`perf stat` / `pidstat` for CPU and cycle sampling at 1 Hz on the server
process; `tcpdump` restricted to the laboratory interface and port for
packet-size/timing metadata only (no payload decryption, no keylog
retention — see `rules.md` §9); TLS-level logging of negotiated group,
negotiated signature algorithm, and handshake outcome.

### 3.6 Network Emulator (optional)
`tc netem` applied to the lab network namespace for a secondary sweep over
latency (0/20/50/100 ms) and loss (0/1/5%), run only after the core C0–C4
decomposition is stable (see `tasks.md` Phase 8).

### 3.7 Defense Layer
Sits in front of expensive handshake processing on the server:
```
ClientHello
    │
    ▼
┌───────────────────────┐
│ Admission decision     │
│ cookie required? (D1)  │
│ source budget? (D2)    │
└───────────┬─────────────┘
            │ accepted
            ▼
      TLS 1.3 processing
```
The defense layer does not alter ML-KEM, ML-DSA, X25519, or ECDSA
behavior — it only gates whether a ClientHello reaches full processing.

## 4. Experiment Matrix
```
Core:        {C0,C1,C2,C3,C4} × {W0,W1}
Key reuse:   C1 × W1 × {fresh_keypair, reused_keypair}
Defense:     C1 × W1 × {D0,D1,D2,D3}
```
Each cell is repeated enough times to produce a variance estimate — see
`rules.md` for the hard attempt/duration ceiling per run, and `tasks.md`
for the minimum repeat count per phase.

## 5. Measurement Model (per run)
Recorded: configuration ID, workload mode, defense mode, attempt count,
duration, server CPU time, client (workload) CPU time, bytes in/out,
per-attempt handshake outcome, legitimate-client success count and
latencies.
Derived at analysis time: CPU-seconds per attempt, bytes per attempt,
workload-client/server CPU ratio, legitimate goodput under load.

## 6. Output Figures
- **A** — CPU-seconds per attempted handshake, by configuration.
- **B** — Incremental cost relative to C0, by configuration.
- **C** — Key-establishment vs. authentication contribution (C1 vs. C2 vs. C4).
- **D** — Fresh vs. reused client ML-KEM keypair, cost comparison.
- **E** — Defense effectiveness (server CPU reduction, D0→D3).
- **F** — Legitimate-client latency/success trade-off per defense.

## 7. Interpretation Boundary
A higher measured CPU cost is a resource-economics finding, not by itself a
cryptographic vulnerability claim. Any security-flavored conclusion in the
final report must be scoped to exactly what the measurements show.

## 8. Repository Layout
```
pq-tls-handshake-research/
├── PRD.md
├── architecture.md
├── design.md
├── rules.md
├── memory.md
├── tasks.md
├── config/
│   ├── experiment_matrix.yaml
│   └── safety_limits.yaml
├── src/
│   ├── controller/
│   ├── workload/
│   ├── legitimate_client/
│   ├── instrumentation/
│   ├── defense/
│   └── analysis/
├── lab/
│   ├── server/
│   └── network/
├── scripts/
│   ├── setup.sh
│   ├── run.sh
│   └── collect.sh
├── tests/
└── results/
    ├── raw/
    ├── processed/
    └── figures/
```
This is the implementation tree. The six root files are the only
project-specification documents; everything under them is code, config, or
output data.
