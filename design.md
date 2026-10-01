# Design — Implementation-Level Detail

This document specifies the concrete formats and module contracts that
`architecture.md` describes at the component level. If a detail here and in
`architecture.md` ever conflict, `architecture.md` wins on topology,
`design.md` wins on format.

## 1. Experiment Config Schema (`config/experiment_matrix.yaml`)
```yaml
experiment_id: c1_w1_r03          # <date>-<Cn>-<Wn>-R<nn> at write time
server:
  configuration: C1                # one of C0..C4, see PRD.md §6
  defense: D0                      # one of D0..D3, see PRD.md §9
workload:
  mode: controlled_abort            # normal_completion | controlled_abort
  key_reuse: fresh_keypair          # fresh_keypair | reused_client_keypair
  max_attempts: 1000                # hard-capped again in code, see rules.md
  max_duration_seconds: 30
  max_concurrency: 1
legitimate_client:
  rate_per_sec: 1.0
target:
  host: tls-server
  port: 4433
network:
  latency_ms: 0
  loss_percent: 0
trial:
  repeats: 3
  seed: 42
```
`safety_limits.yaml` holds the ceiling values independently of any single
experiment file; the controller must refuse to start if an experiment
config requests a value above the ceiling (see `rules.md` §2).

## 2. Result Record Schema (`results/raw/<experiment_id>.json`)
```json
{
  "experiment_id": "2026-10-01-C1-W1-R03",
  "configuration": "C1",
  "defense": "D0",
  "workload_mode": "controlled_abort",
  "key_reuse": "fresh_keypair",
  "attempts": 1000,
  "duration_seconds": 28.4,
  "server_cpu_seconds": 12.43,
  "workload_client_cpu_seconds": 1.02,
  "bytes_received": 123456,
  "bytes_sent": 45678,
  "handshake_outcomes": {"aborted_pre_finished": 1000, "completed": 0},
  "tls_events": [
    {
      "negotiated_group": "X25519MLKEM768",
      "negotiated_signature_algorithm": "ecdsa_secp256r1_sha256",
      "outcome": "completed"
    },
    {
      "negotiated_group": null,
      "negotiated_signature_algorithm": null,
      "outcome": "aborted_pre_finished"
    }
  ],
  "legitimate": {
    "attempts": 29,
    "successes": 28,
    "p50_latency_ms": 41.2,
    "p95_latency_ms": 82.1,
    "timeouts": 1
  },
  "environment": {
    "git_commit": "TBD",
    "os": "TBD",
    "cpu": "TBD",
    "openssl_version": "TBD",
    "timestamp_utc": "TBD"
  }
}
```
Raw result files are append-only: a run writes a new file, it is never
edited in place. Derived/aggregated metrics live under `results/processed/`,
computed from raw files, never the reverse.

**Field semantics (locked 2026-10-01):**
- `server_cpu_seconds`: CPU-seconds consumed by the `openssl s_server`
  process during the workload execution window, measured via `pidstat`
  inside the TLS-server container at 1 Hz.
- `bytes_received`: Total IP-packet bytes received by the TLS server during
  the experiment window. Wire-level IP bytes, not application payload.
- `bytes_sent`: Total IP-packet bytes sent by the TLS server during the
  experiment window. Wire-level IP bytes, not application payload.
- `tls_events`: Normalized TLS observation per handshake attempt. The two
  negotiated algorithm fields MUST be nullable — a controlled abort may
  terminate before negotiation evidence is observable. Do not force invented
  values such as `"unknown"`, `"none"`, `"failed"`, or `"N/A"`. Prefer
  semantic null.

## 3. Module Contracts

### `src/controller`
- `load_config(path) -> ExperimentConfig`
- `validate_against_limits(config, limits) -> ExperimentConfig | SafetyError`
- `run(config) -> ResultRecord`
- Must call the target-allowlist check (see `rules.md` §2) before any
  network action, and must fail closed on any validation error — no partial
  run starts.

### `src/workload`
- `generate(mode, key_reuse, bound) -> Iterator[Attempt]`
- Accepts only the three modes listed in `architecture.md` §3.3.
- Has no code path that accepts a destination outside the resolved
  allowlist — this is a structural constraint, not a runtime flag.

### `src/legitimate_client`
- `run(rate, duration) -> LegitimateStats`
- Runs independently of `src/workload`; must not import it, to keep
  legitimate-traffic CPU accounting uncontaminated by workload code.

### `src/instrumentation`
- `sample_cpu(pid, interval) -> CpuSamples` — CPU sampling via `pidstat`
  inside the TLS-server container, targeting the `openssl s_server` process
  at 1 Hz. Host-side `psutil` is NOT an experimental fallback.
- `capture_packets(interface, port, duration) -> PcapMeta` — packet capture
  via `tcpdump` restricted to the laboratory interface and port. Counts
  IP-packet bytes (wire-level, not application payload). Metadata only; see
  `rules.md` §9 — no plaintext payload or keylog retention.
- `read_tls_log(path) -> list[HandshakeEvent]` — parse TLS-level events.
  Each event has `negotiated_group`, `negotiated_signature_algorithm`
  (both nullable), and `outcome` (`completed` | `aborted_pre_finished` |
  `error`). Every event must be traceable to an underlying observation
  source — negotiated values MUST NOT be manufactured from the experiment
  configuration alone.

### `src/defense`
- `apply(mode: D0..D3, server_config) -> ServerConfig`
- Lives in its own module tree, imported by the server bring-up step only —
  never by `src/workload`, so a workload run cannot silently disable the
  defense it's being measured against.

### `src/analysis`
- `load_raw(path_glob) -> DataFrame`
- `decompose_cost(df) -> Figure_A..Figure_C`
- `compare_key_reuse(df) -> Figure_D`
- `compare_defense(df) -> Figure_E, Figure_F`
- Pure functions over already-collected data; no network or process calls.

## 4. Experiment ID Convention
`<ISO-date>-<Cn>-<Wn>-R<trial-number, zero-padded to 2 digits>`, e.g.
`2026-10-01-C4-W1-R07`. Key-reuse and defense runs append a suffix:
`2026-10-01-C1-W1-R03-reused`, `2026-10-01-C1-W1-R03-D1`.

## 5. Statistical Reporting Convention
Every figure in `architecture.md` §6 reports median, mean, standard
deviation, and p95 across trial repeats, plus the repeat count used. No
figure is generated from a single run. Paired comparisons (e.g., C1 vs. C0,
same trial index) are preferred over independent-sample comparisons where
the experimental design allows pairing.

## 6. What This Document Deliberately Omits
Source code itself, CI/test configuration detail, and the research
narrative — those live in `src/`, `tests/`, and `PRD.md` respectively. This
file is the contract between them.
