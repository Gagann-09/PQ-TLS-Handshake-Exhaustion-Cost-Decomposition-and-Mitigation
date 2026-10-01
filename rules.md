# Rules — Safety and Agent Boundaries

These rules bind any human or coding agent making changes in this
repository. They are not suggestions; violating any rule in Sections 2–5
should block a change from being merged or run.

## 1. Read Before Acting
Before modifying code, read `PRD.md`, `architecture.md`, `design.md`, and
`memory.md`, in that order. Do not implement from a single instruction in
isolation if it conflicts with something recorded in `memory.md`'s decision
log — raise the conflict instead of silently resolving it.

## 2. Target and Load Boundary
- **Allowlist (default):** `localhost`, `127.0.0.1`, `::1`, Docker service
  names resolvable only inside the lab network. Any destination outside
  this list must fail closed — rejection is the default behavior, not an
  opt-in check.
- **Hard limits (default, from `design.md` §1):** `max_attempts: 1000`,
  `max_duration_seconds: 30`, `max_concurrency: 1`. A config file may only
  *lower* these; it may never raise them above the code-level ceiling.
- **Never implement:** an unlimited/infinite/no-cap mode, IP spoofing, raw
  packet forgery, reflection or amplification, random or automated
  public-target discovery, or multi-host/distributed attack coordination.
- The research objective is **normalized cost per attempt**, not maximum
  destructive throughput — there is never a reason to exceed these limits
  to answer RQ1–RQ5.

## 3. Cryptographic Implementation Boundary
Never implement ML-KEM, ML-DSA, X25519, ECDSA, TLS record/handshake logic,
certificate validation, or a random-number generator from scratch. Use
OpenSSL 3.5+ (or `oqs-provider` where needed) exclusively. If a needed
parameter set or mode isn't available in the chosen library, mark the
configuration `UNSUPPORTED` per `PRD.md` §6 — do not patch around it with
custom crypto.

## 4. ML-KEM Key-Reuse Boundary
The only permitted reuse condition is: **reuse the client's ML-KEM
public/private keypair** across multiple controlled attempts.
Per [draft-ietf-tls-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/):
keypair reuse is discouraged for forward secrecy but not prohibited.
No numeric keypair-reuse bound is specified in FIPS 203 or in any citable
security analysis; the project does not invent one. RQ3 is bounded by the
hard limits in §2 (`max_attempts: 1000`, `max_duration_seconds: 30`,
`max_concurrency: 1`), which are project safety ceilings independent of
FIPS 203.
**Absolutely forbidden, no exception:** reusing ML-KEM ciphertext or the
randomness used to generate a ciphertext. The same draft states this as a
MUST NOT. Every encapsulation in every run uses fresh randomness,
regardless of whether the keypair itself is fresh or reused.
Do not generalize this narrow, specification-permitted condition into a
general "reuse arbitrary keys" experiment — X25519 ephemeral reuse is out
of scope entirely.

## 5. Research Integrity
- Never fabricate a measurement, a confidence interval, a citation, or a
  vulnerability. Where a number doesn't exist yet, write `TBD` — not a
  plausible-looking placeholder.
- Never write "first," "novel," or "state of the art" unless `PRD.md` §10
  explicitly supports the specific claim being made, and re-verify that
  support against current literature immediately before submission, not
  once at project start.
- A null or negative result (e.g., key reuse does not measurably change
  cost) is a valid, reportable outcome — do not reshape the experiment
  design after the fact to manufacture a positive one.

## 6. Reproducibility
Every result record carries git commit, OS, CPU, OpenSSL version, the
active configuration and defense IDs, and a UTC timestamp (schema in
`design.md` §2). Raw results are append-only. Derived/aggregated results
are regenerated from raw data, never hand-edited.

## 7. Scope Control
Do not add, without an explicit, recorded decision in `memory.md`:
blockchain components, ML-based IDS/detection beyond the minimal scope (if
any) already in `PRD.md`, 5G/6G infrastructure, Kubernetes, cloud-scale
attack simulation, additional unrelated protocols (MQTT, CoAP, etc.), or
any component not already named in `architecture.md`. This project is
deliberately small; expansion requires a documented research reason, not
convenience.

## 8. Stop Condition
Once the minimum viable set exists — C0 and C1 baselines, component
decomposition for C0–C4, the key-reuse experiment under §4's boundary, one
full defense evaluation (minimum D1), and legitimate-client measurements
for every condition tested — do not keep auto-expanding scope. Check
`tasks.md`'s scope-cut order before adding anything further.

## 9. Data Handling
Packet captures are restricted to the laboratory interface and port, for
the experiment duration only, and record packet-size/timing metadata —
never decrypted payload, and no TLS keylog file is retained past the
debugging session that needed it. Before any publication or sharing of raw
data: scrub unrelated IP addresses, private keys, credentials, and
machine-specific identifiers.

## 10. Mandatory Preflight Test
Before any real experiment run, the test suite must demonstrate both:
```
target("8.8.8.8")    -> rejected
target("tls-server")  -> accepted, only within configured limits
```
A failing or missing preflight test blocks the run.

## 11. Change Discipline
Before changing anything architectural: identify the requirement in
`PRD.md`, confirm the change doesn't violate Sections 2–5 above, update
`tasks.md` if scope changes, record the decision in `memory.md`, make the
smallest change that satisfies the requirement, then run tests.
