"""Phase 6 — RQ3 Key Reuse Experiment Runner.

Matrix: C1 × W1 × {fresh_keypair, reused_client_keypair} × 3 trials.
Bounds: max 1000 attempts / 30 s / concurrency 1, target tls-server:4433.
Defense: D0 (baseline).
Produces Figure D data (fresh vs reused keypair cost comparison).
"""
import json
import sys
import time
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.controller.config import load_config
from src.controller.experiment import run_experiment
from src.instrumentation.tls_log import parse_openssl_handshake_observation

CONFIG_FRESH = "config/c1_w1_fresh.yaml"
CONFIG_REUSED = "config/c1_w1_reused.yaml"
COMPOSE_FILE = "lab/network/docker-compose-c1.yml"
TRIAL_DATE = "2026-10-02"


def observe_config(name: str, compose: str, pin_args: list[str], out_dir: Path) -> dict:
    """One genuine openssl s_client transcript per configuration."""
    import subprocess
    subprocess.run(["docker", "compose", "-f", compose, "up", "-d"],
                   check=True, capture_output=True, text=True)
    try:
        # Wait for server to be ready (package install + startup can take 20-30s)
        time.sleep(30)
        out = subprocess.run(
            ["openssl", "s_client", "-connect", "127.0.0.1:4433", "-tls1_3"] + pin_args,
            input="", capture_output=True, text=True, timeout=20,
        )
        transcript = (out.stdout or "") + (out.stderr or "")
        obs = parse_openssl_handshake_observation(transcript)
        record = {
            "configuration": name,
            "negotiated_group": obs.negotiated_group,
            "negotiated_signature_algorithm": obs.negotiated_signature_algorithm,
            "evidence_source": obs.source,
            "transcript_excerpt": [
                line for line in transcript.splitlines()
                if any(k in line for k in ("Protocol version", "Ciphersuite",
                                           "Peer Temp Key", "Signature type",
                                           "Negotiated TLS", "Peer signature"))
            ],
        }
    finally:
        subprocess.run(["docker", "compose", "-f", compose, "down"],
                       check=True, capture_output=True, text=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{TRIAL_DATE}-{name}-observation.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8")
    print(f"[observe] {name}: group={record['negotiated_group']} "
          f"sig={record['negotiated_signature_algorithm']}")
    return record


def run_key_reuse_trials(key_reuse_label: str, config_path: str, compose: str, pin_args: list[str]) -> list[dict]:
    """Run 3 trials for a given key reuse condition."""
    base = load_config(config_path)
    results = []

    for r in range(1, 4):
        if key_reuse_label == "fresh":
            experiment_id = f"{TRIAL_DATE}-C1-W1-R{r:02d}"
        else:
            experiment_id = f"{TRIAL_DATE}-C1-W1-R{r:02d}-reused"

        config = replace(base, experiment_id=experiment_id)
        print(f"[trial] {experiment_id} key_reuse={key_reuse_label}", flush=True)
        result = run_experiment(config, "results/raw", compose)
        print(f"  attempts={result['attempts']} outcomes={result['handshake_outcomes']} "
              f"cpu={result['server_cpu_seconds']}s rx={result['bytes_received']} "
              f"tx={result['bytes_sent']} status={result['measurement_status']}",
              flush=True)
        results.append(result)
        # Brief pause to ensure Docker cleanup completes before next trial
        time.sleep(5)

    return results


def main() -> None:
    # C1 pin args for observation
    pin_args = ["-groups", "MLKEM768", "-sigalgs", "ecdsa_secp256r1_sha256"]

    # Record one observation transcript for C1 (same for both key reuse conditions)
    observations_dir = Path("results/raw/observations")
    observe_config("C1", COMPOSE_FILE, pin_args, observations_dir)

    # Run fresh keypair trials (3)
    print("\n=== Phase 6: Fresh Keypair Trials ===", flush=True)
    fresh_results = run_key_reuse_trials("fresh", CONFIG_FRESH, COMPOSE_FILE, pin_args)

    # Run reused keypair trials (3)
    print("\n=== Phase 6: Reused Client Keypair Trials ===", flush=True)
    reused_results = run_key_reuse_trials("reused", CONFIG_REUSED, COMPOSE_FILE, pin_args)

    # Summary
    all_results = fresh_results + reused_results
    valid_count = sum(1 for r in all_results
                      if r["measurement_status"]["server_cpu"] == "measured"
                      and r["measurement_status"]["packets"] == "measured"
                      and r["measurement_status"]["tls_events"] == "observed")

    print(f"\n=== Phase 6 Complete ===")
    print(f"Total trials: {len(all_results)} (3 fresh + 3 reused)")
    print(f"Valid trials: {valid_count}")
    print(f"Results written to results/raw/")


if __name__ == "__main__":
    main()