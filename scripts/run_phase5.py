"""Phase 5 full campaign runner.

Matrix: {C0,C1,C2,C3,C4} x {W0,W1} x 3 trials, D0, fresh keypair,
bounds max 1000 attempts / 30 s / concurrency 1, target 127.0.0.1:4433.
Also records one independent openssl s_client observation transcript per
configuration (parsed via parse_openssl_handshake_observation).
"""
import json
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.controller.config import load_config
from src.controller.experiment import run_experiment
from src.instrumentation.tls_log import parse_openssl_handshake_observation

CONFIGS = {
    "C0": ("config/c0_experiment.yaml", "lab/network/docker-compose-c0.yml",
           ["-groups", "X25519", "-sigalgs", "ecdsa_secp256r1_sha256"]),
    "C1": ("config/c1_experiment.yaml", "lab/network/docker-compose-c1.yml",
           ["-groups", "MLKEM768", "-sigalgs", "ecdsa_secp256r1_sha256"]),
    "C2": ("config/c2_experiment.yaml", "lab/network/docker-compose-c2.yml",
           ["-groups", "X25519", "-sigalgs", "mldsa65"]),
    "C3": ("config/c3_experiment.yaml", "lab/network/docker-compose-c3.yml",
           ["-groups", "X25519MLKEM768", "-sigalgs", "ecdsa_secp256r1_sha256"]),
    "C4": ("config/c4_experiment.yaml", "lab/network/docker-compose-c4.yml",
           ["-groups", "MLKEM768", "-sigalgs", "mldsa65"]),
}

MODES = {"W0": "normal_completion", "W1": "controlled_abort"}
TRIAL_DATE = "2026-10-02"


def observe_config(name: str, compose: str, pin_args: list[str], out_dir: Path) -> dict:
    """One genuine openssl s_client transcript per configuration."""
    subprocess.run(["docker", "compose", "-f", compose, "up", "-d"],
                   check=True, capture_output=True, text=True)
    try:
        time.sleep(10)
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


def main() -> None:
    observations_dir = Path("results/raw/observations")
    for cfg_name, (cfg_path, compose, pin_args) in CONFIGS.items():
        observe_config(cfg_name, compose, pin_args, observations_dir)
        base = load_config(cfg_path)
        for w_name, mode in MODES.items():
            for r in range(1, 4):
                experiment_id = f"{TRIAL_DATE}-{cfg_name}-{w_name}-R{r:02d}"
                config = replace(base, experiment_id=experiment_id, workload_mode=mode)
                print(f"[trial] {experiment_id} mode={mode}", flush=True)
                result = run_experiment(config, "results/raw", compose)
                print(f"  attempts={result['attempts']} outcomes={result['handshake_outcomes']} "
                      f"cpu={result['server_cpu_seconds']}s rx={result['bytes_received']} "
                      f"tx={result['bytes_sent']} status={result['measurement_status']}",
                      flush=True)


if __name__ == "__main__":
    main()
