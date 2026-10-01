"""Run C0 baseline trials.

Executes ≥3 C0 (X25519 + ECDSA-P256) baseline trials and writes result records.
"""
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.controller.config import load_config
from src.controller.experiment import run_experiment


def main():
    base_config = load_config("config/c0_experiment.yaml")
    print(f"Running C0 baseline trials")
    print(f"Configuration: {base_config.configuration} ({base_config.workload_mode})")
    print(f"Target: {base_config.target_host}:{base_config.target_port}")
    print(f"Limits: {base_config.max_attempts} attempts, {base_config.max_duration_seconds}s, concurrency {base_config.max_concurrency}")
    print()

    for trial in range(1, 4):
        print(f"--- Trial {trial}/3 ---")
        config = replace(base_config, experiment_id=f"2026-10-01-C0-W0-R{trial:02d}")
        result = run_experiment(config, "results/raw", "lab/network/docker-compose-c0.yml")
        print(f"  Attempts: {result['attempts']}")
        print(f"  Duration: {result['duration_seconds']}s")
        print(f"  Server CPU: {result['server_cpu_seconds']}s")
        print(f"  Handshakes: {result['handshake_outcomes']}")
        print(f"  Legitimate: {result['legitimate']['successes']}/{result['legitimate']['attempts']} succeeded")
        print()


if __name__ == "__main__":
    main()
