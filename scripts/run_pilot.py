"""Run the Phase 5 pilot: one short C0 W0 run and one short C0 W1 run."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.controller.config import load_config
from src.controller.experiment import run_experiment


def main():
    for name, cfg_path in [("C0 W0", "config/pilot_c0_w0.yaml"),
                           ("C0 W1", "config/pilot_c0_w1.yaml")]:
        config = load_config(cfg_path)
        print(f"=== Pilot {name} ===")
        print(f"limits: {config.max_attempts} attempts / {config.max_duration_seconds}s / conc={config.max_concurrency}")
        result = run_experiment(config, "results/raw", "lab/network/docker-compose-c0.yml")
        print(f"attempts={result['attempts']} duration={result['duration_seconds']}s")
        print(f"outcomes={result['handshake_outcomes']}")
        print(f"server_cpu_seconds={result['server_cpu_seconds']} per_attempt={result['server_cpu_seconds_per_attempt']}")
        print(f"bytes_received={result['bytes_received']} bytes_sent={result['bytes_sent']}")
        print(f"rx/attempt={result['bytes_received_per_attempt']} tx/attempt={result['bytes_sent_per_attempt']}")
        print(f"measurement_status={result['measurement_status']}")
        print(f"measurement_errors={result['measurement_errors']}")
        print(f"tls_events[0]={result['tls_events'][0] if result['tls_events'] else None}")
        print(f"legitimate={result['legitimate']}")
        print()


if __name__ == "__main__":
    main()
