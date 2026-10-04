#!/usr/bin/env python3
"""
Phase 7 Full Campaign Script

Runs the complete C1 × W1 × {D0, D1, D2, D3} matrix with ≥3 trials each.

Matrix:
- C1 × W1 × D0 (baseline)
- C1 × W1 × D1 (stateless cookie)
- C1 × W1 × D2 (source admission)
- C1 × W1 × D3 (combined)

Each condition: 3 trials, 1000 attempts, 30 seconds, concurrency 1
"""

import sys
import json
from dataclasses import replace
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.controller.config import load_config
from src.controller import experiment


def run_phase7_campaign():
    """Run the full Phase 7 campaign."""
    print("=" * 60)
    print("PHASE 7 FULL CAMPAIGN")
    print("C1 × W1 × {D0, D1, D2, D3} × 3 trials")
    print("=" * 60)

    # Defense configurations
    defenses = {
        "D0": ("config/c1_w1_d0.yaml", "lab/network/docker-compose-c1.yml"),
        "D1": ("config/c1_w1_d1.yaml", "lab/network/docker-compose-c1-d1.yml"),
        "D2": ("config/c1_w1_d2.yaml", "lab/network/docker-compose-c1-d2.yml"),
        "D3": ("config/c1_w1_d3.yaml", "lab/network/docker-compose-c1-d3.yml"),
    }

    # Note: D0 config needs to be created (it's the baseline)
    results_dir = Path("results/raw")
    results_dir.mkdir(parents=True, exist_ok=True)

    all_results = []

    for defense, (config_path, compose_file) in defenses.items():
        print(f"\n{'='*60}")
        print(f"DEFENSE: {defense}")
        print(f"{'='*60}")

        # Load base config and create campaign-bound config via replace
        base_config = load_config(config_path)
        campaign_config = replace(
            base_config,
            max_attempts=1000,
            max_duration_seconds=30,
            max_concurrency=1,
        )

        for trial in range(1, 4):  # 3 trials
            trial_id = f"{trial:02d}"
            trial_config = replace(
                campaign_config,
                experiment_id=f"2026-10-03-C1-W1-R{trial_id}-{defense}",
            )
            
            print(f"\n  Trial {trial}/3: {trial_config.experiment_id}")
            
            try:
                result = experiment.run_experiment(
                    config=trial_config,
                    results_dir=results_dir,
                    compose_file=compose_file,
                )
                all_results.append(result)
                
                # Quick summary
                cpu = result.get("server_cpu_seconds_per_attempt")
                cpu_str = f"{cpu:.6f}" if cpu else "N/A"
                print(f"    CPU/attempt: {cpu_str}")
                print(f"    Attempts: {result['attempts']}")
                print(f"    Legitimate success: {result['legitimate']['successes']}/{result['legitimate']['attempts']}")
                
            except Exception as e:
                print(f"    FAILED: {e}")
                all_results.append({
                    "experiment_id": trial_config.experiment_id,
                    "error": str(e),
                    "defense": defense,
                    "trial": trial,
                })

    # Summary
    print("\n" + "=" * 60)
    print("CAMPAIGN SUMMARY")
    print("=" * 60)
    
    for defense in defenses:
        defense_results = [r for r in all_results if r.get("defense") == defense]
        if defense_results:
            cpus = [r.get("server_cpu_seconds_per_attempt") for r in defense_results if r.get("server_cpu_seconds_per_attempt")]
            if cpus:
                avg_cpu = sum(cpus) / len(cpus)
                print(f"  {defense}: {len(defense_results)} trials, avg CPU/attempt = {avg_cpu:.6f}")
            else:
                print(f"  {defense}: {len(defense_results)} trials, CPU unavailable")

    # Save summary
    summary_path = results_dir.parent / "processed" / "phase7_campaign_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nSummary saved to {summary_path}")

    return 0


if __name__ == "__main__":
    sys.exit(run_phase7_campaign())