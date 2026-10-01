"""Configuration loading and validation for the experiment controller.

See design.md §1 for the config schema.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from .safety import SafetyError, validate_config


@dataclass(frozen=True)
class ExperimentConfig:
    experiment_id: str
    configuration: str
    defense: str
    workload_mode: str
    key_reuse: str
    max_attempts: int
    max_duration_seconds: int
    max_concurrency: int
    legitimate_rate_per_sec: float
    target_host: str
    target_port: int
    trial_repeats: int
    seed: int


def load_config(path: str | Path) -> ExperimentConfig:
    """Load and validate an experiment config from YAML.

    Raises SafetyError if the config violates safety limits.
    Raises FileNotFoundError if the config file does not exist.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    workload = raw["workload"]
    target = raw["target"]
    trial = raw["trial"]

    config = ExperimentConfig(
        experiment_id=raw["experiment_id"],
        configuration=raw["server"]["configuration"],
        defense=raw["server"]["defense"],
        workload_mode=workload["mode"],
        key_reuse=workload["key_reuse"],
        max_attempts=workload["max_attempts"],
        max_duration_seconds=workload["max_duration_seconds"],
        max_concurrency=workload["max_concurrency"],
        legitimate_rate_per_sec=raw["legitimate_client"]["rate_per_sec"],
        target_host=target["host"],
        target_port=target["port"],
        trial_repeats=trial["repeats"],
        seed=trial["seed"],
    )

    # Validate against safety limits — fail closed.
    validate_config(
        host=config.target_host,
        max_attempts=config.max_attempts,
        max_duration_seconds=config.max_duration_seconds,
        max_concurrency=config.max_concurrency,
    )

    return config
