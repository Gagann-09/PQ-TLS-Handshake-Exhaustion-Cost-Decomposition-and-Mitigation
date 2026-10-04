"""Load raw Phase 5 result records and tag trial validity.

Pure functions over already-collected data; no network or process calls.
"""
from __future__ import annotations

import glob
import json
from pathlib import Path

CAMPAIGN_DATE = "2026-10-02"


def load_raw(path_glob: str) -> list[dict]:
    """Load raw result JSON files matching the glob, campaign trials only."""
    records = []
    for path in sorted(glob.glob(path_glob)):
        name = Path(path).name
        if not name.startswith(CAMPAIGN_DATE + "-C"):
            continue
        if name.endswith("-observation.json"):
            continue
        with open(path, "r", encoding="utf-8") as f:
            records.append(json.load(f))
    return records


def trial_valid(record: dict) -> tuple[bool, str]:
    """A trial is valid only if all three measurement streams are valid,
    counts are consistent, and the workload behaved as intended."""
    outcomes = record.get("handshake_outcomes", {})
    total = sum(outcomes.values())
    if record.get("attempts", 0) <= 0 or total != record["attempts"]:
        return False, "attempts/outcome-count mismatch"
    status = record.get("measurement_status", {})
    if status.get("server_cpu") != "measured":
        return False, "server_cpu not measured"
    if status.get("packets") != "measured":
        return False, "packets not measured"
    if status.get("tls_events") != "observed":
        return False, "tls_events not observed"
    if record.get("server_cpu_seconds_per_attempt") is None:
        return False, "cpu/attempt null"
    if record.get("bytes_received") is None or record.get("bytes_sent") is None:
        return False, "bytes null"
    mode = record.get("workload_mode")
    if mode == "normal_completion" and outcomes.get("completed", 0) == 0:
        return False, "W0 with zero completed"
    if mode == "controlled_abort" and outcomes.get("completed", 0) != 0:
        return False, "W1 with completed handshakes"
    return True, "valid"
