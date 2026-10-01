"""CPU and process instrumentation.

See architecture.md §3.5. Uses psutil for CPU sampling.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class CpuSamples:
    """CPU samples collected during a run."""
    timestamps: list[float] = field(default_factory=list)
    cpu_percent: list[float] = field(default_factory=list)


def sample_cpu(pid: int, interval: float, duration: float) -> CpuSamples:
    """Sample CPU usage for the given process at the specified interval.

    Returns CpuSamples. Uses psutil if available, otherwise returns empty.
    """
    samples = CpuSamples()
    try:
        import psutil
    except ImportError:
        return samples

    try:
        proc = psutil.Process(pid)
    except Exception:
        return samples

    start = time.monotonic()
    while time.monotonic() - start < duration:
        try:
            samples.timestamps.append(time.monotonic() - start)
            samples.cpu_percent.append(proc.cpu_percent(interval=None))
        except Exception:
            break
        time.sleep(interval)

    return samples
