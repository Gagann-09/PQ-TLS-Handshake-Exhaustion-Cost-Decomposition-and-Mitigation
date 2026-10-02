"""Shared helpers for running commands inside the TLS-server container.

Used by the CPU and packet instrumentation. Kept dependency-free (standard
library only) so it does not introduce a new architecture layer.
"""
from __future__ import annotations

import subprocess


def ensure_container_tool(
    container_name: str,
    tool: str,
    package: str,
    attempts: int = 6,
    delay: float = 3.0,
    timeout: float = 240.0,
) -> bool:
    """Ensure ``tool`` is present in the container, installing ``package``.

    ``apk`` can transiently fail with "Failed to open apk database: temporary
    error" while the container is still settling immediately after startup, so
    the install is retried. Returns True only once the tool is actually
    available.
    """
    script = (
        f"command -v {tool} >/dev/null 2>&1 && exit 0; "
        f"i=0; while [ $i -lt {attempts} ]; do "
        f"apk add --no-cache {package} >/dev/null 2>&1 && "
        f"command -v {tool} >/dev/null 2>&1 && exit 0; "
        f"i=$((i+1)); sleep {delay}; done; exit 1"
    )
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "sh", "-c", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False
