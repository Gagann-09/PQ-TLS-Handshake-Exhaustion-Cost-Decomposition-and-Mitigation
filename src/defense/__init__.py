"""
Defense Module - D0/D1/D2/D3 Defense Application

Provides the apply() function to select the appropriate server configuration
and compose file based on the defense mode.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ServerConfig:
    """Configuration for the TLS server under test."""
    compose_file: str
    target_port: int
    server_process_name: str  # For PID resolution (e.g., "openssl s_server", "d1_server")


def apply(defense: str, config: str) -> ServerConfig:
    """
    Map defense mode and TLS configuration to server deployment.

    Args:
        defense: One of "D0", "D1", "D2", "D3"
        config: TLS configuration "C0", "C1", "C2", "C3", "C4"

    Returns:
        ServerConfig with compose file and target port

    Raises:
        ValueError: If defense or config is unknown
    """
    # Map config to base compose file prefix
    config_map = {
        "C0": "c0",
        "C1": "c1",
        "C2": "c2",
        "C3": "c3",
        "C4": "c4",
    }

    if config not in config_map:
        raise ValueError(f"Unknown TLS configuration: {config}")

    base = config_map[config]

    if defense == "D0":
        # Baseline: standard openssl s_server on 4433
        return ServerConfig(
            compose_file=f"lab/network/docker-compose-{base}.yml",
            target_port=4433,
            server_process_name="openssl s_server"
        )

    elif defense == "D1":
        # Stateless cookie: OpenSSL s_server -stateless on 4433 (forces HRR via key-share mismatch)
        # Per D7-010: custom SSL_stateless() C server ABANDONED; use CLI path
        return ServerConfig(
            compose_file=f"lab/network/docker-compose-{base}-d1.yml",
            target_port=4433,
            server_process_name="openssl s_server"
        )

    elif defense == "D2":
        # Source admission: proxy on 4433 -> s_server on 4434
        return ServerConfig(
            compose_file=f"lab/network/docker-compose-{base}-d2.yml",
            target_port=4433,  # Proxy port
            server_process_name="openssl s_server"
        )

    elif defense == "D3":
        # Combined: proxy on 4433 -> D1 server (openssl s_server -stateless) on 4434
        # Per D7-010: custom SSL_stateless() C server ABANDONED; use CLI path
        return ServerConfig(
            compose_file=f"lab/network/docker-compose-{base}-d3.yml",
            target_port=4433,  # Proxy port
            server_process_name="openssl s_server"
        )

    else:
        raise ValueError(f"Unknown defense mode: {defense}")