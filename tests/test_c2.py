"""C2 PQ Authentication tests — verify C2 configuration and negotiation.

C2 = X25519 + ML-DSA-65
Isolates PQ authentication cost (RQ1).
See PRD.md §6.
"""
import pytest

from src.controller.config import load_config
from src.controller.safety import SafetyError, validate_config


class TestC2Config:
    """Test that C2 configuration loads and validates correctly."""

    def test_c2_config_loads(self):
        """C2 config should load without errors."""
        config = load_config("config/c2_experiment.yaml")
        assert config.configuration == "C2"
        assert config.workload_mode == "normal_completion"

    def test_c2_target_is_allowed(self):
        """C2 target should be in the allowlist."""
        config = load_config("config/c2_experiment.yaml")
        # Should not raise
        validate_config(
            host=config.target_host,
            max_attempts=config.max_attempts,
            max_duration_seconds=config.max_duration_seconds,
            max_concurrency=config.max_concurrency,
        )

    def test_c2_hard_limits_enforced(self):
        """C2 must respect hard limits."""
        config = load_config("config/c2_experiment.yaml")
        assert config.max_attempts <= 1000
        assert config.max_duration_seconds <= 30
        assert config.max_concurrency <= 1


class TestC2WorkloadModes:
    """Test that C2 workload modes are supported."""

    def test_w0_mode_supported(self):
        """W0 (normal completion) should be a valid mode."""
        from src.workload.client import generate_attempts
        list(generate_attempts(host="tls-server", port=4433, mode="normal_completion",
                               max_attempts=1, max_duration_seconds=1, groups=[], sigalgs=[]))

    def test_w1_mode_supported(self):
        """W1 (controlled abort) should be a valid mode."""
        from src.workload.client import generate_attempts
        list(generate_attempts(host="tls-server", port=4433, mode="controlled_abort",
                               max_attempts=1, max_duration_seconds=1, groups=[], sigalgs=[]))

    def test_invalid_mode_rejected(self):
        """Invalid modes should be rejected."""
        from src.workload.client import generate_attempts
        with pytest.raises(SafetyError):
            list(generate_attempts(
                host="tls-server",
                port=4433,
                mode="invalid_mode",
                max_attempts=1,
                max_duration_seconds=1,
                groups=[],
                sigalgs=[],
            ))


class TestC2Safety:
    """Test that C2 maintains safety boundaries."""

    def test_c2_rejects_external_target(self):
        """C2 must reject external targets."""
        with pytest.raises(SafetyError):
            validate_config(
                host="8.8.8.8",
                max_attempts=100,
                max_duration_seconds=10,
                max_concurrency=1,
            )

    def test_c2_rejects_excessive_attempts(self):
        """C2 must reject attempts above 1000."""
        with pytest.raises(SafetyError):
            validate_config(
                host="tls-server",
                max_attempts=1001,
                max_duration_seconds=10,
                max_concurrency=1,
            )
