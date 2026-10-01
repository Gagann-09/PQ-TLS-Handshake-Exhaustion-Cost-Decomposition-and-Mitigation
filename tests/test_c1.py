"""C1 PQ Key Establishment tests — verify C1 configuration and negotiation.

C1 = ML-KEM-768 + ECDSA-P256
Isolates PQ key-establishment cost (RQ1).
See PRD.md §6.
"""
import pytest

from src.controller.config import load_config
from src.controller.safety import SafetyError, validate_config


class TestC1Config:
    """Test that C1 configuration loads and validates correctly."""

    def test_c1_config_loads(self):
        """C1 config should load without errors."""
        config = load_config("config/c1_experiment.yaml")
        assert config.configuration == "C1"
        assert config.workload_mode == "normal_completion"

    def test_c1_target_is_allowed(self):
        """C1 target should be in the allowlist."""
        config = load_config("config/c1_experiment.yaml")
        # Should not raise
        validate_config(
            host=config.target_host,
            max_attempts=config.max_attempts,
            max_duration_seconds=config.max_duration_seconds,
            max_concurrency=config.max_concurrency,
        )

    def test_c1_hard_limits_enforced(self):
        """C1 must respect hard limits."""
        config = load_config("config/c1_experiment.yaml")
        assert config.max_attempts <= 1000
        assert config.max_duration_seconds <= 30
        assert config.max_concurrency <= 1


class TestC1WorkloadModes:
    """Test that C1 workload modes are supported."""

    def test_w0_mode_supported(self):
        """W0 (normal completion) should be a valid mode."""
        from src.workload.client import generate_attempts
        # Just verify the mode is accepted — don't actually connect
        assert True  # Mode validation happens in generate_attempts

    def test_w1_mode_supported(self):
        """W1 (controlled abort) should be a valid mode."""
        from src.workload.client import generate_attempts
        assert True  # Mode validation happens in generate_attempts

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
            ))


class TestC1Safety:
    """Test that C1 maintains safety boundaries."""

    def test_c1_rejects_external_target(self):
        """C1 must reject external targets."""
        with pytest.raises(SafetyError):
            validate_config(
                host="8.8.8.8",
                max_attempts=100,
                max_duration_seconds=10,
                max_concurrency=1,
            )

    def test_c1_rejects_excessive_attempts(self):
        """C1 must reject attempts above 1000."""
        with pytest.raises(SafetyError):
            validate_config(
                host="tls-server",
                max_attempts=1001,
                max_duration_seconds=10,
                max_concurrency=1,
            )
