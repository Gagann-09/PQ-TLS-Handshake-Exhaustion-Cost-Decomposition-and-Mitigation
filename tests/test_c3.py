"""C3 Hybrid Key Establishment tests — verify C3 configuration and negotiation.

C3 = X25519MLKEM768 + ECDSA-P256
Hybrid key establishment per RFC 10024 (RQ1).
See PRD.md §6.
"""
import pytest

from src.controller.config import load_config
from src.controller.safety import SafetyError, validate_config


class TestC3Config:
    """Test that C3 configuration loads and validates correctly."""

    def test_c3_config_loads(self):
        """C3 config should load without errors."""
        config = load_config("config/c3_experiment.yaml")
        assert config.configuration == "C3"
        assert config.workload_mode == "normal_completion"

    def test_c3_target_is_allowed(self):
        """C3 target should be in the allowlist."""
        config = load_config("config/c3_experiment.yaml")
        # Should not raise
        validate_config(
            host=config.target_host,
            max_attempts=config.max_attempts,
            max_duration_seconds=config.max_duration_seconds,
            max_concurrency=config.max_concurrency,
        )

    def test_c3_hard_limits_enforced(self):
        """C3 must respect hard limits."""
        config = load_config("config/c3_experiment.yaml")
        assert config.max_attempts <= 1000
        assert config.max_duration_seconds <= 30
        assert config.max_concurrency <= 1


class TestC3WorkloadModes:
    """Test that C3 workload modes are supported."""

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


class TestC3Safety:
    """Test that C3 maintains safety boundaries."""

    def test_c3_rejects_external_target(self):
        """C3 must reject external targets."""
        with pytest.raises(SafetyError):
            validate_config(
                host="8.8.8.8",
                max_attempts=100,
                max_duration_seconds=10,
                max_concurrency=1,
            )

    def test_c3_rejects_excessive_attempts(self):
        """C3 must reject attempts above 1000."""
        with pytest.raises(SafetyError):
            validate_config(
                host="tls-server",
                max_attempts=1001,
                max_duration_seconds=10,
                max_concurrency=1,
            )
