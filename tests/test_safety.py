"""Safety validator tests — verify the safety boundary enforcement.

See rules.md §2 and §10.
"""
import pytest

from src.controller.safety import (
    SafetyError,
    validate_attempts,
    validate_concurrency,
    validate_config,
    validate_duration,
    validate_target,
)


class TestTargetValidation:
    """Test that only allowed targets are accepted."""

    def test_localhost_accepted(self):
        validate_target("localhost")  # Should not raise

    def test_127_0_0_1_accepted(self):
        validate_target("127.0.0.1")  # Should not raise

    def test_tls_server_accepted(self):
        validate_target("tls-server")  # Should not raise

    def test_8_8_8_8_rejected(self):
        with pytest.raises(SafetyError):
            validate_target("8.8.8.8")

    def test_unknown_host_rejected(self):
        with pytest.raises(SafetyError):
            validate_target("example.com")

    def test_empty_host_rejected(self):
        with pytest.raises(SafetyError):
            validate_target("")


class TestAttemptValidation:
    """Test that attempts are bounded."""

    def test_valid_attempts_accepted(self):
        validate_attempts(100)  # Should not raise

    def test_max_attempts_accepted(self):
        validate_attempts(1000)  # Should not raise

    def test_above_max_attempts_rejected(self):
        with pytest.raises(SafetyError):
            validate_attempts(1001)

    def test_zero_attempts_rejected(self):
        with pytest.raises(SafetyError):
            validate_attempts(0)


class TestDurationValidation:
    """Test that duration is bounded."""

    def test_valid_duration_accepted(self):
        validate_duration(10)  # Should not raise

    def test_max_duration_accepted(self):
        validate_duration(30)  # Should not raise

    def test_above_max_duration_rejected(self):
        with pytest.raises(SafetyError):
            validate_duration(31)

    def test_zero_duration_rejected(self):
        with pytest.raises(SafetyError):
            validate_duration(0)


class TestConcurrencyValidation:
    """Test that concurrency is bounded."""

    def test_valid_concurrency_accepted(self):
        validate_concurrency(1)  # Should not raise

    def test_above_max_concurrency_rejected(self):
        with pytest.raises(SafetyError):
            validate_concurrency(2)


class TestFullConfigValidation:
    """Test the combined config validation."""

    def test_valid_config_accepted(self):
        validate_config(
            host="tls-server",
            max_attempts=100,
            max_duration_seconds=10,
            max_concurrency=1,
        )  # Should not raise

    def test_invalid_host_rejected(self):
        with pytest.raises(SafetyError):
            validate_config(
                host="8.8.8.8",
                max_attempts=100,
                max_duration_seconds=10,
                max_concurrency=1,
            )

    def test_invalid_attempts_rejected(self):
        with pytest.raises(SafetyError):
            validate_config(
                host="tls-server",
                max_attempts=1001,
                max_duration_seconds=10,
                max_concurrency=1,
            )
