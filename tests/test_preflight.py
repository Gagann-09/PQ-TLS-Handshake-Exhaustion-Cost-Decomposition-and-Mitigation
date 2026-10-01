"""Preflight test — mandatory safety check before any real experiment run.

See rules.md §10. This test MUST pass before any experiment proceeds.
"""
import pytest

from src.controller.safety import SafetyError, validate_target


def test_preflight_8_8_8_8_rejected():
    """8.8.8.8 must be rejected — it is outside the allowlist."""
    with pytest.raises(SafetyError):
        validate_target("8.8.8.8")


def test_preflight_tls_server_accepted():
    """tls-server must be accepted — it is the lab service name."""
    validate_target("tls-server")  # Should not raise


def test_preflight_localhost_accepted():
    """localhost must be accepted."""
    validate_target("localhost")  # Should not raise


def test_preflight_127_0_0_1_accepted():
    """127.0.0.1 must be accepted."""
    validate_target("127.0.0.1")  # Should not raise


if __name__ == "__main__":
    # Run preflight directly — exit non-zero on failure.
    print("Running preflight safety checks...")
    try:
        test_preflight_8_8_8_8_rejected()
        print("  [PASS] 8.8.8.8 is rejected")
    except AssertionError:
        print("  [FAIL] 8.8.8.8 was not rejected")
        exit(1)

    try:
        test_preflight_tls_server_accepted()
        print("  [PASS] tls-server is accepted")
    except Exception:
        print("  [FAIL] tls-server was not accepted")
        exit(1)

    try:
        test_preflight_localhost_accepted()
        print("  [PASS] localhost is accepted")
    except Exception:
        print("  [FAIL] localhost was not accepted")
        exit(1)

    try:
        test_preflight_127_0_0_1_accepted()
        print("  [PASS] 127.0.0.1 is accepted")
    except Exception:
        print("  [FAIL] 127.0.0.1 was not accepted")
        exit(1)

    print("")
    print("All preflight checks PASSED.")
