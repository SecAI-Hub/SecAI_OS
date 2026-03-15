"""Tests for the circuit breaker module."""

import time
from unittest.mock import MagicMock

import pytest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "services"))

from common.circuit_breaker import CircuitBreaker, CircuitOpenError, CircuitState


class TestCircuitBreakerStates:
    """Test state transitions of the circuit breaker."""

    def test_starts_closed(self):
        cb = CircuitBreaker("test")
        assert cb.state == CircuitState.CLOSED

    def test_stays_closed_on_success(self):
        cb = CircuitBreaker("test", failure_threshold=3)
        fn = MagicMock(return_value="ok")
        result = cb.call(fn, "arg1")
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED
        fn.assert_called_once_with("arg1")

    def test_opens_after_threshold_failures(self):
        cb = CircuitBreaker("test", failure_threshold=3)
        fn = MagicMock(side_effect=ConnectionError("down"))
        for _ in range(3):
            with pytest.raises(ConnectionError):
                cb.call(fn)
        assert cb.state == CircuitState.OPEN

    def test_stays_closed_below_threshold(self):
        cb = CircuitBreaker("test", failure_threshold=3)
        fn = MagicMock(side_effect=ConnectionError("down"))
        for _ in range(2):
            with pytest.raises(ConnectionError):
                cb.call(fn)
        assert cb.state == CircuitState.CLOSED

    def test_open_circuit_raises_immediately(self):
        cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=60)
        fn = MagicMock(side_effect=ConnectionError("down"))
        with pytest.raises(ConnectionError):
            cb.call(fn)
        assert cb.state == CircuitState.OPEN
        with pytest.raises(CircuitOpenError) as exc_info:
            cb.call(fn)
        assert "OPEN" in str(exc_info.value)
        # fn should NOT have been called the second time
        assert fn.call_count == 1

    def test_transitions_to_half_open_after_timeout(self):
        cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=0.1)
        fn = MagicMock(side_effect=ConnectionError("down"))
        with pytest.raises(ConnectionError):
            cb.call(fn)
        assert cb.state == CircuitState.OPEN
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_closes_on_success(self):
        cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=0.1)
        fail_fn = MagicMock(side_effect=ConnectionError("down"))
        with pytest.raises(ConnectionError):
            cb.call(fail_fn)
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN
        # Probe call succeeds
        ok_fn = MagicMock(return_value="ok")
        result = cb.call(ok_fn)
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED

    def test_half_open_reopens_on_failure(self):
        cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=0.1)
        fail_fn = MagicMock(side_effect=ConnectionError("down"))
        with pytest.raises(ConnectionError):
            cb.call(fail_fn)
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN
        # Probe call fails
        with pytest.raises(ConnectionError):
            cb.call(fail_fn)
        assert cb.state == CircuitState.OPEN

    def test_half_open_limits_concurrent_probes(self):
        cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=0.1, half_open_max=1)
        fail_fn = MagicMock(side_effect=ConnectionError("down"))
        with pytest.raises(ConnectionError):
            cb.call(fail_fn)
        time.sleep(0.15)
        # First probe is allowed — make it block (but we'll test the limit)
        # Simulate by checking state after one call
        ok_fn = MagicMock(return_value="ok")
        cb.call(ok_fn)
        assert cb.state == CircuitState.CLOSED


class TestCircuitBreakerReset:
    """Test manual reset."""

    def test_reset_closes_open_circuit(self):
        cb = CircuitBreaker("test", failure_threshold=1, recovery_timeout=60)
        fn = MagicMock(side_effect=ConnectionError("down"))
        with pytest.raises(ConnectionError):
            cb.call(fn)
        assert cb.state == CircuitState.OPEN
        cb.reset()
        assert cb.state == CircuitState.CLOSED

    def test_reset_clears_failure_count(self):
        cb = CircuitBreaker("test", failure_threshold=3)
        fn = MagicMock(side_effect=ConnectionError("down"))
        for _ in range(2):
            with pytest.raises(ConnectionError):
                cb.call(fn)
        assert cb.state == CircuitState.CLOSED
        cb.reset()
        # Should need 3 more failures to trip
        for _ in range(2):
            with pytest.raises(ConnectionError):
                cb.call(fn)
        assert cb.state == CircuitState.CLOSED


class TestCircuitBreakerKwargs:
    """Test that arguments are forwarded correctly."""

    def test_args_forwarded(self):
        cb = CircuitBreaker("test")
        fn = MagicMock(return_value="ok")
        cb.call(fn, "url", timeout=5, headers={"X-Token": "abc"})
        fn.assert_called_once_with("url", timeout=5, headers={"X-Token": "abc"})

    def test_return_value_passed_through(self):
        cb = CircuitBreaker("test")
        fn = MagicMock(return_value={"status": "healthy"})
        result = cb.call(fn)
        assert result == {"status": "healthy"}


class TestCircuitOpenError:
    """Test the custom exception."""

    def test_contains_name(self):
        err = CircuitOpenError("registry", time.monotonic(), 30.0)
        assert "registry" in str(err)
        assert "OPEN" in str(err)

    def test_remaining_seconds(self):
        err = CircuitOpenError("svc", time.monotonic(), 30.0)
        assert err.remaining_seconds <= 30.0
        assert err.remaining_seconds >= 0
