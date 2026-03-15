"""
Circuit breaker for inter-service HTTP calls.

Prevents cascading failures when a downstream service is unavailable by
short-circuiting calls after repeated failures.

States:
    CLOSED   — Normal operation. Calls pass through.
    OPEN     — Circuit tripped. Calls fail immediately without hitting the
               downstream service.
    HALF_OPEN — After recovery_timeout, one probe call is allowed through.
                If it succeeds, circuit closes. If it fails, circuit reopens.

Usage:
    breaker = CircuitBreaker("registry", failure_threshold=3, recovery_timeout=30)

    try:
        resp = breaker.call(requests.get, url, timeout=5)
    except CircuitOpenError:
        # Downstream is known to be unavailable
        ...
    except requests.RequestException:
        # Normal request error (already counted by the breaker)
        ...
"""

from __future__ import annotations

import logging
import threading
import time
from enum import Enum
from typing import Any, Callable

log = logging.getLogger(__name__)


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when a call is attempted on an open circuit."""

    def __init__(self, name: str, open_since: float, recovery_timeout: float):
        remaining = max(0, recovery_timeout - (time.monotonic() - open_since))
        super().__init__(
            f"circuit '{name}' is OPEN — retry in {remaining:.0f}s"
        )
        self.name = name
        self.remaining_seconds = remaining


class CircuitBreaker:
    """Thread-safe circuit breaker for HTTP service calls."""

    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: float = 30.0,
        half_open_max: int = 1,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max = half_open_max

        self._lock = threading.Lock()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = 0.0
        self._half_open_calls = 0

    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._get_state()

    def _get_state(self) -> CircuitState:
        """Return current state, auto-transitioning OPEN → HALF_OPEN if timeout elapsed."""
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
                log.info("circuit '%s': OPEN → HALF_OPEN (recovery timeout elapsed)", self.name)
        return self._state

    def call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute *fn* through the circuit breaker.

        Args:
            fn: Callable (e.g. ``requests.get``).
            *args, **kwargs: Forwarded to *fn*.

        Returns:
            Whatever *fn* returns on success.

        Raises:
            CircuitOpenError: If the circuit is open.
            Exception: Any exception from *fn* (also recorded as a failure).
        """
        with self._lock:
            state = self._get_state()

            if state == CircuitState.OPEN:
                raise CircuitOpenError(self.name, self._last_failure_time, self.recovery_timeout)

            if state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max:
                    raise CircuitOpenError(self.name, self._last_failure_time, self.recovery_timeout)
                self._half_open_calls += 1

        # Execute outside the lock
        try:
            result = fn(*args, **kwargs)
        except Exception:
            self._record_failure()
            raise

        self._record_success()
        return result

    def _record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            self._success_count = 0

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                log.warning("circuit '%s': HALF_OPEN → OPEN (probe failed)", self.name)
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                log.warning(
                    "circuit '%s': CLOSED → OPEN (threshold %d reached)",
                    self.name, self.failure_threshold,
                )

    def _record_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._success_count = 0
                self._half_open_calls = 0
                log.info("circuit '%s': HALF_OPEN → CLOSED (probe succeeded)", self.name)
            elif self._state == CircuitState.CLOSED:
                self._success_count += 1
                # Reset failure count on consecutive successes
                if self._success_count > self.failure_threshold:
                    self._failure_count = 0

    def reset(self) -> None:
        """Manually reset the circuit to CLOSED state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._half_open_calls = 0
            log.info("circuit '%s': manually reset to CLOSED", self.name)
