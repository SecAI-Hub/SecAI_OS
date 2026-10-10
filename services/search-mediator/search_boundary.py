"""Admission, deadlines and durable intent for every search egress route."""

import secrets
import threading
import time

import requests
from flask import g, has_request_context, jsonify, request


class AuditUnavailable(RuntimeError):
    pass


class EgressDenied(RuntimeError):
    def __init__(self, message, status=403):
        super().__init__(message)
        self.status = status


class SearchEgress:
    def __init__(self, app, *, authenticate, authorize, audit, transport, origin,
                 total_seconds=20.0, concurrency=1):
        self.authenticate = authenticate
        self.authorize = authorize
        self.append_audit = audit
        self.transport = transport
        self.origin = origin
        self.total_seconds = total_seconds
        self.slots = threading.BoundedSemaphore(concurrency)
        app.before_request(self.begin)
        app.teardown_request(self.end)
        app.errorhandler(AuditUnavailable)(self.audit_error)
        app.errorhandler(EgressDenied)(self.policy_error)
        app.errorhandler(requests.Timeout)(self.timeout_error)

    def begin(self):
        if request.path not in {"/v1/search", "/v1/search/test", "/health"}:
            return None
        authenticated, error = self.authenticate()
        if not authenticated:
            return error
        if not self.slots.acquire(blocking=False):
            response = jsonify({"error": "search is busy; retry later", "code": "search_busy"})
            response.headers["Retry-After"] = "1"
            return response, 429
        g.search_slot = True
        g.search_deadline = time.monotonic() + self.total_seconds
        g.search_request_id = secrets.token_hex(16)
        g.search_egress_attempts = 0

    def end(self, _error):
        if getattr(g, "search_slot", False):
            g.search_slot = False
            self.slots.release()

    def metadata(self):
        if not has_request_context():
            return {}
        return {"request_id": getattr(g, "search_request_id", None),
                "egress_attempts": getattr(g, "search_egress_attempts", 0)}

    def audit(self, event, payload):
        try:
            self.append_audit(event, {**payload, **self.metadata()})
        except Exception:
            raise AuditUnavailable("search audit unavailable") from None

    def remaining(self):
        if not has_request_context() or not getattr(g, "search_slot", False):
            raise EgressDenied("egress requires an admitted authenticated request")
        remaining = g.search_deadline - time.monotonic()
        if remaining <= 0:
            raise requests.Timeout("search deadline exceeded")
        return remaining

    def sleep(self, duration):
        duration = max(0.0, duration)
        if has_request_context() and getattr(g, "search_slot", False):
            if duration >= self.remaining():
                raise requests.Timeout("search deadline exceeded")
        time.sleep(duration)

    def get(self, endpoint, *, params=None, timeout, expect_json, kind="search"):
        self.remaining()
        # Recheck policy immediately before intent/egress, including connectivity
        # tests, readiness, cover traffic and decoys. No direct transport fallback.
        self.authorize(endpoint, params or {})
        self.audit("search_egress_intent", {"kind": kind, "endpoint": endpoint,
                                           "ordinal": g.search_egress_attempts + 1})
        budget = min(timeout, self.remaining())
        g.search_egress_attempts += 1
        outcome = "failed"
        try:
            result = self.transport(self.origin(), endpoint, params=params,
                                    timeout=budget, expect_json=expect_json)
            outcome = "succeeded"
            return result
        finally:
            # An outcome append failure is reported as potentially sent, never
            # as safe to retry. It cannot undo an already attempted request.
            self.audit("search_egress_outcome", {"kind": kind, "endpoint": endpoint,
                                                "outcome": outcome})

    def audit_error(self, _error):
        attempted = getattr(g, "search_egress_attempts", 0)
        return jsonify({"error": "search audit unavailable", "code": "audit_unavailable",
                        "egress": "may_have_been_sent" if attempted else "not_sent",
                        "retry_safe": not bool(attempted), **self.metadata()}), 503

    def policy_error(self, error):
        return jsonify({"error": str(error), "code": "egress_denied", **self.metadata()}), error.status

    def timeout_error(self, _error):
        return jsonify({"error": "search deadline exceeded", "code": "search_timeout",
                        **self.metadata()}), 504
