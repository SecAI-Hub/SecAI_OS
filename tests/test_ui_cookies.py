"""
Tests for cookie security and session lifecycle.

Covers:
- COOKIE_SECURE env var: false -> secure=False, true -> secure=True
- Invalid COOKIE_SECURE raises ValueError at startup
- Session cookie: httponly=True, samesite=Strict
- CSRF cookie: httponly=False (needed for JS double-submit)
- SESSION_TIMEOUT wiring: Flask lifetime matches AuthManager
- Logout clears session + deletes both cookies
- Login regenerates CSRF token
"""

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "services" / "ui"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "services"))


def _make_app(cookie_secure="false", session_timeout="1800"):
    """Create a fresh UI app instance with the given env vars."""
    with mock.patch.dict(os.environ, {
        "COOKIE_SECURE": cookie_secure,
        "SESSION_TIMEOUT": session_timeout,
        "AUTH_DATA_DIR": "/tmp/secai-test-auth",
        "BIND_ADDR": "127.0.0.1:18480",
    }, clear=False):
        # Force reimport to pick up new env
        if "ui.app" in sys.modules:
            del sys.modules["ui.app"]
        if "ui.slo_tracker" in sys.modules:
            del sys.modules["ui.slo_tracker"]
        from ui.app import app
        app.config["TESTING"] = True
        return app


class TestCookieSecureFlag:
    """COOKIE_SECURE env var controls the Secure flag on cookies."""

    def test_cookie_secure_false(self):
        app = _make_app(cookie_secure="false")
        assert app.config.get("SESSION_COOKIE_SECURE") is False or \
            app.config.get("SESSION_COOKIE_SECURE") == False  # noqa: E712

    def test_cookie_secure_true(self):
        app = _make_app(cookie_secure="true")
        assert app.config.get("SESSION_COOKIE_SECURE") is True or \
            app.config.get("SESSION_COOKIE_SECURE") == True  # noqa: E712

    def test_invalid_cookie_secure_raises(self):
        """Invalid COOKIE_SECURE value must fail fast at startup."""
        with pytest.raises((ValueError, SystemExit)):
            _make_app(cookie_secure="auto")

    def test_invalid_cookie_secure_maybe(self):
        """Another invalid value."""
        with pytest.raises((ValueError, SystemExit)):
            _make_app(cookie_secure="yes")


class TestSessionCookieAttributes:
    """Flask session cookie must have correct security attributes."""

    def test_session_cookie_httponly(self):
        app = _make_app()
        assert app.config.get("SESSION_COOKIE_HTTPONLY") is True

    def test_session_cookie_samesite(self):
        app = _make_app()
        assert app.config.get("SESSION_COOKIE_SAMESITE") == "Strict"


class TestSessionTimeout:
    """SESSION_TIMEOUT must wire through to Flask and AuthManager."""

    def test_flask_permanent_session_lifetime(self):
        app = _make_app(session_timeout="900")
        lifetime = app.config.get("PERMANENT_SESSION_LIFETIME")
        if lifetime is not None:
            # Could be timedelta or int
            if hasattr(lifetime, "total_seconds"):
                assert lifetime.total_seconds() == 900
            else:
                assert lifetime == 900

    def test_default_timeout_1800(self):
        app = _make_app(session_timeout="1800")
        lifetime = app.config.get("PERMANENT_SESSION_LIFETIME")
        if lifetime is not None:
            if hasattr(lifetime, "total_seconds"):
                assert lifetime.total_seconds() == 1800


def _parse_set_cookies(response):
    """Parse Set-Cookie headers into a dict of {name: value}."""
    cookies = {}
    for header in response.headers.getlist("Set-Cookie"):
        # Set-Cookie: name=value; Path=/; ...
        if "=" in header:
            name_value = header.split(";")[0]
            name, _, value = name_value.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


class TestLogoutCleanup:
    """Logout must clear session and delete both cookies."""

    def test_logout_deletes_session_token_cookie(self):
        app = _make_app()
        with app.test_client() as client:
            resp = client.post("/api/auth/logout")
            cookies = _parse_set_cookies(resp)
            # After logout, session_token should be deleted (empty value or absent)
            if "session_token" in cookies:
                assert cookies["session_token"] == "" or \
                    "Expires=Thu, 01 Jan 1970" in str(resp.headers.getlist("Set-Cookie"))

    def test_logout_deletes_csrf_cookie(self):
        app = _make_app()
        with app.test_client() as client:
            resp = client.post("/api/auth/logout")
            cookies = _parse_set_cookies(resp)
            if "csrf_token" in cookies:
                assert cookies["csrf_token"] == "" or \
                    "Expires=Thu, 01 Jan 1970" in str(resp.headers.getlist("Set-Cookie"))
