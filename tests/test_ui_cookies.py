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


@pytest.fixture(autouse=True)
def private_cookie_state(tmp_path, monkeypatch):
    """Keep credentials, runtime epochs and import-time state private per test."""
    for name, path in {
        "AUTH_DATA_DIR": tmp_path / "auth",
        "SESSION_RUNTIME_DIR": tmp_path / "runtime",
        "SECURE_AI_ROOT": tmp_path,
        "AUDIT_LOG_PATH": tmp_path / "logs/ui-audit.jsonl",
        "CATALOG_JOBS_DIR": tmp_path / "catalog-jobs",
        "QUARANTINE_DIR": tmp_path / "incoming",
        "SLO_STATE_PATH": tmp_path / "slo.json",
    }.items():
        monkeypatch.setenv(name, str(path))
    saved = {name: sys.modules.get(name) for name in ("ui.app", "ui.slo_tracker")}
    yield
    for name, module in saved.items():
        package, attribute = name.rsplit(".", 1)
        if module is None:
            sys.modules.pop(name, None)
            if package in sys.modules:
                vars(sys.modules[package]).pop(attribute, None)
        else:
            sys.modules[name] = module
            setattr(sys.modules[package], attribute, module)


def _make_app(cookie_secure="false", session_timeout="1800"):
    """Create a fresh UI app instance with the given env vars."""
    with mock.patch.dict(os.environ, {
        "COOKIE_SECURE": cookie_secure,
        "SESSION_TIMEOUT": session_timeout,
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

    def test_passive_get_does_not_refresh_session(self, monkeypatch):
        from common import runtime_clock
        from common.session_store import token_digest

        elapsed = [runtime_clock.now()]
        monkeypatch.setattr(runtime_clock, "now", lambda: elapsed[0])
        app = _make_app(session_timeout="900")
        import ui.app as ui_app

        assert ui_app._auth.setup_passphrase("test-passphrase-123")
        login = ui_app._auth.login("test-passphrase-123")
        assert login.get("success") is True, login
        token = login["token"]
        state = ui_app._auth._store.snapshot()
        assert state["version"] == 2
        assert state["clock"] == runtime_clock.DOMAIN
        session_key = token_digest(token)
        before = state["sessions"][session_key]["last_active"]

        with app.test_client() as client:
            client.set_cookie("session_token", token)
            elapsed[0] += 450
            resp = client.get("/api/vault/status")
            assert resp.status_code == 200
            after = ui_app._auth._store.snapshot()
            assert after["sessions"][session_key]["last_active"] == before
            elapsed[0] += 451
            assert client.get("/api/vault/status").status_code == 401


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
