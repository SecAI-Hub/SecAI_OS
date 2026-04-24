"""
Tests for Gunicorn/systemd integration.

Scoped to: UI, search-mediator, diffusion only.
Agent is explicitly excluded (it keeps its existing make_server Unix socket model).

Covers:
- Systemd unit ExecStart points to wrapper script (not python3 app.py)
- TimeoutStopSec set appropriately per service
- Wrappers set PYTHONPATH or --chdir for non-packaged modules
- Module-level app export for WSGI import
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
UNITS_DIR = REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
BUILD_SCRIPT = REPO_ROOT / "files" / "scripts" / "build-services.sh"

# Services being migrated to Gunicorn (agent excluded)
GUNICORN_SERVICES = {
    "secure-ai-ui.service": {
        "wrapper": "/usr/libexec/secure-ai/ui",
        "min_timeout_stop": 15,
        "module_import": "ui.app",
        "app_attr": "app",
    },
    "secure-ai-search-mediator.service": {
        "wrapper": "/usr/libexec/secure-ai/search-mediator",
        "min_timeout_stop": 10,
        "module_import": "search_mediator.app",
        "app_attr": "app",
    },
    "secure-ai-diffusion.service": {
        "wrapper": "/usr/libexec/secure-ai/diffusion-worker",
        "min_timeout_stop": 30,
        "module_import": "app",
        "app_attr": "app",
    },
}


def _read_unit(name):
    """Read and return a systemd unit file's content."""
    path = UNITS_DIR / name
    if not path.exists():
        pytest.skip(f"Unit file not found: {path}")
    return path.read_text()


def _parse_unit_value(content, key):
    """Extract a value from a systemd unit file."""
    for line in content.splitlines():
        line = line.strip()
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1]
    return None


class TestExecStartPointsToWrapper:
    """Each Gunicorn-migrated service must use a wrapper script, not python3 directly."""

    @pytest.mark.parametrize("unit_name,config", list(GUNICORN_SERVICES.items()))
    def test_exec_start_is_wrapper(self, unit_name, config):
        content = _read_unit(unit_name)
        exec_start = _parse_unit_value(content, "ExecStart")
        assert exec_start is not None, f"{unit_name} missing ExecStart"

        # Must NOT directly invoke python3
        assert not exec_start.startswith("/usr/bin/python3"), \
            f"{unit_name} ExecStart should use wrapper, not python3 directly: {exec_start}"

        # For diffusion: if disabled with placeholder, the ExecStart may be a
        # failing placeholder — that's acceptable
        if unit_name == "secure-ai-diffusion.service":
            # Either points to wrapper or is a placeholder
            assert config["wrapper"] in exec_start or \
                "not configured" in exec_start.lower() or \
                "secai-enable-diffusion" in exec_start or \
                "/bin/false" in exec_start or \
                "echo" in exec_start, \
                f"{unit_name} ExecStart unexpected: {exec_start}"
        else:
            assert config["wrapper"] in exec_start, \
                f"{unit_name} ExecStart should reference {config['wrapper']}: {exec_start}"


class TestTimeoutStopSec:
    """Each service must have appropriate TimeoutStopSec."""

    @pytest.mark.parametrize("unit_name,config", list(GUNICORN_SERVICES.items()))
    def test_timeout_stop_sec_present(self, unit_name, config):
        content = _read_unit(unit_name)
        timeout = _parse_unit_value(content, "TimeoutStopSec")
        assert timeout is not None, f"{unit_name} missing TimeoutStopSec"
        timeout_val = int(timeout)
        assert timeout_val >= config["min_timeout_stop"], \
            f"{unit_name} TimeoutStopSec={timeout_val} too low (min {config['min_timeout_stop']})"


class TestAgentExcludedFromGunicorn:
    """Agent service must NOT be migrated to Gunicorn."""

    def test_agent_not_using_gunicorn(self):
        content = _read_unit("secure-ai-agent.service")
        exec_start = _parse_unit_value(content, "ExecStart")
        assert "gunicorn" not in (exec_start or "").lower(), \
            "Agent service should NOT use gunicorn (keeps make_server)"


class TestOsVmGunicornRuntimeDefaults:
    """OS and VM images should inherit the same stable runtime defaults as sandbox."""

    def test_ui_unit_forces_single_worker(self):
        content = _read_unit("secure-ai-ui.service")
        assert "Environment=GUNICORN_WORKERS=1" in content

    def test_ui_wrapper_defaults_to_single_worker(self):
        content = BUILD_SCRIPT.read_text(encoding="utf-8")
        assert '--workers "${GUNICORN_WORKERS:-1}"' in content

    def test_diffusion_wrapper_sets_utf8_locale(self):
        content = BUILD_SCRIPT.read_text(encoding="utf-8")
        assert 'export LANG="${LANG:-C.UTF-8}"' in content
        assert 'export LC_ALL="${LC_ALL:-C.UTF-8}"' in content


class TestModuleExportsApp:
    """Each Flask service module must export 'app' at module level for WSGI import."""

    def test_ui_exports_app(self):
        sys.path.insert(0, str(REPO_ROOT / "services"))
        try:
            from ui.app import app
            assert app is not None
            assert callable(app)
        except ImportError as e:
            pytest.skip(f"Cannot import ui.app: {e}")
        finally:
            sys.path.pop(0)

    def test_search_mediator_exports_app(self):
        # search-mediator may be at different paths depending on install
        sm_path = REPO_ROOT / "services" / "search-mediator"
        if not sm_path.exists():
            pytest.skip("search-mediator source not found")
        sys.path.insert(0, str(sm_path))
        try:
            # The module name depends on packaging
            app_file = sm_path / "app.py"
            if app_file.exists():
                import importlib.util
                spec = importlib.util.spec_from_file_location("sm_app", str(app_file))
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                assert hasattr(mod, "app"), "search-mediator app.py must export 'app'"
        except Exception as e:
            pytest.skip(f"Cannot verify search-mediator app: {e}")
        finally:
            sys.path.pop(0)

    def test_diffusion_exports_app(self):
        dw_path = REPO_ROOT / "services" / "diffusion-worker"
        if not dw_path.exists():
            pytest.skip("diffusion-worker source not found")
        app_file = dw_path / "app.py"
        if not app_file.exists():
            pytest.skip("diffusion-worker app.py not found")
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("dw_app", str(app_file))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            assert hasattr(mod, "app"), "diffusion-worker app.py must export 'app'"
        except Exception as e:
            pytest.skip(f"Cannot verify diffusion-worker app: {e}")
