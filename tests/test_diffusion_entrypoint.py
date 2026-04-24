import importlib.util
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT_PATH = REPO_ROOT / "services" / "diffusion-worker" / "entrypoint.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("diffusion_entrypoint_under_test", str(ENTRYPOINT_PATH))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_enforce_unicode_locale_sets_utf8_defaults(monkeypatch):
    module = _load_module()

    monkeypatch.delenv("LANG", raising=False)
    monkeypatch.delenv("LC_ALL", raising=False)

    def fake_setlocale(_category, value):
        assert value == ""
        return "C.UTF-8"

    monkeypatch.setattr(module.locale, "setlocale", fake_setlocale)
    monkeypatch.setattr(module.locale, "getpreferredencoding", lambda _do_setlocale=False: "UTF-8")

    current, preferred = module._enforce_unicode_locale()

    assert current == "C.UTF-8"
    assert preferred == "UTF-8"
    assert module.os.environ["LANG"] == "C.UTF-8"
    assert module.os.environ["LC_ALL"] == "C.UTF-8"


def test_enforce_unicode_locale_rejects_non_utf8_locale(monkeypatch):
    module = _load_module()

    monkeypatch.setenv("LANG", "C")
    monkeypatch.setenv("LC_ALL", "C")

    with pytest.raises(RuntimeError, match="UTF-8 locale"):
        module._enforce_unicode_locale()
