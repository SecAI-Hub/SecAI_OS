import locale
import os
from pathlib import Path


def _ensure_dir(env_var: str, default: str) -> None:
    path = Path(os.getenv(env_var, default))
    os.environ.setdefault(env_var, str(path))
    path.mkdir(parents=True, exist_ok=True)


def _enforce_unicode_locale() -> tuple[str, str]:
    for env_var in ("LANG", "LC_ALL"):
        value = os.getenv(env_var)
        if not value:
            value = "C.UTF-8"
            os.environ[env_var] = value
        if "UTF-8" not in value.upper():
            raise RuntimeError(
                f"{env_var} must stay on a UTF-8 locale for secure diffusion runtime operation"
            )

    try:
        current = locale.setlocale(locale.LC_CTYPE, "")
    except locale.Error as exc:
        raise RuntimeError("failed to activate the configured UTF-8 locale") from exc

    preferred = locale.getpreferredencoding(False)
    if "UTF-8" not in current.upper() or "UTF-8" not in preferred.upper():
        raise RuntimeError(
            "diffusion runtime requires a UTF-8 locale; refusing to start on a non-Unicode locale"
        )
    return current, preferred


def main() -> None:
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    os.environ.setdefault("HOME", "/tmp")
    _enforce_unicode_locale()
    _ensure_dir("XDG_CACHE_HOME", "/tmp/.cache")
    _ensure_dir("HF_HOME", "/tmp/.hf")
    _ensure_dir("TORCH_HOME", "/tmp/.torch")

    gunicorn = os.path.join(os.getenv("VIRTUAL_ENV", "/opt/venv"), "bin", "gunicorn")
    cmd = [
        gunicorn,
        "--chdir", "/app",
        "--bind", os.getenv("BIND_ADDR", "0.0.0.0:8455"),
        "--workers", os.getenv("GUNICORN_WORKERS", "1"),
        "--threads", os.getenv("GUNICORN_THREADS", "2"),
        "--timeout", os.getenv("GUNICORN_TIMEOUT", "1800"),
        "--graceful-timeout", os.getenv("GUNICORN_GRACEFUL_TIMEOUT", "30"),
        "--worker-tmp-dir", "/tmp",
        "--max-requests", os.getenv("GUNICORN_MAX_REQUESTS", "500"),
        "--max-requests-jitter", os.getenv("GUNICORN_MAX_REQUESTS_JITTER", "25"),
        "--access-logfile", "-",
        "--error-logfile", "-",
        "app:app",
    ]
    os.execv(cmd[0], cmd)


if __name__ == "__main__":
    main()
