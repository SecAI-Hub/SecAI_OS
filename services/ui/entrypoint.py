#!/opt/venv/bin/python
import os
import sys
from pathlib import Path


def _tmpdir() -> str:
    secure_ai_tmpdir = os.getenv("SECURE_AI_TMPDIR", "/var/lib/secure-ai/import-staging/.tmp")
    tmpdir = Path(secure_ai_tmpdir)
    tmpdir.mkdir(parents=True, exist_ok=True)
    try:
        tmpdir.chmod(0o700)
    except PermissionError:
        pass
    os.environ["TMPDIR"] = secure_ai_tmpdir
    os.environ["TMP"] = secure_ai_tmpdir
    os.environ["TEMP"] = secure_ai_tmpdir
    return secure_ai_tmpdir


def main() -> None:
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    os.environ.setdefault("PYTHONPATH", "/app:/app/services")
    tmpdir = _tmpdir()

    workers = int(os.getenv("GUNICORN_WORKERS", "1"))
    if workers != 1:
        raise ValueError("GUNICORN_WORKERS must be 1; shared audit writers are not qualified")

    argv = [
        "/opt/venv/bin/gunicorn",
        "--chdir",
        "/app",
        "--bind",
        os.getenv("BIND_ADDR", "0.0.0.0:8480"),
        "--workers",
        str(workers),
        "--threads",
        os.getenv("GUNICORN_THREADS", "4"),
        "--timeout",
        os.getenv("GUNICORN_TIMEOUT", "60"),
        "--graceful-timeout",
        os.getenv("GUNICORN_GRACEFUL_TIMEOUT", "15"),
        "--worker-tmp-dir",
        tmpdir,
        "--max-requests",
        os.getenv("GUNICORN_MAX_REQUESTS", "1000"),
        "--max-requests-jitter",
        os.getenv("GUNICORN_MAX_REQUESTS_JITTER", "50"),
        "--no-control-socket",
        "--access-logfile",
        "-",
        "--error-logfile",
        "-",
        "ui.app:app",
    ]
    supervisor = [sys.executable, "-I", "/app/ui/runtime.py", "--", *argv]
    os.execv(supervisor[0], supervisor)


if __name__ == "__main__":
    main()
