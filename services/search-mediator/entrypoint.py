#!/opt/venv/bin/python
import os


def main() -> None:
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    os.environ.setdefault("PYTHONPATH", "/app/services")

    argv = [
        "/opt/venv/bin/gunicorn",
        "--chdir",
        "/app/services/search-mediator",
        "--bind",
        os.getenv("BIND_ADDR", "0.0.0.0:8485"),
        "--workers",
        os.getenv("GUNICORN_WORKERS", "2"),
        "--threads",
        os.getenv("GUNICORN_THREADS", "2"),
        "--timeout",
        os.getenv("GUNICORN_TIMEOUT", "30"),
        "--graceful-timeout",
        os.getenv("GUNICORN_GRACEFUL_TIMEOUT", "10"),
        "--worker-tmp-dir",
        "/tmp",
        "--max-requests",
        os.getenv("GUNICORN_MAX_REQUESTS", "1000"),
        "--max-requests-jitter",
        os.getenv("GUNICORN_MAX_REQUESTS_JITTER", "50"),
        "--access-logfile",
        "-",
        "--error-logfile",
        "-",
        "app:app",
    ]
    os.execv(argv[0], argv)


if __name__ == "__main__":
    main()
