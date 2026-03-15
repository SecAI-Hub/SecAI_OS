"""
Secure AI Appliance - Local Web UI

Chat interface + model management + image/video generation.
Talks to local services only. One-click model download flows through
the airlock (if enabled) into quarantine for automatic scanning.
"""

import hmac
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import requests
import yaml
from flask import Flask, Response, jsonify, render_template, request, session

# Add services/ to path so we can import common.audit_chain
_services_root = str(Path(__file__).resolve().parent.parent.parent)
if _services_root not in sys.path:
    sys.path.insert(0, _services_root)

from common.audit_chain import AuditChain
from common.auth import AuthManager

log = logging.getLogger("ui")

app = Flask(__name__, template_folder="templates", static_folder="static")

# --- Security: Max input sizes ---
MAX_PASSPHRASE_LENGTH = 256

# --- Flask secret key (persistent, regenerated on passphrase change) ---
_FLASK_SECRET_FILE = Path(os.getenv("AUTH_DATA_DIR", "/var/lib/secure-ai/auth")) / "flask-secret"


def _load_or_create_secret_key() -> str:
    """Load the Flask secret key from file, or generate and save a new one."""
    env_key = os.getenv("FLASK_SECRET_KEY")
    if env_key:
        return env_key
    try:
        if _FLASK_SECRET_FILE.exists():
            return _FLASK_SECRET_FILE.read_text().strip()
    except OSError:
        pass
    new_key = os.urandom(32).hex()
    try:
        _FLASK_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        _FLASK_SECRET_FILE.write_text(new_key)
        os.chmod(str(_FLASK_SECRET_FILE), 0o600)
    except OSError:
        pass
    return new_key


app.secret_key = _load_or_create_secret_key()


# --- CSRF Protection (double-submit cookie pattern) ---

def _generate_csrf_token() -> str:
    """Generate a 32-byte hex CSRF token."""
    return os.urandom(32).hex()


# Routes exempt from CSRF validation
_CSRF_EXEMPT_PATHS = {
    "/login", "/api/auth/login", "/api/auth/setup", "/api/auth/status",
    "/api/status", "/health",
}


@app.before_request
def csrf_protect():
    """Validate CSRF token on state-changing requests."""
    # Skip safe (read-only) methods
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None

    # Skip exempt routes
    if request.path in _CSRF_EXEMPT_PATHS:
        return None

    # Skip if auth not yet configured (first-boot setup flow)
    if not _auth.is_configured():
        return None

    # Skip for service-to-service calls with valid Bearer token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if _auth.validate_session(token):
            return None

    # Extract the submitted CSRF token
    submitted = request.headers.get("X-CSRF-Token", "")
    if not submitted:
        # Fall back to form field
        submitted = request.form.get("csrf_token", "")

    # Compare against session-stored token
    expected = session.get("csrf_token", "")

    if not submitted or not expected:
        return jsonify({"error": "CSRF validation failed"}), 403

    if not hmac.compare_digest(submitted, expected):
        return jsonify({"error": "CSRF validation failed"}), 403

    return None


@app.context_processor
def inject_csrf_token():
    """Expose CSRF token to all templates."""
    token = session.get("csrf_token", "")
    return {"csrf_token": token}


@app.after_request
def add_security_headers(response):
    """Add defense-in-depth HTTP security headers to every response."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "media-src 'self' data:; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=()"
    )
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    # Cache-Control: prevent caching of sensitive pages
    if not request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"

    # Set CSRF cookie (readable by JavaScript for double-submit pattern)
    csrf_token = session.get("csrf_token", "")
    if csrf_token:
        response.set_cookie(
            "csrf_token", csrf_token,
            httponly=False, samesite="Strict", secure=False,
        )
    return response

INFERENCE_URL = os.getenv("INFERENCE_URL", "http://127.0.0.1:8465")
DIFFUSION_URL = os.getenv("DIFFUSION_URL", "http://127.0.0.1:8455")
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://127.0.0.1:8470")
TOOL_FIREWALL_URL = os.getenv("TOOL_FIREWALL_URL", "http://127.0.0.1:8475")
AIRLOCK_URL = os.getenv("AIRLOCK_URL", "http://127.0.0.1:8490")
AGENT_SOCKET = os.getenv("AGENT_SOCKET", "")  # Unix socket path (production)
AGENT_URL = os.getenv("AGENT_URL", "http://127.0.0.1:8476")  # TCP fallback (dev)
SEARCH_MEDIATOR_URL = os.getenv("SEARCH_MEDIATOR_URL", "http://127.0.0.1:8485")
APPLIANCE_CONFIG = os.getenv("APPLIANCE_CONFIG", "/etc/secure-ai/config/appliance.yaml")
QUARANTINE_DIR = Path(os.getenv("QUARANTINE_DIR", "/var/lib/secure-ai/quarantine"))
VAULT_ACTIVITY_FILE = Path(os.getenv("VAULT_ACTIVITY_FILE", "/run/secure-ai/last-activity"))
VAULT_STATE_FILE = Path(os.getenv("VAULT_STATE_FILE", "/run/secure-ai/vault-state"))

_ui_audit = AuditChain(os.getenv("AUDIT_LOG_PATH", "/var/lib/secure-ai/logs/ui-audit.jsonl"))

AUTH_DATA_DIR = os.getenv("AUTH_DATA_DIR", "/var/lib/secure-ai/auth")
_auth = AuthManager(AUTH_DATA_DIR)

# ---------------------------------------------------------------------------
# Circuit breakers — prevent cascading failures from downed services
# ---------------------------------------------------------------------------
from common.circuit_breaker import CircuitBreaker, CircuitOpenError  # noqa: E402

_breakers = {
    "registry": CircuitBreaker("registry", failure_threshold=3, recovery_timeout=30),
    "inference": CircuitBreaker("inference", failure_threshold=3, recovery_timeout=30),
    "search": CircuitBreaker("search-mediator", failure_threshold=3, recovery_timeout=30),
    "diffusion": CircuitBreaker("diffusion", failure_threshold=3, recovery_timeout=30),
    "agent": CircuitBreaker("agent", failure_threshold=3, recovery_timeout=30),
}

# Endpoints that don't require authentication
_PUBLIC_ENDPOINTS = {
    "/api/auth/login", "/api/auth/setup", "/api/auth/status",
    "/login", "/health",
}

ALLOWED_EXTENSIONS = {".gguf", ".safetensors"}
MAX_UPLOAD_SIZE = 50 * 1024 * 1024 * 1024  # 50 GB
SECURE_AI_ROOT = Path(os.getenv("SECURE_AI_ROOT", "/var/lib/secure-ai"))

# ---------------------------------------------------------------------------
# Model catalog — loaded from YAML file with hardcoded fallback
# ---------------------------------------------------------------------------

_MODEL_CATALOG_PATH = os.getenv(
    "MODEL_CATALOG_PATH", "/etc/secure-ai/model-catalog.yaml"
)

# Hardcoded fallback catalog (used if YAML file is missing or malformed)
_FALLBACK_CATALOG: list[dict] = [
    {
        "name": "Phi-3 Mini 3.8B (Q4_K_M)", "type": "llm",
        "filename": "Phi-3-mini-4k-instruct-q4.gguf",
        "url": "https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf",
        "size_gb": 2.3, "vram_gb": 4,
        "description": "Fast, small LLM. Good for testing and low-VRAM systems.",
    },
    {
        "name": "Mistral 7B Instruct (Q4_K_M)", "type": "llm",
        "filename": "mistral-7b-instruct-v0.3.Q4_K_M.gguf",
        "url": "https://huggingface.co/MaziyarPanahi/Mistral-7B-Instruct-v0.3-GGUF/resolve/main/Mistral-7B-Instruct-v0.3.Q4_K_M.gguf",
        "size_gb": 4.4, "vram_gb": 6,
        "description": "General-purpose LLM. Good balance of speed and quality.",
    },
    {
        "name": "Llama 3.1 8B Instruct (Q4_K_M)", "type": "llm",
        "filename": "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
        "url": "https://huggingface.co/bartowski/Meta-Llama-3.1-8B-Instruct-GGUF/resolve/main/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
        "size_gb": 4.9, "vram_gb": 7,
        "description": "Strong reasoning and instruction following.",
    },
    {
        "name": "Stable Diffusion XL Base", "type": "diffusion",
        "filename": "stable-diffusion-xl-base-1.0",
        "url": "https://huggingface.co/stabilityai/stable-diffusion-xl-base-1.0",
        "size_gb": 6.9, "vram_gb": 8,
        "description": "Image generation. 1024x1024 output. Requires 8GB+ VRAM.",
    },
    {
        "name": "Stable Diffusion 1.5", "type": "diffusion",
        "filename": "stable-diffusion-v1-5",
        "url": "https://huggingface.co/stable-diffusion-v1-5/stable-diffusion-v1-5",
        "size_gb": 4.3, "vram_gb": 4,
        "description": "Image generation. 512x512 output. Lower VRAM requirement.",
    },
    {
        "name": "Stable Video Diffusion XT", "type": "diffusion",
        "filename": "stable-video-diffusion-img2vid-xt",
        "url": "https://huggingface.co/stabilityai/stable-video-diffusion-img2vid-xt",
        "size_gb": 9.6, "vram_gb": 16,
        "description": "Video generation from image. 25 frames. Requires 16GB+ VRAM.",
    },
]


def load_model_catalog(path: str = _MODEL_CATALOG_PATH) -> list[dict]:
    """Load model catalog from YAML file, falling back to hardcoded defaults.

    Each entry must have at minimum: name, type, filename, url.
    Entries missing required fields are silently skipped.
    """
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict) or "models" not in data:
            log.warning("model catalog %s: missing 'models' key — using fallback", path)
            return list(_FALLBACK_CATALOG)
        models = data["models"]
        if not isinstance(models, list) or len(models) == 0:
            log.warning("model catalog %s: empty or invalid — using fallback", path)
            return list(_FALLBACK_CATALOG)
        # Validate required fields
        required = {"name", "type", "filename", "url"}
        valid: list[dict] = []
        for entry in models:
            if not isinstance(entry, dict):
                continue
            if not required.issubset(entry.keys()):
                log.warning("model catalog: skipping entry missing fields: %s", entry.get("name", "?"))
                continue
            # Add computed fields for backward compat
            if "expected_sha256" not in entry:
                entry["expected_sha256"] = "pin-on-first-download"
            if "expected_size_bytes" not in entry and "size_gb" in entry:
                entry["expected_size_bytes"] = int(float(entry["size_gb"]) * 1024 * 1024 * 1024)
            valid.append(entry)
        if not valid:
            log.warning("model catalog %s: no valid entries — using fallback", path)
            return list(_FALLBACK_CATALOG)
        log.info("model catalog loaded: %d models from %s", len(valid), path)
        return valid
    except FileNotFoundError:
        log.info("model catalog %s not found — using built-in defaults", path)
        return list(_FALLBACK_CATALOG)
    except Exception:
        log.warning("model catalog %s: load error — using fallback", path, exc_info=True)
        return list(_FALLBACK_CATALOG)


MODEL_CATALOG: list[dict] = load_model_catalog()

# Track active downloads
_active_downloads = {}
_download_lock = threading.Lock()


def _get_session_token():
    """Extract session token from cookie or Authorization header."""
    token = request.cookies.get("session_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    return token


def _touch_vault_activity():
    """Update the vault last-activity timestamp on authenticated requests."""
    try:
        VAULT_ACTIVITY_FILE.parent.mkdir(parents=True, exist_ok=True)
        VAULT_ACTIVITY_FILE.write_text(str(time.time()))
    except OSError:
        pass


def _read_vault_state() -> dict:
    """Read the current vault state from the watchdog state file."""
    try:
        return json.loads(VAULT_STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {"state": "unknown", "timestamp": 0}


@app.before_request
def require_auth():
    """Enforce authentication on all endpoints except public ones."""
    # Skip auth for public endpoints
    if request.path in _PUBLIC_ENDPOINTS:
        return None

    # Skip auth if not yet configured (first boot)
    if not _auth.is_configured():
        if request.path == "/login":
            return None
        return None  # Allow everything during first boot until passphrase is set

    # Check for valid session
    token = _get_session_token()
    if _auth.validate_session(token):
        _touch_vault_activity()
        return None

    # Not authenticated — redirect pages to login, return 401 for API
    if request.path.startswith("/api/"):
        return jsonify({"error": "authentication required"}), 401
    return render_template("login.html")


# --- API: Authentication ---

@app.route("/api/auth/status")
def auth_status():
    """Check if authentication is configured and current session state."""
    token = _get_session_token()
    return jsonify({
        "configured": _auth.is_configured(),
        "authenticated": _auth.validate_session(token) if token else False,
        "session": _auth.get_session_info(token) if token else {},
    })


@app.route("/api/auth/setup", methods=["POST"])
def auth_setup():
    """Set the initial passphrase (first boot only)."""
    if _auth.is_configured():
        return jsonify({"success": False, "error": "already configured"}), 400

    body = request.get_json()
    passphrase = body.get("passphrase", "") if body else ""

    if len(passphrase) < 8:
        return jsonify({"success": False, "error": "passphrase must be at least 8 characters"}), 400
    if len(passphrase) > MAX_PASSPHRASE_LENGTH:
        return jsonify({"success": False, "error": "passphrase too long"}), 400

    if _auth.setup_passphrase(passphrase):
        _ui_audit.append("auth_setup", {"action": "passphrase_configured"})
        # Session regeneration for setup flow
        session.clear()
        session["csrf_token"] = _generate_csrf_token()
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "setup failed"}), 500


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """Authenticate with passphrase and receive a session cookie."""
    body = request.get_json()
    passphrase = body.get("passphrase", "") if body else ""

    if len(passphrase) > MAX_PASSPHRASE_LENGTH:
        return jsonify({"success": False, "error": "invalid credentials"}), 401

    result = _auth.login(passphrase)

    if result.get("success"):
        _ui_audit.append("login", {"success": True})
        # Session regeneration: clear old session, create fresh one
        session.clear()
        csrf_token = _generate_csrf_token()
        session["csrf_token"] = csrf_token
        resp = jsonify(result)
        resp.set_cookie(
            "session_token", result["token"],
            httponly=True, samesite="Strict", secure=False,
            max_age=_auth._session_timeout,
        )
        return resp

    _ui_audit.append("login_failed", {
        "locked": result.get("locked", False),
    })
    status = 423 if result.get("locked") else 401
    return jsonify(result), status


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    """Invalidate the current session."""
    token = _get_session_token()
    if token:
        _auth.logout(token)
        _ui_audit.append("logout", {})
    resp = jsonify({"success": True})
    resp.delete_cookie("session_token")
    return resp


@app.route("/api/auth/change", methods=["POST"])
def auth_change_passphrase():
    """Change the passphrase. Requires current passphrase."""
    token = _get_session_token()
    if not _auth.validate_session(token):
        return jsonify({"error": "authentication required"}), 401

    body = request.get_json()
    current = body.get("current", "") if body else ""
    new_pass = body.get("new_passphrase", "") if body else ""

    if len(new_pass) > MAX_PASSPHRASE_LENGTH or len(current) > MAX_PASSPHRASE_LENGTH:
        return jsonify({"error": "passphrase too long"}), 400

    result = _auth.change_passphrase(current, new_pass)
    if result.get("success"):
        _ui_audit.append("passphrase_changed", {})

        # Regenerate Flask secret key to invalidate ALL existing sessions
        new_secret = os.urandom(32).hex()
        app.secret_key = new_secret
        try:
            _FLASK_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
            _FLASK_SECRET_FILE.write_text(new_secret)
            os.chmod(str(_FLASK_SECRET_FILE), 0o600)
        except OSError:
            pass

        # Give them a new session
        login_result = _auth.login(new_pass)
        session.clear()
        session["csrf_token"] = _generate_csrf_token()
        resp = jsonify({"success": True})
        if login_result.get("token"):
            resp.set_cookie(
                "session_token", login_result["token"],
                httponly=True, samesite="Strict", secure=False,
                max_age=_auth._session_timeout,
            )
        return resp
    return jsonify(result), 400


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/settings")
def settings_page():
    return render_template("settings.html", active_page="settings")


def is_first_boot() -> bool:
    return not (SECURE_AI_ROOT / ".initialized").exists()


def has_models() -> bool:
    try:
        resp = requests.get(f"{REGISTRY_URL}/v1/models", timeout=2)
        models = resp.json()
        return isinstance(models, list) and len(models) > 0
    except Exception:
        return False


def load_appliance_config() -> dict:
    try:
        with open(APPLIANCE_CONFIG) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


# --- Pages ---

@app.route("/")
def index():
    if is_first_boot() or not has_models():
        return render_template("setup.html")
    return render_template("index.html", active_page="chat")


@app.route("/chat")
def chat_page():
    return render_template("index.html", active_page="chat")


@app.route("/models")
def models_page():
    return render_template("models.html", active_page="models")


@app.route("/generate")
def generate_page():
    return render_template("generate.html", active_page="generate")


@app.route("/security")
def security_page():
    return render_template("security.html", active_page="security")


@app.route("/updates")
def updates_page():
    return render_template("updates.html", active_page="updates")


# --- API: Model Catalog (one-click download) ---

@app.route("/api/catalog")
def model_catalog():
    """Return the pre-curated model catalog for one-click download."""
    return jsonify(MODEL_CATALOG)


@app.route("/api/catalog/download", methods=["POST"])
def catalog_download():
    """Initiate a one-click model download from the catalog.

    The download runs in the background. The file is placed directly into
    quarantine with a .source metadata file so the pipeline can verify
    the origin against the source allowlist. The quarantine watcher
    automatically handles scanning and promotion.
    """
    body = request.get_json()
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    url = body.get("url", "").strip()
    filename = body.get("filename", "").strip()
    model_type = body.get("type", "llm")

    if not url or not filename:
        return jsonify({"error": "url and filename are required"}), 400

    if not url.startswith("https://"):
        return jsonify({"error": "only HTTPS downloads allowed"}), 400

    with _download_lock:
        if filename in _active_downloads:
            return jsonify({"error": "download already in progress", "filename": filename}), 409

    # Look up catalog entry for post-download verification
    catalog_entry = next(
        (m for m in MODEL_CATALOG if m.get("url") == url and m.get("filename") == filename),
        None,
    )

    thread = threading.Thread(
        target=_background_download,
        args=(url, filename, model_type, catalog_entry),
        daemon=True,
    )
    with _download_lock:
        _active_downloads[filename] = {"status": "downloading", "progress": 0}
    thread.start()

    return jsonify({
        "status": "downloading",
        "filename": filename,
        "message": "Download started. The model will be automatically scanned and promoted when complete.",
    }), 202


@app.route("/api/catalog/downloads")
def download_status():
    """Return the status of all active and recent downloads."""
    with _download_lock:
        return jsonify(_active_downloads)


def _background_download(url: str, filename: str, model_type: str,
                         catalog_entry: dict | None = None):
    """Download a model file into quarantine in the background."""
    try:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

        if model_type == "diffusion":
            _download_diffusion_model(url, filename)
        else:
            _download_single_file(url, filename, catalog_entry=catalog_entry)

        with _download_lock:
            _active_downloads[filename] = {
                "status": "quarantined",
                "message": "Download complete. Scanning in progress...",
            }
        log.info("download complete, in quarantine: %s", filename)

    except Exception as e:
        log.exception("download failed: %s", filename)
        with _download_lock:
            _active_downloads[filename] = {"status": "failed", "error": str(e)}


def _download_single_file(url: str, filename: str, catalog_entry: dict | None = None):
    """Download a single file (LLM GGUF) into quarantine.

    If a catalog_entry is provided, post-download verification checks the
    file size (within 5% tolerance) and SHA-256 hash (if a real pin exists).
    """
    dest = QUARANTINE_DIR / filename
    source_meta = QUARANTINE_DIR / f".{filename}.source"

    resp = requests.get(url, stream=True, timeout=30, allow_redirects=True)
    resp.raise_for_status()
    # Verify final URL is still HTTPS (prevent downgrade via redirect)
    if not resp.url.startswith("https://"):
        raise ValueError("download redirected to non-HTTPS URL")
    total = int(resp.headers.get("content-length", 0))
    downloaded = 0

    with open(dest, "wb") as f:
        for chunk in resp.iter_content(chunk_size=1 << 20):
            f.write(chunk)
            downloaded += len(chunk)
            if total > 0:
                pct = round(downloaded / total * 100, 1)
                with _download_lock:
                    _active_downloads[filename] = {
                        "status": "downloading",
                        "progress": pct,
                        "downloaded_mb": round(downloaded / (1 << 20), 1),
                        "total_mb": round(total / (1 << 20), 1),
                    }

    # Post-download verification
    if catalog_entry:
        actual_size = dest.stat().st_size
        expected_size = catalog_entry.get("expected_size_bytes")
        if expected_size and expected_size > 0:
            tolerance = 0.05
            if abs(actual_size - expected_size) / expected_size > tolerance:
                dest.unlink(missing_ok=True)
                raise ValueError(
                    f"downloaded file size {actual_size} differs from expected "
                    f"{expected_size} by more than 5%"
                )

        expected_hash = catalog_entry.get("expected_sha256", "")
        if expected_hash and expected_hash != "pin-on-first-download":
            import hashlib
            h = hashlib.sha256()
            with open(dest, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            actual_hash = h.hexdigest()
            if actual_hash != expected_hash:
                dest.unlink(missing_ok=True)
                raise ValueError(
                    f"SHA-256 mismatch: expected {expected_hash[:16]}..., "
                    f"got {actual_hash[:16]}..."
                )

    source_meta.write_text(url)


def _download_diffusion_model(url: str, dirname: str):
    """Download a diffusion model (HuggingFace repo) into quarantine."""
    dest = QUARANTINE_DIR / dirname
    source_meta = QUARANTINE_DIR / f".{dirname}.source"

    if dest.exists():
        shutil.rmtree(dest)

    with _download_lock:
        _active_downloads[dirname] = {"status": "downloading", "progress": 0, "message": "Cloning repository..."}

    try:
        subprocess.run(
            ["huggingface-cli", "download", url.replace("https://huggingface.co/", ""),
             "--local-dir", str(dest), "--local-dir-use-symlinks", "False"],
            check=True, capture_output=True, text=True, timeout=3600,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        if not url.startswith("https://huggingface.co/"):
            raise ValueError("source not in allowlist for git clone")
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(dest)],
            check=True, capture_output=True, text=True, timeout=3600,
        )

    source_meta.write_text(url)


# --- API: Models ---

@app.route("/api/models")
def list_models():
    try:
        resp = requests.get(f"{REGISTRY_URL}/v1/models", timeout=5)
        return jsonify(resp.json())
    except requests.ConnectionError:
        return jsonify([])


@app.route("/api/models/fsverity")
def model_fsverity_status():
    """Check fs-verity status of all trusted models."""
    try:
        resp = requests.get(f"{REGISTRY_URL}/v1/models", timeout=5)
        models = resp.json()
        results = []
        for m in models:
            provenance_path = SECURE_AI_ROOT / "registry" / f"{m['filename']}.provenance.json"
            prov = {}
            if provenance_path.exists():
                prov = json.loads(provenance_path.read_text())
            results.append({
                "name": m["name"],
                "fsverity_enabled": prov.get("integrity", {}).get("fsverity_enabled", False),
                "fsverity_digest": prov.get("integrity", {}).get("fsverity_digest"),
                "provenance_signed": Path(str(provenance_path) + ".sig").exists(),
            })
        return jsonify(results)
    except Exception:
        return jsonify([])


@app.route("/api/models/verify", methods=["POST"])
def verify_model():
    name = request.json.get("name", "")
    try:
        resp = requests.post(f"{REGISTRY_URL}/v1/model/verify?name={name}", timeout=30)
        return jsonify(resp.json()), resp.status_code
    except requests.ConnectionError:
        return jsonify({"error": "registry unreachable"}), 503


@app.route("/api/models/verify-manifest", methods=["POST"])
def verify_model_manifest():
    """Verify per-tensor integrity manifest via gguf-guard."""
    name = request.json.get("name", "")
    try:
        resp = requests.post(f"{REGISTRY_URL}/v1/model/verify-manifest?name={name}", timeout=120)
        return jsonify(resp.json()), resp.status_code
    except requests.ConnectionError:
        return jsonify({"error": "registry unreachable"}), 503


@app.route("/api/models/delete", methods=["POST"])
def delete_model():
    name = request.json.get("name", "")
    try:
        resp = requests.delete(f"{REGISTRY_URL}/v1/model/delete?name={name}", timeout=10)
        return jsonify(resp.json()), resp.status_code
    except requests.ConnectionError:
        return jsonify({"error": "registry unreachable"}), 503


@app.route("/api/models/import", methods=["POST"])
def import_model():
    """Import a model file by copying it to the quarantine directory.

    Accepts either:
    - A file upload (multipart form)
    - A local filesystem path (JSON body with "path" field)

    The file goes into quarantine and is automatically scanned and promoted.
    """
    if "file" in request.files:
        uploaded = request.files["file"]
        if not uploaded.filename:
            return jsonify({"error": "no file selected"}), 400

        ext = Path(uploaded.filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({
                "error": "file format not allowed",
                "allowed": list(ALLOWED_EXTENSIONS),
            }), 400

        dest = QUARANTINE_DIR / uploaded.filename
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        uploaded.save(str(dest))
        log.info("imported via upload: %s -> %s", uploaded.filename, dest)
        return jsonify({
            "status": "queued",
            "filename": uploaded.filename,
            "message": "File is in quarantine. It will be automatically scanned and promoted.",
        }), 202

    body = request.get_json(silent=True) or {}
    local_path = body.get("path", "")
    if local_path:
        src = Path(local_path)
        if not src.exists():
            return jsonify({"error": "file not found"}), 404
        if not src.is_file():
            return jsonify({"error": "path is not a file"}), 400

        ext = src.suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({
                "error": "file format not allowed",
                "allowed": list(ALLOWED_EXTENSIONS),
            }), 400

        dest = QUARANTINE_DIR / src.name
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src), str(dest))
        log.info("imported from path: %s -> %s", src, dest)
        return jsonify({
            "status": "queued",
            "filename": src.name,
            "message": "File is in quarantine. It will be automatically scanned and promoted.",
        }), 202

    return jsonify({"error": "provide a file upload or a JSON body with 'path'"}), 400


@app.route("/api/models/quarantine")
def quarantine_status():
    """List files currently in quarantine (pending scan/promotion)."""
    if not QUARANTINE_DIR.exists():
        return jsonify([])
    files = []
    for f in sorted(QUARANTINE_DIR.iterdir()):
        if f.name.startswith("."):
            continue
        if f.is_file():
            files.append({"filename": f.name, "size_bytes": f.stat().st_size, "type": "file"})
        elif f.is_dir():
            total = sum(p.stat().st_size for p in f.rglob("*") if p.is_file())
            files.append({"filename": f.name, "size_bytes": total, "type": "directory"})
    return jsonify(files)


# --- API: Chat ---

def _verify_active_model() -> dict:
    """Pre-inference check: verify the active model's hash before use.

    Returns {"safe": True/False, "detail": "..."}.
    This ensures every inference request uses a verified, non-tampered model.
    """
    try:
        # Get the active/default model from the registry
        models_resp = requests.get(f"{REGISTRY_URL}/v1/models", timeout=3)
        models = models_resp.json()
        if not models:
            return {"safe": False, "detail": "no models in registry"}

        # Verify the first (active) model
        name = models[0].get("name", "")
        verify_resp = requests.post(
            f"{REGISTRY_URL}/v1/model/verify?name={name}", timeout=30
        )
        result = verify_resp.json()
        if result.get("safe_to_use") == "true":
            return {"safe": True, "detail": f"{name} verified"}
        return {
            "safe": False,
            "detail": f"{name} failed integrity check: {result.get('error', 'unknown')}",
        }
    except Exception as e:
        log.warning("pre-inference verification failed: %s", e)
        return {"safe": False, "detail": f"verification error: {e}"}


@app.route("/api/chat", methods=["POST"])
def chat():
    body = request.get_json()
    messages = body.get("messages", [])

    # Pre-inference integrity check
    check = _verify_active_model()
    if not check["safe"]:
        _ui_audit.append("inference_blocked", {"reason": check["detail"]})
        return jsonify({
            "error": "inference blocked: model integrity check failed",
            "detail": check["detail"],
            "integrity_failed": True,
        }), 403

    try:
        resp = requests.post(
            f"{INFERENCE_URL}/v1/chat/completions",
            json={"messages": messages, "stream": False},
            timeout=300,
        )
        return jsonify(resp.json())
    except requests.ConnectionError:
        return jsonify({"error": "inference worker not available"}), 503


@app.route("/api/chat/stream", methods=["POST"])
def chat_stream():
    body = request.get_json()
    messages = body.get("messages", [])

    # Pre-inference integrity check
    check = _verify_active_model()
    if not check["safe"]:
        return jsonify({
            "error": "inference blocked: model integrity check failed",
            "detail": check["detail"],
            "integrity_failed": True,
        }), 403

    def generate():
        try:
            resp = requests.post(
                f"{INFERENCE_URL}/v1/chat/completions",
                json={"messages": messages, "stream": True},
                stream=True,
                timeout=300,
            )
            for line in resp.iter_lines():
                if line:
                    yield line.decode() + "\n\n"
        except requests.ConnectionError:
            yield json.dumps({"error": "inference worker not available"}) + "\n\n"

    return Response(generate(), mimetype="text/event-stream")


# --- API: Web Search (Tor-routed via search mediator) ---

@app.route("/api/search", methods=["POST"])
def web_search():
    """Perform a Tor-routed web search. The query is sanitized by the mediator.

    Returns search results + a pre-built context string for augmenting LLM responses.
    """
    try:
        resp = requests.post(
            f"{SEARCH_MEDIATOR_URL}/v1/search",
            json=request.get_json(),
            timeout=45,
        )
        return jsonify(resp.json()), resp.status_code
    except requests.ConnectionError:
        return jsonify({"error": "search mediator not available (is Tor running?)"}), 503


@app.route("/api/search/status")
def search_status():
    """Check if Tor-routed search is available."""
    try:
        resp = requests.get(f"{SEARCH_MEDIATOR_URL}/health", timeout=5)
        return jsonify(resp.json())
    except requests.ConnectionError:
        return jsonify({"status": "unavailable", "search_enabled": False})


@app.route("/api/chat/search", methods=["POST"])
def chat_with_search():
    """Chat with optional web search augmentation.

    If the request includes "search": true, the user's last message is used
    to perform a Tor-routed search. Results are injected as context before
    sending to the LLM. The response includes a flag indicating online sources
    were used.
    """
    body = request.get_json()
    messages = body.get("messages", [])
    do_search = body.get("search", False)

    search_context = None
    search_results = None

    if do_search and messages:
        # Use the last user message as the search query
        last_user = next(
            (m for m in reversed(messages) if m.get("role") == "user"),
            None,
        )
        if last_user:
            try:
                search_resp = requests.post(
                    f"{SEARCH_MEDIATOR_URL}/v1/search",
                    json={"query": last_user["content"]},
                    timeout=45,
                )
                if search_resp.status_code == 200:
                    search_data = search_resp.json()
                    search_context = search_data.get("context", "")
                    search_results = search_data.get("results", [])
            except Exception:
                log.warning("search augmentation failed, proceeding without")

    # Pre-inference integrity check
    check = _verify_active_model()
    if not check["safe"]:
        return jsonify({
            "error": "inference blocked: model integrity check failed",
            "detail": check["detail"],
            "integrity_failed": True,
        }), 403

    # If we got search context, inject it as a system message
    augmented_messages = list(messages)
    if search_context:
        augmented_messages.insert(0, {
            "role": "system",
            "content": (
                "You have access to the following web search results. "
                "Use them to inform your answer if relevant. "
                "Always cite sources by number when using information from search results. "
                "If the search results aren't helpful, rely on your own knowledge.\n\n"
                + search_context
            ),
        })

    try:
        resp = requests.post(
            f"{INFERENCE_URL}/v1/chat/completions",
            json={"messages": augmented_messages, "stream": False},
            timeout=300,
        )
        result = resp.json()
        result["web_search_used"] = search_context is not None
        if search_results:
            result["search_sources"] = search_results
        return jsonify(result)
    except requests.ConnectionError:
        return jsonify({"error": "inference worker not available"}), 503


# --- API: Image/Video Generation (proxy to diffusion worker) ---

@app.route("/api/generate/image", methods=["POST"])
def generate_image():
    """Proxy image generation request to the diffusion worker."""
    try:
        resp = requests.post(
            f"{DIFFUSION_URL}/v1/generate/image",
            json=request.get_json(),
            timeout=600,
        )
        return jsonify(resp.json()), resp.status_code
    except requests.ConnectionError:
        return jsonify({"error": "diffusion worker not available"}), 503


@app.route("/api/generate/video", methods=["POST"])
def generate_video():
    """Proxy video generation request to the diffusion worker."""
    try:
        resp = requests.post(
            f"{DIFFUSION_URL}/v1/generate/video",
            json=request.get_json(),
            timeout=1800,
        )
        return jsonify(resp.json()), resp.status_code
    except requests.ConnectionError:
        return jsonify({"error": "diffusion worker not available"}), 503


@app.route("/api/generate/img2img", methods=["POST"])
def generate_img2img():
    """Proxy img2img request to the diffusion worker."""
    try:
        resp = requests.post(
            f"{DIFFUSION_URL}/v1/generate/img2img",
            json=request.get_json(),
            timeout=600,
        )
        return jsonify(resp.json()), resp.status_code
    except requests.ConnectionError:
        return jsonify({"error": "diffusion worker not available"}), 503


@app.route("/api/diffusion/models")
def diffusion_models():
    """List available diffusion models from the diffusion worker."""
    try:
        resp = requests.get(f"{DIFFUSION_URL}/v1/models", timeout=5)
        return jsonify(resp.json())
    except requests.ConnectionError:
        return jsonify([])


# --- API: Status ---

@app.route("/api/status")
def status():
    checks = {}
    # Map service names to their circuit breaker keys
    svc_breaker_map = {
        "registry": "registry", "inference": "inference",
        "diffusion": "diffusion", "search": "search",
    }
    for name, url in [
        ("registry", REGISTRY_URL),
        ("inference", INFERENCE_URL),
        ("diffusion", DIFFUSION_URL),
        ("tool_firewall", TOOL_FIREWALL_URL),
        ("airlock", AIRLOCK_URL),
        ("search", SEARCH_MEDIATOR_URL),
    ]:
        breaker_key = svc_breaker_map.get(name)
        try:
            if breaker_key and breaker_key in _breakers:
                r = _breakers[breaker_key].call(requests.get, f"{url}/health", timeout=2)
            else:
                r = requests.get(f"{url}/health", timeout=2)
            checks[name] = r.json()
        except CircuitOpenError:
            checks[name] = {"status": "circuit_open"}
        except Exception:
            checks[name] = {"status": "unreachable"}

    config = load_appliance_config()
    return jsonify({
        "appliance_mode": config.get("appliance", {}).get("mode", "unknown"),
        "services": checks,
    })


@app.route("/api/security/stats")
def security_stats():
    """Aggregate security stats from tool-firewall and airlock."""
    stats = {}
    for name, url in [("tool_firewall", TOOL_FIREWALL_URL), ("airlock", AIRLOCK_URL)]:
        try:
            resp = requests.get(f"{url}/v1/stats", timeout=2)
            stats[name] = resp.json()
        except Exception:
            stats[name] = {"error": "unreachable"}
    return jsonify(stats)


# --- API: Model Integrity Monitoring ---

@app.route("/api/integrity/status")
def integrity_status():
    """Return the last integrity check result and current verification state."""
    try:
        resp = requests.get(f"{REGISTRY_URL}/v1/integrity/status", timeout=5)
        return jsonify(resp.json())
    except requests.ConnectionError:
        return jsonify({"status": "unknown", "detail": "registry unreachable"})


@app.route("/api/integrity/verify-all", methods=["POST"])
def integrity_verify_all():
    """Trigger an immediate verification of all model hashes."""
    try:
        resp = requests.post(f"{REGISTRY_URL}/v1/models/verify-all", timeout=120)
        return jsonify(resp.json()), resp.status_code
    except requests.ConnectionError:
        return jsonify({"error": "registry unreachable"}), 503


# --- API: Audit Log Integrity ---

@app.route("/api/audit/status")
def audit_status():
    """Return the last audit chain verification result."""
    result_path = SECURE_AI_ROOT / "logs" / "audit-verify-last.json"
    if not result_path.exists():
        return jsonify({"status": "unknown", "detail": "no audit verification has run yet"})
    try:
        data = json.loads(result_path.read_text())
        return jsonify(data)
    except Exception:
        return jsonify({"status": "unknown", "detail": "could not read verification result"})


@app.route("/api/audit/verify", methods=["POST"])
def audit_verify_now():
    """Trigger an immediate audit chain verification."""
    try:
        result = subprocess.run(
            ["/usr/bin/python3", "/usr/libexec/secure-ai/verify-audit-chains.py"],
            capture_output=True, text=True, timeout=60,
            env={**os.environ, "AUDIT_LOGS_DIR": str(SECURE_AI_ROOT / "logs")},
        )
        _ui_audit.append("audit_verify_triggered", {"exit_code": result.returncode})
        # Read the fresh result
        result_path = SECURE_AI_ROOT / "logs" / "audit-verify-last.json"
        if result_path.exists():
            return jsonify(json.loads(result_path.read_text()))
        return jsonify({"status": "completed", "exit_code": result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "verification timed out"}), 504
    except FileNotFoundError:
        return jsonify({"error": "verification script not found"}), 500


# --- API: Boot Chain Integrity (M17) ---

@app.route("/api/boot/status")
def boot_status():
    """Return the last boot chain verification result."""
    result_path = SECURE_AI_ROOT / "logs" / "boot-verify-last.json"
    if not result_path.exists():
        return jsonify({"status": "unknown", "detail": "no boot verification has run yet"})
    try:
        data = json.loads(result_path.read_text())
        return jsonify(data)
    except Exception:
        return jsonify({"status": "unknown", "detail": "could not read boot verification result"})


@app.route("/api/boot/tpm2/status")
def tpm2_status():
    """Return TPM2 state from the runtime state file."""
    state_path = Path("/run/secure-ai/tpm2-state")
    if not state_path.exists():
        return jsonify({"tpm2_available": False, "sealed": False, "detail": "no TPM2 state"})
    try:
        return jsonify(json.loads(state_path.read_text()))
    except Exception:
        return jsonify({"tpm2_available": False, "detail": "could not read TPM2 state"})


@app.route("/api/boot/secureboot/status")
def secureboot_status():
    """Return Secure Boot state from the runtime state file."""
    state_path = Path("/run/secure-ai/secureboot-state")
    if not state_path.exists():
        return jsonify({"secure_boot": "unknown", "mok_enrolled": "unknown"})
    try:
        return jsonify(json.loads(state_path.read_text()))
    except Exception:
        return jsonify({"secure_boot": "unknown", "detail": "could not read state"})


# --- API: Vault Auto-Lock ---

@app.route("/api/vault/status")
def vault_status():
    """Return the current vault lock state and idle time."""
    state = _read_vault_state()
    last_activity = 0.0
    try:
        last_activity = float(VAULT_ACTIVITY_FILE.read_text().strip())
    except (OSError, ValueError):
        pass

    idle_seconds = int(time.time() - last_activity) if last_activity > 0 else 0
    return jsonify({
        "state": state.get("state", "unknown"),
        "detail": state.get("detail", ""),
        "idle_seconds": idle_seconds,
        "last_activity": last_activity,
    })


@app.route("/api/vault/lock", methods=["POST"])
def vault_lock():
    """Manually lock the vault immediately."""
    token = _get_session_token()
    if not _auth.validate_session(token):
        return jsonify({"error": "authentication required"}), 401

    _ui_audit.append("vault_manual_lock", {"user_initiated": True})

    try:
        result = subprocess.run(
            ["/usr/bin/python3", "/usr/libexec/secure-ai/vault-watchdog.py"],
            input="",  # not used, just need the module
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        pass

    # Direct lock via systemctl — the watchdog will detect the state change
    try:
        # Stop services first
        for svc in ["secure-ai-inference.service", "secure-ai-diffusion.service"]:
            subprocess.run(["systemctl", "stop", svc], capture_output=True, timeout=30)

        subprocess.run(["sync"], timeout=10)
        subprocess.run(["umount", "/var/lib/secure-ai"], capture_output=True, timeout=30)
        result = subprocess.run(
            ["cryptsetup", "close", "secure-ai-vault"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return jsonify({"success": False, "error": result.stderr.strip()}), 500

        # Update state file
        VAULT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        VAULT_STATE_FILE.write_text(json.dumps({
            "state": "locked",
            "timestamp": time.time(),
            "detail": "manual_lock",
        }))
        return jsonify({"success": True, "state": "locked"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/vault/unlock", methods=["POST"])
def vault_unlock():
    """Unlock the vault with the LUKS passphrase."""
    body = request.get_json()
    passphrase = body.get("passphrase", "") if body else ""

    if not passphrase:
        return jsonify({"success": False, "error": "passphrase required"}), 400
    if len(passphrase) > MAX_PASSPHRASE_LENGTH:
        return jsonify({"success": False, "error": "passphrase too long"}), 400

    # Find partition from crypttab
    partition = ""
    try:
        for line in Path("/etc/crypttab").read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "secure-ai-vault":
                device = parts[1]
                if device.startswith("UUID="):
                    uuid_path = Path(f"/dev/disk/by-uuid/{device[5:]}")
                    if uuid_path.exists():
                        partition = str(uuid_path.resolve())
                else:
                    partition = device
                break
    except OSError:
        pass

    if not partition:
        return jsonify({"success": False, "error": "cannot determine vault partition"}), 500

    try:
        proc = subprocess.run(
            ["cryptsetup", "open", partition, "secure-ai-vault"],
            input=passphrase, capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            _ui_audit.append("vault_unlock_failed", {})
            return jsonify({"success": False, "error": "incorrect passphrase or device error"}), 401

        Path("/var/lib/secure-ai").mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["mount", "/dev/mapper/secure-ai-vault", "/var/lib/secure-ai"],
            capture_output=True, check=True, timeout=30,
        )

        _touch_vault_activity()

        # Restart services
        for svc in ["secure-ai-inference.service", "secure-ai-diffusion.service", "secure-ai-ui.service"]:
            subprocess.run(["systemctl", "start", svc], capture_output=True, timeout=30)

        VAULT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        VAULT_STATE_FILE.write_text(json.dumps({
            "state": "unlocked",
            "timestamp": time.time(),
            "detail": "",
        }))

        _ui_audit.append("vault_unlock", {})
        return jsonify({"success": True, "state": "unlocked"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/vault/keepalive", methods=["POST"])
def vault_keepalive():
    """Explicitly reset the idle timer (e.g., during long inference runs)."""
    _touch_vault_activity()
    return jsonify({"success": True})


# --- API: VM Status and GPU Passthrough Toggle ---

def _read_vm_env() -> dict:
    """Read VM detection results."""
    vm_env = SECURE_AI_ROOT / "vm.env"
    result = {"is_vm": False, "hypervisor": "none", "gpu_passthrough": False, "vm_gpu_enabled": False}
    if not vm_env.exists():
        return result
    try:
        for line in vm_env.read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip().lower()
            val = val.strip()
            if key == "is_vm":
                result["is_vm"] = val.lower() == "true"
            elif key == "hypervisor":
                result["hypervisor"] = val
            elif key == "gpu_passthrough":
                result["gpu_passthrough"] = val.lower() == "true"
            elif key == "vm_gpu_enabled":
                result["vm_gpu_enabled"] = val.lower() == "true"
            elif key == "vm_warnings":
                result["warnings"] = [w.strip() for w in val.split("|") if w.strip()]
    except Exception:
        pass
    return result


@app.route("/api/vm/status")
def vm_status():
    """Return VM detection results and security warnings."""
    info = _read_vm_env()
    if info["is_vm"]:
        info["security_notice"] = {
            "level": "warning",
            "title": f"Running in a Virtual Machine ({info['hypervisor']})",
            "details": [
                "The host OS and hypervisor can read all VM memory, including "
                "decrypted vault contents, model weights, and inference data.",
                "VM snapshots may capture decrypted secrets and active session data. "
                "Avoid taking snapshots while the vault is unlocked.",
                "Disable clipboard sharing between VM and host to prevent data leakage.",
                "Co-located VMs on the same host may observe timing patterns from inference workloads.",
            ],
        }
        if info["gpu_passthrough"] and not info["vm_gpu_enabled"]:
            info["gpu_notice"] = {
                "level": "info",
                "title": "GPU Passthrough Detected but Disabled",
                "details": [
                    "A physical GPU is passed through to this VM but GPU acceleration "
                    "is currently disabled for security.",
                    "Enabling GPU passthrough allows the host hypervisor to access GPU memory, "
                    "which may contain model weights, intermediate computations, and generated outputs.",
                    "GPU DMA (Direct Memory Access) can bypass some VM memory isolation boundaries.",
                    "Only enable GPU passthrough if you trust the host machine and hypervisor.",
                ],
                "action": "Use POST /api/vm/gpu to enable or disable GPU acceleration.",
            }
        elif info["gpu_passthrough"] and info["vm_gpu_enabled"]:
            info["gpu_notice"] = {
                "level": "warning",
                "title": "GPU Passthrough ENABLED",
                "details": [
                    "GPU acceleration is active. The host hypervisor can access GPU memory.",
                    "Model weights, computations, and generated outputs in GPU memory are "
                    "visible to the host OS.",
                ],
            }
    return jsonify(info)


@app.route("/api/vm/gpu", methods=["POST"])
def toggle_vm_gpu():
    """Enable or disable GPU passthrough in VM mode.

    Body: {"enabled": true/false}
    Requires restart of inference/diffusion services to take effect.
    """
    vm_info = _read_vm_env()
    if not vm_info["is_vm"]:
        return jsonify({"error": "not running in a VM"}), 400

    if not vm_info["gpu_passthrough"]:
        return jsonify({"error": "no GPU passthrough detected"}), 400

    body = request.get_json()
    if not body or "enabled" not in body:
        return jsonify({"error": "JSON body with 'enabled' (bool) required"}), 400

    enabled = bool(body["enabled"])
    vm_env_path = SECURE_AI_ROOT / "vm.env"

    try:
        content = vm_env_path.read_text()
        new_lines = []
        for line in content.splitlines():
            if line.strip().startswith("VM_GPU_ENABLED="):
                new_lines.append(f"VM_GPU_ENABLED={'true' if enabled else 'false'}")
            else:
                new_lines.append(line)
        vm_env_path.write_text("\n".join(new_lines) + "\n")

        # Rewrite inference.env based on new setting
        if enabled:
            # Re-run GPU detection to get real GPU info
            try:
                import subprocess
                subprocess.run(
                    ["/usr/libexec/secure-ai/detect-gpu.sh"],
                    capture_output=True, timeout=30,
                )
            except Exception:
                pass
        else:
            # Force CPU mode
            inf_env = SECURE_AI_ROOT / "inference.env"
            inf_env.write_text(
                "GPU_BACKEND=cpu\n"
                "GPU_NAME=CPU (VM mode - GPU disabled for security)\n"
                "GPU_LAYERS=0\n"
            )

        action = "enabled" if enabled else "disabled"
        log.info("VM GPU passthrough %s by user", action)
        _ui_audit.append("vm_gpu_toggle", {"action": action})

        return jsonify({
            "status": "ok",
            "vm_gpu_enabled": enabled,
            "message": f"GPU passthrough {action}. Restart inference and diffusion services to apply.",
            "warning": (
                "GPU memory is now accessible to the host hypervisor. "
                "Model weights and inference data in VRAM are visible to the host OS."
            ) if enabled else None,
        })

    except Exception as e:
        log.exception("failed to toggle VM GPU")
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Emergency panic (M23)
# ---------------------------------------------------------------------------
PANIC_STATE_FILE = Path(os.getenv("PANIC_STATE_FILE", "/run/secure-ai/panic-state.json"))
SECURECTL = "/usr/libexec/secure-ai/securectl"


@app.route("/api/emergency/status")
def emergency_status():
    """Return current panic state."""
    if PANIC_STATE_FILE.exists():
        try:
            return jsonify(json.loads(PANIC_STATE_FILE.read_text()))
        except Exception:
            return jsonify({"panic_active": False, "error": "failed to read state"})
    return jsonify({"panic_active": False})


@app.route("/api/emergency/panic", methods=["POST"])
def emergency_panic():
    """Trigger emergency panic at specified level.

    Body: {"level": 1|2|3, "passphrase": "<passphrase>"}
    Level 1 does not require passphrase.
    Levels 2 and 3 require passphrase confirmation.
    """
    body = request.get_json()
    if not body or "level" not in body:
        return jsonify({"error": "JSON body with 'level' (1, 2, or 3) required"}), 400

    level = body["level"]
    if level not in (1, 2, 3):
        return jsonify({"error": "level must be 1, 2, or 3"}), 400

    passphrase = body.get("passphrase", "")

    # Levels 2 and 3 require passphrase re-authentication
    if level >= 2 and not passphrase:
        return jsonify({"error": f"Level {level} requires passphrase confirmation"}), 400
    if level >= 2 and not _auth._verify_stored(passphrase):
        _ui_audit.append("emergency_panic_reauth_failed", {"level": level})
        return jsonify({"error": "passphrase verification failed"}), 401

    cmd = [SECURECTL, "panic", str(level), "--no-countdown"]
    if level >= 2:
        cmd.extend(["--confirm", passphrase])

    log.warning("EMERGENCY PANIC LEVEL %d triggered via UI", level)
    _ui_audit.append("emergency_panic", {
        "level": level,
        "source": "ui",
        "severity": "CRITICAL",
    })

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            return jsonify({"error": error_msg or "panic command failed"}), 500

        return jsonify({
            "status": "ok",
            "level": level,
            "message": f"Emergency panic level {level} executed successfully",
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "panic command timed out"}), 500
    except Exception as e:
        log.exception("emergency panic failed")
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Update verification + auto-rollback (M24)
# ---------------------------------------------------------------------------
UPDATE_VERIFY = "/usr/libexec/secure-ai/update-verify.sh"
UPDATE_STATE_FILE = Path(os.getenv("UPDATE_STATE_FILE", "/run/secure-ai/update-state.json"))
HEALTH_LOG_FILE = Path(os.getenv("HEALTH_LOG_FILE", "/var/lib/secure-ai/logs/health-check.json"))


@app.route("/api/update/status")
def update_status():
    """Return current update state and deployment info."""
    result = {}
    if UPDATE_STATE_FILE.exists():
        try:
            result = json.loads(UPDATE_STATE_FILE.read_text())
        except Exception:
            result = {"status": "unknown"}
    else:
        result = {"status": "unknown", "detail": "no update check has run yet"}

    # Include health check result
    if HEALTH_LOG_FILE.exists():
        try:
            result["health_check"] = json.loads(HEALTH_LOG_FILE.read_text())
        except Exception:
            pass

    return jsonify(result)


@app.route("/api/update/check", methods=["POST"])
def update_check():
    """Check for available updates."""
    _ui_audit.append("update_check", {"source": "ui"})
    try:
        result = subprocess.run(
            [UPDATE_VERIFY, "check"],
            capture_output=True, text=True, timeout=120,
        )
        # The script outputs JSON on stdout
        try:
            return jsonify(json.loads(result.stdout.strip()))
        except (json.JSONDecodeError, ValueError):
            return jsonify({"status": "checked", "output": result.stdout.strip()})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "update check timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/update/stage", methods=["POST"])
def update_stage():
    """Stage (download) an update without applying it."""
    _ui_audit.append("update_stage", {"source": "ui"})
    try:
        result = subprocess.run(
            [UPDATE_VERIFY, "stage"],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip()
            return jsonify({"error": error or "staging failed"}), 500
        try:
            return jsonify(json.loads(result.stdout.strip()))
        except (json.JSONDecodeError, ValueError):
            return jsonify({"status": "staged", "output": result.stdout.strip()})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "staging timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/update/apply", methods=["POST"])
def update_apply():
    """Apply a staged update and reboot."""
    body = request.get_json() or {}
    if not body.get("confirm"):
        return jsonify({"error": "must include {\"confirm\": true} to apply update"}), 400

    _ui_audit.append("update_apply", {"source": "ui", "severity": "WARNING"})
    try:
        result = subprocess.run(
            [UPDATE_VERIFY, "apply"],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip()
            return jsonify({"error": error or "apply failed"}), 500
        return jsonify({"status": "applied", "message": "Update applied. System is rebooting."})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "apply timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/update/rollback", methods=["POST"])
def update_rollback():
    """Roll back to the previous deployment."""
    body = request.get_json() or {}
    if not body.get("confirm"):
        return jsonify({"error": "must include {\"confirm\": true} to rollback"}), 400

    _ui_audit.append("update_rollback", {"source": "ui", "severity": "WARNING"})
    try:
        result = subprocess.run(
            [UPDATE_VERIFY, "rollback"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip()
            return jsonify({"error": error or "rollback failed"}), 500
        return jsonify({"status": "rolled_back", "message": "Rollback applied. System is rebooting."})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "rollback timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/update/health")
def update_health():
    """Return last health check result."""
    if HEALTH_LOG_FILE.exists():
        try:
            return jsonify(json.loads(HEALTH_LOG_FILE.read_text()))
        except Exception:
            return jsonify({"status": "unknown", "error": "failed to read health log"})
    return jsonify({"status": "unknown", "detail": "no health check has run yet"})


# ---------------------------------------------------------------------------
# Agent IPC helper (Unix socket in production, TCP fallback for dev)
# ---------------------------------------------------------------------------

def _agent_request(method: str, path: str, *, json_body=None, params=None, timeout=10):
    """Send an HTTP request to the agent service.

    Uses a Unix domain socket when AGENT_SOCKET is set (production),
    falls back to TCP via AGENT_URL for local development.
    """
    if AGENT_SOCKET:
        import http.client
        import json as _json
        import socket as _socket

        conn = http.client.HTTPConnection("localhost")
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(AGENT_SOCKET)
        conn.sock = sock

        headers = {"Host": "localhost"}
        body = None
        if json_body is not None:
            body = _json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        if params:
            from urllib.parse import urlencode
            path = f"{path}?{urlencode(params)}"

        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return _json.loads(data), resp.status
    else:
        url = f"{AGENT_URL}{path}"
        if method == "GET":
            r = requests.get(url, params=params, timeout=timeout)
        else:
            r = requests.post(url, json=json_body, timeout=timeout)
        return r.json(), r.status_code


# ---------------------------------------------------------------------------
# Agent mode endpoints (proxy to agent service)
# ---------------------------------------------------------------------------

@app.route("/api/agent/task", methods=["POST"])
def agent_submit_task():
    """Submit a task to the agent service."""
    body = request.get_json(silent=True) or {}
    try:
        data, status = _agent_request("POST", "/v1/task", json_body=body, timeout=30)
        _ui_audit.append("agent_task_submitted", {
            "intent_length": len(body.get("intent", "")),
            "mode": body.get("mode", "standard"),
        })
        return jsonify(data), status
    except Exception as e:
        return jsonify({"error": f"agent service unavailable: {e}"}), 503


@app.route("/api/agent/task/<task_id>")
def agent_get_task(task_id):
    """Get task status from agent service."""
    try:
        data, status = _agent_request("GET", f"/v1/task/{task_id}")
        return jsonify(data), status
    except Exception as e:
        return jsonify({"error": f"agent service unavailable: {e}"}), 503


@app.route("/api/agent/task/<task_id>/approve", methods=["POST"])
def agent_approve_steps(task_id):
    """Approve pending steps in an agent task."""
    body = request.get_json(silent=True) or {}
    try:
        data, status = _agent_request("POST", f"/v1/task/{task_id}/approve", json_body=body)
        _ui_audit.append("agent_steps_approved", {"task_id": task_id})
        return jsonify(data), status
    except Exception as e:
        return jsonify({"error": f"agent service unavailable: {e}"}), 503


@app.route("/api/agent/task/<task_id>/deny", methods=["POST"])
def agent_deny_steps(task_id):
    """Deny pending steps in an agent task."""
    body = request.get_json(silent=True) or {}
    try:
        data, status = _agent_request("POST", f"/v1/task/{task_id}/deny", json_body=body)
        _ui_audit.append("agent_steps_denied", {"task_id": task_id})
        return jsonify(data), status
    except Exception as e:
        return jsonify({"error": f"agent service unavailable: {e}"}), 503


@app.route("/api/agent/task/<task_id>/cancel", methods=["POST"])
def agent_cancel_task(task_id):
    """Cancel an agent task."""
    try:
        data, status = _agent_request("POST", f"/v1/task/{task_id}/cancel", json_body={})
        _ui_audit.append("agent_task_cancelled", {"task_id": task_id})
        return jsonify(data), status
    except Exception as e:
        return jsonify({"error": f"agent service unavailable: {e}"}), 503


@app.route("/api/agent/tasks")
def agent_list_tasks():
    """List agent tasks."""
    limit = request.args.get("limit", 50)
    try:
        data, status = _agent_request("GET", "/v1/tasks", params={"limit": limit})
        return jsonify(data), status
    except Exception as e:
        return jsonify({"error": f"agent service unavailable: {e}"}), 503


@app.route("/api/agent/modes")
def agent_list_modes():
    """List available agent operating modes."""
    try:
        data, status = _agent_request("GET", "/v1/modes", timeout=5)
        return jsonify(data), status
    except Exception as e:
        return jsonify({"error": f"agent service unavailable: {e}"}), 503


def main():
    logging.basicConfig(level=logging.INFO)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE
    bind = os.getenv("BIND_ADDR", "0.0.0.0:8480")
    host, port = bind.rsplit(":", 1)
    log.info("secure-ai-ui starting on %s", bind)
    app.run(host=host, port=int(port), debug=False)


if __name__ == "__main__":
    main()
