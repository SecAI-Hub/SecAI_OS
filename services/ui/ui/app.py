"""
Secure AI Appliance - Local Web UI

Chat interface + model management. Talks to local services only.
"""

import json
import logging
import os
import shutil
from pathlib import Path

import requests
import yaml
from flask import Flask, Response, jsonify, render_template, request

log = logging.getLogger("ui")

app = Flask(__name__, template_folder="templates", static_folder="static")

INFERENCE_URL = os.getenv("INFERENCE_URL", "http://127.0.0.1:8465")
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://127.0.0.1:8470")
TOOL_FIREWALL_URL = os.getenv("TOOL_FIREWALL_URL", "http://127.0.0.1:8475")
AIRLOCK_URL = os.getenv("AIRLOCK_URL", "http://127.0.0.1:8490")
APPLIANCE_CONFIG = os.getenv("APPLIANCE_CONFIG", "/etc/secure-ai/config/appliance.yaml")
QUARANTINE_DIR = Path(os.getenv("QUARANTINE_DIR", "/var/lib/secure-ai/quarantine"))

ALLOWED_EXTENSIONS = {".gguf", ".safetensors"}
MAX_UPLOAD_SIZE = 50 * 1024 * 1024 * 1024  # 50 GB
SECURE_AI_ROOT = Path(os.getenv("SECURE_AI_ROOT", "/var/lib/secure-ai"))


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
    # On first boot or with no models, redirect to setup
    if is_first_boot() or not has_models():
        return render_template("setup.html")
    config = load_appliance_config()
    return render_template("index.html", config=config)


@app.route("/chat")
def chat_page():
    config = load_appliance_config()
    return render_template("index.html", config=config)


@app.route("/models")
def models_page():
    return render_template("models.html")


# --- API: Models ---

@app.route("/api/models")
def list_models():
    try:
        resp = requests.get(f"{REGISTRY_URL}/v1/models", timeout=5)
        return jsonify(resp.json())
    except requests.ConnectionError:
        return jsonify([])


@app.route("/api/models/verify", methods=["POST"])
def verify_model():
    name = request.json.get("name", "")
    try:
        resp = requests.post(f"{REGISTRY_URL}/v1/model/verify?name={name}", timeout=30)
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
    """
    # Handle file upload
    if "file" in request.files:
        uploaded = request.files["file"]
        if not uploaded.filename:
            return jsonify({"error": "no file selected"}), 400

        ext = Path(uploaded.filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({
                "error": f"format not allowed: {ext}",
                "allowed": list(ALLOWED_EXTENSIONS),
            }), 400

        dest = QUARANTINE_DIR / uploaded.filename
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        uploaded.save(str(dest))
        log.info("imported via upload: %s -> %s", uploaded.filename, dest)
        return jsonify({
            "status": "queued",
            "filename": uploaded.filename,
            "message": "File is in quarantine. It will be scanned and promoted automatically.",
        }), 202

    # Handle local path import
    body = request.get_json(silent=True) or {}
    local_path = body.get("path", "")
    if local_path:
        src = Path(local_path)
        if not src.exists():
            return jsonify({"error": f"file not found: {local_path}"}), 404
        if not src.is_file():
            return jsonify({"error": "path is not a file"}), 400

        ext = src.suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({
                "error": f"format not allowed: {ext}",
                "allowed": list(ALLOWED_EXTENSIONS),
            }), 400

        dest = QUARANTINE_DIR / src.name
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src), str(dest))
        log.info("imported from path: %s -> %s", src, dest)
        return jsonify({
            "status": "queued",
            "filename": src.name,
            "message": "File is in quarantine. It will be scanned and promoted automatically.",
        }), 202

    return jsonify({"error": "provide a file upload or a JSON body with 'path'"}), 400


@app.route("/api/models/quarantine")
def quarantine_status():
    """List files currently in quarantine (pending scan/promotion)."""
    if not QUARANTINE_DIR.exists():
        return jsonify([])
    files = []
    for f in sorted(QUARANTINE_DIR.iterdir()):
        if f.is_file() and not f.name.startswith("."):
            files.append({
                "filename": f.name,
                "size_bytes": f.stat().st_size,
            })
    return jsonify(files)


# --- API: Chat ---

@app.route("/api/chat", methods=["POST"])
def chat():
    body = request.get_json()
    messages = body.get("messages", [])

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


# --- API: Status ---

@app.route("/api/status")
def status():
    checks = {}
    for name, url in [("registry", REGISTRY_URL), ("inference", INFERENCE_URL), ("tool_firewall", TOOL_FIREWALL_URL), ("airlock", AIRLOCK_URL)]:
        try:
            r = requests.get(f"{url}/health", timeout=2)
            checks[name] = r.json()
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


def main():
    logging.basicConfig(level=logging.INFO)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE
    bind = os.getenv("BIND_ADDR", "0.0.0.0:8480")
    host, port = bind.rsplit(":", 1)
    log.info("secure-ai-ui starting on %s", bind)
    app.run(host=host, port=int(port), debug=False)


if __name__ == "__main__":
    main()
