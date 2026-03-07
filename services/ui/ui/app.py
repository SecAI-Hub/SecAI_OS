"""
Secure AI Appliance - Local Web UI

Chat interface + model management + image/video generation.
Talks to local services only. One-click model download flows through
the airlock (if enabled) into quarantine for automatic scanning.
"""

import json
import logging
import os
import shutil
import subprocess
import threading
from pathlib import Path

import requests
import yaml
from flask import Flask, Response, jsonify, render_template, request

log = logging.getLogger("ui")

app = Flask(__name__, template_folder="templates", static_folder="static")

INFERENCE_URL = os.getenv("INFERENCE_URL", "http://127.0.0.1:8465")
DIFFUSION_URL = os.getenv("DIFFUSION_URL", "http://127.0.0.1:8455")
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://127.0.0.1:8470")
TOOL_FIREWALL_URL = os.getenv("TOOL_FIREWALL_URL", "http://127.0.0.1:8475")
AIRLOCK_URL = os.getenv("AIRLOCK_URL", "http://127.0.0.1:8490")
APPLIANCE_CONFIG = os.getenv("APPLIANCE_CONFIG", "/etc/secure-ai/config/appliance.yaml")
QUARANTINE_DIR = Path(os.getenv("QUARANTINE_DIR", "/var/lib/secure-ai/quarantine"))

ALLOWED_EXTENSIONS = {".gguf", ".safetensors"}
MAX_UPLOAD_SIZE = 50 * 1024 * 1024 * 1024  # 50 GB
SECURE_AI_ROOT = Path(os.getenv("SECURE_AI_ROOT", "/var/lib/secure-ai"))

# Pre-curated model catalog — users can download these with one click.
# All URLs point to Hugging Face (allowlisted source).
MODEL_CATALOG = [
    {
        "name": "Phi-3 Mini 3.8B (Q4_K_M)",
        "type": "llm",
        "filename": "Phi-3-mini-4k-instruct-q4.gguf",
        "url": "https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf",
        "size_gb": 2.3,
        "vram_gb": 4,
        "description": "Fast, small LLM. Good for testing and low-VRAM systems.",
    },
    {
        "name": "Mistral 7B Instruct (Q4_K_M)",
        "type": "llm",
        "filename": "mistral-7b-instruct-v0.3.Q4_K_M.gguf",
        "url": "https://huggingface.co/MaziyarPanahi/Mistral-7B-Instruct-v0.3-GGUF/resolve/main/Mistral-7B-Instruct-v0.3.Q4_K_M.gguf",
        "size_gb": 4.4,
        "vram_gb": 6,
        "description": "General-purpose LLM. Good balance of speed and quality.",
    },
    {
        "name": "Llama 3.1 8B Instruct (Q4_K_M)",
        "type": "llm",
        "filename": "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
        "url": "https://huggingface.co/bartowski/Meta-Llama-3.1-8B-Instruct-GGUF/resolve/main/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
        "size_gb": 4.9,
        "vram_gb": 7,
        "description": "Strong reasoning and instruction following.",
    },
    {
        "name": "Stable Diffusion XL Base",
        "type": "diffusion",
        "filename": "stable-diffusion-xl-base-1.0",
        "url": "https://huggingface.co/stabilityai/stable-diffusion-xl-base-1.0",
        "size_gb": 6.9,
        "vram_gb": 8,
        "description": "Image generation. 1024x1024 output. Requires 8GB+ VRAM.",
    },
    {
        "name": "Stable Diffusion 1.5",
        "type": "diffusion",
        "filename": "stable-diffusion-v1-5",
        "url": "https://huggingface.co/stable-diffusion-v1-5/stable-diffusion-v1-5",
        "size_gb": 4.3,
        "vram_gb": 4,
        "description": "Image generation. 512x512 output. Lower VRAM requirement.",
    },
    {
        "name": "Stable Video Diffusion XT",
        "type": "diffusion",
        "filename": "stable-video-diffusion-img2vid-xt",
        "url": "https://huggingface.co/stabilityai/stable-video-diffusion-img2vid-xt",
        "size_gb": 9.6,
        "vram_gb": 16,
        "description": "Video generation from image. 25 frames. Requires 16GB+ VRAM.",
    },
]

# Track active downloads
_active_downloads = {}
_download_lock = threading.Lock()


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
    config = load_appliance_config()
    return render_template("index.html", config=config)


@app.route("/chat")
def chat_page():
    config = load_appliance_config()
    return render_template("index.html", config=config)


@app.route("/models")
def models_page():
    return render_template("models.html")


@app.route("/generate")
def generate_page():
    return render_template("generate.html")


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

    thread = threading.Thread(
        target=_background_download,
        args=(url, filename, model_type),
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


def _background_download(url: str, filename: str, model_type: str):
    """Download a model file into quarantine in the background."""
    try:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

        if model_type == "diffusion":
            _download_diffusion_model(url, filename)
        else:
            _download_single_file(url, filename)

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


def _download_single_file(url: str, filename: str):
    """Download a single file (LLM GGUF) into quarantine."""
    dest = QUARANTINE_DIR / filename
    source_meta = QUARANTINE_DIR / f".{filename}.source"

    resp = requests.get(url, stream=True, timeout=30)
    resp.raise_for_status()
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

    The file goes into quarantine and is automatically scanned and promoted.
    """
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
            "message": "File is in quarantine. It will be automatically scanned and promoted.",
        }), 202

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
    for name, url in [
        ("registry", REGISTRY_URL),
        ("inference", INFERENCE_URL),
        ("diffusion", DIFFUSION_URL),
        ("tool_firewall", TOOL_FIREWALL_URL),
        ("airlock", AIRLOCK_URL),
    ]:
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
