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
SEARCH_MEDIATOR_URL = os.getenv("SEARCH_MEDIATOR_URL", "http://127.0.0.1:8485")
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
    for name, url in [
        ("registry", REGISTRY_URL),
        ("inference", INFERENCE_URL),
        ("diffusion", DIFFUSION_URL),
        ("tool_firewall", TOOL_FIREWALL_URL),
        ("airlock", AIRLOCK_URL),
        ("search", SEARCH_MEDIATOR_URL),
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


def main():
    logging.basicConfig(level=logging.INFO)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE
    bind = os.getenv("BIND_ADDR", "0.0.0.0:8480")
    host, port = bind.rsplit(":", 1)
    log.info("secure-ai-ui starting on %s", bind)
    app.run(host=host, port=int(port), debug=False)


if __name__ == "__main__":
    main()
