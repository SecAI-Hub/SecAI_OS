"""
Secure AI Appliance - Diffusion Worker

Image and video generation service using the diffusers library.
Runs locally with no internet access (PrivateNetwork=yes).
Models are loaded locally from the registry; runtime admission does not verify model integrity.
"""

import base64
import binascii
import ctypes
import errno
import hmac
import io
import json
import logging
import os
import secrets
import stat
import sys
import threading
import time
import warnings
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml
from common import diffusion_registry, runtime_assurance
from flask import Flask, g, has_request_context, jsonify, request, send_file

log = logging.getLogger("diffusion-worker")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(
    os.getenv("MAX_REQUEST_BODY_BYTES", str(24 * 1024 * 1024))
)

REGISTRY_DIR = Path(os.getenv("REGISTRY_DIR", "/var/lib/secure-ai/vault/models"))
APPLIANCE_CONFIG = os.getenv("APPLIANCE_CONFIG", "/etc/secure-ai/config/appliance.yaml")
BIND_ADDR = os.getenv("BIND_ADDR", "0.0.0.0:8455")
OUTPUTS_DIR = Path(os.getenv("OUTPUTS_DIR", "/var/lib/secure-ai/vault/outputs"))
OUTPUT_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".webm"}
MAX_RESOLUTION = int(os.getenv("MAX_RESOLUTION", "2048"))
MAX_STEPS = int(os.getenv("MAX_STEPS", "100"))
MAX_FRAMES = int(os.getenv("MAX_FRAMES", "120"))
VIDEO_DIMENSION_MULTIPLE = int(os.getenv("VIDEO_DIMENSION_MULTIPLE", "16"))
DEVICE_PREFERENCE = os.getenv("DIFFUSION_DEVICE_PREFERENCE", "auto").strip().lower()
CPU_OFFLOAD = os.getenv("DIFFUSION_CPU_OFFLOAD", "0").strip().lower()
SERVICE_TOKEN_PATH = Path(
    os.getenv("SERVICE_TOKEN_PATH", "/run/secure-ai/service-token")
)
MAX_INPUT_IMAGE_BYTES = int(
    os.getenv("MAX_INPUT_IMAGE_BYTES", str(16 * 1024 * 1024))
)
MAX_INPUT_IMAGE_PIXELS = int(
    os.getenv("MAX_INPUT_IMAGE_PIXELS", str(16_777_216))
)
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://127.0.0.1:8470")
REGISTRY_VERIFY_TOKEN_PATH = Path(os.getenv("REGISTRY_VERIFY_TOKEN_PATH", "/run/secure-ai/registry-verify-token"))
ATTESTOR_URL = os.getenv("ATTESTOR_URL", "http://127.0.0.1:8505")
ATTESTOR_TOKEN_PATH = Path(os.getenv("ATTESTOR_TOKEN_PATH", "/run/secure-ai/attestor-token"))
MAX_CONCURRENT_GENERATIONS = max(
    1, int(os.getenv("MAX_CONCURRENT_GENERATIONS", "1"))
)
ALLOWED_INPUT_IMAGE_FORMATS = {"PNG", "JPEG", "WEBP"}

# Loaded pipeline instances (lazy init)
_pipelines: dict[str, Any] = {}
_generation_slots = threading.BoundedSemaphore(MAX_CONCURRENT_GENERATIONS)


def _read_service_token() -> str:
    try:
        return SERVICE_TOKEN_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


@app.before_request
def _protect_generation_endpoints():
    """Require service identity for every non-health API and reserve GPU capacity."""
    if not request.path.startswith("/v1/"):
        return None

    token = _read_service_token()
    if not token:
        return jsonify({"error": "service authentication unavailable"}), 503
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or not hmac.compare_digest(auth[7:], token):
        return jsonify({"error": "forbidden"}), 403

    if request.path.startswith("/v1/generate/"):
        try:
            _require_generation_runtime()
        except runtime_assurance.RuntimeAssuranceUnavailable:
            return _runtime_denial()
        if not _generation_slots.acquire(blocking=False):
            return jsonify({"error": "generation capacity exhausted"}), 429
        g.generation_slot_acquired = True
    return None


@app.teardown_request
def _release_generation_slot(_error=None):
    if getattr(g, "generation_slot_acquired", False):
        _generation_slots.release()
        g.generation_slot_acquired = False


def _is_sandbox_deployment() -> bool:
    return os.getenv("SECURE_AI_DEPLOYMENT_MODE", "").strip().lower() == "sandbox"


def _require_generation_runtime() -> str | None:
    """Read a current native decision; sandbox has unsupported host assurance."""
    if _is_sandbox_deployment():
        return None
    try:
        token = ATTESTOR_TOKEN_PATH.read_text(encoding="utf-8").strip()
        mode = runtime_assurance.require_runtime(ATTESTOR_URL, token)
    except (OSError, ValueError, UnicodeError):
        raise runtime_assurance.RuntimeAssuranceUnavailable() from None
    if mode not in {"required", "optional", "no_gpu"}:
        raise runtime_assurance.RuntimeAssuranceUnavailable()
    return mode


def _runtime_denial():
    return jsonify({"error": runtime_assurance.UNAVAILABLE,
                    "code": "runtime_assurance_unavailable"}), 503


def _pipeline_binding(gpu_mode: str | None) -> tuple[str | None, str, bool]:
    device = _get_device(gpu_mode)
    return gpu_mode, device, device in {"cuda", "xpu"} and _cpu_offload_enabled()


def _verified_diffusion_model(filename: str):
    try:
        token = REGISTRY_VERIFY_TOKEN_PATH.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        raise diffusion_registry.ModelIntegrityUnavailable() from None
    return diffusion_registry.verify_model(REGISTRY_URL, token, filename, REGISTRY_DIR,
                                           sandbox=_is_sandbox_deployment())


def _model_denial():
    return jsonify({"error": diffusion_registry.UNAVAILABLE,
                    "code": "model_integrity_unavailable"}), 503


def _select_generation_model(filename: str):
    verified = _verified_diffusion_model(filename)
    # Local discovery supplies capability diagnostics only after enrollment has
    # been verified. Its paths never authorize loading on their own.
    matches = [model for model in _find_diffusion_models()
               if model["name"] == verified.filename and model["path"] == verified.path]
    if len(matches) != 1:
        raise diffusion_registry.ModelIntegrityUnavailable()
    g.model_binding = verified
    return matches[0]


def _recheck_model_binding(expected):
    if _verified_diffusion_model(expected.filename) != expected:
        raise diffusion_registry.ModelIntegrityUnavailable()


def _prepare_generation_pipeline(model_path: str, pipeline_type: str):
    binding = _pipeline_binding(_require_generation_runtime())
    _recheck_model_binding(g.model_binding)
    g.pipeline_binding = binding
    return _load_pipeline(model_path, pipeline_type, binding=binding, verified=g.model_binding)


def _recheck_pipeline_runtime():
    _recheck_model_binding(g.model_binding)
    if _pipeline_binding(_require_generation_runtime()) != g.pipeline_binding:
        raise runtime_assurance.RuntimeAssuranceUnavailable()



def _env_truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _cpu_offload_enabled() -> bool:
    return _env_truthy(os.getenv("DIFFUSION_CPU_OFFLOAD", CPU_OFFLOAD))


def _device_preference() -> str:
    preference = os.getenv("DIFFUSION_DEVICE_PREFERENCE", DEVICE_PREFERENCE).strip().lower()
    return preference if preference in {"auto", "cuda", "rocm", "mps", "xpu", "cpu"} else "auto"


def load_config() -> dict:
    try:
        with open(APPLIANCE_CONFIG) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def _legacy_get_device():
    """Detect best available compute device.

    Priority: CUDA (NVIDIA) > ROCm (AMD) > MPS (Apple) > XPU (Intel) > CPU
    All backends keep data local — no cloud compute.
    """
    try:
        import torch

        if torch.cuda.is_available():
            return "cuda"
        # ROCm exposes AMD GPUs via torch.cuda when built with ROCm
        # but we also check the HIP runtime explicitly
        if hasattr(torch.version, "hip") and torch.version.hip is not None:
            return "cuda"  # ROCm uses the cuda device interface in PyTorch
        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            return "mps"
        # Intel XPU (Arc / Data Center) via Intel Extension for PyTorch
        if hasattr(torch, "xpu") and torch.xpu.is_available():
            return "xpu"
    except ImportError:
        pass
    return "cpu"


def _torch_backend_available(torch, backend: str) -> bool:
    if backend == "cpu":
        return True
    if backend in {"cuda", "rocm"}:
        if not hasattr(torch, "cuda") or not torch.cuda.is_available():
            return False
        hip_runtime = bool(getattr(getattr(torch, "version", object()), "hip", None))
        return hip_runtime if backend == "rocm" else not hip_runtime
    if backend == "mps":
        return bool(
            hasattr(torch, "backends")
            and hasattr(torch.backends, "mps")
            and torch.backends.mps.is_available()
        )
    if backend == "xpu":
        return bool(hasattr(torch, "xpu") and torch.xpu.is_available())
    return False


def _get_device(gpu_mode: str | None = None):
    """Detect compute hardware, respecting explicit no-GPU admission."""
    if gpu_mode == "no_gpu":
        return "cpu"
    try:
        import torch

        preference = _device_preference()
        if preference == "cpu":
            return "cpu"
        if preference in {"cuda", "rocm", "mps", "xpu"}:
            if _torch_backend_available(torch, preference):
                return "cuda" if preference in {"cuda", "rocm"} else preference
            log.warning("requested diffusion device %s is unavailable; falling back to auto", preference)

        if hasattr(torch, "cuda") and torch.cuda.is_available():
            return "cuda"
        if hasattr(torch, "backends") and hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            return "mps"
        if hasattr(torch, "xpu") and torch.xpu.is_available():
            return "xpu"
    except ImportError:
        pass
    return "cpu"


def _clamp(value, low, high):
    return max(low, min(high, value))


def _optional_bounded_int(value, default: int, low: int, high: int) -> int:
    """Parse an optional integer and keep it within bounds."""
    if value is None:
        return default
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return _clamp(value, low, high)


def _decode_input_image(image_b64: str):
    """Strictly decode and validate an untrusted base64 image.

    The encoded and decoded byte counts are bounded before Pillow parses the
    payload. Pillow verifies the container once, then a fresh decoder loads
    pixels under a hard decompression-bomb ceiling.
    """
    if not isinstance(image_b64, str) or not image_b64:
        raise ValueError("image (base64) is required")
    max_encoded = ((MAX_INPUT_IMAGE_BYTES + 2) // 3) * 4
    if len(image_b64) > max_encoded:
        raise ValueError("encoded image exceeds size limit")
    try:
        img_bytes = base64.b64decode(image_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("image is not valid base64") from exc
    if len(img_bytes) > MAX_INPUT_IMAGE_BYTES:
        raise ValueError("decoded image exceeds size limit")

    from PIL import Image

    Image.MAX_IMAGE_PIXELS = MAX_INPUT_IMAGE_PIXELS
    bomb_warning = getattr(Image, "DecompressionBombWarning", Warning)
    with warnings.catch_warnings():
        warnings.simplefilter("error", bomb_warning)
        probe = Image.open(io.BytesIO(img_bytes))
        try:
            image_format = str(getattr(probe, "format", "") or "").upper()
            if image_format not in ALLOWED_INPUT_IMAGE_FORMATS:
                raise ValueError(
                    f"unsupported image format: {image_format or 'unknown'}"
                )
            width, height = probe.size
            if (
                width <= 0
                or height <= 0
                or width * height > MAX_INPUT_IMAGE_PIXELS
            ):
                raise ValueError("image dimensions exceed safety limit")
            probe.verify()
        finally:
            close = getattr(probe, "close", None)
            if callable(close):
                close()

        decoded = Image.open(io.BytesIO(img_bytes))
        try:
            decoded.load()
            converted = decoded.convert("RGB")
        finally:
            close = getattr(decoded, "close", None)
            if callable(close):
                close()
    return converted


def _load_pipeline(model_path: str, pipeline_type: str = "image", *, binding=None, verified=None):
    """Load a diffusion pipeline from a local model directory or safetensors file."""
    if binding is None:
        # Direct callers also require admission and do not need a Flask context.
        binding = _pipeline_binding(_require_generation_runtime())
    if verified is None:
        verified = _verified_diffusion_model(Path(model_path).name)
    if verified.path != model_path:
        raise diffusion_registry.ModelIntegrityUnavailable()
    gpu_mode, device, offload = binding
    if has_request_context():
        g.pipeline_binding = binding
        g.model_binding = verified
    cache_key = json.dumps([verified.name, verified.filename, verified.sha256, model_path,
                            pipeline_type, gpu_mode, device, offload], separators=(",", ":"))
    if cache_key in _pipelines:
        return _pipelines[cache_key]

    try:
        import torch
        from diffusers import (
            AutoPipelineForImage2Image,
            AutoPipelineForText2Image,
            DiffusionPipeline,
        )
    except ImportError:
        raise RuntimeError("diffusers library not installed")

    # float16 for GPU backends; float32 for CPU (no half-precision support on most CPUs)
    dtype = torch.float16 if device in ("cuda", "mps", "xpu") else torch.float32

    model_dir = Path(model_path)
    if not model_dir.exists():
        raise FileNotFoundError(f"model not found: {model_path}")

    log.info("loading diffusion pipeline from %s (device=%s, dtype=%s)", model_path, device, dtype)
    load_kwargs = {
        "torch_dtype": dtype,
        "local_files_only": True,
        "use_safetensors": True,
        "trust_remote_code": False,
    }
    if any(model_dir.rglob("*.fp16.safetensors")):
        load_kwargs["variant"] = "fp16"

    if pipeline_type == "img2img":
        pipe = AutoPipelineForImage2Image.from_pretrained(
            str(model_dir), **load_kwargs
        )
    elif pipeline_type == "video":
        pipe = DiffusionPipeline.from_pretrained(
            str(model_dir), **load_kwargs
        )
    else:
        pipe = AutoPipelineForText2Image.from_pretrained(
            str(model_dir), **load_kwargs
        )

    pipe = pipe.to(device)

    # Memory optimizations for GPU backends
    if device in ("cuda", "xpu"):
        if device == "cuda":
            try:
                torch.backends.cuda.matmul.allow_tf32 = True
            except Exception:
                pass
        try:
            pipe.enable_xformers_memory_efficient_attention()
        except Exception:
            pass
        try:
            pipe.enable_attention_slicing()
        except Exception:
            pass
        if offload:
            try:
                pipe.enable_model_cpu_offload()
            except Exception:
                pass

    # Catch a changed enrollment or on-disk tree while an uncached load ran.
    _recheck_model_binding(verified)
    _pipelines[cache_key] = pipe
    log.info("pipeline loaded: %s", cache_key)
    return pipe


def _image_conditioned_video_markers(class_name: str, entry_name: str = "") -> bool:
    marker = f"{class_name} {entry_name}".lower()
    return any(token in marker for token in (
        "stablevideodiffusion",
        "img2vid",
        "image2video",
        "image-to-video",
        "imagetovideo",
        "i2v",
        "svd",
    ))


def _supports_image_to_image(class_name: str, entry_name: str = "") -> bool:
    marker = f"{class_name} {entry_name}".lower()
    return any(token in marker for token in (
        "img2img",
        "image2image",
        "image-to-image",
        "stablediffusion",
        "stable-diffusion",
        "stable_diffusion",
        "sdxl",
        "flux",
        "kandinsky",
        "kolors",
    ))


def _model_capabilities(entry: Path, model_type: str, class_name: str) -> list[str]:
    """Return generation capabilities advertised by a local diffusers model."""
    if model_type == "video":
        if _image_conditioned_video_markers(class_name, entry.name):
            return ["img2vid"]
        return ["txt2vid"]
    if model_type == "img2img":
        return ["img2img"]

    capabilities = ["txt2img"]
    if _supports_image_to_image(class_name, entry.name):
        capabilities.append("img2img")
    return capabilities


def _find_diffusion_models() -> list[dict[str, Any]]:
    """Find diffusion model directories in the registry."""
    models: list[dict[str, Any]] = []
    if not REGISTRY_DIR.exists():
        return models
    for entry in sorted(REGISTRY_DIR.iterdir()):
        if entry.is_dir():
            # Check for model_index.json (standard diffusers model marker)
            if (entry / "model_index.json").exists():
                try:
                    with open(entry / "model_index.json") as f:
                        index = json.load(f)
                    model_type = "image"
                    class_name = str(index.get("_class_name", "") or "")
                    class_marker = class_name.lower()
                    entry_marker = entry.name.lower()
                    if (
                        "video" in class_marker
                        or "ltx" in class_marker
                        or entry_marker.startswith("video-")
                        or "-video" in entry_marker
                    ):
                        model_type = "video"
                    elif "img2img" in class_marker or "image2image" in class_marker:
                        model_type = "img2img"
                    capabilities = _model_capabilities(entry, model_type, class_name)
                    models.append({
                        "name": entry.name,
                        "path": str(entry),
                        "type": model_type,
                        "class": class_name,
                        "capabilities": capabilities,
                    })
                except (json.JSONDecodeError, OSError):
                    models.append({
                        "name": entry.name,
                        "path": str(entry),
                        "type": "image",
                        "class": "unknown",
                        "capabilities": ["txt2img"],
                    })
    return models


def _is_image_conditioned_video_model(model_info: dict) -> bool:
    """Return True when a video pipeline expects an input image."""
    capabilities = model_info.get("capabilities")
    if isinstance(capabilities, list) and "img2vid" in capabilities:
        return True
    class_name = str(model_info.get("class", "") or "")
    return _image_conditioned_video_markers(class_name, str(model_info.get("name", "") or ""))


def _video_encoder_image_size(pipe) -> int | None:
    """Return the video encoder image size when available."""
    image_encoder = getattr(pipe, "image_encoder", None)
    config = getattr(image_encoder, "config", None)
    size = getattr(config, "image_size", None)
    if size is None:
        return None
    try:
        size = int(size)
    except (TypeError, ValueError):
        return None
    return size if size > 0 else None


def _prepare_video_conditioning_input(init_image, pipe, torch):
    """Prepare an input image for image-conditioned video pipelines.

    Diffusers' Stable Video Diffusion pipeline hardcodes a 224x224 resize for
    PIL inputs. Some tiny or compatibility test models use smaller encoder
    sizes, so convert to a tensor at the model's declared image size when it
    differs from the upstream default.
    """
    target_size = _video_encoder_image_size(pipe)
    if not target_size or target_size == 224:
        return init_image

    import numpy as np

    if init_image.size != (target_size, target_size):
        init_image = init_image.resize((target_size, target_size))

    arr = np.asarray(init_image).astype("float32") / 255.0
    return torch.from_numpy(arr).permute(2, 0, 1).unsqueeze(0)


def _round_up_dimension(value: int, multiple: int, minimum: int) -> int:
    """Round image dimensions up to a safe multiple for diffusion preprocessors."""
    value = max(minimum, int(value))
    if value % multiple == 0:
        return value
    return value + (multiple - (value % multiple))


def _normalize_img2img_input(init_image):
    """Resize img2img inputs to a safe size for latent-space preprocessing."""
    w, h = init_image.size
    if w <= 0 or h <= 0:
        raise ValueError("image dimensions must be > 0")

    if w > MAX_RESOLUTION or h > MAX_RESOLUTION:
        ratio = min(MAX_RESOLUTION / w, MAX_RESOLUTION / h)
        init_image = init_image.resize((max(1, int(w * ratio)), max(1, int(h * ratio))))
        w, h = init_image.size

    target_w = _round_up_dimension(w, multiple=8, minimum=8)
    target_h = _round_up_dimension(h, multiple=8, minimum=8)
    if (target_w, target_h) != (w, h):
        init_image = init_image.resize((target_w, target_h))
    return init_image


def _normalize_generation_dimensions(width: int, height: int) -> tuple[int, int]:
    """Round generation dimensions up to safe multiples for diffusion pipelines."""
    return (
        _round_up_dimension(width, multiple=8, minimum=8),
        _round_up_dimension(height, multiple=8, minimum=8),
    )


def _normalize_video_dimensions(width: int, height: int) -> tuple[int, int]:
    """Round video dimensions up to codec-friendly multiples before export."""
    return (
        _round_up_dimension(width, multiple=VIDEO_DIMENSION_MULTIPLE, minimum=VIDEO_DIMENSION_MULTIPLE),
        _round_up_dimension(height, multiple=VIDEO_DIMENSION_MULTIPLE, minimum=VIDEO_DIMENSION_MULTIPLE),
    )


# --- Health ---

@app.route("/health")
def health():
    device = _get_device()
    models = _find_diffusion_models()
    gpu_info = _get_gpu_info()
    return jsonify({
        "status": "ok",
        "deployment_mode": "sandbox" if _is_sandbox_deployment() else "appliance",
        "host_assurance": "unsupported" if _is_sandbox_deployment() else "native",
        "device": device,
        "gpu": gpu_info,
        "loaded_pipelines": list(_pipelines.keys()),
        "available_models": len(models),
    })


def _get_gpu_info() -> dict:
    """Return GPU name and backend for diagnostics."""
    info = {
        "backend": "cpu",
        "name": "CPU",
        "selected_device": _get_device(),
        "device_preference": _device_preference(),
        "cpu_offload": _cpu_offload_enabled(),
    }
    try:
        import torch

        if torch.cuda.is_available():
            info["backend"] = "rocm" if (hasattr(torch.version, "hip") and torch.version.hip) else "cuda"
            info["name"] = torch.cuda.get_device_name(0)
            info["vram_mb"] = round(torch.cuda.get_device_properties(0).total_mem / 1048576)
        elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            info["backend"] = "mps"
            info["name"] = "Apple Silicon (Metal)"
        elif hasattr(torch, "xpu") and torch.xpu.is_available():
            info["backend"] = "xpu"
            info["name"] = torch.xpu.get_device_name(0)
    except Exception:
        pass
    return info


# --- List available diffusion models ---

@app.route("/v1/models")
def list_models():
    return jsonify(_find_diffusion_models())


def _open_output_root() -> int:
    """Anchor the configured output directory without following any component."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for component in OUTPUTS_DIR.absolute().parts[1:]:
            if component in {".", ".."}:
                raise OSError("unsafe output directory")
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_output_root(descriptor: int) -> None:
    """Reject root/mount replacement before publishing a response."""
    current = _open_output_root()
    try:
        before, after = os.fstat(descriptor), os.fstat(current)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise OSError("output directory replaced")
    finally:
        os.close(current)


def _open_output_file(root: int, filename: str) -> tuple[int, os.stat_result]:
    # Hold the checked inode so unlink/recreate cannot recycle its identity.
    identity = os.open(filename, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
    descriptor = None
    try:
        before = os.fstat(identity)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OSError("output is not a private regular file")
        descriptor = os.open(
            filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=root,
        )
        opened = os.fstat(descriptor)
        current = os.stat(filename, dir_fd=root, follow_symlinks=False)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)):
            raise OSError("output replaced during open")
        result = descriptor
        descriptor = None
        return result, opened
    finally:
        os.close(identity)
        if descriptor is not None:
            os.close(descriptor)


class _OutputPublicationError(OSError):
    def __init__(self, detail: str, *, published: bool | None, cleanup_ambiguous: bool):
        self.published = published
        self.cleanup_ambiguous = cleanup_ambiguous
        super().__init__(detail)


def _output_identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _output_directory_identity(fd: int) -> tuple:
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _output_label(fd: int) -> bytes | None:
    try:
        return os.getxattr(fd, "security.selinux")
    except OSError as exc:
        if exc.errno not in (errno.ENODATA, errno.ENOTSUP):
            raise
        return None


def _rename_output_no_replace(source: int, name: str, target: int, filename: str) -> None:
    # Same Linux primitive as the agent storage gateway; no overwrite fallback.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise OSError(errno.ENOTSUP, "atomic output publication unavailable")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(source, os.fsencode(name), target, os.fsencode(filename), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _publish_output(prefix: str, suffix: str, *, content: bytes | None = None,
                    serialize: Callable[[str], None] | None = None) -> tuple[Path, bytes]:
    """Publish one complete output; a batch is not an all-or-nothing transaction.

    Stage/entry checks reject observed swaps, not arbitrary same-UID writers
    racing the final check and rename/rmdir. Cleanup never recurses or removes
    an unknown entry. Once publication occurs, failure never rolls it back.
    """
    root = stage = payload = -1
    staging: str | None = None
    stage_identity = created = None
    published: bool | None = False
    ambiguous = rename_attempted = False
    failure = None
    result = b""
    filename = f"{prefix}_{int(time.time())}_{secrets.token_hex(16)}{suffix}"
    payload_name = "payload" + suffix

    def check_stage():
        if staging is None:
            raise OSError("private output workspace unavailable; cleanup ambiguous")
        held = _output_directory_identity(stage)
        current = os.stat(staging, dir_fd=root, follow_symlinks=False)
        named = (current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_gid)
        if (held != stage_identity or named != stage_identity or held[3] != os.geteuid()
                or not stat.S_ISDIR(held[2]) or stat.S_IMODE(held[2]) & 0o777 != 0o700):
            raise OSError("private output workspace changed; cleanup ambiguous")

    def check_payload(directory, name, expected=None):
        held = os.fstat(payload)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        value = _output_identity(held)
        if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1
                or (held.st_dev, held.st_ino) != created or _output_identity(named) != value
                or expected is not None and value != expected):
            raise OSError("output payload changed or is not singly linked; cleanup ambiguous")
        return value

    def check_root():
        _validate_output_root(root)
        if _output_directory_identity(root) != root_identity:
            raise OSError("output directory metadata changed")

    def publication_state() -> bool | None:
        # A trusted syscall wrapper can raise after rename already succeeded.
        # Classify only names bound to our still-held original payload inode.
        try:
            held = os.fstat(payload)
            if (held.st_dev, held.st_ino) != created or not stat.S_ISREG(held.st_mode):
                return None
            for directory, name, state in ((root, filename, True), (stage, payload_name, False)):
                try:
                    named = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if ((named.st_dev, named.st_ino, stat.S_IFMT(named.st_mode), named.st_uid) ==
                        (held.st_dev, held.st_ino, stat.S_IFMT(held.st_mode), held.st_uid)):
                    return state
        except OSError:
            return None
        return None

    try:
        if sys.platform != "linux" or (content is None) == (serialize is None):
            raise OSError("output publication requires Linux and one trusted producer")
        if (prefix, suffix) not in {("gen", ".png"), ("gen", ".mp4"), ("img2img", ".png")}:
            raise OSError("unsupported generated output name")
        root = _open_output_root()
        root_identity = _output_directory_identity(root)
        candidate = ".diffusion-write-" + secrets.token_hex(16)
        os.mkdir(candidate, 0o700, dir_fd=root)
        staging = candidate
        stage = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        stage_identity = _output_directory_identity(stage)
        check_stage()  # Inherited setgid is compatible with private access 0700.
        if _output_label(stage) != _output_label(root):
            raise OSError("output workspace changes the parent SELinux context")
        # Keep normal creation mode, umask, inherited group/default ACL semantics;
        # the private workspace prevents exposure until publication.
        payload = os.open(payload_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o666, dir_fd=stage)
        info = os.fstat(payload)
        created = info.st_dev, info.st_ino
        if serialize is not None:
            # Child encoders can resolve the parent's held directory descriptor
            # without inheriting it or traversing the replaceable public root.
            serialize(f"/proc/{os.getpid()}/fd/{stage}/{payload_name}")
        else:
            assert content is not None
            view = memoryview(content)
            while view:
                count = os.write(payload, view)
                if count <= 0:
                    raise OSError("short output write")
                view = view[count:]
        prepared = check_payload(stage, payload_name)
        os.lseek(payload, 0, os.SEEK_SET)
        if content is None:
            with os.fdopen(os.dup(payload), "rb") as stream:
                result = stream.read()
        else:
            offset = 0
            while chunk := os.read(payload, 1024**2):
                if chunk != content[offset:offset + len(chunk)]:
                    raise OSError("encoded PNG differs from staged output")
                offset += len(chunk)
            if offset != len(content):
                raise OSError("incomplete encoded PNG output")
            result = content
        check_payload(stage, payload_name, prepared)
        os.fsync(payload)
        check_root()
        check_stage()
        check_payload(stage, payload_name, prepared)
        rename_attempted = True
        _rename_output_no_replace(stage, payload_name, root, filename)
        published = True
        # Rename may change ctime; all other prepared inode/data metadata stays.
        published_identity = check_payload(root, filename)
        if published_identity[:-1] != prepared[:-1]:
            raise OSError("published output changed")
        os.fsync(stage)
        os.fsync(root)
        check_root()
    except BaseException as exc:  # noqa: BLE001 - cancellation must also clean proven private work.
        failure = exc
        if rename_attempted and published is False:
            published = publication_state()
    finally:
        try:
            if published is None:
                raise OSError("publication state unknown; cleanup ambiguous")
            if staging is not None:
                if stage < 0 or stage_identity is None:
                    raise OSError("workspace ownership unverified; cleanup ambiguous")
                check_stage()
                try:
                    os.stat(payload_name, dir_fd=stage, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    if payload < 0 or created is None:
                        raise OSError("payload ownership unverified; cleanup ambiguous")
                    check_payload(stage, payload_name)
                    os.unlink(payload_name, dir_fd=stage)
                check_stage()
                os.rmdir(staging, dir_fd=root)
                staging = None
                os.fsync(root)
            if published and failure is None:
                check_root()
                check_payload(root, filename, published_identity)
        except OSError as exc:
            ambiguous = True
            if failure is None or isinstance(failure, Exception):
                failure = OSError(f"{failure or ''}; output cleanup/final validation failed: {exc}")
            else:
                log.error("output cleanup failed during cancellation: %s", exc)
        finally:
            for fd in (payload, stage, root):
                if fd >= 0:
                    os.close(fd)
    if failure is not None:
        if not isinstance(failure, Exception):
            raise failure
        if published is None:
            detail = "output publication state unknown; durability or identity unconfirmed"
        else:
            detail = "output published; durability or identity unconfirmed" if published else "output not published"
        if ambiguous:
            detail += "; cleanup ambiguous; private workspace retained where present"
        raise _OutputPublicationError(detail, published=published,
                                      cleanup_ambiguous=ambiguous) from failure
    return OUTPUTS_DIR / filename, result


@app.route("/v1/outputs")
def list_outputs():
    """List only real generated outputs belonging to the anchored directory."""
    try:
        root = _open_output_root()
    except FileNotFoundError:
        return jsonify([])
    except OSError:
        return jsonify({"error": "outputs unavailable"}), 503
    outputs = []
    try:
        for filename in os.listdir(root):
            suffix = Path(filename).suffix.lower()
            if suffix not in OUTPUT_EXTENSIONS:
                continue
            try:
                descriptor, info = _open_output_file(root, filename)
            except OSError:
                continue
            os.close(descriptor)
            outputs.append({
                "filename": filename,
                "kind": "video" if suffix in {".mp4", ".webm"} else "image",
                "size_bytes": info.st_size,
                "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(info.st_mtime)),
                "url": f"/v1/outputs/{filename}",
            })
        _validate_output_root(root)
    except OSError:
        return jsonify({"error": "outputs unavailable"}), 503
    finally:
        os.close(root)
    outputs.sort(key=lambda item: item["modified_at"], reverse=True)
    return jsonify(outputs[:50])


@app.route("/v1/outputs/<path:filename>")
def get_output(filename: str):
    """Serve the validated open file, never reopen its pathname for transfer."""
    if Path(filename).name != filename:
        return jsonify({"error": "invalid output filename"}), 400
    if Path(filename).suffix.lower() not in OUTPUT_EXTENSIONS:
        return jsonify({"error": "output not found"}), 404
    root = descriptor = None
    stream = None
    try:
        root = _open_output_root()
        descriptor, info = _open_output_file(root, filename)
        _validate_output_root(root)
        stream = os.fdopen(descriptor, "rb")
        descriptor = None  # Ownership moved to the response stream.
        response = send_file(
            stream, download_name=filename, last_modified=info.st_mtime,
            etag=f"{info.st_dev}-{info.st_ino}-{info.st_mtime_ns}-{info.st_size}",
            conditional=False,
        )
        response.content_length = info.st_size
        response.make_conditional(request.environ, accept_ranges=True, complete_length=info.st_size)
        response.call_on_close(stream.close)
        stream = None  # WSGI response/wrapper closes the file on success.
        return response
    except OSError:
        return jsonify({"error": "output not found"}), 404
    finally:
        if stream is not None:
            stream.close()
        if descriptor is not None:
            os.close(descriptor)
        if root is not None:
            os.close(root)


# --- Image Generation ---

@app.route("/v1/generate/image", methods=["POST"])
def generate_image():
    body = request.get_json()
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    prompt = body.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "prompt is required"}), 400
    if len(prompt) > 2000:
        return jsonify({"error": "prompt too long (max 2000 chars)"}), 400

    negative_prompt = body.get("negative_prompt", "")
    model_name = body.get("model", "")
    if not isinstance(model_name, str) or not model_name:
        return jsonify({"error": "select a registered model before generating"}), 400
    width = _clamp(body.get("width", 512), 256, MAX_RESOLUTION)
    height = _clamp(body.get("height", 512), 256, MAX_RESOLUTION)
    steps = _clamp(body.get("steps", 30), 1, MAX_STEPS)
    guidance_scale = _clamp(body.get("guidance_scale", 7.5), 1.0, 30.0)
    seed = body.get("seed")
    num_images = _clamp(body.get("num_images", 1), 1, 4)

    try:
        model_info = _select_generation_model(model_name)
    except diffusion_registry.ModelIntegrityUnavailable:
        return _model_denial()

    if "txt2img" not in model_info.get("capabilities", ["txt2img"]):
        return jsonify({"error": f"model does not support text-to-image: {model_info['name']}"}), 400

    try:
        import torch

        pipe = _prepare_generation_pipeline(model_info["path"], "image")
        generator = None
        if seed is not None:
            generator = torch.Generator(device=g.pipeline_binding[1]).manual_seed(int(seed))

        start = time.monotonic()
        _recheck_pipeline_runtime()
        result = pipe(
            prompt=prompt,
            negative_prompt=negative_prompt or None,
            width=width,
            height=height,
            num_inference_steps=steps,
            guidance_scale=guidance_scale,
            generator=generator,
            num_images_per_prompt=num_images,
        )
        elapsed = round(time.monotonic() - start, 2)

        images_b64 = []
        saved_paths = []
        for img in result.images:
            # Encode to base64 PNG
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            encoded = buf.getvalue()
            images_b64.append(base64.b64encode(encoded).decode())
            out_path, _ = _publish_output("gen", ".png", content=encoded)
            saved_paths.append(str(out_path))

        log.info("generated %d image(s) in %.2fs model=%s", num_images, elapsed, model_info["name"])

        return jsonify({
            "images": images_b64,
            "saved_to": saved_paths,
            "model": model_info["name"],
            "elapsed_seconds": elapsed,
            "parameters": {
                "prompt": prompt,
                "width": width,
                "height": height,
                "steps": steps,
                "guidance_scale": guidance_scale,
                "seed": seed,
            },
        })

    except diffusion_registry.ModelIntegrityUnavailable:
        return _model_denial()
    except runtime_assurance.RuntimeAssuranceUnavailable:
        return _runtime_denial()
    except _OutputPublicationError as exc:
        log.exception("image output publication failed")
        return jsonify({"error": str(exc)}), 500
    except Exception:
        log.exception("image generation failed")
        return jsonify({"error": "image generation failed"}), 500


# --- Video Generation ---

@app.route("/v1/generate/video", methods=["POST"])
def generate_video():
    body = request.get_json()
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    prompt = body.get("prompt", "").strip()
    if len(prompt) > 2000:
        return jsonify({"error": "prompt too long (max 2000 chars)"}), 400

    negative_prompt = body.get("negative_prompt", "")
    model_name = body.get("model", "")
    if not isinstance(model_name, str) or not model_name:
        return jsonify({"error": "select a registered model before generating"}), 400
    image_b64 = body.get("image", "")
    requested_width = body.get("width")
    requested_height = body.get("height")
    width = _optional_bounded_int(requested_width, 512, 32, MAX_RESOLUTION)
    height = _optional_bounded_int(requested_height, 512, 32, MAX_RESOLUTION)
    width, height = _normalize_video_dimensions(width, height)
    num_frames = _clamp(body.get("num_frames", 25), 4, MAX_FRAMES)
    steps = _clamp(body.get("steps", 25), 1, MAX_STEPS)
    fps = _clamp(body.get("fps", 8), 1, 30)
    seed = body.get("seed")

    try:
        model_info = _select_generation_model(model_name)
    except diffusion_registry.ModelIntegrityUnavailable:
        return _model_denial()

    image_conditioned = _is_image_conditioned_video_model(model_info)
    if image_conditioned:
        if not image_b64:
            return jsonify({
                "error": "image (base64) is required for this video model",
                "model_class": model_info.get("class", "unknown"),
            }), 400
    else:
        if not prompt:
            return jsonify({"error": "prompt is required"}), 400
    required_capability = "img2vid" if image_b64 else "txt2vid"
    if required_capability not in model_info.get("capabilities", []):
        label = "image-to-video" if required_capability == "img2vid" else "text-to-video"
        return jsonify({"error": f"model does not support {label}: {model_info['name']}"}), 400

    try:
        import torch
        from diffusers.utils import export_to_video

        pipe = _prepare_generation_pipeline(model_info["path"], "video")
        generator = None
        if seed is not None:
            generator = torch.Generator(device=g.pipeline_binding[1]).manual_seed(int(seed))

        start = time.monotonic()
        if image_conditioned:
            init_image = _decode_input_image(image_b64)
            w, h = init_image.size
            if w <= 0 or h <= 0:
                return jsonify({"error": "image dimensions must be > 0"}), 400
            if w > MAX_RESOLUTION or h > MAX_RESOLUTION:
                ratio = min(MAX_RESOLUTION / w, MAX_RESOLUTION / h)
                init_image = init_image.resize((max(1, int(w * ratio)), max(1, int(h * ratio))))
            init_image = _normalize_img2img_input(init_image)
            if requested_width is None:
                width = init_image.size[0]
            if requested_height is None:
                height = init_image.size[1]
            width, height = _normalize_video_dimensions(width, height)
            conditioning_input = _prepare_video_conditioning_input(init_image, pipe, torch)
            _recheck_pipeline_runtime()
            result = pipe(
                image=conditioning_input,
                width=width,
                height=height,
                num_frames=num_frames,
                num_inference_steps=steps,
                generator=generator,
            )
        else:
            _recheck_pipeline_runtime()
            result = pipe(
                prompt=prompt,
                negative_prompt=negative_prompt or None,
                width=width,
                height=height,
                num_frames=num_frames,
                num_inference_steps=steps,
                generator=generator,
            )
        elapsed = round(time.monotonic() - start, 2)

        # Serialize privately and encode the same held inode that is published.
        out_path, encoded = _publish_output(
            "gen", ".mp4", serialize=lambda path: export_to_video(result.frames[0], path, fps=fps),
        )
        video_b64 = base64.b64encode(encoded).decode()

        log.info("generated video in %.2fs model=%s frames=%d", elapsed, model_info["name"], num_frames)

        return jsonify({
            "video": video_b64,
            "saved_to": str(out_path),
            "model": model_info["name"],
            "elapsed_seconds": elapsed,
            "parameters": {
                "prompt": prompt,
                "image_conditioned": image_conditioned,
                "width": width,
                "height": height,
                "num_frames": num_frames,
                "steps": steps,
                "fps": fps,
                "seed": seed,
            },
        })

    except diffusion_registry.ModelIntegrityUnavailable:
        return _model_denial()
    except runtime_assurance.RuntimeAssuranceUnavailable:
        return _runtime_denial()
    except _OutputPublicationError as exc:
        log.exception("video output publication failed")
        return jsonify({"error": str(exc)}), 500
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        log.exception("video generation failed")
        return jsonify({"error": "video generation failed"}), 500


# --- Image-to-Image ---

@app.route("/v1/generate/img2img", methods=["POST"])
def generate_img2img():
    body = request.get_json()
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    prompt = body.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "prompt is required"}), 400
    if len(prompt) > 2000:
        return jsonify({"error": "prompt too long (max 2000 chars)"}), 400

    image_b64 = body.get("image", "")
    if not image_b64:
        return jsonify({"error": "image (base64) is required"}), 400

    model_name = body.get("model", "")
    if not isinstance(model_name, str) or not model_name:
        return jsonify({"error": "select a registered model before generating"}), 400
    strength = _clamp(body.get("strength", 0.75), 0.0, 1.0)
    steps = _clamp(body.get("steps", 30), 1, MAX_STEPS)
    guidance_scale = _clamp(body.get("guidance_scale", 7.5), 1.0, 30.0)
    seed = body.get("seed")

    if strength <= 0:
        return jsonify({"error": "strength must be greater than 0"}), 400
    if steps * strength < 1:
        return jsonify({
            "error": "strength and steps combination must yield at least one denoising step",
        }), 400

    try:
        model_info = _select_generation_model(model_name)
    except diffusion_registry.ModelIntegrityUnavailable:
        return _model_denial()

    if "img2img" not in model_info.get("capabilities", []):
        return jsonify({"error": f"model does not support image-to-image: {model_info['name']}"}), 400

    try:
        import torch
        # Decode input image
        init_image = _decode_input_image(image_b64)
        init_image = _normalize_img2img_input(init_image)

        pipe = _prepare_generation_pipeline(model_info["path"], "img2img")
        generator = None
        if seed is not None:
            generator = torch.Generator(device=g.pipeline_binding[1]).manual_seed(int(seed))

        start = time.monotonic()
        _recheck_pipeline_runtime()
        result = pipe(
            prompt=prompt,
            image=init_image,
            strength=strength,
            num_inference_steps=steps,
            guidance_scale=guidance_scale,
            generator=generator,
        )
        elapsed = round(time.monotonic() - start, 2)

        buf = io.BytesIO()
        result.images[0].save(buf, format="PNG")
        encoded = buf.getvalue()
        out_b64 = base64.b64encode(encoded).decode()
        out_path, _ = _publish_output("img2img", ".png", content=encoded)

        log.info("img2img in %.2fs model=%s", elapsed, model_info["name"])

        return jsonify({
            "image": out_b64,
            "saved_to": str(out_path),
            "model": model_info["name"],
            "elapsed_seconds": elapsed,
        })

    except diffusion_registry.ModelIntegrityUnavailable:
        return _model_denial()
    except runtime_assurance.RuntimeAssuranceUnavailable:
        return _runtime_denial()
    except _OutputPublicationError as exc:
        log.exception("img2img output publication failed")
        return jsonify({"error": str(exc)}), 500
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        log.exception("img2img generation failed")
        return jsonify({"error": "img2img generation failed"}), 500


# --- Unload / Memory Management ---

@app.route("/v1/unload", methods=["POST"])
def unload_pipelines():
    """Unload all cached pipelines to free GPU memory."""
    count = len(_pipelines)
    _pipelines.clear()

    try:
        import gc

        import torch

        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        if hasattr(torch, "xpu") and torch.xpu.is_available():
            torch.xpu.empty_cache()
    except ImportError:
        pass

    log.info("unloaded %d pipeline(s)", count)
    return jsonify({"status": "ok", "unloaded": count})


def main():
    """Dev-mode entry point. Production uses gunicorn via systemd wrapper."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    host, port = BIND_ADDR.rsplit(":", 1)
    log.warning("Running Flask dev server — use gunicorn in production")
    log.info("diffusion-worker starting on %s", BIND_ADDR)
    app.run(host=host, port=int(port), debug=False, threaded=True)


if __name__ == "__main__":
    main()
