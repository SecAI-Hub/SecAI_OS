"""
Secure AI Appliance - Diffusion Worker

Image and video generation service using the diffusers library.
Runs locally with no internet access (PrivateNetwork=yes).
Models are loaded from the trusted registry only.
"""

import base64
import io
import json
import logging
import os
import time
from pathlib import Path

import yaml
from flask import Flask, jsonify, request

log = logging.getLogger("diffusion-worker")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB max request size

REGISTRY_DIR = Path(os.getenv("REGISTRY_DIR", "/var/lib/secure-ai/registry"))
APPLIANCE_CONFIG = os.getenv("APPLIANCE_CONFIG", "/etc/secure-ai/config/appliance.yaml")
BIND_ADDR = os.getenv("BIND_ADDR", "0.0.0.0:8455")
OUTPUTS_DIR = Path(os.getenv("OUTPUTS_DIR", "/var/lib/secure-ai/vault/outputs"))
MAX_RESOLUTION = int(os.getenv("MAX_RESOLUTION", "2048"))
MAX_STEPS = int(os.getenv("MAX_STEPS", "100"))
MAX_FRAMES = int(os.getenv("MAX_FRAMES", "120"))
VIDEO_DIMENSION_MULTIPLE = int(os.getenv("VIDEO_DIMENSION_MULTIPLE", "16"))

# Loaded pipeline instances (lazy init)
_pipelines = {}


def load_config() -> dict:
    try:
        with open(APPLIANCE_CONFIG) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def _get_device():
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


def _load_pipeline(model_path: str, pipeline_type: str = "image"):
    """Load a diffusion pipeline from a local model directory or safetensors file."""
    cache_key = f"{model_path}:{pipeline_type}"
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

    device = _get_device()
    # float16 for GPU backends; float32 for CPU (no half-precision support on most CPUs)
    dtype = torch.float16 if device in ("cuda", "mps", "xpu") else torch.float32

    model_dir = Path(model_path)
    if not model_dir.exists():
        raise FileNotFoundError(f"model not found: {model_path}")

    log.info("loading diffusion pipeline from %s (device=%s, dtype=%s)", model_path, device, dtype)

    if pipeline_type == "img2img":
        pipe = AutoPipelineForImage2Image.from_pretrained(
            str(model_dir), torch_dtype=dtype, local_files_only=True
        )
    elif pipeline_type == "video":
        pipe = DiffusionPipeline.from_pretrained(
            str(model_dir), torch_dtype=dtype, local_files_only=True
        )
    else:
        pipe = AutoPipelineForText2Image.from_pretrained(
            str(model_dir), torch_dtype=dtype, local_files_only=True
        )

    pipe = pipe.to(device)

    # Memory optimizations for GPU backends
    if device in ("cuda", "xpu"):
        try:
            pipe.enable_model_cpu_offload()
        except Exception:
            pass
        try:
            pipe.enable_xformers_memory_efficient_attention()
        except Exception:
            pass

    _pipelines[cache_key] = pipe
    log.info("pipeline loaded: %s", cache_key)
    return pipe


def _find_diffusion_models() -> list:
    """Find diffusion model directories in the registry."""
    models = []
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
                    class_name = index.get("_class_name", "")
                    if "Video" in class_name or "video" in class_name:
                        model_type = "video"
                    elif "Img2Img" in class_name or "Image2Image" in class_name:
                        model_type = "img2img"
                    models.append({
                        "name": entry.name,
                        "path": str(entry),
                        "type": model_type,
                        "class": class_name,
                    })
                except (json.JSONDecodeError, OSError):
                    models.append({
                        "name": entry.name,
                        "path": str(entry),
                        "type": "image",
                        "class": "unknown",
                    })
    return models


def _is_image_conditioned_video_model(model_info: dict) -> bool:
    """Return True when a video pipeline expects an input image."""
    class_name = str(model_info.get("class", "") or "")
    return (
        "StableVideoDiffusion" in class_name
        or "Img2Vid" in class_name
        or "ImageToVideo" in class_name
    )


def _video_encoder_image_size(pipe) -> int | None:
    """Return the video encoder image size when available."""
    image_encoder = getattr(pipe, "image_encoder", None)
    config = getattr(image_encoder, "config", None)
    size = getattr(config, "image_size", None)
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
        "device": device,
        "gpu": gpu_info,
        "loaded_pipelines": list(_pipelines.keys()),
        "available_models": len(models),
    })


def _get_gpu_info() -> dict:
    """Return GPU name and backend for diagnostics."""
    info = {"backend": "cpu", "name": "CPU"}
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
    width = _clamp(body.get("width", 512), 256, MAX_RESOLUTION)
    height = _clamp(body.get("height", 512), 256, MAX_RESOLUTION)
    steps = _clamp(body.get("steps", 30), 1, MAX_STEPS)
    guidance_scale = _clamp(body.get("guidance_scale", 7.5), 1.0, 30.0)
    seed = body.get("seed")
    num_images = _clamp(body.get("num_images", 1), 1, 4)

    # Find model
    models = _find_diffusion_models()
    if not models:
        return jsonify({"error": "no diffusion models available in registry"}), 503

    if model_name:
        matches = [m for m in models if m["name"] == model_name]
        if not matches:
            return jsonify({"error": f"model not found: {model_name}"}), 404
        model_info = matches[0]
    else:
        model_info = models[0]

    try:
        import torch

        pipe = _load_pipeline(model_info["path"], "image")
        generator = None
        if seed is not None:
            generator = torch.Generator(device=_get_device()).manual_seed(int(seed))

        start = time.monotonic()
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
        for i, img in enumerate(result.images):
            # Encode to base64 PNG
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            images_b64.append(base64.b64encode(buf.getvalue()).decode())

            # Save to outputs
            OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
            ts = int(time.time())
            out_path = OUTPUTS_DIR / f"gen_{ts}_{i}.png"
            img.save(str(out_path))
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

    # Find a video-capable model
    models = _find_diffusion_models()
    video_models = [m for m in models if m["type"] == "video"]

    if model_name:
        matches = [m for m in models if m["name"] == model_name]
        if not matches:
            return jsonify({"error": f"model not found: {model_name}"}), 404
        model_info = matches[0]
    elif video_models:
        model_info = video_models[0]
    else:
        return jsonify({"error": "no video generation models available"}), 503

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

    try:
        import torch
        from PIL import Image
        from diffusers.utils import export_to_video

        pipe = _load_pipeline(model_info["path"], "video")
        generator = None
        if seed is not None:
            generator = torch.Generator(device=_get_device()).manual_seed(int(seed))

        start = time.monotonic()
        if image_conditioned:
            img_bytes = base64.b64decode(image_b64)
            init_image = Image.open(io.BytesIO(img_bytes)).convert("RGB")
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
            result = pipe(
                image=conditioning_input,
                width=width,
                height=height,
                num_frames=num_frames,
                num_inference_steps=steps,
                generator=generator,
            )
        else:
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

        # Export video
        OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = int(time.time())
        out_path = OUTPUTS_DIR / f"gen_{ts}.mp4"
        export_to_video(result.frames[0], str(out_path), fps=fps)

        # Read and encode
        with open(out_path, "rb") as f:
            video_b64 = base64.b64encode(f.read()).decode()

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

    models = _find_diffusion_models()
    if model_name:
        matches = [m for m in models if m["name"] == model_name]
        if not matches:
            return jsonify({"error": f"model not found: {model_name}"}), 404
        model_info = matches[0]
    elif models:
        model_info = models[0]
    else:
        return jsonify({"error": "no diffusion models available"}), 503

    try:
        import torch
        from PIL import Image

        # Decode input image
        img_bytes = base64.b64decode(image_b64)
        init_image = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        init_image = _normalize_img2img_input(init_image)

        pipe = _load_pipeline(model_info["path"], "img2img")
        generator = None
        if seed is not None:
            generator = torch.Generator(device=_get_device()).manual_seed(int(seed))

        start = time.monotonic()
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
        out_b64 = base64.b64encode(buf.getvalue()).decode()

        OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = int(time.time())
        out_path = OUTPUTS_DIR / f"img2img_{ts}.png"
        result.images[0].save(str(out_path))

        log.info("img2img in %.2fs model=%s", elapsed, model_info["name"])

        return jsonify({
            "image": out_b64,
            "saved_to": str(out_path),
            "model": model_info["name"],
            "elapsed_seconds": elapsed,
        })

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
