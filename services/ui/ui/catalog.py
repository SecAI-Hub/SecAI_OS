"""Canonical pinned catalog and acquisition helpers, without Flask or audit writers."""
import ctypes
import errno
import hashlib
import json
import logging
import os
import posixpath
import re
import shutil
import stat
import sys
import uuid
from pathlib import Path
from urllib.parse import quote, urlparse

import yaml
from werkzeug.security import safe_join

log = logging.getLogger("ui.catalog")

_CATALOG_MAX_SINGLE_FILE_BYTES = 50 * 1024**3
_CATALOG_MAX_DIRECTORY_BYTES = 64 * 1024**3
_CATALOG_MAX_DIRECTORY_FILES = 20_000
_CATALOG_MAX_REPO_FILE_BYTES = _CATALOG_MAX_SINGLE_FILE_BYTES
_CATALOG_MAX_HF_MODEL_METADATA_BYTES = 1024**2
_CATALOG_MAX_HF_TREE_METADATA_BYTES = 32 * 1024**2

_MODEL_CATALOG_PATH = os.getenv(
    "MODEL_CATALOG_PATH", "/etc/secure-ai/model-catalog.yaml"
)

# Hardcoded fallback catalog (used if YAML is missing or malformed). Entries
# are immutable-pinned acquisition candidates; they still require quarantine
# on the current appliance before they can become trusted runtime models.
_FALLBACK_CATALOG: list[dict] = [
    {
        "name": "Granite Guardian 3.1 2B (Q4_K_M)",
        "type": "llm",
        "category": "llm",
        "filename": "granite-guardian-3.1-2b-q4_k_m.gguf",
        "url": "https://huggingface.co/Mungert/granite-guardian-3.1-2b-GGUF/resolve/01d30577cdd395fb65947d398f9e2b776c71355e/granite-guardian-3.1-2b-q4_k_m.gguf",
        "expected_revision": "01d30577cdd395fb65947d398f9e2b776c71355e",
        "size_gb": 1.5,
        "vram_gb": 3,
        "description": "Pinned guard-focused LLM candidate.",
        "expected_sha256": "2eaa7ed23bbd122fc654d9409f3076d35799b1cbc58f992b159d53cbaa51bed2",
        "expected_size_bytes": 1530557952,
        "security_status": "pinned-candidate",
    },
    {
        "name": "ShieldGemma 2B (Q4_K_M)",
        "type": "llm",
        "category": "llm",
        "filename": "shieldgemma-2b.Q4_K_M.gguf",
        "url": "https://huggingface.co/QuantFactory/shieldgemma-2b-GGUF/resolve/8755ece4b20dd84d7564131e385d9c205d03621a/shieldgemma-2b.Q4_K_M.gguf",
        "expected_revision": "8755ece4b20dd84d7564131e385d9c205d03621a",
        "size_gb": 1.7,
        "vram_gb": 3,
        "description": "Pinned safety-tuned LLM candidate.",
        "expected_sha256": "47b0c3f4ec0bf93659ab2fc92cf2041374ef78bf1cb5b8c790421f463e7b7979",
        "expected_size_bytes": 1708583104,
        "security_status": "pinned-candidate",
    },
    {
        "name": "GA Guard Core (Q2_K)",
        "type": "llm",
        "category": "llm",
        "filename": "GA_Guard_Core.Q2_K.gguf",
        "url": "https://huggingface.co/prithivMLmods/GA-Guard-AIO-GGUF/resolve/7d7a73c98639749fc9d6bcacec97df9b621b9340/GA_Guard_Core.Q2_K.gguf",
        "expected_revision": "7d7a73c98639749fc9d6bcacec97df9b621b9340",
        "size_gb": 1.7,
        "vram_gb": 3,
        "description": "Pinned guard-focused LLM candidate.",
        "expected_sha256": "ff6087763f3886e3355058f34a8f9f6b3a8ba4a8f70a5795001bdaee1b3368b3",
        "expected_size_bytes": 1668960032,
        "security_status": "pinned-candidate",
    },
    {
        "name": "ShieldGemma 2B (Q5_K_M)",
        "type": "llm",
        "category": "llm",
        "filename": "shieldgemma-2b.Q5_K_M.gguf",
        "url": "https://huggingface.co/QuantFactory/shieldgemma-2b-GGUF/resolve/8755ece4b20dd84d7564131e385d9c205d03621a/shieldgemma-2b.Q5_K_M.gguf",
        "expected_revision": "8755ece4b20dd84d7564131e385d9c205d03621a",
        "size_gb": 1.9,
        "vram_gb": 4,
        "description": "Pinned higher-quality safety-tuned LLM candidate.",
        "expected_sha256": "265ec9c9c2b069aa8737fdb79bf56d561b48e165b76728d52dd82b1932069b0f",
        "expected_size_bytes": 1923279040,
        "security_status": "pinned-candidate",
    },
    {
        "name": "ShieldGemma 9B (Q2_K)",
        "type": "llm",
        "category": "llm",
        "filename": "shieldgemma-9b.Q2_K.gguf",
        "url": "https://huggingface.co/QuantFactory/shieldgemma-9b-GGUF/resolve/ee6d7475c96d0beaba677f3f9c9d4d3b03bc1d55/shieldgemma-9b.Q2_K.gguf",
        "expected_revision": "ee6d7475c96d0beaba677f3f9c9d4d3b03bc1d55",
        "size_gb": 3.8,
        "vram_gb": 6,
        "description": "Pinned larger safety-tuned LLM candidate.",
        "expected_sha256": "3e86670d2abe5ce0be1c31582216dd6ae9731cc85cf3978e27f2d3b9238edf08",
        "expected_size_bytes": 3805398560,
        "security_status": "pinned-candidate",
    },
    {
        "name": "Tiny Random SDXL",
        "type": "diffusion",
        "category": "image",
        "filename": "image-tiny-sdxl-dg845",
        "url": "https://huggingface.co/dg845/tiny-random-stable-diffusion-xl",
        "expected_revision": "7ae769dd7f63b06308f2f23881d329a0cb1c89d2",
        "expected_manifest_sha256": "e0123078fb614ddfe0b7b0346ad03e46d9083c6084aec2ed2635879b590713e6",
        "expected_size_bytes": 3373961,
        "size_gb": 0.01,
        "vram_gb": 2,
        "description": "Pinned tiny SDXL image candidate.",
        "security_status": "pinned-candidate",
    },
    {
        "name": "BK-SDM Tiny",
        "type": "diffusion",
        "category": "image",
        "filename": "image-bk-sdm-tiny",
        "url": "https://huggingface.co/nota-ai/bk-sdm-tiny",
        "expected_revision": "0364108e53b7f7f4d2585e817a0b7a83dc261cfa",
        "expected_manifest_sha256": "a1f361875311fc21730eb6e8573864d4ee3666dd20a5206f46c7df9db7095aea",
        "expected_size_bytes": 1669906169,
        "size_gb": 1.7,
        "vram_gb": 4,
        "description": "Pinned compact Stable Diffusion candidate.",
        "security_status": "pinned-candidate",
    },
    {
        "name": "BK-SDM Small",
        "type": "diffusion",
        "category": "image",
        "filename": "image-bk-sdm-small",
        "url": "https://huggingface.co/nota-ai/bk-sdm-small",
        "expected_revision": "572238db7ed3a10858900803f3fc8cca53e893e0",
        "expected_manifest_sha256": "5bb2dcca00811e04c4769b4d0051f0004033fa26099498ff0d174d65e3c27a68",
        "expected_size_bytes": 1987834232,
        "size_gb": 2.0,
        "vram_gb": 5,
        "description": "Pinned small Stable Diffusion candidate.",
        "security_status": "pinned-candidate",
    },
    {
        "name": "BK-SDM Base",
        "type": "diffusion",
        "category": "image",
        "filename": "image-bk-sdm-base",
        "url": "https://huggingface.co/nota-ai/bk-sdm-base",
        "expected_revision": "0c03b7a0369b49f97d1acf7256d4ee55ced9b2e0",
        "expected_manifest_sha256": "9737280ab316298e3026b021e3c3c78c1ceb943a577b73bc359e24cd88b5ac27",
        "expected_size_bytes": 2181916172,
        "size_gb": 2.2,
        "vram_gb": 6,
        "description": "Pinned base Stable Diffusion candidate.",
        "security_status": "pinned-candidate",
    },
    {
        "name": "Stable Diffusion 1.5",
        "type": "diffusion",
        "category": "image",
        "filename": "image-sd15",
        "url": "https://huggingface.co/stable-diffusion-v1-5/stable-diffusion-v1-5",
        "expected_revision": "451f4fe16113bff5a5d2269ed5ad43b0592e9a14",
        "expected_manifest_sha256": "007714ef9c28cd3e97686d321f7ec5dc497031bef2d8e39034177ed975caf23e",
        "expected_size_bytes": 2742217630,
        "size_gb": 2.7,
        "vram_gb": 4,
        "description": "Pinned Stable Diffusion 1.5 candidate.",
        "security_status": "pinned-candidate",
    },
    {
        "name": "Tiny Stable Video Diffusion",
        "type": "diffusion",
        "category": "video",
        "filename": "video-tiny-svd-seinpark",
        "url": "https://huggingface.co/seinpark/tiny-stable-video-diffusion-img2vid",
        "expected_revision": "701088dac555f81b9961077c99bc3527d6548cd3",
        "expected_manifest_sha256": "bf49b5c212bdce95473eecc87e12a4c934cdfe8527f0c276682158d869fce4ce",
        "expected_size_bytes": 10240860,
        "size_gb": 0.01,
        "vram_gb": 2,
        "description": "Pinned tiny image-to-video candidate.",
        "security_status": "pinned-candidate",
    },
    {
        "name": "Tiny Random LTX Video",
        "type": "diffusion",
        "category": "video",
        "filename": "video-tiny-ltx-katuni4ka",
        "url": "https://huggingface.co/katuni4ka/tiny-random-ltx-video",
        "expected_revision": "5a116fa316d6f98ef4ee4a50f8d2024d39beacdc",
        "expected_manifest_sha256": "c1da3d0051f7dc8217f9409f5ea10f11190887a6f3d934124ed5ec4bf2b7852d",
        "expected_size_bytes": 1141266,
        "size_gb": 0.01,
        "vram_gb": 2,
        "description": "Pinned tiny LTX video candidate.",
        "security_status": "pinned-candidate",
    },
    {
        "name": "Stable Video Diffusion",
        "type": "diffusion",
        "category": "video",
        "filename": "video-svd-img2vid",
        "url": "https://huggingface.co/stabilityai/stable-video-diffusion-img2vid",
        "expected_revision": "9cf024d5bfa8f56622af86c884f26a52f6676f2e",
        "expected_manifest_sha256": "3a5c50adeb6d07668cd2da7ca59ae14244f1125f32dc2d17fa900a1a7e3e403c",
        "expected_size_bytes": 4509188849,
        "size_gb": 4.5,
        "vram_gb": 16,
        "description": "Pinned image-to-video candidate.",
        "security_status": "pinned-candidate",
    },
    {
        "name": "Stable Video Diffusion XT",
        "type": "diffusion",
        "category": "video",
        "filename": "video-svd-img2vid-xt",
        "url": "https://huggingface.co/stabilityai/stable-video-diffusion-img2vid-xt",
        "expected_revision": "9e43909513c6714f1bc78bcb44d96e733cd242aa",
        "expected_manifest_sha256": "5108113b09d11fd2c9a3b47853cc106933584f316ddd14f3185aec10834e7724",
        "expected_size_bytes": 4509188841,
        "size_gb": 4.5,
        "vram_gb": 16,
        "description": "Pinned image-to-video XT candidate.",
        "security_status": "pinned-candidate",
    },
    {
        "name": "Stable Video Diffusion XT 1.1",
        "type": "diffusion",
        "category": "video",
        "filename": "video-svd-xt-1-1-weights",
        "url": "https://huggingface.co/weights/stable-video-diffusion-img2vid-xt-1-1",
        "expected_revision": "a423ba0d3e1a94a57ebc68e98691c43104198394",
        "expected_manifest_sha256": "634f478b142fa65531d327fd79c2eb02a092edebbbde129a544813e77c0a2301",
        "expected_size_bytes": 4509188809,
        "size_gb": 4.5,
        "vram_gb": 16,
        "description": "Pinned public XT 1.1 image-to-video candidate mirror.",
        "security_status": "pinned-candidate",
    },
]


def load_model_catalog(path: str = _MODEL_CATALOG_PATH) -> list[dict]:
    """Load model catalog from YAML file, falling back to hardcoded defaults.

    Remote entries fail closed unless all immutable digest/size pins required by
    their artifact type are present and well formed.
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
        # Validate required fields and immutable acquisition pins.
        required = {"name", "type", "filename", "url"}
        valid: list[dict] = []
        seen_filenames: set[str] = set()
        for entry in models:
            if not isinstance(entry, dict):
                continue
            if not required.issubset(entry.keys()):
                log.warning("model catalog: skipping entry missing fields: %s", entry.get("name", "?"))
                continue
            candidate = dict(entry)
            filename = candidate.get("filename")
            model_type = candidate.get("type")
            url = candidate.get("url")
            expected_size = candidate.get("expected_size_bytes")
            parsed = urlparse(url) if isinstance(url, str) else None
            if (
                not isinstance(filename, str)
                or not filename
                or filename in {".", ".."}
                or filename.startswith(".")
                or Path(filename).name != filename
                or "/" in filename
                or "\\" in filename
                or filename in seen_filenames
                or model_type not in {"llm", "diffusion"}
                or parsed is None
                or parsed.scheme != "https"
                or parsed.hostname != "huggingface.co"
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or isinstance(expected_size, bool)
                or not isinstance(expected_size, int)
                or expected_size <= 0
                or expected_size > (
                    _CATALOG_MAX_SINGLE_FILE_BYTES
                    if model_type == "llm"
                    else _CATALOG_MAX_DIRECTORY_BYTES
                )
                or candidate.get("blocked")
                or candidate.get("security_status") != "pinned-candidate"
            ):
                log.warning(
                    "model catalog: skipping invalid or unpinned entry: %s",
                    candidate.get("name", "?"),
                )
                continue
            if model_type == "llm":
                expected_revision = str(candidate.get("expected_revision", ""))
                url_parts = parsed.path.strip("/").split("/")
                if (
                    not re.fullmatch(
                        r"[0-9a-f]{64}",
                        str(candidate.get("expected_sha256", "")),
                    )
                    or not re.fullmatch(r"[0-9a-f]{40}", expected_revision)
                    or len(url_parts) != 5
                    or url_parts[2] != "resolve"
                    or url_parts[3] != expected_revision
                    or url_parts[4] != filename
                ):
                    log.warning(
                        "model catalog: skipping unpinned LLM entry: %s",
                        candidate.get("name", "?"),
                    )
                    continue
            elif (
                not re.fullmatch(
                    r"[0-9a-f]{40}",
                    str(candidate.get("expected_revision", "")),
                )
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(candidate.get("expected_manifest_sha256", "")),
                )
            ):
                log.warning(
                    "model catalog: skipping unpinned diffusion entry: %s",
                    candidate.get("name", "?"),
                )
                continue
            seen_filenames.add(filename)
            valid.append(candidate)
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


_DIFFUSION_REPO_EXTENSIONS = {
    ".json", ".safetensors", ".txt", ".model", ".vocab", ".merges",
}
_DIFFUSION_COMPONENT_WEIGHT_RE = re.compile(
    r"^(?P<prefix>.+/)(?P<stem>.+?)(?:\.fp16)?\.safetensors$"
)




def _is_safe_catalog_name(name: str) -> bool:
    """Return True when a catalog-managed file/dir name is a single path segment."""
    if not name or name in (".", ".."):
        return False
    return (
        "/" not in name
        and "\\" not in name
        and Path(name).name == name
        and not Path(name).is_absolute()
    )


def _confined_child(root: Path, name: str, *, kind: str) -> Path:
    """Return a child path confined to root, or raise ValueError."""
    if not _is_safe_catalog_name(name):
        raise ValueError(f"invalid {kind} name")
    joined = safe_join(str(root), name)
    if joined is None:
        raise ValueError(f"{kind} path escapes root")
    return Path(joined)


def _publish_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a staged artifact without replacing an existing one.

    Fedora/glibc exposes renameat2(2), which gives us atomic RENAME_NOREPLACE
    semantics and preserves a single link throughout publication. The
    hard-link fallback is used only on development platforms lacking that API.
    """
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameat2.restype = ctypes.c_int
            result = renameat2(
                -100,  # AT_FDCWD
                os.fsencode(source),
                -100,
                os.fsencode(destination),
                1,  # RENAME_NOREPLACE
            )
            if result == 0:
                return
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number), str(destination))
        # The supervised Linux path must never use link/unlink emulation.
        raise OSError(errno.ENOTSUP, "atomic no-replace publication unavailable")

    # Portable create-if-absent fallback. The production Fedora path above is
    # a single rename; this fallback is retained for macOS developer testing.
    os.link(source, destination, follow_symlinks=False)
    try:
        source.unlink()
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def _publish_directory_noreplace(source: Path, destination: Path) -> None:
    """Publish a directory without replacement (atomic on production Fedora)."""
    if sys.platform.startswith("linux"):
        _publish_noreplace(source, destination)
        return
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), destination)
    # Development-only fallback for platforms that cannot link directories.
    os.rename(source, destination)


def _huggingface_token() -> str:
    """Return an operator-supplied Hugging Face token, if configured."""
    for name in ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_HUB_TOKEN"):
        token = os.getenv(name, "").strip()
        if token:
            return token
    return ""


def _huggingface_headers() -> dict:
    token = _huggingface_token()
    return {"Authorization": f"Bearer {token}"} if token else {}


def _huggingface_auth_error() -> str:
    return (
        "Hugging Face rejected the request. Accept the provider terms for this "
        "model and, if required, configure an operator-supplied HF_TOKEN for "
        "the sandbox."
    )


def _bounded_response_json(response, *, max_bytes: int):
    """Decode a streamed metadata response without unbounded buffering."""
    raw_content_length = str(response.headers.get("content-length", "")).strip()
    try:
        content_length = int(raw_content_length) if raw_content_length else 0
    except ValueError as exc:
        raise ValueError("metadata response has an invalid content length") from exc
    if content_length < 0 or content_length > max_bytes:
        raise ValueError("metadata response exceeds the safety limit")

    raw = bytearray()
    try:
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            if not isinstance(chunk, bytes):
                raise ValueError("metadata response produced non-binary data")
            raw.extend(chunk)
            if len(raw) > max_bytes:
                raise ValueError("metadata response exceeds the safety limit")
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()
    try:
        def reject_duplicate_keys(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError(f"duplicate metadata JSON key: {key!r}")
                value[key] = item
            return value

        return json.loads(
            bytes(raw).decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("metadata response is not valid JSON") from exc


def _is_huggingface_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.netloc == "huggingface.co"


def _huggingface_repo_id_from_url(url: str) -> str:
    if not _is_huggingface_url(url):
        raise ValueError("source must be a Hugging Face HTTPS repository URL")
    parts = [p for p in urlparse(url).path.split("/") if p]
    if len(parts) < 2:
        raise ValueError("source must include Hugging Face namespace and repository")
    return "/".join(parts[:2])


def _safe_hf_repo_file_path(raw_path: str) -> str | None:
    """Return a safe repo-relative file path or None when it should be skipped."""
    if not raw_path or "\x00" in raw_path or "\\" in raw_path:
        return None
    try:
        if len(raw_path.encode("utf-8")) > 4096:
            return None
    except UnicodeEncodeError:
        return None
    normalized = posixpath.normpath(raw_path)
    if normalized in (".", "") or normalized.startswith("../") or normalized.startswith("/"):
        return None
    if normalized != raw_path:
        return None
    if any(
        part in ("", ".", "..") or part.startswith(".")
        for part in normalized.split("/")
    ):
        return None
    suffix = Path(normalized).suffix.lower()
    if suffix not in _DIFFUSION_REPO_EXTENSIONS:
        return None
    return normalized


def _diffusion_component_key(path: str) -> str | None:
    match = _DIFFUSION_COMPONENT_WEIGHT_RE.match(path)
    if not match:
        return None
    return f"{match.group('prefix')}{match.group('stem')}.safetensors"


def _select_diffusion_repo_files(repo_files: list[dict]) -> tuple[list[dict], str | None]:
    """Keep a diffusers-ready subset and prefer fp16 component weights."""
    selected: list[dict] = []
    component_weights: dict[str, dict] = {}
    component_variant: str | None = None

    for item in repo_files:
        path = str(item.get("path", ""))
        suffix = Path(path).suffix.lower()
        if suffix != ".safetensors":
            selected.append(item)
            continue

        # Root safetensors files are standalone checkpoints or examples. The
        # directory loader uses component weights under subdirectories instead.
        if "/" not in path:
            continue
        if "non_ema" in path or "lora" in path.lower():
            continue

        component_key = _diffusion_component_key(path)
        if not component_key:
            selected.append(item)
            continue
        existing = component_weights.get(component_key)
        is_fp16 = path.endswith(".fp16.safetensors")
        if existing is None or is_fp16:
            component_weights[component_key] = item
        if is_fp16:
            component_variant = "fp16"

    selected.extend(component_weights.values())
    selected.sort(
        key=lambda item: str(item.get("path", "")).encode("utf-8")
    )
    if not any(str(item.get("path", "")).endswith(".safetensors") for item in selected):
        raise ValueError("Hugging Face repo did not expose diffusers component weights")
    return selected, component_variant


def _huggingface_manifest_payload(
    *,
    source_url: str,
    repo_id: str,
    revision: str,
    variant: str | None,
    files: list[dict],
) -> dict:
    """Build the deterministic receipt covered by an image-owned digest pin."""
    return {
        "version": 1,
        "source": source_url,
        "repo_id": repo_id,
        "revision": revision,
        "variant": variant,
        "files": [
            {
                "path": item["path"],
                "size": item.get("size", 0),
                "oid": item.get("oid", ""),
                "oid_type": item.get("oid_type", ""),
            }
            for item in files
        ],
    }


def _canonical_manifest_sha256(payload: dict) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class Transfer:
    def __init__(self, root, *, response, fetch, check, progress, partial=None,
                 owned=None, before_publish=None, published=None, manage_cleanup=True):
        self.manage_cleanup = manage_cleanup
        self.root = Path(root)
        self.response = response
        self.fetch = fetch
        self.check = check
        self.progress = progress
        self.partial = partial or (lambda name: self.path(f".{name}.{uuid.uuid4().hex}.part"))
        self.owned = owned or (lambda path: None)
        self.before_publish = before_publish or (lambda: None)
        self.published = published or (lambda path: None)

    def path(self, name):
        return _confined_child(self.root, name, kind="quarantine")

    def metadata_path(self, name, suffix):
        return self.path(f".{name}{suffix}")

    def sync_directory(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def publish(self, source, destination, *, directory=False):
        self.before_publish()
        if directory:
            for root, dirs, files in os.walk(source, followlinks=False):
                self.sync_directory(root)
        (_publish_directory_noreplace if directory else _publish_noreplace)(source, destination)
        self.sync_directory(self.root)
        self.published(destination)

    def _huggingface_tree(self, repo_id: str, revision: str = "main") -> list[dict]:
        """List safe downloadable files in a Hugging Face repo via HTTPS API."""
        api_url = (
            "https://huggingface.co/api/models/"
            f"{quote(repo_id, safe='/')}/tree/{quote(revision, safe='')}?recursive=1"
        )
        resp = self.fetch(
            api_url,
            upstream_headers=_huggingface_headers(),
            stream=True,
            timeout=30,
        )
        if resp.status_code in (401, 403):
            raise ValueError(_huggingface_auth_error())
        resp.raise_for_status()
        payload = _bounded_response_json(
            resp,
            max_bytes=_CATALOG_MAX_HF_TREE_METADATA_BYTES,
        )
        if not isinstance(payload, list) or len(payload) > 100_000:
            raise ValueError("Hugging Face metadata response was not a file tree")

        files: list[dict] = []
        for item in payload:
            if not isinstance(item, dict) or item.get("type") != "file":
                continue
            safe_path = _safe_hf_repo_file_path(str(item.get("path", "")))
            if not safe_path:
                continue
            raw_lfs = item.get("lfs")
            lfs = raw_lfs if isinstance(raw_lfs, dict) else {}
            lfs_oid = str(lfs.get("oid") or "")
            raw_size = item.get("size")
            if (
                isinstance(raw_size, bool)
                or not isinstance(raw_size, int)
                or not 1 <= raw_size <= _CATALOG_MAX_REPO_FILE_BYTES
            ):
                raise ValueError(f"Hugging Face metadata has an invalid size for {safe_path}")
            oid = lfs_oid or str(item.get("oid") or "")
            if (
                (lfs_oid and not re.fullmatch(r"[0-9a-f]{64}", oid))
                or (not lfs_oid and not re.fullmatch(r"[0-9a-f]{40}", oid))
            ):
                raise ValueError(
                    f"Hugging Face metadata has an invalid object ID for {safe_path}"
                )
            files.append({
                "path": safe_path,
                "size": raw_size,
                "oid": oid,
                "oid_type": "sha256" if lfs_oid else "git-sha1",
                "revision": revision,
            })
            if len(files) > _CATALOG_MAX_DIRECTORY_FILES:
                raise ValueError("Hugging Face repo exposes too many diffusion files")

        if not files:
            raise ValueError("Hugging Face repo did not expose any safe diffusion files")
        return files

    def _write_quarantine_metadata(self, path: Path, content: bytes) -> None:
        """Publish one bounded metadata sidecar without following or replacing links."""
        if len(content) > 16 * 1024 * 1024:
            raise ValueError("quarantine metadata exceeds safety limit")
        temporary = self.path(f".metadata.{uuid.uuid4().hex}.part")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o660,
            )
            self.owned(temporary)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            _publish_noreplace(temporary, path)
            self.owned(path)
            self.sync_directory(self.root)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if self.manage_cleanup:
                temporary.unlink(missing_ok=True)

    def _write_huggingface_manifest(self, path: Path, payload: dict) -> None:
        """Write a deterministic Hugging Face receipt for quarantine verification."""
        encoded = (
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        self._write_quarantine_metadata(path, encoded)

    def _download_single_file(self, url: str, filename: str, catalog_entry: dict | None = None):
        """Download a single file (LLM GGUF) into quarantine.

        Catalog downloads are streamed into a no-follow exclusive inode and must
        exactly match both their byte-count and SHA-256 pins before publication.
        """
        if not _is_safe_catalog_name(filename):
            raise ValueError("invalid catalog filename")

        dest = self.path(filename)
        tmp_dest = self.partial(filename)
        source_meta = self.path(f".{filename}.source")
        if dest.exists():
            raise ValueError("artifact already exists in quarantine")

        expected_size: int | None = None
        expected_hash = ""
        if catalog_entry is not None:
            raw_expected_size = catalog_entry.get("expected_size_bytes")
            expected_hash = str(catalog_entry.get("expected_sha256", ""))
            if (
                isinstance(raw_expected_size, bool)
                or not isinstance(raw_expected_size, int)
                or not 1 <= raw_expected_size <= _CATALOG_MAX_SINGLE_FILE_BYTES
                or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
            ):
                raise ValueError("catalog entry is missing an immutable file pin")
            expected_size = raw_expected_size

        descriptor: int | None = None
        source_written = False
        published = False
        resp = None
        try:
            resp = self.response(url)
            raw_content_length = str(resp.headers.get("content-length", "")).strip()
            try:
                total = int(raw_content_length) if raw_content_length else 0
            except ValueError as exc:
                raise ValueError("download response has an invalid content length") from exc
            if total < 0 or total > _CATALOG_MAX_SINGLE_FILE_BYTES:
                raise ValueError("download response exceeds the catalog size limit")
            if expected_size is not None and total and total != expected_size:
                raise ValueError("download response does not match the catalog size pin")

            downloaded = 0
            digest = hashlib.sha256()
            descriptor = os.open(
                tmp_dest,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o660,
            )
            self.owned(tmp_dest)
            with os.fdopen(descriptor, "wb") as f:
                descriptor = None
                for chunk in resp.iter_content(chunk_size=1 << 20):
                    if not chunk:
                        continue
                    if not isinstance(chunk, bytes):
                        raise ValueError("download response produced non-binary data")
                    downloaded += len(chunk)
                    hard_limit = expected_size or _CATALOG_MAX_SINGLE_FILE_BYTES
                    if downloaded > hard_limit:
                        raise ValueError("download exceeded its immutable size limit")
                    f.write(chunk)
                    digest.update(chunk)
                    self.progress(filename, downloaded=downloaded, total=total)
                f.flush()
                os.fsync(f.fileno())

            if expected_size is not None and downloaded != expected_size:
                raise ValueError("downloaded file does not match the catalog size pin")
            actual_hash = digest.hexdigest()
            if expected_hash and actual_hash != expected_hash:
                raise ValueError(
                    f"SHA-256 mismatch: expected {expected_hash[:16]}..., "
                    f"got {actual_hash[:16]}..."
                )

            self.before_publish()
            encoded_source = url.encode("utf-8")
            if len(encoded_source) > 4096 or any(
                byte < 0x20 or byte == 0x7F for byte in encoded_source
            ):
                raise ValueError("catalog source URL is invalid")
            self._write_quarantine_metadata(source_meta, encoded_source)
            source_written = True
            self.publish(tmp_dest, dest)
            published = True
        except Exception:
            if source_written and self.manage_cleanup:
                source_meta.unlink(missing_ok=True)
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if not published and self.manage_cleanup:
                tmp_dest.unlink(missing_ok=True)
            close = getattr(resp, "close", None)
            if callable(close):
                close()

    def _download_diffusion_model(self,
        url: str,
        dirname: str,
        *,
        catalog_entry: dict | None = None,
    ):
        """Download an immutable, manifest-pinned diffusion repository."""
        if not _is_safe_catalog_name(dirname):
            raise ValueError("invalid catalog directory name")
        if catalog_entry is None:
            raise ValueError("diffusion downloads require an immutable catalog pin")

        allowed, _, reason = self.check(url, method="GET")
        if not allowed:
            raise ValueError(reason or "airlock blocked download")
        repo_id = _huggingface_repo_id_from_url(url)
        revision = str(catalog_entry.get("expected_revision", ""))
        expected_manifest_sha256 = str(
            catalog_entry.get("expected_manifest_sha256", "")
        )
        expected_total_size = catalog_entry.get("expected_size_bytes")
        if (
            not re.fullmatch(r"[0-9a-f]{40}", revision)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256)
            or isinstance(expected_total_size, bool)
            or not isinstance(expected_total_size, int)
            or not 1 <= expected_total_size <= _CATALOG_MAX_DIRECTORY_BYTES
        ):
            raise ValueError("diffusion catalog entry is missing immutable pins")

        repo_files, variant = _select_diffusion_repo_files(
            self._huggingface_tree(repo_id, revision=revision)
        )
        if not 1 <= len(repo_files) <= _CATALOG_MAX_DIRECTORY_FILES:
            raise ValueError("diffusion repository has an unsafe file count")
        total_bytes = sum(item["size"] for item in repo_files)
        if total_bytes != expected_total_size:
            raise ValueError("diffusion repository size does not match the catalog pin")
        manifest_payload = _huggingface_manifest_payload(
            source_url=url,
            repo_id=repo_id,
            revision=revision,
            variant=variant,
            files=repo_files,
        )
        if _canonical_manifest_sha256(manifest_payload) != expected_manifest_sha256:
            raise ValueError("diffusion repository manifest does not match the catalog pin")

        dest = self.path(dirname)
        tmp_dest = self.partial(dirname)
        source_meta = self.path(f".{dirname}.source")
        manifest_meta = self.metadata_path(dirname, ".hf-manifest.json")
        if dest.exists():
            raise ValueError("artifact already exists in quarantine")

        source_written = False
        manifest_written = False
        published = False
        try:
            tmp_dest.mkdir(mode=0o750, parents=True, exist_ok=False)
            self.owned(tmp_dest)
            downloaded = 0

            for index, item in enumerate(repo_files, start=1):
                rel_path = item["path"]
                target_path = tmp_dest / Path(*rel_path.split("/"))
                parent = tmp_dest
                for component in Path(*rel_path.split("/")).parts[:-1]:
                    parent = parent / component
                    try:
                        parent.mkdir(mode=0o750)
                    except FileExistsError:
                        if parent.is_symlink() or not parent.is_dir():
                            raise ValueError("unsafe diffusion staging directory") from None

                file_url = (
                    "https://huggingface.co/"
                    f"{quote(repo_id, safe='/')}/resolve/{revision}/{quote(rel_path, safe='/')}"
                )
                message = f"Downloading {index}/{len(repo_files)}: {rel_path}"
                self.progress(
                    dirname,
                    downloaded=downloaded,
                    total=total_bytes,
                    message=message,
                )

                resp = self.response(file_url)
                descriptor: int | None = None
                file_downloaded = 0
                if item["oid_type"] == "sha256":
                    file_digest = hashlib.sha256()
                else:
                    file_digest = hashlib.sha1()  # nosec B324 - Git blob identity
                    file_digest.update(f"blob {item['size']}\0".encode("ascii"))
                try:
                    raw_content_length = str(
                        resp.headers.get("content-length", "")
                    ).strip()
                    try:
                        content_length = (
                            int(raw_content_length) if raw_content_length else 0
                        )
                    except ValueError as exc:
                        raise ValueError(
                            f"invalid content length for {rel_path}"
                        ) from exc
                    if content_length and content_length != item["size"]:
                        raise ValueError(
                            f"download response size mismatch for {rel_path}"
                        )

                    descriptor = os.open(
                        target_path,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o640,
                    )
                    with os.fdopen(descriptor, "wb") as f:
                        descriptor = None
                        for chunk in resp.iter_content(chunk_size=1 << 20):
                            if not chunk:
                                continue
                            if not isinstance(chunk, bytes):
                                raise ValueError(
                                    f"download returned non-binary data for {rel_path}"
                                )
                            file_downloaded += len(chunk)
                            downloaded += len(chunk)
                            if (
                                file_downloaded > item["size"]
                                or downloaded > total_bytes
                            ):
                                raise ValueError(
                                    f"download exceeded immutable size for {rel_path}"
                                )
                            f.write(chunk)
                            file_digest.update(chunk)
                            self.progress(
                                dirname,
                                downloaded=downloaded,
                                total=total_bytes,
                                message=message,
                            )
                        f.flush()
                        os.fsync(f.fileno())
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
                    close = getattr(resp, "close", None)
                    if callable(close):
                        close()

                if file_downloaded != item["size"]:
                    raise ValueError(f"downloaded file size mismatch for {rel_path}")
                if file_digest.hexdigest() != item["oid"]:
                    raise ValueError(f"downloaded file digest mismatch for {rel_path}")

            if downloaded != total_bytes:
                raise ValueError("diffusion download did not match its total size pin")
            self.before_publish()
            self._write_quarantine_metadata(source_meta, url.encode("utf-8"))
            source_written = True
            self._write_huggingface_manifest(
                manifest_meta,
                manifest_payload,
            )
            manifest_written = True
            self.publish(tmp_dest, dest, directory=True)
            published = True
        except Exception:
            if source_written and self.manage_cleanup:
                source_meta.unlink(missing_ok=True)
            if manifest_written and self.manage_cleanup:
                manifest_meta.unlink(missing_ok=True)
            raise
        finally:
            if not published and self.manage_cleanup:
                try:
                    metadata = tmp_dest.lstat()
                except FileNotFoundError:
                    pass
                else:
                    if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(
                        metadata.st_mode
                    ):
                        shutil.rmtree(tmp_dest)
