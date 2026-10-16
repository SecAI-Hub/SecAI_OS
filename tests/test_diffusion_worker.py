import importlib.util
import os
import sys
import types
from pathlib import Path

import pytest
from common import diffusion_registry

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_PATH = REPO_ROOT / "services" / "diffusion-worker" / "app.py"
TINY_PNG_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7Z0ioAAAAASUVORK5CYII="
)
_DIFFUSION_TEST_TOKEN = "diffusion-unit-test-service-credential"


@pytest.fixture(autouse=True)
def provision_diffusion_service_credential(tmp_path, monkeypatch):
    token_path = tmp_path / "diffusion-service.token"
    token_path.write_text(_DIFFUSION_TEST_TOKEN, encoding="utf-8")
    token_path.chmod(0o600)
    monkeypatch.setenv("SERVICE_TOKEN_PATH", str(token_path))
    monkeypatch.setenv("REGISTRY_DIR", str(tmp_path))
    # These pipeline behavior tests explicitly exercise the sandbox evaluation.
    monkeypatch.setenv("SECURE_AI_DEPLOYMENT_MODE", "sandbox")


def _client(module):
    client = module.app.test_client()
    client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {_DIFFUSION_TEST_TOKEN}"
    return client


def _load_module():
    spec = importlib.util.spec_from_file_location("diffusion_app_under_test", str(APP_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # These behavior tests use explicit verified metadata; the transport and
    # replacement denial contract is covered by the registry-specific tests.
    def verified(filename):
        matches = [m for m in module._find_diffusion_models() if m["name"] == filename]
        path = matches[0]["path"] if matches else str(module.REGISTRY_DIR / filename)
        return diffusion_registry.VerifiedModel(filename, filename, "c" * 64, path)
    module._verified_diffusion_model = verified
    return module


@pytest.fixture
def generated_output_case(tmp_path, monkeypatch):
    """Exercise all publication routes without loading a model or GPU library."""
    module = _load_module()
    module.app.config["TESTING"] = True
    module._find_diffusion_models = lambda: [
        {"name": "tiny-image", "path": "/tmp/tiny-image", "type": "image",
         "capabilities": ["txt2img", "img2img"]},
        {"name": "tiny-video", "path": "/tmp/tiny-video", "type": "video",
         "class": "StableVideoDiffusionPipeline", "capabilities": ["img2vid"]},
    ]
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    state = types.SimpleNamespace(module=module, outputs=outputs, calls=0, video_hook=None,
                                  png_encodings=0, vary_png=False)

    class OutputImage:
        def __init__(self, content):
            self.content = content

        def save(self, target, format=None):
            state.png_encodings += 1
            content = self.content + (str(state.png_encodings).encode() if state.vary_png else b"")
            if hasattr(target, "write"):
                target.write(content)
            else:
                Path(target).write_bytes(content)

    class InputImage:
        size = (16, 16)
        format = "PNG"

        def convert(self, _mode):
            return self

        def resize(self, _size):
            return self

        def verify(self):
            pass

        def load(self):
            pass

        def close(self):
            pass

    def pipeline(**_kwargs):
        state.calls += 1
        content = f"generated-{state.calls}".encode()
        return types.SimpleNamespace(images=[OutputImage(content)], frames=[[content]])

    image = types.ModuleType("PIL.Image")
    image.open = lambda _stream: InputImage()
    pil = types.ModuleType("PIL")
    pil.Image = image
    utils = types.ModuleType("diffusers.utils")

    def export(frames, path, fps=8):
        Path(path).write_bytes(frames[0])
        if state.video_hook:
            state.video_hook(Path(path))

    utils.export_to_video = export
    diffusers = types.ModuleType("diffusers")
    diffusers.utils = utils
    for name, value in {"torch": types.ModuleType("torch"), "PIL": pil, "PIL.Image": image,
                        "diffusers": diffusers, "diffusers.utils": utils}.items():
        monkeypatch.setitem(sys.modules, name, value)
    module._load_pipeline = lambda *_args, **_kwargs: pipeline
    monkeypatch.setattr(module, "OUTPUTS_DIR", outputs)
    monkeypatch.setattr(module, "time", types.SimpleNamespace(monotonic=lambda: 100.0, time=lambda: 1234567890))

    def generate(kind):
        body = {"model": "tiny-video" if kind == "video" else "tiny-image", "steps": 2}
        if kind == "video":
            body.update(image=TINY_PNG_BASE64, num_frames=4, fps=6)
        elif kind == "img2img":
            body.update(prompt="test", image=TINY_PNG_BASE64, strength=0.5)
        else:
            body.update(prompt="test", width=16, height=16)
        with _client(module) as client:
            return client.post("/v1/generate/" + kind, json=body)

    state.generate = generate
    return state


@pytest.mark.parametrize("kind", ["image", "video", "img2img"])
@pytest.mark.parametrize("existing", ["regular", "symlink", "hardlink"])
def test_generation_preserves_preexisting_timestamp_targets(generated_output_case, tmp_path, kind, existing):
    case = generated_output_case
    old_name = {"image": "gen_1234567890_0.png", "video": "gen_1234567890.mp4",
                "img2img": "img2img_1234567890.png"}[kind]
    target = case.outputs / old_name
    victim = tmp_path / "existing-data"
    victim.write_bytes(b"preserve existing data")
    if existing == "regular":
        target.write_bytes(b"preserve existing data")
    elif existing == "symlink":
        target.symlink_to(victim)
    else:
        os.link(victim, target)
    response = case.generate(kind)
    assert response.status_code == 200
    assert victim.read_bytes() == b"preserve existing data"
    assert target.read_bytes() == b"preserve existing data"
    payload = response.get_json()
    saved = payload["saved_to"][0] if kind == "image" else payload["saved_to"]
    assert Path(saved) != target and Path(saved).read_bytes() == b"generated-1"


@pytest.mark.parametrize("kind", ["image", "video", "img2img"])
def test_generations_in_same_second_keep_both_outputs(generated_output_case, kind):
    case = generated_output_case
    first = case.generate(kind)
    assert first.status_code == 200
    first_saved = first.get_json()["saved_to"]
    first_path = Path(first_saved[0] if kind == "image" else first_saved)
    second = case.generate(kind)
    assert second.status_code == 200
    second_saved = second.get_json()["saved_to"]
    second_path = Path(second_saved[0] if kind == "image" else second_saved)
    assert first_path != second_path
    assert first_path.read_bytes() == b"generated-1" and second_path.read_bytes() == b"generated-2"


def test_failed_video_export_never_publishes_partial_output(generated_output_case):
    case = generated_output_case

    def fail(_path):
        raise OSError("synthetic encoder failure after partial write")

    case.video_hook = fail
    response = case.generate("video")
    assert response.status_code == 500
    assert list(case.outputs.iterdir()) == []


def test_video_serializer_path_replacement_cannot_leak_other_file(generated_output_case, tmp_path):
    import base64
    case = generated_output_case
    victim = tmp_path / "private-fixture-data"
    victim.write_bytes(b"PRIVATE-FIXTURE-DATA")

    def replace(path):
        path.rename(path.with_suffix(".moved"))
        path.symlink_to(victim)

    case.video_hook = replace
    response = case.generate("video")
    assert base64.b64encode(victim.read_bytes()).decode() not in response.get_data(as_text=True)
    assert response.status_code != 200
    assert victim.read_bytes() == b"PRIVATE-FIXTURE-DATA"


@pytest.mark.parametrize("kind", ["image", "video", "img2img"])
def test_generation_rejects_linked_output_root(generated_output_case, tmp_path, kind):
    case = generated_output_case
    outside = tmp_path / "outside"
    outside.mkdir()
    case.outputs.rmdir()
    case.outputs.symlink_to(outside, target_is_directory=True)
    response = case.generate(kind)
    assert response.status_code != 200
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("kind", ["image", "img2img"])
def test_generated_png_publishes_exact_response_encoding_once(generated_output_case, kind):
    import base64
    case = generated_output_case
    case.vary_png = True
    response = case.generate(kind)
    assert response.status_code == 200
    result = response.get_json()
    saved = Path(result["saved_to"][0] if kind == "image" else result["saved_to"])
    encoded = result["images"][0] if kind == "image" else result["image"]
    assert saved.read_bytes() == base64.b64decode(encoded)
    assert case.png_encodings == 1


def test_video_stays_private_and_unlisted_until_encoder_completes(generated_output_case):
    import stat
    case = generated_output_case
    observed = {}

    def during_export(path):
        observed["parent_is_output_root"] = path.parent.resolve() == case.outputs.resolve()
        info = path.parent.stat()
        observed["private_access"] = stat.S_IMODE(info.st_mode) & 0o077 == 0
        observed["owner"] = info.st_uid
        with _client(case.module) as client:
            listing = client.get("/v1/outputs")
            observed["status"] = listing.status_code
            observed["listed"] = listing.get_json()

    case.video_hook = during_export
    response = case.generate("video")
    assert response.status_code == 200
    assert observed == {"parent_is_output_root": False, "private_access": True,
                        "owner": os.geteuid(), "status": 200, "listed": []}
    assert Path(response.get_json()["saved_to"]).is_file()


@pytest.mark.parametrize("kind", ["image", "video", "img2img"])
def test_generated_output_preserves_umask_and_output_group(generated_output_case, kind):
    import stat
    case = generated_output_case
    group = next((gid for gid in os.getgroups() if gid != os.getgid()), os.getgid())
    os.chown(case.outputs, -1, group)
    case.outputs.chmod(0o2770)
    original_umask = os.umask(0o027)
    try:
        response = case.generate(kind)
    finally:
        os.umask(original_umask)
    assert response.status_code == 200
    result = response.get_json()["saved_to"]
    saved = Path(result[0] if kind == "image" else result)
    info = saved.stat()
    assert info.st_uid == os.geteuid() and info.st_gid == group
    assert stat.S_IMODE(info.st_mode) == 0o640 and info.st_nlink == 1
    assert list(case.outputs.iterdir()) == [saved]


def test_output_publication_late_collision_preserves_other_file(generated_output_case, monkeypatch):
    case = generated_output_case
    original = case.module._rename_output_no_replace
    collision = []

    def create_collision(source, name, target, filename):
        path = case.outputs / filename
        path.write_bytes(b"concurrent existing output")
        collision.append(path)
        original(source, name, target, filename)

    monkeypatch.setattr(case.module, "_rename_output_no_replace", create_collision)
    with pytest.raises(case.module._OutputPublicationError) as error:
        case.module._publish_output("gen", ".png", content=b"new output")
    assert error.value.published is False and error.value.cleanup_ambiguous is False
    assert collision[0].read_bytes() == b"concurrent existing output"
    assert list(case.outputs.iterdir()) == collision


def test_output_publication_error_after_rename_reports_actual_publication(generated_output_case, monkeypatch):
    case = generated_output_case
    original = case.module._rename_output_no_replace

    def after_rename(*args):
        original(*args)
        raise OSError("synthetic post-rename reporting failure")

    monkeypatch.setattr(case.module, "_rename_output_no_replace", after_rename)
    with pytest.raises(case.module._OutputPublicationError) as error:
        case.module._publish_output("gen", ".png", content=b"complete output")
    assert error.value.published is True
    files = list(case.outputs.glob("*.png"))
    assert len(files) == 1 and files[0].read_bytes() == b"complete output"


def test_output_publication_unknown_rename_preserves_replacement(generated_output_case, monkeypatch):
    case = generated_output_case
    original = case.module._rename_output_no_replace
    replacement = []

    def after_rename(source, name, target, filename):
        original(source, name, target, filename)
        path = case.outputs / filename
        path.unlink()
        path.write_bytes(b"unrelated replacement")
        replacement.append(path)
        raise OSError("synthetic unknown rename result")

    monkeypatch.setattr(case.module, "_rename_output_no_replace", after_rename)
    with pytest.raises(case.module._OutputPublicationError) as error:
        case.module._publish_output("gen", ".png", content=b"complete output")
    assert error.value.published is None
    assert replacement[0].read_bytes() == b"unrelated replacement"


def test_output_publication_handles_short_writes(generated_output_case, monkeypatch):
    case = generated_output_case
    original = os.write

    def short(fd, data):
        return original(fd, data[:2])

    monkeypatch.setattr(case.module.os, "write", short)
    path, data = case.module._publish_output("gen", ".png", content=b"complete encoded bytes")
    assert path.read_bytes() == data == b"complete encoded bytes"
    assert list(case.outputs.iterdir()) == [path]


def test_output_publication_cancellation_cleans_only_private_work(generated_output_case):
    case = generated_output_case
    existing = case.outputs / "existing.png"
    existing.write_bytes(b"existing data")

    def cancel(path):
        Path(path).write_bytes(b"partial output")
        raise KeyboardInterrupt("synthetic cancellation")

    with pytest.raises(KeyboardInterrupt):
        case.module._publish_output("gen", ".mp4", serialize=cancel)
    assert list(case.outputs.iterdir()) == [existing]
    assert existing.read_bytes() == b"existing data"


def test_output_publication_preserves_unknown_workspace_entries(generated_output_case):
    case = generated_output_case
    unknown = []

    def produce(path):
        path = Path(path)
        path.write_bytes(b"complete output")
        extra = path.parent / "unrelated"
        extra.write_bytes(b"preserve unknown data")
        unknown.append(extra.resolve())

    with pytest.raises(case.module._OutputPublicationError) as error:
        case.module._publish_output("gen", ".mp4", serialize=produce)
    assert error.value.cleanup_ambiguous is True
    assert unknown[0].read_bytes() == b"preserve unknown data"


@pytest.mark.parametrize("after_publication", [False, True])
def test_output_publication_sync_failure_preserves_published_data(generated_output_case, monkeypatch,
                                                                after_publication):
    case = generated_output_case
    original_sync = os.fsync
    original_rename = case.module._rename_output_no_replace
    state = {"renamed": False, "failed": False}

    def rename(*args):
        original_rename(*args)
        state["renamed"] = True

    def sync(fd):
        if not state["failed"] and state["renamed"] is after_publication:
            state["failed"] = True
            raise OSError("synthetic sync failure")
        return original_sync(fd)

    monkeypatch.setattr(case.module, "_rename_output_no_replace", rename)
    monkeypatch.setattr(case.module.os, "fsync", sync)
    with pytest.raises(case.module._OutputPublicationError) as error:
        case.module._publish_output("gen", ".png", content=b"complete output")
    assert state["failed"] and error.value.published is after_publication
    entries = list(case.outputs.iterdir())
    assert len(entries) == (1 if after_publication else 0)
    if entries:
        assert entries[0].read_bytes() == b"complete output"


def test_output_publication_checks_post_sync_metadata_changes(generated_output_case, monkeypatch):
    case = generated_output_case
    original = os.fsync
    changed = []

    def sync(fd):
        result = original(fd)
        files = list(case.outputs.glob("*.png"))
        if files and not changed:
            os.setxattr(files[0], "user.publication-probe", b"changed")
            changed.append(files[0])
        return result

    monkeypatch.setattr(case.module.os, "fsync", sync)
    with pytest.raises(case.module._OutputPublicationError) as error:
        case.module._publish_output("gen", ".png", content=b"complete output")
    assert error.value.published is True
    assert len(changed) == 1 and changed[0].read_bytes() == b"complete output"


def test_output_publication_does_not_create_missing_vault_root(generated_output_case):
    case = generated_output_case
    case.outputs.rmdir()
    with pytest.raises(case.module._OutputPublicationError) as error:
        case.module._publish_output("gen", ".png", content=b"complete output")
    assert error.value.published is False and not case.outputs.exists()


def test_max_content_length_applies_in_wsgi_mode():
    module = _load_module()
    assert module.app.config["MAX_CONTENT_LENGTH"] == 24 * 1024 * 1024


def test_load_pipeline_uses_fp16_variant_when_present(monkeypatch, tmp_path):
    module = _load_module()
    model_dir = tmp_path / "model"
    (model_dir / "unet").mkdir(parents=True)
    (model_dir / "unet" / "diffusion_pytorch_model.fp16.safetensors").write_bytes(b"fake")
    calls = {}

    class FakePipeline:
        def to(self, _device):
            return self

    class FakeAutoPipeline:
        @staticmethod
        def from_pretrained(path, **kwargs):
            calls["path"] = path
            calls["kwargs"] = kwargs
            return FakePipeline()

    fake_torch = types.SimpleNamespace(
        float16="float16",
        float32="float32",
        version=types.SimpleNamespace(hip=None),
        cuda=types.SimpleNamespace(is_available=lambda: False),
        backends=types.SimpleNamespace(mps=types.SimpleNamespace(is_available=lambda: False)),
        xpu=types.SimpleNamespace(is_available=lambda: False),
    )
    fake_diffusers = types.ModuleType("diffusers")
    fake_diffusers.AutoPipelineForText2Image = FakeAutoPipeline
    fake_diffusers.AutoPipelineForImage2Image = FakeAutoPipeline
    fake_diffusers.DiffusionPipeline = FakeAutoPipeline
    monkeypatch.setitem(sys.modules, "torch", fake_torch)
    monkeypatch.setitem(sys.modules, "diffusers", fake_diffusers)

    module._load_pipeline(str(model_dir), "image")

    assert calls["path"] == str(model_dir)
    assert calls["kwargs"]["variant"] == "fp16"
    assert calls["kwargs"]["local_files_only"] is True
    assert calls["kwargs"]["use_safetensors"] is True
    assert calls["kwargs"]["trust_remote_code"] is False


def test_find_diffusion_models_classifies_ltx_video_pipeline(monkeypatch, tmp_path):
    module = _load_module()
    registry_dir = tmp_path / "registry"
    model_dir = registry_dir / "video-tiny-ltx-katuni4ka"
    model_dir.mkdir(parents=True)
    (model_dir / "model_index.json").write_text('{"_class_name": "LTXPipeline"}')
    monkeypatch.setattr(module, "REGISTRY_DIR", registry_dir)

    models = module._find_diffusion_models()

    assert models == [{
        "name": "video-tiny-ltx-katuni4ka",
        "path": str(model_dir),
        "type": "video",
        "class": "LTXPipeline",
        "capabilities": ["txt2vid"],
    }]


def test_find_diffusion_models_advertises_generation_capabilities(monkeypatch, tmp_path):
    module = _load_module()
    registry_dir = tmp_path / "registry"
    image_dir = registry_dir / "stable-image"
    svd_dir = registry_dir / "video-svd-img2vid"
    image_dir.mkdir(parents=True)
    svd_dir.mkdir(parents=True)
    (image_dir / "model_index.json").write_text('{"_class_name": "StableDiffusionPipeline"}')
    (svd_dir / "model_index.json").write_text('{"_class_name": "StableVideoDiffusionPipeline"}')
    monkeypatch.setattr(module, "REGISTRY_DIR", registry_dir)

    models = {model["name"]: model for model in module._find_diffusion_models()}

    assert models["stable-image"]["capabilities"] == ["txt2img", "img2img"]
    assert models["video-svd-img2vid"]["capabilities"] == ["img2vid"]


def test_load_pipeline_keeps_cuda_pipeline_on_gpu_by_default(monkeypatch, tmp_path):
    module = _load_module()
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    calls = {"to": [], "offload": 0, "attention": 0}

    class FakePipeline:
        def to(self, device):
            calls["to"].append(device)
            return self

        def enable_model_cpu_offload(self):
            calls["offload"] += 1

        def enable_xformers_memory_efficient_attention(self):
            calls["attention"] += 1

        def enable_attention_slicing(self):
            calls["attention"] += 1

    class FakeAutoPipeline:
        @staticmethod
        def from_pretrained(path, **kwargs):
            calls["path"] = path
            calls["kwargs"] = kwargs
            return FakePipeline()

    fake_torch = types.SimpleNamespace(
        float16="float16",
        float32="float32",
        version=types.SimpleNamespace(hip=None),
        cuda=types.SimpleNamespace(is_available=lambda: True),
        backends=types.SimpleNamespace(
            mps=types.SimpleNamespace(is_available=lambda: False),
            cuda=types.SimpleNamespace(matmul=types.SimpleNamespace(allow_tf32=False)),
        ),
        xpu=types.SimpleNamespace(is_available=lambda: False),
    )
    fake_diffusers = types.ModuleType("diffusers")
    fake_diffusers.AutoPipelineForText2Image = FakeAutoPipeline
    fake_diffusers.AutoPipelineForImage2Image = FakeAutoPipeline
    fake_diffusers.DiffusionPipeline = FakeAutoPipeline
    monkeypatch.setitem(sys.modules, "torch", fake_torch)
    monkeypatch.setitem(sys.modules, "diffusers", fake_diffusers)
    monkeypatch.delenv("DIFFUSION_CPU_OFFLOAD", raising=False)
    monkeypatch.delenv("DIFFUSION_DEVICE_PREFERENCE", raising=False)

    module._load_pipeline(str(model_dir), "image")

    assert calls["to"] == ["cuda"]
    assert calls["kwargs"]["torch_dtype"] == "float16"
    assert calls["offload"] == 0
    assert calls["attention"] == 2


def test_outputs_list_serves_recent_generated_files(monkeypatch, tmp_path):
    module = _load_module()
    monkeypatch.setattr(module, "OUTPUTS_DIR", tmp_path)
    (tmp_path / "gen_1.png").write_bytes(b"png")
    (tmp_path / "gen_2.mp4").write_bytes(b"mp4")
    (tmp_path / "notes.txt").write_text("ignore")

    with _client(module) as client:
        list_resp = client.get("/v1/outputs")
        file_resp = client.get("/v1/outputs/gen_1.png")
        traversal_resp = client.get("/v1/outputs/../secret.png")

    assert list_resp.status_code == 200
    payload = list_resp.get_json()
    assert {item["filename"] for item in payload} == {"gen_1.png", "gen_2.mp4"}
    assert {item["kind"] for item in payload} == {"image", "video"}
    assert file_resp.status_code == 200
    assert file_resp.data == b"png"
    assert traversal_resp.status_code == 400


def test_img2img_rejects_zero_effective_steps_before_pipeline_load():
    module = _load_module()
    module.app.config["TESTING"] = True

    def _unexpected_load(*args, **kwargs):
        raise AssertionError("_load_pipeline should not be called for invalid parameters")

    module._find_diffusion_models = lambda: [{"name": "tiny", "path": "/tmp/tiny", "type": "image"}]
    module._load_pipeline = _unexpected_load

    with _client(module) as client:
        resp = client.post(
            "/v1/generate/img2img",
            json={
                "prompt": "test",
                "image": TINY_PNG_BASE64,
                "model": "tiny",
                "steps": 1,
                "strength": 0.2,
            },
        )

    assert resp.status_code == 400
    assert "denoising step" in resp.get_json()["error"]


def test_img2img_rejects_overlong_prompt():
    module = _load_module()
    module.app.config["TESTING"] = True

    with _client(module) as client:
        resp = client.post(
            "/v1/generate/img2img",
            json={
                "prompt": "x" * 2001,
                "image": TINY_PNG_BASE64,
            },
        )

    assert resp.status_code == 400
    assert "prompt too long" in resp.get_json()["error"]


def test_img2img_upscales_tiny_images_before_pipeline_call(monkeypatch, tmp_path):
    module = _load_module()
    module.app.config["TESTING"] = True
    module._find_diffusion_models = lambda: [{
        "name": "tiny",
        "path": "/tmp/tiny",
        "type": "image",
        "capabilities": ["img2img"],
    }]

    calls = {}

    class FakePipeline:
        def __call__(self, **kwargs):
            calls["image_size"] = kwargs["image"].size
            return types.SimpleNamespace(images=[FakeOutputImage()])

    class FakeImage:
        def __init__(self, size=(1, 1)):
            self.size = size
            self.format = "PNG"

        def convert(self, _mode):
            return self

        def resize(self, size):
            return FakeImage(size)

        def verify(self):
            return None

        def load(self):
            return None

        def close(self):
            return None

    class FakeOutputImage:
        def save(self, target, format=None):
            if hasattr(target, "write"):
                target.write(b"fake-png")
                return
            Path(target).write_bytes(b"fake-png")

    fake_image_module = types.ModuleType("PIL.Image")
    fake_image_module.open = lambda _stream: FakeImage()

    fake_pil_module = types.ModuleType("PIL")
    fake_pil_module.Image = fake_image_module

    fake_torch_module = types.ModuleType("torch")

    module._load_pipeline = lambda *args, **kwargs: FakePipeline()
    monkeypatch.setattr(
        module,
        "time",
        types.SimpleNamespace(monotonic=lambda: 100.0, time=lambda: 1234567890),
    )
    monkeypatch.setattr(module, "OUTPUTS_DIR", tmp_path)

    monkeypatch.setitem(sys.modules, "torch", fake_torch_module)
    monkeypatch.setitem(sys.modules, "PIL", fake_pil_module)
    monkeypatch.setitem(sys.modules, "PIL.Image", fake_image_module)

    with _client(module) as client:
        resp = client.post(
            "/v1/generate/img2img",
            json={
                "prompt": "test",
                "image": TINY_PNG_BASE64,
                "model": "tiny",
                "steps": 2,
                "strength": 0.5,
            },
        )

    assert resp.status_code == 200
    assert calls["image_size"] == (8, 8)
    assert resp.get_json()["saved_to"].endswith(".png")


def test_generate_video_requires_image_for_image_conditioned_models():
    module = _load_module()
    module.app.config["TESTING"] = True
    module._find_diffusion_models = lambda: [{
        "name": "tiny-video",
        "path": "/tmp/tiny-video",
        "type": "video",
        "class": "StableVideoDiffusionPipeline",
        "capabilities": ["img2vid"],
    }]

    def _unexpected_load(*args, **kwargs):
        raise AssertionError("_load_pipeline should not be called when image is missing")

    module._load_pipeline = _unexpected_load

    with _client(module) as client:
        resp = client.post(
            "/v1/generate/video",
            json={
                "model": "tiny-video",
                "prompt": "ignored for image-conditioned model",
                "num_frames": 4,
                "steps": 2,
            },
        )

    assert resp.status_code == 400
    assert "image (base64) is required" in resp.get_json()["error"]


def test_generate_video_requires_prompt_for_text_conditioned_models():
    module = _load_module()
    module.app.config["TESTING"] = True
    module._find_diffusion_models = lambda: [{
        "name": "txt2vid",
        "path": "/tmp/txt2vid",
        "type": "video",
        "class": "TextToVideoPipeline",
        "capabilities": ["txt2vid"],
    }]

    def _unexpected_load(*args, **kwargs):
        raise AssertionError("_load_pipeline should not be called when prompt is missing")

    module._load_pipeline = _unexpected_load

    with _client(module) as client:
        resp = client.post(
            "/v1/generate/video",
            json={
                "model": "txt2vid",
                "num_frames": 4,
                "steps": 2,
            },
        )

    assert resp.status_code == 400
    assert resp.get_json()["error"] == "prompt is required"


def test_prepare_video_conditioning_input_resizes_for_nonstandard_encoder_size(monkeypatch):
    module = _load_module()

    class FakeImage:
        def __init__(self, size=(256, 256)):
            self.size = size

        def resize(self, size):
            return FakeImage(size)

    class FakeArray:
        def __init__(self, image):
            self.image = image

        def astype(self, _dtype):
            return self

        def __truediv__(self, _value):
            return self

    class FakeTensor:
        def __init__(self):
            self.permute_args = None
            self.unsqueeze_arg = None

        def permute(self, *args):
            self.permute_args = args
            return self

        def unsqueeze(self, arg):
            self.unsqueeze_arg = arg
            return self

    fake_numpy = types.ModuleType("numpy")
    fake_numpy.asarray = lambda image: FakeArray(image)

    captured = {}

    def _from_numpy(arr):
        captured["image_size"] = arr.image.size
        tensor = FakeTensor()
        captured["tensor"] = tensor
        return tensor

    fake_torch = types.SimpleNamespace(from_numpy=_from_numpy)
    fake_pipe = types.SimpleNamespace(
        image_encoder=types.SimpleNamespace(config=types.SimpleNamespace(image_size=32))
    )

    monkeypatch.setitem(sys.modules, "numpy", fake_numpy)

    prepared = module._prepare_video_conditioning_input(FakeImage(), fake_pipe, fake_torch)

    assert prepared is captured["tensor"]
    assert captured["image_size"] == (32, 32)
    assert prepared.permute_args == (2, 0, 1)
    assert prepared.unsqueeze_arg == 0


def test_generate_video_passes_image_for_image_conditioned_models(monkeypatch, tmp_path):
    module = _load_module()
    module.app.config["TESTING"] = True
    module._find_diffusion_models = lambda: [{
        "name": "tiny-video",
        "path": "/tmp/tiny-video",
        "type": "video",
        "class": "StableVideoDiffusionPipeline",
        "capabilities": ["img2vid"],
    }]

    calls = {}

    class FakePipeline:
        def __call__(self, **kwargs):
            calls["kwargs"] = kwargs
            return types.SimpleNamespace(frames=[[b"frame-bytes"]])

    class FakeImage:
        def __init__(self, size=(1, 1)):
            self.size = size
            self.format = "PNG"

        def convert(self, _mode):
            return self

        def resize(self, size):
            return FakeImage(size)

        def verify(self):
            return None

        def load(self):
            return None

        def close(self):
            return None

    fake_image_module = types.ModuleType("PIL.Image")
    fake_image_module.open = lambda _stream: FakeImage()

    fake_pil_module = types.ModuleType("PIL")
    fake_pil_module.Image = fake_image_module

    fake_torch_module = types.ModuleType("torch")

    fake_diffusers_utils = types.ModuleType("diffusers.utils")

    def _export_to_video(frames, path, fps=8):
        calls["export"] = {"frames": frames, "path": path, "fps": fps}
        Path(path).write_bytes(b"fake-video")

    fake_diffusers_utils.export_to_video = _export_to_video
    fake_diffusers_module = types.ModuleType("diffusers")
    fake_diffusers_module.utils = fake_diffusers_utils

    module._load_pipeline = lambda *args, **kwargs: FakePipeline()
    monkeypatch.setattr(
        module,
        "time",
        types.SimpleNamespace(monotonic=lambda: 100.0, time=lambda: 1234567890),
    )
    monkeypatch.setattr(module, "OUTPUTS_DIR", tmp_path)

    monkeypatch.setitem(sys.modules, "torch", fake_torch_module)
    monkeypatch.setitem(sys.modules, "PIL", fake_pil_module)
    monkeypatch.setitem(sys.modules, "PIL.Image", fake_image_module)
    monkeypatch.setitem(sys.modules, "diffusers", fake_diffusers_module)
    monkeypatch.setitem(sys.modules, "diffusers.utils", fake_diffusers_utils)

    with _client(module) as client:
        resp = client.post(
            "/v1/generate/video",
            json={
                "model": "tiny-video",
                "image": TINY_PNG_BASE64,
                "num_frames": 4,
                "steps": 2,
                "fps": 6,
            },
        )

    assert resp.status_code == 200
    assert "image" in calls["kwargs"]
    assert "prompt" not in calls["kwargs"]
    assert calls["kwargs"]["width"] == 16
    assert calls["kwargs"]["height"] == 16
    assert calls["kwargs"]["num_frames"] == 4
    assert calls["kwargs"]["num_inference_steps"] == 2
    assert calls["export"]["fps"] == 6


def test_generate_video_honors_requested_dimensions_for_image_conditioned_models(monkeypatch, tmp_path):
    module = _load_module()
    module.app.config["TESTING"] = True
    module._find_diffusion_models = lambda: [{
        "name": "tiny-video",
        "path": "/tmp/tiny-video",
        "type": "video",
        "class": "StableVideoDiffusionPipeline",
        "capabilities": ["img2vid"],
    }]

    calls = {}

    class FakePipeline:
        def __call__(self, **kwargs):
            calls["kwargs"] = kwargs
            return types.SimpleNamespace(frames=[[b"frame-bytes"]])

    class FakeImage:
        def __init__(self, size=(64, 48)):
            self.size = size
            self.format = "PNG"

        def convert(self, _mode):
            return self

        def resize(self, size):
            return FakeImage(size)

        def verify(self):
            return None

        def load(self):
            return None

        def close(self):
            return None

    fake_image_module = types.ModuleType("PIL.Image")
    fake_image_module.open = lambda _stream: FakeImage()

    fake_pil_module = types.ModuleType("PIL")
    fake_pil_module.Image = fake_image_module

    fake_torch_module = types.ModuleType("torch")
    fake_diffusers_utils = types.ModuleType("diffusers.utils")
    def _export_to_video(frames, path, fps=8):
        calls["export"] = {"frames": frames, "path": path, "fps": fps}
        Path(path).write_bytes(b"video")

    fake_diffusers_utils.export_to_video = _export_to_video
    fake_diffusers_module = types.ModuleType("diffusers")
    fake_diffusers_module.utils = fake_diffusers_utils

    module._load_pipeline = lambda *args, **kwargs: FakePipeline()
    monkeypatch.setattr(
        module,
        "time",
        types.SimpleNamespace(monotonic=lambda: 100.0, time=lambda: 1234567890),
    )
    monkeypatch.setattr(module, "OUTPUTS_DIR", tmp_path)

    monkeypatch.setitem(sys.modules, "torch", fake_torch_module)
    monkeypatch.setitem(sys.modules, "PIL", fake_pil_module)
    monkeypatch.setitem(sys.modules, "PIL.Image", fake_image_module)
    monkeypatch.setitem(sys.modules, "diffusers", fake_diffusers_module)
    monkeypatch.setitem(sys.modules, "diffusers.utils", fake_diffusers_utils)

    with _client(module) as client:
        resp = client.post(
            "/v1/generate/video",
            json={
                "model": "tiny-video",
                "image": TINY_PNG_BASE64,
                "width": 40,
                "height": 36,
                "num_frames": 4,
                "steps": 2,
            },
        )

    assert resp.status_code == 200
    assert calls["kwargs"]["width"] == 48
    assert calls["kwargs"]["height"] == 48
    payload = resp.get_json()
    assert not Path(calls["export"]["path"]).exists()
    assert Path(payload["saved_to"]).is_file()
    assert payload["parameters"]["image_conditioned"] is True
    assert payload["saved_to"].endswith(".mp4")


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory"])
def test_outputs_reject_nonprivate_entries(monkeypatch, tmp_path, kind):
    module = _load_module()
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    outside = tmp_path / "outside.png"
    outside.write_bytes(b"outside-secret")
    entry = outputs / "unsafe.png"
    if kind == "symlink":
        entry.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, entry)
    elif kind == "fifo":
        os.mkfifo(entry)
    else:
        entry.mkdir()
    monkeypatch.setattr(module, "OUTPUTS_DIR", outputs)
    with _client(module) as client:
        listing = client.get("/v1/outputs")
        download = client.get("/v1/outputs/unsafe.png")
    assert listing.status_code == 200
    assert listing.get_json() == []
    assert download.status_code == 404
    assert b"outside-secret" not in download.data


@pytest.mark.parametrize("ancestor", [False, True])
def test_outputs_reject_linked_root_or_ancestor(monkeypatch, tmp_path, ancestor):
    module = _load_module()
    real = tmp_path / "real"
    outputs = real / "outputs"
    outputs.mkdir(parents=True)
    (outputs / "secret.png").write_bytes(b"outside-secret")
    alias = tmp_path / "alias"
    alias.symlink_to(real if ancestor else outputs, target_is_directory=True)
    monkeypatch.setattr(module, "OUTPUTS_DIR", alias / "outputs" if ancestor else alias)
    with _client(module) as client:
        assert client.get("/v1/outputs").status_code == 503
        response = client.get("/v1/outputs/secret.png")
    assert response.status_code == 404
    assert b"outside-secret" not in response.data


@pytest.mark.parametrize("replacement", ["symlink", "regular", "fifo"])
def test_output_replacement_before_open_fails_closed(monkeypatch, tmp_path, replacement):
    module = _load_module()
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    entry = outputs / "saved.png"
    entry.write_bytes(b"normal")
    outside = tmp_path / "outside.png"
    outside.write_bytes(b"outside-secret")
    monkeypatch.setattr(module, "OUTPUTS_DIR", outputs)
    original_open = module.os.open
    def replace_at_open(path, flags, *args, **kwargs):
        if path == "saved.png" and kwargs.get("dir_fd") is not None and not flags & os.O_PATH:
            entry.unlink()
            if replacement == "symlink":
                entry.symlink_to(outside)
            elif replacement == "regular":
                entry.write_bytes(b"replacement")
            else:
                os.mkfifo(entry)
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(module.os, "open", replace_at_open)
    with _client(module) as client:
        response = client.get("/v1/outputs/saved.png")
    assert response.status_code == 404
    assert b"outside-secret" not in response.data


def test_output_response_uses_validated_fd_after_path_swap(monkeypatch, tmp_path):
    module = _load_module()
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    entry = outputs / "saved.png"
    entry.write_bytes(b"original-output")
    outside = tmp_path / "outside.png"
    outside.write_bytes(b"outside-secret")
    monkeypatch.setattr(module, "OUTPUTS_DIR", outputs)
    original_send = module.send_file
    captured = []
    def replace_before_send(stream, **kwargs):
        captured.append(stream)
        entry.unlink()
        entry.symlink_to(outside)
        return original_send(stream, **kwargs)
    monkeypatch.setattr(module, "send_file", replace_before_send)
    with _client(module) as client:
        response = client.get("/v1/outputs/saved.png", buffered=True)
        assert response.status_code == 200
        assert response.data == b"original-output"
        response.close()
    assert captured[0].closed


def test_output_root_replacement_fails_closed(monkeypatch, tmp_path):
    module = _load_module()
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    (outputs / "saved.png").write_bytes(b"normal")
    monkeypatch.setattr(module, "OUTPUTS_DIR", outputs)
    original_open = module._open_output_file
    def replace_root(root, filename):
        result = original_open(root, filename)
        outputs.rename(tmp_path / "old-outputs")
        outputs.mkdir()
        (outputs / "saved.png").write_bytes(b"replacement")
        return result
    monkeypatch.setattr(module, "_open_output_file", replace_root)
    with _client(module) as client:
        response = client.get("/v1/outputs/saved.png")
    assert response.status_code == 404
    assert b"replacement" not in response.data


def test_output_fd_closed_when_response_construction_fails(monkeypatch, tmp_path):
    module = _load_module()
    (tmp_path / "saved.png").write_bytes(b"normal")
    monkeypatch.setattr(module, "OUTPUTS_DIR", tmp_path)
    captured = []
    def fail_send(stream, **kwargs):
        captured.append(stream)
        raise OSError("simulated transfer setup failure")
    monkeypatch.setattr(module, "send_file", fail_send)
    with _client(module) as client:
        assert client.get("/v1/outputs/saved.png").status_code == 404
    assert captured[0].closed


@pytest.mark.parametrize("name,mimetype", [("saved.png", "image/png"), ("saved.mp4", "video/mp4")])
def test_output_file_headers_ranges_and_closure(monkeypatch, tmp_path, name, mimetype):
    module = _load_module()
    (tmp_path / name).write_bytes(b"0123456789")
    monkeypatch.setattr(module, "OUTPUTS_DIR", tmp_path)
    original_send = module.send_file
    streams = []
    def capture_send(stream, **kwargs):
        streams.append(stream)
        return original_send(stream, **kwargs)
    monkeypatch.setattr(module, "send_file", capture_send)
    with _client(module) as client:
        response = client.get("/v1/outputs/" + name, buffered=True)
        assert response.status_code == 200
        assert response.data == b"0123456789"
        assert response.content_type == mimetype
        assert response.content_length == 10
        etag = response.headers["ETag"]
        response.close()
        partial = client.get("/v1/outputs/" + name, headers={"Range": "bytes=2-4"}, buffered=True)
        assert partial.status_code == 206
        assert partial.data == b"234"
        partial.close()
        cached = client.get("/v1/outputs/" + name, headers={"If-None-Match": etag}, buffered=True)
        assert cached.status_code == 304
        cached.close()
        invalid = client.get("/v1/outputs/" + name, headers={"Range": "bytes=100-200"}, buffered=True)
        assert invalid.status_code == 416
        invalid.close()
    assert len(streams) == 4
    assert all(stream.closed for stream in streams)
