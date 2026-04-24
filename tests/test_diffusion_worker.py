import importlib.util
import sys
import types
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
APP_PATH = REPO_ROOT / "services" / "diffusion-worker" / "app.py"
TINY_PNG_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7Z0ioAAAAASUVORK5CYII="
)


def _load_module():
    spec = importlib.util.spec_from_file_location("diffusion_app_under_test", str(APP_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_max_content_length_applies_in_wsgi_mode():
    module = _load_module()
    assert module.app.config["MAX_CONTENT_LENGTH"] == 100 * 1024 * 1024


def test_img2img_rejects_zero_effective_steps_before_pipeline_load():
    module = _load_module()
    module.app.config["TESTING"] = True

    def _unexpected_load(*args, **kwargs):
        raise AssertionError("_load_pipeline should not be called for invalid parameters")

    module._find_diffusion_models = lambda: [{"name": "tiny", "path": "/tmp/tiny", "type": "image"}]
    module._load_pipeline = _unexpected_load

    with module.app.test_client() as client:
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

    with module.app.test_client() as client:
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
    }]

    calls = {}

    class FakePipeline:
        def __call__(self, **kwargs):
            calls["image_size"] = kwargs["image"].size
            return types.SimpleNamespace(images=[FakeOutputImage()])

    class FakeImage:
        def __init__(self, size=(1, 1)):
            self.size = size

        def convert(self, _mode):
            return self

        def resize(self, size):
            return FakeImage(size)

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

    with module.app.test_client() as client:
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
    }]

    def _unexpected_load(*args, **kwargs):
        raise AssertionError("_load_pipeline should not be called when image is missing")

    module._load_pipeline = _unexpected_load

    with module.app.test_client() as client:
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
    }]

    def _unexpected_load(*args, **kwargs):
        raise AssertionError("_load_pipeline should not be called when prompt is missing")

    module._load_pipeline = _unexpected_load

    with module.app.test_client() as client:
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
    }]

    calls = {}

    class FakePipeline:
        def __call__(self, **kwargs):
            calls["kwargs"] = kwargs
            return types.SimpleNamespace(frames=[[b"frame-bytes"]])

    class FakeImage:
        def __init__(self, size=(1, 1)):
            self.size = size

        def convert(self, _mode):
            return self

        def resize(self, size):
            return FakeImage(size)

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

    with module.app.test_client() as client:
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
    }]

    calls = {}

    class FakePipeline:
        def __call__(self, **kwargs):
            calls["kwargs"] = kwargs
            return types.SimpleNamespace(frames=[[b"frame-bytes"]])

    class FakeImage:
        def __init__(self, size=(64, 48)):
            self.size = size

        def convert(self, _mode):
            return self

        def resize(self, size):
            return FakeImage(size)

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

    with module.app.test_client() as client:
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
    assert Path(calls["export"]["path"]).exists()
    payload = resp.get_json()
    assert payload["parameters"]["image_conditioned"] is True
    assert payload["saved_to"].endswith(".mp4")
