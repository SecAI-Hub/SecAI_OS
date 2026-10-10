"""Safe-format admission must not dispatch the scanner into ZIP/pickle input."""

import io
import json
import struct
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/quarantine"))
from quarantine import pipeline


def _tensor(path, data=b"\0", *, header_length=None):
    header = json.dumps({"value": {"dtype": "U8", "shape": [len(data)],
                                   "data_offsets": [0, len(data)]}}).encode()
    length = len(header) if header_length is None else header_length
    with path.open("wb") as handle:
        handle.write(struct.pack("<Q", length))
        handle.write(header)
        remaining = length - len(header)
        while remaining:
            size = min(remaining, 1024 * 1024)
            handle.write(b" " * size)
            remaining -= size
        handle.write(data)


def _directory(tmp_path):
    (tmp_path / "model_index.json").write_text(json.dumps({
        "_class_name": "StableDiffusionPipeline", "requires_safety_checker": False,
        "unet": ["diffusers", "UNet2DConditionModel"],
    }))
    return tmp_path / "weights.safetensors"


def test_real_inert_zip_tensor_rejected_before_static_scan(tmp_path, monkeypatch):
    path = _directory(tmp_path)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("inert.pkl", b"\x80\x02N.")  # Never deserialize.
    payload = buffer.getvalue()
    length = int.from_bytes(b"PK\x03\x04" + b"\0" * 4, "little")
    assert length < pipeline.SAFETENSORS_MAX_HEADER
    _tensor(path, payload, header_length=length)
    # Demonstrate genuine ZIP interpretation, not merely an extension or a
    # malformed JSON fixture. The former gate accepted this same byte layout.
    with zipfile.ZipFile(path) as archive:
        assert archive.read("inert.pkl") == b"\x80\x02N."
    single = pipeline.check_format_gate(path)
    directory = pipeline.check_format_gate_directory(tmp_path)
    assert not single["passed"] and "ambiguous ZIP magic" in single["reason"]
    assert not directory["passed"]
    assert any("ambiguous ZIP magic" in issue for issue in directory["issues"])

    def static_scan_forbidden(*args, **kwargs):
        pytest.fail("rejected format reached a downstream scanner")

    monkeypatch.setattr(pipeline, "check_source_policy", lambda *args: {"passed": True})
    monkeypatch.setattr(pipeline, "check_static_scan", static_scan_forbidden)
    monkeypatch.setattr(pipeline, "check_static_scan_directory", static_scan_forbidden)
    assert pipeline.run_pipeline(path, "a" * 64, {})["reason"] == "format_gate"
    assert pipeline.run_pipeline_directory(tmp_path, "a" * 64, {})["reason"] == "format_gate"


def test_ordinary_safe_formats_and_tensor_bytes_remain_accepted(tmp_path):
    path = _directory(tmp_path)
    # ZIP-like tensor bytes are ordinary numeric data; only dispatch magic in
    # the file's initial header length is ambiguous to the installed detector.
    _tensor(path, b"PK\x03\x04PK\x05\x06PK\x07\x08")
    assert pipeline.check_format_gate(path)["passed"]
    assert pipeline.check_format_gate_directory(tmp_path)["passed"]
    gguf = tmp_path / "ordinary.gguf"
    gguf.write_bytes(b"GGUF" + struct.pack("<IQQ", 3, 0, 0))
    assert pipeline.check_format_gate(gguf)["passed"]
