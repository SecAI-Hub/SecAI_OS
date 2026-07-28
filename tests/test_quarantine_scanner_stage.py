"""Tests for isolated single-stage quarantine execution."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "quarantine"))

from quarantine import scanner_stage


def test_stage_dispatch_cannot_claim_unexecuted_stages(tmp_path, monkeypatch):
    artifact = tmp_path / "model.gguf"
    artifact.write_bytes(b"GGUF")
    calls = []

    monkeypatch.setattr(
        scanner_stage.pipeline,
        "check_format_gate",
        lambda path, policy: calls.append(("format_gate", path)) or {"passed": True},
    )
    monkeypatch.setattr(
        scanner_stage.pipeline,
        "check_source_policy",
        lambda _source: (_ for _ in ()).throw(
            AssertionError("unrequested source stage executed")
        ),
    )

    result = scanner_stage.run_stage(
        "format_gate",
        artifact,
        "a" * 64,
        {},
        source_url="",
        directory=False,
    )

    assert result == {"passed": True}
    assert calls == [("format_gate", artifact)]


def test_directory_hash_stage_uses_image_owned_manifest_fallback(
    tmp_path,
    monkeypatch,
):
    artifact = tmp_path / "diffusion"
    artifact.mkdir()
    monkeypatch.setattr(
        scanner_stage.pipeline,
        "check_hash_pin",
        lambda *_args, **_kwargs: {
            "passed": False,
            "reason": "remote artifact has no pinned hash",
        },
    )
    monkeypatch.setattr(
        scanner_stage.pipeline,
        "check_huggingface_directory_manifest",
        lambda *_args, **_kwargs: {
            "passed": True,
            "manifest_sha256": "b" * 64,
            "revision": "c" * 40,
        },
    )

    result = scanner_stage.run_stage(
        "hash_pin",
        artifact,
        "a" * 64,
        {},
        source_url="https://huggingface.co/example/model",
        directory=True,
    )

    assert result["passed"] is True
    assert result["mechanism"] == "image-owned-huggingface-manifest"
    assert result["directory_hash_pin"]["passed"] is False


def test_directory_hash_stage_never_overrides_block_or_accepts_local_tofu(
    tmp_path,
    monkeypatch,
):
    artifact = tmp_path / "diffusion"
    artifact.mkdir()
    monkeypatch.setattr(
        scanner_stage.pipeline,
        "check_huggingface_directory_manifest",
        lambda *_args, **_kwargs: {
            "passed": True,
            "manifest_sha256": "b" * 64,
            "revision": "c" * 40,
        },
    )

    monkeypatch.setattr(
        scanner_stage.pipeline,
        "check_hash_pin",
        lambda *_args, **_kwargs: {
            "passed": False,
            "pinned": True,
            "match": True,
            "blocked": True,
            "reason": "model blocked by policy",
        },
    )
    blocked = scanner_stage.run_stage(
        "hash_pin",
        artifact,
        "a" * 64,
        {},
        source_url="https://huggingface.co/example/model",
        directory=True,
    )
    assert blocked["passed"] is False

    monkeypatch.setattr(
        scanner_stage.pipeline,
        "check_hash_pin",
        lambda *_args, **_kwargs: {
            "passed": True,
            "pinned": False,
            "note": "first-install trust",
        },
    )
    local = scanner_stage.run_stage(
        "hash_pin",
        artifact,
        "a" * 64,
        {},
        source_url="",
        directory=True,
    )
    assert local["passed"] is False
