import importlib.util
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
PARSER_PATH = REPO_ROOT / ".github" / "scripts" / "normalize-govulncheck.py"


def _load_parser():
    spec = importlib.util.spec_from_file_location("normalize_govulncheck", PARSER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_parses_pretty_printed_concatenated_govulncheck_stream(tmp_path):
    parser = _load_parser()
    messages = [
        {"config": {"protocol_version": "v1.0.0"}},
        {"osv": {"id": "GO-TEST-0001", "aliases": ["CVE-2099-0001"]}},
        {"finding": {"osv": "GO-TEST-0001"}},
    ]
    stream = "\n".join(json.dumps(message, indent=2) for message in messages)
    parsed = parser.parse_json_stream(stream)
    assert parsed == messages

    output = tmp_path / "govuln.json"
    output.write_text(stream, encoding="utf-8")
    assert parser.normalize("registry", output) == [
        {
            "service": "registry",
            "primary_id": "GO-TEST-0001",
            "identifiers": ["CVE-2099-0001", "GO-TEST-0001"],
        }
    ]


def test_rejects_non_json_trailing_content():
    parser = _load_parser()
    try:
        parser.parse_json_stream('{"config":{"protocol_version":"v1"}} trailing')
    except ValueError as exc:
        assert "invalid JSON" in str(exc)
    else:
        raise AssertionError("malformed trailing stream content was accepted")
