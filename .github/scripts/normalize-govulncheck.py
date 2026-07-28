#!/usr/bin/env python3
"""Normalize govulncheck's concatenated JSON stream into finding JSONL."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def parse_json_stream(text: str) -> list[dict[str, Any]]:
    """Decode adjacent JSON objects, including pretty-printed objects."""
    decoder = json.JSONDecoder()
    messages: list[dict[str, Any]] = []
    offset = 0
    length = len(text)

    while offset < length:
        while offset < length and text[offset].isspace():
            offset += 1
        if offset == length:
            break
        try:
            message, end = decoder.raw_decode(text, offset)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSON at byte {exc.pos} (line {exc.lineno}, column {exc.colno}): "
                f"{exc.msg}"
            ) from exc
        if not isinstance(message, dict):
            raise ValueError(f"message at byte {offset} is not a JSON object")
        messages.append(message)
        offset = end

    return messages


def normalize(service: str, output: Path) -> list[dict[str, Any]]:
    try:
        messages = parse_json_stream(output.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read govulncheck output: {exc}") from exc

    configs = [message.get("config") for message in messages if message.get("config")]
    if len(configs) != 1 or not configs[0].get("protocol_version"):
        raise ValueError("govulncheck stream lacks one valid configuration message")

    aliases: dict[str, set[str]] = {}
    for message in messages:
        osv = message.get("osv") or {}
        primary = osv.get("id")
        if not primary:
            continue
        identifiers = {primary}
        identifiers.update(
            alias
            for alias in osv.get("aliases", [])
            if isinstance(alias, str) and alias
        )
        aliases[primary] = identifiers

    finding_ids = {
        finding["osv"]
        for message in messages
        if (finding := message.get("finding"))
        and isinstance(finding.get("osv"), str)
        and finding["osv"]
    }
    return [
        {
            "service": service,
            "primary_id": primary,
            "identifiers": sorted(aliases.get(primary, {primary})),
        }
        for primary in sorted(finding_ids)
    ]


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"Usage: {argv[0]} SERVICE GOVULNCHECK_JSON", file=sys.stderr)
        return 2
    service = argv[1]
    try:
        findings = normalize(service, Path(argv[2]))
    except ValueError as exc:
        print(f"::error::{service}: {exc}", file=sys.stderr)
        return 1
    for finding in findings:
        print(json.dumps(finding, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
