"""Bounded normalization and conservative credential detection for egress.

These checks are heuristics. They do not establish anonymity or declassify
confidential subject matter. Authorization and offline policy remain separate.
"""

import re
import unicodedata
from urllib.parse import unquote, urlsplit, urlunsplit


_CREDENTIAL_PATTERNS = (
    re.compile(r"\b(?:bearer|basic)\s+[A-Za-z0-9+/_.=~\-]{8,}", re.I),
    re.compile(
        r"(?:\b(?:password|passwd|passphrase|secret|token|пароль|contraseña|senha|"
        r"mot\s+de\s+passe|(?:api|access|auth|private|client|session|refresh|id)[ _-]?(?:key|token|secret|password))"
        r"|密码|密碼|パスワード|비밀번호)[\"']?\s*[:=]\s*[\"']?[^\s,;\"']+", re.I
    ),
    re.compile(r"\b(?:sk-(?:proj-|svcacct-)?|gh[pousr]_|github_pat_|xox[baprs]-)[A-Za-z0-9_\-]{12,}\b", re.I),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b"),
    re.compile(r"-----BEGIN\s+(?:[A-Z0-9]+\s+)?PRIVATE KEY-----", re.I),
    re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@"),
)


def decoded_url_text(raw: str) -> str:
    if not isinstance(raw, str) or len(raw) > 16 * 1024:
        raise ValueError("invalid or oversized query")
    value = unicodedata.normalize("NFKC", raw)
    # Percent-encoded and HTML-form query fragments must be inspected before
    # their separators or identifiers can be split by an outbound length cap.
    for _ in range(3):
        decoded = unquote(value, errors="strict")
        if decoded == value:
            break
        value = decoded
    else:
        raise ValueError("query encoding is too deep")
    return unicodedata.normalize("NFKC", value)


def normalized_query(raw: str) -> str:
    value = decoded_url_text(raw)
    if any(unicodedata.category(c) == "Cs" or (unicodedata.category(c) == "Cc" and not c.isspace()) for c in value):
        raise ValueError("invalid Unicode query")
    # Removing zero-width formatting also prevents obfuscated credential keys.
    value = "".join(c for c in value if unicodedata.category(c) != "Cf")
    return value.strip()


def contains_credentials(query: str) -> bool:
    return any(pattern.search(query) for pattern in _CREDENTIAL_PATTERNS)


_TRACKING_QUERY_KEYS = frozenset({
    "fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid", "yclid",
    "twclid", "ttclid", "igshid", "_ga", "_gl",
})


def strip_tracking_parameters(url: str) -> str:
    """Remove known tracking query keys without rewriting unrelated values.

    Call only after URL validation. Local rules avoid downloading an unpinned
    third-party tracker list during service startup.
    """
    parts = urlsplit(url)
    kept = []
    for field in parts.query.split("&"):
        key = decoded_url_text(field.split("=", 1)[0]).casefold()
        if key.startswith("utm_") or key in _TRACKING_QUERY_KEYS:
            continue
        kept.append(field)
    query = "&".join(kept)
    if query == parts.query:
        return url
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
