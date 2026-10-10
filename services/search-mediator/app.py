"""
Secure AI Appliance - Search Mediator

Tor-routed web search via local SearXNG instance.
Sanitizes outbound queries (strips PII) and inbound results (strips HTML/scripts,
detects injection attempts, enforces size limits).

This bridge limits requests to a configured SearXNG origin. Tor routing and
execution isolation need independent OS enforcement and verification.
"""

# ruff: noqa: E402

import hmac
import html
import ipaddress
import logging
import math
import os
import re
import secrets
import stat
import sys
import time
import unicodedata
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, Response, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

# Add services/ to path so we can import common.audit_chain
_services_root = str(Path(__file__).resolve().parent.parent)
if _services_root not in sys.path:
    sys.path.insert(0, _services_root)

from common.audit_chain import AuditChain

from search_privacy import contains_credentials, decoded_url_text, normalized_query, strip_tracking_parameters

from search_boundary import AuditUnavailable, EgressDenied, SearchEgress
from search_transport import request_bounded as _transport_get
from flask import g, has_request_context

log = logging.getLogger("search-mediator")

app = Flask(__name__)
_privacy_random = secrets.SystemRandom()

BIND_ADDR = os.getenv("BIND_ADDR", "127.0.0.1:8485")
SEARXNG_URL = os.getenv("SEARXNG_URL", "http://127.0.0.1:8888")
APPLIANCE_CONFIG = os.getenv("APPLIANCE_CONFIG", "/etc/secure-ai/config/appliance.yaml")
POLICY_PATH = os.getenv("POLICY_PATH", "/etc/secure-ai/policy/policy.yaml")
AUDIT_DIR = os.getenv("AUDIT_DIR", "/var/lib/secure-ai/logs")
SEARCH_HEALTH_TIMEOUT = float(os.getenv("SEARCH_HEALTH_TIMEOUT", "1.0"))

_audit_chain = AuditChain(os.path.join(AUDIT_DIR, "search-audit.jsonl"))

# Limits
MAX_SEARCH_BODY_BYTES = 16 * 1024
MAX_QUERY_LENGTH = 200
MAX_RESULTS = 5
MAX_SNIPPET_LENGTH = 500
MAX_CONTEXT_LENGTH = 4000
MAX_RESULT_URL_LENGTH = 2048
app.config["MAX_CONTENT_LENGTH"] = MAX_SEARCH_BODY_BYTES

# Traffic analysis protection (M19)
QUERY_DELAY_MIN = float(os.getenv("QUERY_DELAY_MIN", "0.5"))   # seconds
QUERY_DELAY_MAX = float(os.getenv("QUERY_DELAY_MAX", "3.0"))   # seconds
QUERY_PAD_BUCKETS = [256, 512, 1024]  # fixed-size query padding buckets (bytes)

# Differential privacy for search queries (M20)
DECOY_QUERIES = [
    "weather forecast today",
    "world news headlines",
    "popular recipes",
    "movie reviews 2026",
    "stock market update",
    "sports scores today",
    "technology news",
    "book recommendations",
    "travel destinations",
    "music new releases",
    "science discoveries",
    "health tips",
    "home improvement ideas",
    "gardening basics",
    "history facts",
    "programming tutorials",
    "fitness exercises",
    "cooking techniques",
    "photography tips",
    "language learning",
    # Expanded pool for better differential privacy (M25)
    "best restaurants near me",
    "how to change a tire",
    "local events this weekend",
    "job interview tips",
    "budget travel planning",
    "online learning platforms",
    "pet care advice",
    "diy crafts for beginners",
    "smartphone comparison 2026",
    "electric vehicle reviews",
    "climate change statistics",
    "space exploration news",
    "mental health resources",
    "investment strategies",
    "home workout routines",
    "organic food benefits",
    "renewable energy facts",
    "video game releases 2026",
    "interior design trends",
    "car maintenance schedule",
    "hiking trails nearby",
    "resume writing guide",
    "sleep improvement tips",
    "public transit schedules",
    "volunteer opportunities",
    "digital privacy guide",
    "meal prep ideas",
    "apartment hunting tips",
    "common houseplant care",
    "tax preparation help",
    "camping gear checklist",
    "first aid basics",
    "music theory fundamentals",
    "recycling guidelines",
    "time management techniques",
    "outdoor grilling recipes",
    "yoga for beginners",
    "home energy efficiency",
    "water conservation tips",
    "college application advice",
    "podcast recommendations",
    "bicycle maintenance",
    "coffee brewing methods",
    "board game suggestions",
    "seasonal allergy remedies",
    "mindfulness meditation",
    "weekend brunch ideas",
    "local library services",
    "skin care routine",
    "bird watching guide",
    "earthquake preparedness",
    "foreign currency exchange",
    "used car buying guide",
    "composting for beginners",
    "national park information",
    "free online courses",
    "home security systems",
    "holiday gift ideas",
    "effective study habits",
    "community garden programs",
]

# Words that make a query highly unique / identifying
RARE_QUERY_PATTERNS = [
    re.compile(r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b"),       # Proper names (First Last)
    re.compile(r"\b\d+\s+[A-Z][a-z]+\s+(?:St|Ave|Rd|Blvd|Dr|Ln|Ct)\b"),  # Street addresses
    re.compile(r"\b[A-Z]{2,}\s*-?\s*\d{3,}\b"),           # Case/ID numbers
    re.compile(r"\brare\s+disease\b", re.I),               # Rare medical terms
    re.compile(r"\bcase\s+(?:no|number|#)\s*\d+\b", re.I), # Case references
]

# Query generalization: keyword → broader category term for cover traffic.
# Before the real query, we search the category term first so that the specific
# query is harder to isolate from network traffic.
CATEGORY_KEYWORDS = {
    "treatment": "medical conditions",
    "symptom": "health information",
    "disease": "medical conditions",
    "diagnosis": "health information",
    "medication": "pharmaceutical information",
    "drug": "pharmaceutical information",
    "lawyer": "legal services",
    "attorney": "legal services",
    "lawsuit": "legal news",
    "court": "legal news",
    "salary": "employment statistics",
    "income": "financial planning",
    "debt": "financial planning",
    "invest": "financial news",
    "crypto": "financial news",
    "divorce": "family law",
    "custody": "family law",
    "arrest": "crime news",
    "criminal": "crime news",
    "immigration": "government services",
    "visa": "travel documents",
    "passport": "travel documents",
    "addiction": "health information",
    "rehab": "health information",
    "therapy": "mental health",
    "depression": "mental health",
    "anxiety": "mental health",
}

# Batch timing state — tracks when the last search was sent
_batch_lock = None  # initialized lazily
_last_batch_time = 0.0

# ---------------------------------------------------------------------------
# Traffic analysis protection (M19)
# ---------------------------------------------------------------------------

def _upstream_get(endpoint, *, params=None, timeout, expect_json, kind="search"):
    return _egress.get(endpoint, params=params, timeout=timeout, expect_json=expect_json, kind=kind)


def _random_delay() -> float:
    """Sleep a random duration to decorrelate query timing."""
    delay = _privacy_random.uniform(QUERY_DELAY_MIN, QUERY_DELAY_MAX)
    _egress.sleep(delay)
    return delay


def pad_query(query: str) -> str:
    """Pad query to the next fixed-size bucket to obscure length patterns.

    Padding uses URL-safe whitespace that SearXNG trims, so results are
    unaffected.  Buckets: 256, 512, 1024 bytes.
    """
    encoded = query.encode("utf-8")
    query_len = len(encoded)

    target = QUERY_PAD_BUCKETS[-1]  # default to largest
    for bucket in QUERY_PAD_BUCKETS:
        if query_len <= bucket:
            target = bucket
            break

    if query_len >= target:
        return query  # already at or above largest bucket

    # Pad with spaces (SearXNG collapses whitespace)
    pad_len = target - query_len
    return query + (" " * pad_len)


# ---------------------------------------------------------------------------
# Differential privacy for search queries (M20)
# ---------------------------------------------------------------------------

def _load_dp_config() -> dict:
    """Load differential privacy settings from policy.yaml."""
    policy = load_policy()
    search = policy.get("search", {})
    dp = search.get("differential_privacy", {})
    value = {
        "enabled": dp.get("enabled", True),
        "decoy_count": dp.get("decoy_count", 2),
        "uniqueness_mode": dp.get("uniqueness_mode", "warn"),  # auto-block | warn | allow
        "batch_window": dp.get("batch_window", 5.0),  # seconds
    }
    if (not isinstance(value["enabled"], bool)
            or type(value["decoy_count"]) is not int or not 0 <= value["decoy_count"] <= 10
            or value["uniqueness_mode"] not in {"auto-block", "warn", "allow"}
            or type(value["batch_window"]) not in {int, float}
            or not math.isfinite(value["batch_window"]) or not 0 <= value["batch_window"] <= 30):
        raise EgressDenied("service privacy policy unavailable", 503)
    return value


def check_query_uniqueness(query: str) -> dict:
    """Check if a query is highly unique/identifying (k-anonymity risk).

    Returns:
        {"unique": bool, "matches": list of matched patterns}
    """
    matches = []
    for pattern in RARE_QUERY_PATTERNS:
        found = pattern.findall(query)
        if found:
            matches.extend(found)

    return {"unique": bool(matches), "matches": matches}


def generate_decoy_queries(count: int) -> list:
    """Select random decoy queries from the curated list."""
    count = min(count, len(DECOY_QUERIES))
    return _privacy_random.sample(DECOY_QUERIES, count)


def send_decoy_search(query: str, *, kind="decoy") -> bool:
    """Best-effort, audited cover traffic within the real search's deadline."""
    if has_request_context() and _egress.remaining() <= 10:
        return False
    try:
        params = {"q": pad_query(query), "format": "json", "categories": "general", "language": "en", "safesearch": "1"}
        engines = _decoy_engines_param()
        if not engines:
            return False
        params["engines"] = engines
        status = _upstream_get("/search", params=params, timeout=2, expect_json=False, kind=kind)
        return status == 200
    except (AuditUnavailable, EgressDenied):
        raise
    except (requests.RequestException, OSError, ValueError):
        log.info("cover request failed; details omitted")
        return False


def run_decoy_searches(count: int) -> int:
    """Return successful decoys, not attempts, while reserving real-search time."""
    succeeded = 0
    for query in generate_decoy_queries(max(0, min(count, 10))):
        if has_request_context() and _egress.remaining() <= 10:
            break
        _egress.sleep(_privacy_random.uniform(0.2, 0.5))
        if has_request_context():
            g.decoys_attempted = getattr(g, "decoys_attempted", 0) + 1
        succeeded += int(send_decoy_search(query))
    return succeeded


def generalize_query(query: str) -> str | None:
    """Return a broader category term for the query, or None if not needed.

    Scans the query for sensitive keywords and returns the matching category
    so a cover search can be sent before the real query.
    """
    query_lower = query.lower()
    for keyword, category in CATEGORY_KEYWORDS.items():
        if keyword in query_lower:
            return category
    return None


def send_cover_search(category_term: str) -> bool:
    return send_decoy_search(category_term, kind="cover")


def apply_batch_delay(batch_window: float) -> float:
    """Enforce batch timing: wait until at least *batch_window* seconds have
    elapsed since the last search, so queries are grouped into fixed windows.

    Returns the actual delay applied (0 if no wait was needed).
    """
    global _last_batch_time
    import threading

    global _batch_lock
    if _batch_lock is None:
        _batch_lock = threading.Lock()

    with _batch_lock:
        now = time.time()
        elapsed = now - _last_batch_time
        if elapsed < batch_window:
            wait = batch_window - elapsed
            _egress.sleep(wait)
            _last_batch_time = time.time()
            return wait
        else:
            _last_batch_time = now
            return 0.0


# ---------------------------------------------------------------------------
# PII patterns to strip from outbound queries
# ---------------------------------------------------------------------------

PII_PATTERNS = [
    # Email addresses
    (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), "[EMAIL]"),
    # Phone numbers (various formats)
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[PHONE]"),
    # SSN
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    # Credit card numbers (basic)
    (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "[CARD]"),
    # IP addresses
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "[IP]"),
    # Dates of birth patterns
    (re.compile(r"\b(?:born|dob|birthday)[:\s]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b", re.I), "[DOB]"),
    # Bank account and routing numbers when they are explicitly labeled
    (re.compile(r"\b(?:bank\s+)?account(?:\s+number|\s+no\.?|\s*#)?[:\s-]*\d{6,17}\b", re.I), "[BANK_ACCOUNT]"),
    (re.compile(r"\b(?:routing(?:\s+number)?|aba)(?:\s+number|\s+no\.?|\s*#)?[:\s-]*\d{9}\b", re.I), "[BANK_ROUTING]"),
    # Passport numbers when they are explicitly labeled
    (re.compile(r"\bpassport(?:\s+number|\s+no\.?|\s*#)?[:\s-]*[A-Z0-9]{6,12}\b", re.I), "[PASSPORT]"),
    # Full street addresses with house number + street name + suffix
    (
        re.compile(
            r"\b\d{1,6}\s+(?:[A-Za-z0-9.'-]+\s+){0,5}"
            r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b\.?",
            re.I,
        ),
        "[ADDRESS]",
    ),
    # API keys / tokens (long hex or base64 strings)
    (re.compile(r"\b(?:sk-|pk-|api[_-]?key[:\s=]+)[a-zA-Z0-9]{20,}\b", re.I), "[API_KEY]"),
    (re.compile(r"\b[a-fA-F0-9]{32,}\b"), "[HEX_TOKEN]"),
]

# Patterns that suggest prompt injection in search results
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions", re.I),
    re.compile(r"you\s+are\s+now\s+(?:a|an|in)\s+", re.I),
    re.compile(r"system\s*prompt\s*:", re.I),
    re.compile(r"<\s*(?:script|iframe|object|embed)", re.I),
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"data\s*:\s*text/html", re.I),
]

# HTML tag stripper
HTML_TAG_RE = re.compile(r"<[^>]+>")
MULTI_SPACE_RE = re.compile(r"\s+")


def _read_mapping(path: str) -> dict:
    """Read one bounded, stable, non-writable policy/configuration file."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {}
    except OSError:
        raise EgressDenied("service policy unavailable", 503) from None
    try:
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o022 or before.st_size > 1024 * 1024:
                raise ValueError("unsafe policy file")
            raw = source.read(1024 * 1024 + 1)
            after = os.fstat(source.fileno())
            if len(raw) > 1024 * 1024 or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("policy changed")
        value = yaml.safe_load(raw) or {}
        if not isinstance(value, dict):
            raise ValueError("configuration root must be an object")
        return value
    except (OSError, ValueError, yaml.YAMLError):
        raise EgressDenied("service policy unavailable", 503) from None


def load_config() -> dict:
    config = _read_mapping(APPLIANCE_CONFIG)
    if not isinstance(config.get("session", {}), dict):
        raise EgressDenied("service session configuration unavailable", 503)
    return config


def load_policy() -> dict:
    policy = _read_mapping(POLICY_PATH)
    search = policy.get("search", {})
    if (not isinstance(search, dict) or not isinstance(search.get("enabled", False), bool)
            or not isinstance(search.get("differential_privacy", {}), dict)):
        raise EgressDenied("service search policy unavailable", 503)
    for key in ("allowed_engines", "allowed_categories"):
        values = search.get(key, [])
        if not isinstance(values, list) or len(values) > 64 or any(not isinstance(v, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", v) for v in values):
            raise EgressDenied("service search policy unavailable", 503)
    return policy


def _read_service_token() -> str:
    """Read the inter-service token."""
    token_path = os.getenv("SERVICE_TOKEN_PATH", "/run/secure-ai/service-token")
    try:
        return Path(token_path).read_text().strip()
    except OSError:
        return ""


def _insecure_loopback_dev_auth_allowed() -> bool:
    """Allow an explicit no-auth mode only on a loopback listener."""
    if os.getenv("SECAI_ALLOW_INSECURE_NO_AUTH") != "1":
        return False
    try:
        host, _port = BIND_ADDR.rsplit(":", 1)
        host = host.strip("[]")
        return host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _require_service_token() -> tuple[bool, Response | None]:
    """Validate Bearer auth for egress-capable endpoints, fail closed."""
    token = _read_service_token()
    if not token:
        if _insecure_loopback_dev_auth_allowed():
            log.warning("explicit loopback-only insecure authentication mode is active")
            return True, None
        return False, (jsonify({"error": "service authentication unavailable"}), 503)

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False, (jsonify({"error": "forbidden"}), 403)

    provided = auth[7:]
    if not hmac.compare_digest(provided, token):
        return False, (jsonify({"error": "forbidden"}), 403)

    return True, None


def _is_search_enabled() -> bool:
    """Check if web search is enabled in policy."""
    policy = load_policy()
    search_cfg = policy.get("search", {})
    return search_cfg.get("enabled", False)


def _get_session_mode() -> str:
    """Get current session mode from config."""
    config = load_config()
    mode = config.get("session", {}).get("mode", "offline-only")
    if mode not in {"normal", "sensitive", "offline-only"}:
        raise EgressDenied("service session configuration unavailable", 503)
    return mode


def _allowed_engines_param() -> str | None:
    """Return the policy-allowed SearXNG engines as a comma-separated value."""
    policy = load_policy()
    search_cfg = policy.get("search", {})
    allowed = search_cfg.get("allowed_engines", [])
    if not isinstance(allowed, list):
        return None
    engines = [str(engine).strip() for engine in allowed if str(engine).strip()]
    if not engines:
        return None
    return ",".join(engines)


def _decoy_engines_param() -> str | None:
    """Return a lower-risk engine subset for decoy searches."""
    policy = load_policy()
    search_cfg = policy.get("search", {})
    allowed = search_cfg.get("allowed_engines", [])
    if not isinstance(allowed, list):
        return None
    engines = [str(engine).strip() for engine in allowed if str(engine).strip()]
    if not engines:
        return None
    preferred = [engine for engine in engines if engine in {"wikipedia", "github", "stackoverflow"}]
    selected = preferred or [engine for engine in engines if engine != "duckduckgo"]
    if not selected:
        return None
    return ",".join(selected)


def sanitize_query(raw_query: str) -> dict:
    """Strip PII and sensitive data from an outbound search query.

    Returns:
        {"query": sanitized_string, "redactions": [...], "blocked": bool, "reason": str}
    """
    if not isinstance(raw_query, str) or not raw_query.strip():
        return {"query": "", "redactions": [], "blocked": True, "reason": "empty query"}

    try:
        query = normalized_query(raw_query)
    except (ValueError, UnicodeError):
        return {"query": "", "redactions": [], "blocked": True, "reason": "invalid query encoding or length"}
    if contains_credentials(query):
        return {"query": "[API_KEY]", "redactions": ["credential"], "blocked": True, "reason": "remove credentials from the query"}

    redactions = []
    for pattern, replacement in PII_PATTERNS:
        matches = pattern.findall(query)
        if matches:
            redactions.extend([replacement] * len(matches))
            query = pattern.sub(replacement, query)

    pii_placeholders = {
        "[EMAIL]",
        "[PHONE]",
        "[SSN]",
        "[CARD]",
        "[IP]",
        "[DOB]",
        "[BANK_ACCOUNT]",
        "[BANK_ROUTING]",
        "[PASSPORT]",
        "[ADDRESS]",
        "[API_KEY]",
        "[HEX_TOKEN]",
    }
    high_risk_placeholders = {
        "[SSN]",
        "[CARD]",
        "[BANK_ACCOUNT]",
        "[BANK_ROUTING]",
        "[PASSPORT]",
        "[ADDRESS]",
        "[API_KEY]",
        "[HEX_TOKEN]",
    }

    # If the query is mostly redacted, or combines multiple high-risk
    # identifiers, block it before any outbound search request is sent.
    tokens = query.split()
    redacted_tokens = sum(1 for t in tokens if t in pii_placeholders)
    high_risk_redactions = sum(1 for t in tokens if t in high_risk_placeholders)
    if (tokens and redacted_tokens / len(tokens) > 0.5) or high_risk_redactions >= 2:
        return {
            "query": query,
            "redactions": redactions,
            "blocked": True,
            "reason": "query contains too much PII",
        }

    if len(query) > MAX_QUERY_LENGTH or len(raw_query) > MAX_QUERY_LENGTH:
        return {"query": "", "redactions": redactions, "blocked": True, "reason": "query exceeds maximum length"}

    return {"query": query, "redactions": redactions, "blocked": False, "reason": ""}


# ---------------------------------------------------------------------------
# Result sanitization (inbound)
# ---------------------------------------------------------------------------

def sanitize_snippet(raw_text: str) -> str:
    """Clean a search result snippet: strip HTML, decode entities, remove injection."""
    if not isinstance(raw_text, str) or not raw_text:
        return ""

    text = HTML_TAG_RE.sub(" ", raw_text)
    text = html.unescape(text)
    text = unicodedata.normalize("NFKC", text)
    # Remove controls, bidi overrides, zero-width format characters, and
    # unpaired surrogates before pattern matching and JSON serialization.
    text = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in text
    )
    text = MULTI_SPACE_RE.sub(" ", text).strip()
    if len(text) > MAX_SNIPPET_LENGTH:
        text = text[:MAX_SNIPPET_LENGTH] + "..."

    return text


def check_injection(text: str) -> bool:
    """Return True if text contains suspected prompt injection."""
    for pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            return True
    return False


def sanitize_results(raw_results: list) -> list:
    """Sanitize a list of search results from SearXNG."""
    if not isinstance(raw_results, list):
        return []
    clean = []
    for r in raw_results[:MAX_RESULTS]:
        if not isinstance(r, dict):
            continue
        title = sanitize_snippet(r.get("title", ""))
        snippet = sanitize_snippet(r.get("content", ""))
        url = r.get("url", "")

        try:
            if not isinstance(url, str) or len(url.encode("utf-8")) > MAX_RESULT_URL_LENGTH:
                raise ValueError("invalid URL")
            decoded_url = decoded_url_text(url)
            if (
                "\\" in decoded_url
                or any(character.isspace() for character in url)
                or any(
                    unicodedata.category(character).startswith("C")
                    for character in decoded_url
                )
            ):
                raise ValueError("invalid URL")
            parsed = urlparse(url)
            if (
                parsed.scheme not in ("http", "https")
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("invalid URL")
            _ = parsed.port
        except (TypeError, UnicodeError, ValueError):
            url = ""

        if check_injection(title) or check_injection(snippet) or (url and check_injection(decoded_url)):
            log.warning("search result rejected by content policy")
            continue

        if title or snippet:
            clean.append({
                "title": title,
                "snippet": snippet,
                "url": strip_tracking_parameters(url),
                "source": parsed.hostname if url else "unknown",
            })

    return clean


def build_context(results: list) -> str:
    """Build a context string from sanitized results for the LLM."""
    if not results:
        return ""

    parts = ["The following untrusted information was retrieved from web search:\n"]
    for i, r in enumerate(results, 1):
        parts.append(f"[{i}] {r['title']}")
        if r["snippet"]:
            parts.append(f"    {r['snippet']}")
        if r["url"]:
            parts.append(f"    Source: {r['url']}")
        parts.append("")

    context = "\n".join(parts)
    if len(context) > MAX_CONTEXT_LENGTH:
        context = context[:MAX_CONTEXT_LENGTH] + "\n[... truncated for length]"

    return context


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def audit_search(query: str, redactions: list, num_results: int, blocked: bool,
                 *, uniqueness_detected: bool = False):
    """Write a privacy-preserving audit record for every search attempt."""
    _egress.audit("web_search", {
        "query_length": len(query),
        "redactions_count": len(redactions),
        "results_returned": num_results,
        "blocked": blocked,
        "uniqueness_detected": uniqueness_detected,
    })


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    """Authenticated readiness probe; may contact the Tor-backed upstream."""
    authorized, auth_response = _require_service_token()
    if not authorized:
        return auth_response
    enabled = _is_search_enabled()
    session_mode = _get_session_mode()

    # Check SearXNG availability
    searxng_ok = False
    if enabled and session_mode != "offline-only":
        try:
            status = _upstream_get("/healthz", timeout=SEARCH_HEALTH_TIMEOUT, expect_json=False, kind="health")
            searxng_ok = status == 200
        except (AuditUnavailable, EgressDenied):
            raise
        except Exception:
            pass

    healthy = not enabled or session_mode == "offline-only" or searxng_ok
    return jsonify({
        "status": "ok" if healthy else "degraded",
        "search_enabled": enabled,
        "session_mode": session_mode,
        "searxng_reachable": searxng_ok,
        "tor_routed": None,
        "routing_verified": False,
    }), 200 if healthy else 503


@app.route("/live")
def live():
    """Fast liveness probe that does not depend on optional upstream services."""
    return jsonify({
        "status": "ok",
        "search_enabled": _is_search_enabled(),
        "session_mode": _get_session_mode(),
        "searxng_reachable": None,
        "tor_routed": None,
    })


@app.route("/v1/search", methods=["POST"])
def search():
    """Perform a sanitized, Tor-routed web search."""
    if request.content_length and request.content_length > MAX_SEARCH_BODY_BYTES:
        return jsonify({"error": "request too large"}), 413

    authorized, auth_response = _require_service_token()
    if not authorized:
        return auth_response

    # Check if search is enabled
    if not _is_search_enabled():
        return jsonify({"error": "web search is disabled in policy"}), 403

    # Block in offline-only mode
    session_mode = _get_session_mode()
    if session_mode == "offline-only":
        return jsonify({"error": "web search blocked in offline-only mode"}), 403

    body = request.get_json(silent=True)
    if not isinstance(body, dict) or set(body) - {"query", "categories"}:
        return jsonify({"error": "JSON object with query and optional categories required"}), 400

    raw_query = body.get("query", "")
    categories = body.get("categories", "general")
    if not isinstance(raw_query, str):
        return jsonify({"error": "query must be a string"}), 400
    allowed_categories = load_policy().get("search", {}).get("allowed_categories", ["general"])
    if not isinstance(categories, str) or categories not in allowed_categories:
        return jsonify({"error": "search category is not allowed"}), 400

    # Sanitize the outbound query
    san = sanitize_query(raw_query)
    if san["blocked"]:
        audit_search(raw_query, san["redactions"], 0, True)
        return jsonify({
            "error": f"query blocked: {san['reason']}",
            "redactions": len(san["redactions"]),
        }), 422

    # Optional cover-traffic heuristics
    dp_config = _load_dp_config()
    uniqueness_warning = None
    decoys_sent = 0

    if dp_config["enabled"]:
        # Heuristic identifier check
        uq = check_query_uniqueness(san["query"])
        if uq["unique"]:
            mode = dp_config["uniqueness_mode"]
            if mode == "auto-block":
                audit_search(
                    raw_query,
                    san["redactions"],
                    0,
                    True,
                    uniqueness_detected=True,
                )
                return jsonify({
                    "error": "query blocked: contains highly unique/identifying terms",
                    "unique_match_count": len(uq["matches"]),
                }), 422
            elif mode == "warn":
                uniqueness_warning = (
                    "This query contains potentially identifying terms"
                )
                log.warning("unique query detected (warn mode; matches=%d)", len(uq["matches"]))

        # Query generalization: send a broader cover search first
        category = generalize_query(san["query"])
        if category:
            log.debug("cover search requested")
            send_cover_search(category)

        # Send decoy searches before the real query
        decoys_sent = run_decoy_searches(dp_config["decoy_count"])

        # Batch timing: ensure queries are spaced by at least batch_window seconds
        apply_batch_delay(dp_config["batch_window"])

    # Traffic analysis protection: random delay before sending query
    delay = _random_delay()

    # Pad query to fixed-size bucket to obscure length
    padded_query = pad_query(san["query"])

    # Query SearXNG (which routes through Tor)
    try:
        params = {
            "q": padded_query,
            "format": "json",
            "categories": categories,
            "language": "en",
            "safesearch": "1",
        }
        engines = _allowed_engines_param()
        if engines:
            params["engines"] = engines
        data = _upstream_get("/search", params=params, timeout=30, expect_json=True)
    except (AuditUnavailable, EgressDenied):
        raise
    except requests.Timeout:
        audit_search(raw_query, san["redactions"], 0, False)
        return jsonify({"error": "search timed out (Tor may be connecting)"}), 504
    except Exception:
        log.warning("SearXNG request failed; upstream details omitted")
        audit_search(raw_query, san["redactions"], 0, False)
        return jsonify({"error": "search failed"}), 502

    # Sanitize the inbound results
    raw_results = data.get("results", [])
    clean_results = sanitize_results(raw_results)
    context = build_context(clean_results)

    audit_search(
        raw_query,
        san["redactions"],
        len(clean_results),
        False,
        uniqueness_detected=bool(uniqueness_warning),
    )

    log.info("search completed: query_len=%d results=%d redactions=%d delay=%.2fs decoys=%d",
             len(san["query"]), len(clean_results), len(san["redactions"]), delay, decoys_sent)

    result = {
        "results": clean_results,
        "context": context,
        "query_used": san["query"],
        "redactions": len(san["redactions"]),
        "tor_routed": None,
        "routing_verified": False,
        "decoys_sent": decoys_sent,
        "decoys_attempted": getattr(g, "decoys_attempted", 0),
        "privacy_method": "heuristic cover traffic; no formal differential privacy guarantee",
        **_egress.metadata(),
        "untrusted_external_data": True,
    }
    if uniqueness_warning:
        result["uniqueness_warning"] = uniqueness_warning

    return jsonify(result)


@app.route("/v1/search/test", methods=["GET"])
def search_test():
    """Check SearXNG connectivity; this does not attest a Tor circuit."""
    authorized, auth_response = _require_service_token()
    if not authorized:
        return auth_response

    if not _is_search_enabled():
        return jsonify({"error": "web search is disabled"}), 403

    if _get_session_mode() == "offline-only":
        return jsonify({"error": "web search blocked in offline-only mode"}), 403

    try:
        params = {"q": "test", "format": "json"}
        engines = _allowed_engines_param()
        if engines:
            params["engines"] = engines
        status = _upstream_get("/search", params=params, timeout=30, expect_json=False, kind="test")
        return jsonify({
            "status": "ok",
            "searxng_status": status,
            "tor_routed": None,
            "routing_verified": False,
        })
    except (AuditUnavailable, EgressDenied):
        raise
    except Exception:
        log.warning("SearXNG health check failed; upstream details omitted")
        return jsonify({
            "status": "error",
            "error": "search health check failed",
        }), 502


def main():
    """Dev-mode entry point. Production uses gunicorn via systemd wrapper."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    host, port = BIND_ADDR.rsplit(":", 1)
    log.warning("Running Flask dev server — use gunicorn in production")
    log.info("search-mediator starting on %s", BIND_ADDR)
    app.run(host=host, port=int(port), debug=False, threaded=True)


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(_error):
    return jsonify({"error": "request body too large"}), 413


def _authorize_egress(endpoint, params):
    if not _is_search_enabled():
        raise EgressDenied("web search is disabled in policy")
    if _get_session_mode() == "offline-only":
        raise EgressDenied("web search blocked in offline-only mode")
    search = load_policy().get("search", {})
    if params.get("categories", "general") not in search.get("allowed_categories", ["general"]):
        raise EgressDenied("search category is not allowed")
    configured = search.get("allowed_engines", [])
    selected = params.get("engines", "").split(",")
    if configured and (selected == [""] or any(engine not in configured for engine in selected)) and endpoint == "/search":
        raise EgressDenied("search engines changed; retry with current policy")


_egress = SearchEgress(
    app, authenticate=lambda: _require_service_token(), authorize=_authorize_egress,
    audit=lambda event, payload: _audit_chain.append(event, payload),
    transport=lambda *args, **kwargs: _transport_get(*args, **kwargs),
    origin=lambda: SEARXNG_URL,
)


if __name__ == "__main__":
    main()
