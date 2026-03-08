"""
Secure AI Appliance - Search Mediator

Tor-routed web search via local SearXNG instance.
Sanitizes outbound queries (strips PII) and inbound results (strips HTML/scripts,
detects injection attempts, enforces size limits).

The LLM never touches the network. This service is the only bridge between
inference and online information, and it routes everything through Tor.
"""

import hashlib
import html
import logging
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, jsonify, request

# Add services/ to path so we can import common.audit_chain
_services_root = str(Path(__file__).resolve().parent.parent)
if _services_root not in sys.path:
    sys.path.insert(0, _services_root)

from common.audit_chain import AuditChain

log = logging.getLogger("search-mediator")

app = Flask(__name__)

BIND_ADDR = os.getenv("BIND_ADDR", "127.0.0.1:8485")
SEARXNG_URL = os.getenv("SEARXNG_URL", "http://127.0.0.1:8888")
APPLIANCE_CONFIG = os.getenv("APPLIANCE_CONFIG", "/etc/secure-ai/config/appliance.yaml")
POLICY_PATH = os.getenv("POLICY_PATH", "/etc/secure-ai/policy/policy.yaml")
AUDIT_DIR = os.getenv("AUDIT_DIR", "/var/lib/secure-ai/logs")

_audit_chain = AuditChain(os.path.join(AUDIT_DIR, "search-audit.jsonl"))

# Limits
MAX_QUERY_LENGTH = 200
MAX_RESULTS = 5
MAX_SNIPPET_LENGTH = 500
MAX_CONTEXT_LENGTH = 4000

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


def load_config() -> dict:
    try:
        with open(APPLIANCE_CONFIG) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def load_policy() -> dict:
    try:
        with open(POLICY_PATH) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def _is_search_enabled() -> bool:
    """Check if web search is enabled in policy."""
    policy = load_policy()
    search_cfg = policy.get("search", {})
    return search_cfg.get("enabled", False)


def _get_session_mode() -> str:
    """Get current session mode from config."""
    config = load_config()
    return config.get("session", {}).get("mode", "normal")


# ---------------------------------------------------------------------------
# Query sanitization (outbound)
# ---------------------------------------------------------------------------

def sanitize_query(raw_query: str) -> dict:
    """Strip PII and sensitive data from an outbound search query.

    Returns:
        {"query": sanitized_string, "redactions": [...], "blocked": bool, "reason": str}
    """
    if not raw_query or not raw_query.strip():
        return {"query": "", "redactions": [], "blocked": True, "reason": "empty query"}

    query = raw_query.strip()

    # Enforce length limit
    if len(query) > MAX_QUERY_LENGTH:
        query = query[:MAX_QUERY_LENGTH]

    redactions = []
    for pattern, replacement in PII_PATTERNS:
        matches = pattern.findall(query)
        if matches:
            redactions.extend(matches)
            query = pattern.sub(replacement, query)

    # If the query is mostly redacted, block it
    tokens = query.split()
    redacted_tokens = sum(1 for t in tokens if t.startswith("[") and t.endswith("]"))
    if tokens and redacted_tokens / len(tokens) > 0.5:
        return {
            "query": query,
            "redactions": redactions,
            "blocked": True,
            "reason": "query contains too much PII",
        }

    return {"query": query, "redactions": redactions, "blocked": False, "reason": ""}


# ---------------------------------------------------------------------------
# Result sanitization (inbound)
# ---------------------------------------------------------------------------

def sanitize_snippet(raw_text: str) -> str:
    """Clean a search result snippet: strip HTML, decode entities, remove injection."""
    if not raw_text:
        return ""

    # Strip HTML tags
    text = HTML_TAG_RE.sub(" ", raw_text)
    # Decode HTML entities
    text = html.unescape(text)
    # Collapse whitespace
    text = MULTI_SPACE_RE.sub(" ", text).strip()
    # Truncate
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
    clean = []
    for r in raw_results[:MAX_RESULTS]:
        title = sanitize_snippet(r.get("title", ""))
        snippet = sanitize_snippet(r.get("content", ""))
        url = r.get("url", "")

        # Validate URL
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                url = ""
        except Exception:
            url = ""

        # Check for injection in title and snippet
        if check_injection(title) or check_injection(snippet):
            log.warning("injection detected in result from %s, skipping", url)
            continue

        if title or snippet:
            clean.append({
                "title": title,
                "snippet": snippet,
                "url": url,
                "source": parsed.netloc if url else "unknown",
            })

    return clean


def build_context(results: list) -> str:
    """Build a context string from sanitized results for the LLM."""
    if not results:
        return ""

    parts = ["The following information was retrieved from the web via Tor-routed search:\n"]
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

def audit_search(query: str, sanitized_query: str, redactions: list,
                 num_results: int, blocked: bool):
    """Write a hash-chained audit record for every search attempt."""
    query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]
    _audit_chain.append("web_search", {
        "query_hash": query_hash,
        "sanitized_query": sanitized_query,
        "redactions_count": len(redactions),
        "results_returned": num_results,
        "blocked": blocked,
    })


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    enabled = _is_search_enabled()
    session_mode = _get_session_mode()

    # Check SearXNG availability
    searxng_ok = False
    try:
        resp = requests.get(f"{SEARXNG_URL}/healthz", timeout=3)
        searxng_ok = resp.status_code == 200
    except Exception:
        pass

    return jsonify({
        "status": "ok",
        "search_enabled": enabled,
        "session_mode": session_mode,
        "searxng_reachable": searxng_ok,
        "tor_routed": True,
    })


@app.route("/v1/search", methods=["POST"])
def search():
    """Perform a sanitized, Tor-routed web search."""

    # Check if search is enabled
    if not _is_search_enabled():
        return jsonify({"error": "web search is disabled in policy"}), 403

    # Block in offline-only mode
    session_mode = _get_session_mode()
    if session_mode == "offline-only":
        return jsonify({"error": "web search blocked in offline-only mode"}), 403

    body = request.get_json()
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    raw_query = body.get("query", "")
    categories = body.get("categories", "general")

    # Sanitize the outbound query
    san = sanitize_query(raw_query)
    if san["blocked"]:
        audit_search(raw_query, san["query"], san["redactions"], 0, True)
        return jsonify({
            "error": f"query blocked: {san['reason']}",
            "redactions": len(san["redactions"]),
        }), 422

    # Query SearXNG (which routes through Tor)
    try:
        resp = requests.get(
            f"{SEARXNG_URL}/search",
            params={
                "q": san["query"],
                "format": "json",
                "categories": categories,
                "language": "en",
                "safesearch": "1",
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.Timeout:
        audit_search(raw_query, san["query"], san["redactions"], 0, False)
        return jsonify({"error": "search timed out (Tor may be connecting)"}), 504
    except Exception as e:
        log.exception("SearXNG request failed")
        audit_search(raw_query, san["query"], san["redactions"], 0, False)
        return jsonify({"error": f"search failed: {str(e)}"}), 502

    # Sanitize the inbound results
    raw_results = data.get("results", [])
    clean_results = sanitize_results(raw_results)
    context = build_context(clean_results)

    audit_search(raw_query, san["query"], san["redactions"], len(clean_results), False)

    log.info("search completed: query_len=%d results=%d redactions=%d",
             len(san["query"]), len(clean_results), len(san["redactions"]))

    return jsonify({
        "results": clean_results,
        "context": context,
        "query_used": san["query"],
        "redactions": len(san["redactions"]),
        "tor_routed": True,
    })


@app.route("/v1/search/test", methods=["GET"])
def search_test():
    """Quick connectivity test: verify Tor circuit is working."""
    if not _is_search_enabled():
        return jsonify({"error": "web search is disabled"}), 403

    try:
        resp = requests.get(
            f"{SEARXNG_URL}/search",
            params={"q": "test", "format": "json"},
            timeout=30,
        )
        return jsonify({
            "status": "ok",
            "searxng_status": resp.status_code,
            "tor_routed": True,
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e),
        }), 502


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    host, port = BIND_ADDR.rsplit(":", 1)
    log.info("search-mediator starting on %s (SearXNG=%s)", BIND_ADDR, SEARXNG_URL)
    app.run(host=host, port=int(port), debug=False, threaded=True)


if __name__ == "__main__":
    main()
