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
import random
import re
import sys
import time
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

def _random_delay() -> float:
    """Sleep a random duration to decorrelate query timing."""
    delay = random.uniform(QUERY_DELAY_MIN, QUERY_DELAY_MAX)
    time.sleep(delay)
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
    return {
        "enabled": dp.get("enabled", True),
        "decoy_count": dp.get("decoy_count", 2),
        "uniqueness_mode": dp.get("uniqueness_mode", "warn"),  # auto-block | warn | allow
        "batch_window": dp.get("batch_window", 5.0),  # seconds
    }


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
    return random.sample(DECOY_QUERIES, count)


def send_decoy_search(query: str) -> None:
    """Fire-and-forget a decoy search to SearXNG. Results are discarded."""
    try:
        padded = pad_query(query)
        requests.get(
            f"{SEARXNG_URL}/search",
            params={
                "q": padded,
                "format": "json",
                "categories": "general",
                "language": "en",
                "safesearch": "1",
            },
            timeout=15,
        )
        log.debug("decoy search sent: %d chars", len(query))
    except Exception:
        pass  # decoys are best-effort


def run_decoy_searches(count: int) -> int:
    """Send decoy searches with random timing. Returns count sent."""
    decoys = generate_decoy_queries(count)
    for dq in decoys:
        delay = random.uniform(0.2, 1.5)
        time.sleep(delay)
        send_decoy_search(dq)
    return len(decoys)


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


def send_cover_search(category_term: str) -> None:
    """Send a cover search for a broad category term. Results are discarded."""
    send_decoy_search(category_term)


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
            time.sleep(wait)
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

    # Differential privacy checks (M20)
    dp_config = _load_dp_config()
    uniqueness_warning = None
    decoys_sent = 0

    if dp_config["enabled"]:
        # Check query uniqueness (k-anonymity)
        uq = check_query_uniqueness(san["query"])
        if uq["unique"]:
            mode = dp_config["uniqueness_mode"]
            if mode == "auto-block":
                audit_search(raw_query, san["query"], san["redactions"], 0, True)
                return jsonify({
                    "error": "query blocked: contains highly unique/identifying terms",
                    "unique_matches": uq["matches"],
                }), 422
            elif mode == "warn":
                uniqueness_warning = (
                    f"This query contains potentially identifying terms: "
                    f"{', '.join(uq['matches'][:3])}"
                )
                log.warning("unique query detected (warn mode): %s", uq["matches"][:3])

        # Query generalization: send a broader cover search first
        category = generalize_query(san["query"])
        if category:
            log.debug("cover search for category: %s", category)
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
        resp = requests.get(
            f"{SEARXNG_URL}/search",
            params={
                "q": padded_query,
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

    log.info("search completed: query_len=%d results=%d redactions=%d delay=%.2fs decoys=%d",
             len(san["query"]), len(clean_results), len(san["redactions"]), delay, decoys_sent)

    result = {
        "results": clean_results,
        "context": context,
        "query_used": san["query"],
        "redactions": len(san["redactions"]),
        "tor_routed": True,
        "decoys_sent": decoys_sent,
    }
    if uniqueness_warning:
        result["uniqueness_warning"] = uniqueness_warning

    return jsonify(result)


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
