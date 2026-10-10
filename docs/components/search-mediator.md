# Search mediator

The native `secure-ai-search-mediator.service` exposes the authenticated API at
`127.0.0.1:8485`. It sends approved requests only to the configured SearXNG origin
(default `http://127.0.0.1:8888`). The source is the embedded
`services/search-mediator` implementation, installed as `app:app`; separately
staged helper sources cannot override the appliance's offline policy.

`POST /v1/search` accepts a JSON object containing a string `query` and an optional
allowed string `categories`. Bodies are capped at 16 KiB, including streams without
Content-Length. Queries longer than 200 characters are rejected without sending a
truncated identifier. Common PII is redacted; credential-bearing queries are blocked.
Normalization checks supported Unicode and percent-encoded forms before egress.
These heuristics do not detect every secret or declassify confidential topics.

Search must be enabled in `/etc/secure-ai/policy/policy.yaml`. The current session
mode in `/etc/secure-ai/config/appliance.yaml` must permit networking; missing or
invalid session configuration fails closed. The same checks gate ordinary searches,
cover traffic, decoys, `GET /v1/search/test`, and authenticated `GET /health`.
`GET /live` performs no network requests. Health returns 503 when enabled search
cannot reach its upstream. The UI requires explicit positive readiness fields.

SearXNG is intended to use the appliance's Tor proxy. The mediator cannot attest
the actual network route: its `tor_routed` value is null and `routing_verified` is
false. Configured routing, successful HTTP, and verified Tor routing are separate
claims. Full OS packet/circuit tests remain required before making an anonymity
claim. Results carry untrusted provenance, with typed/bounded text and URL checks.
An executor must enforce action permissions independently of model interpretation.

Every outbound attempt needs a durable minimized audit intent before HTTP and an
outcome afterward. Audit failure before intent returns 503 with `egress=not_sent`;
a later failure says `egress=may_have_been_sent` and `retry_safe=false`. Do not
retry that response automatically. A random request ID links the attempt's events.
Cross-request and restart-persistent client idempotency is not yet implemented.
Logs omit raw queries, argument values, result URLs, and query hashes; Gunicorn's
access format omits URL/query strings. The native journal has stable service
ownership. Broader audit isolation, anchoring and retention are separate controls.

Each worker admits one active egress request and returns 429 for excess load.
The default deployment uses one worker with multiple threads, so liveness remains
responsive. Searches share a 20-second egress/timing budget. Decoys reserve time for
the real query; `decoys_attempted` and `decoys_sent` distinguish attempted and
successful cover requests. Cover traffic provides heuristic obfuscation, with no
formal differential privacy guarantee.

The transport invokes only the installed Python interpreter with an isolated
worker module. Queries pass through stdin, never process arguments or environment.
The worker drops proxy/credential environment variables, disables redirects and
ambient proxies, fixes request headers, rejects compressed/non-JSON responses,
and caps response bytes at 2 MiB. A parent timeout kills a stalled worker, including
while it waits for DNS, headers or body data. No caller chooses the executable,
origin, or endpoint. The native seccomp lifecycle and Landlock interpreter allowlist
must be qualified together. Immediate client-disconnect cancellation and a hard
incoming-body deadline are not yet claimed.

Local regression suites exercise credential formats, URL controls, streamed body
limits, disabled/offline routes, audit faults, admission, and real loopback transport
redirect/size/deadline behavior. These tests do not certify Tor, SELinux, installed
systemd isolation, or production load limits.


The native SearXNG process uses the locked Gunicorn runtime and an ephemeral
cache under `/run/secure-ai-searxng`. Its config inherits the pinned upstream
application defaults while keeping exactly six reviewed engines. HTML and JSON
formats are explicit, and Wikipedia emits ordinary results for the mediator.
Startup tracker-list downloads are disabled; common tracking query parameters
are removed locally without changing the encoding of retained parameters.
The [upstream settings contract](https://docs.searxng.org/admin/settings/settings.html#use-default-settings)
explains the defaults/engine merge, and the [format contract](https://docs.searxng.org/admin/settings/settings_search.html#formats)
defines enabled outputs. Runtime regression checks must accompany future pins:
schema-only imports do not exercise request initialization or result shapes.
