# UI evidence and accessibility contract

The Security dashboard describes evidence from specific checks. It does not certify the whole appliance. A positive runtime summary says **Runtime checks reported passing**. The UI has no attestation or audit signing key and does not independently verify a returned attestation bundle signature.

## Evidence sources and freshness

| Display | Required source and positive conditions | Maximum producer age |
|---|---|---|
| Runtime attestation | Credentialed GET `/api/v1/attest`; matching outer/bundle states, hardware mode, all required verification flags, Secure Boot measurement, nonempty service digests and expected hash shapes | 10 minutes |
| Integrity monitor | Credentialed GET `/api/v1/status`; known trusted state, positive watched-file and completed-scan counts, no violations | 2 minutes |
| Incident counts | Credentialed live GET `/api/v1/stats`; bounded nonnegative counts, known severity names and severity sum equal to open total; omitted zero severity keys are normalized only after this relationship validates | Live read; producer provides no event timestamp |
| Model hashes | Credentialed registry report; positive models checked, zero failures, known successful status and timestamp | 35 minutes |
| Audit verification | Root-owned regular file, no writable group/other mode, no symlinks or hardlinks, unchanged during bounded read; successful ready report, consistent counts, applicable nonempty coverage and known verification classes | 35 minutes |
| Native network | Root-owned report from this boot, wall-clock and monotonic freshness, verified IPv4/IPv6/ARP enforcement, exact scope/allowances and live lease constraints | 30 seconds, capped by the remaining lease and monotonic validity |
| TPM enrollment | Current root-owned schema-v1 inspection at `tpm2-state.json` with known flags, counts and PCR policy | 35 minutes; enrollment is never displayed as proof of successful hardware unsealing |

Credentialed reads use each producer's configured token and fixed local endpoint. Successful HTTP authentication is a producer report basis, not independent signature verification or mutually authenticated TLS. Missing credentials prevent the request. Requests use a fresh session with ambient proxies, netrc and cookies disabled; redirects and non-200 responses are rejected. Public failures are fixed messages without tokens, backend URLs, raw exceptions or internal paths.

Evidence JSON is bounded to 256 KiB before decoding. Unsupported compression, duplicate keys, invalid Unicode, nonfinite numbers, non-object schemas and excessive structure are rejected. The inventory endpoint uses the same bounded reader with an explicitly required list. There is a 2-second connect timeout, a 3-second per-read timeout and a 5-second elapsed check between body bytes. These are **not a hard whole-request or whole-dashboard deadline**: DNS and trickled response headers are not covered by the body deadline. The aggregate currently reads its three producers sequentially. Resource admission and a complete end-to-end deadline remain separate work.

An aggregate passes only when every required producer report is known, current, schema-valid and obtained through its configured credentialed read. The returned `reported_healthy` enum is not a `trusted` claim. Other aggregate states are `degraded`, `recovery_required` and `evaluation`. A fresh attestation bundle shape does not imply its HMAC was verified by the UI. No HMAC value, signing key, quote, raw security path or internal digest is sent to the UI display.

Positive display snapshots expire within 30 seconds and earlier when required evidence expires. A timer clears positive presentation without waiting for the next poll. The dashboard and global status use the same rendered aggregate; an older outstanding poll cannot overwrite a newer requested snapshot. A reported model-integrity failure remains visible through later unavailable responses, until a fresh successful model check clears it. This is a page-local display rule, not durable incident storage.

The selected profile is shown as configuration. It cannot establish host-offline assurance. Native runtime network evidence distinguishes blocked host egress from finite research, full-lab or maintenance leases; active leases explicitly state that the host is not offline and show their allowed egress and expiry. Unavailable resolver combinations or rejected profile changes do not imply connectivity. Sandbox evidence cannot establish host firewall or hardware protection. There are no new networking or hardware-enrollment actions in this UI change.

Audit coverage remains split into keyed chains, unkeyed linkage, syntax-only logs and not-applicable entries. Unkeyed linkage and syntax do not authenticate records. Manifest flags and signature-file presence are labeled unverified claims; the UI does not turn them into current fs-verity or signature assurance. SLO values are browser-triggered observations with unverified sampling coverage. Empty samples and optional services have `compliant: null`; no continuous availability claim is made. This change does not implement the independent SLO collector.

## Interaction contract

Generation inputs have explicit names and visible labels. Required prompts and numeric fields receive native validation, an associated status message and focus on the invalid field. Generation tabs expose tab/tablist/tabpanel semantics and arrow, Home and End keyboard navigation. HTTP errors, missing media and malformed base64 produce failure text; returned content is rendered through DOM properties, not HTML interpolation. Output links use the local output route, and video controls are outside links. This is presentation validation, not qualification of real diffusion generation or every video codec.

Confirmation uses a named native modal dialog, explanatory text, initial Cancel focus, keyboard wrapping, Escape dismissal and focus return. Hidden mobile navigation is inert and exposes its expanded state. Polling retains focus in generation fields, dialogs and the completed agent approval UI. Existing immutable operation review, stale-plan reapproval, history minimization and deletion contracts are unchanged.

The shared muted color is `#97a0c5`; setup's quiet color is `#9ba8b8`. Visible text contrast was measured from computed colors in Chromium on login, setup, generation, approval and security pages, alongside desktop/mobile screenshot review. Error/status regions have live announcements. Repeated unchanged status text is not reinserted into the main live region.

Qualification uses synthetic reports, prompts, outputs and tasks in a private user/network namespace. No model, hardware enrollment, host firewall change or real agent action is exercised. Browser checks cover actual rendered templates and accessibility trees, not only source-string assertions. Chromium keyboard/tree checks and computed solid-background contrast do not replace screen-reader testing, a complete WCAG audit or cross-browser testing.
