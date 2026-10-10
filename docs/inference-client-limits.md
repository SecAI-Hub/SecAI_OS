# Local inference client limits

The UI and agent share `common.inference_client`. Each authenticated operation
runs its HTTP exchange in an isolated Python helper, loaded from the packaged
`common/inference_transport.py` with `-I`. No additional dependency is required.
Native builds copy the common package into the locked application environment;
sandbox images copy it into their immutable application tree. The interpreter
must permit subprocess execution and the packaged requests runtime must remain
available under isolated Python loading.

| Bound | Contract |
| --- | --- |
| Concurrent operations | Four per caller process; excess admission fails immediately with a sanitized 503. |
| Absolute operation budget | Caller-selected, at most 300 seconds, starts before request encoding/spawn. Includes headers, body, IPC and downstream consumption time. |
| Request IPC | 1 MiB encoded JSON, depth 64 and 65,536 visited nodes. |
| Response body | 4 MiB total; nonstreaming callers also consume incrementally. |
| HTTP wire | 4 MiB + 256 KiB, including headers and chunk framing. |
| HTTP metadata | 8 KiB per line and 32 headers; private protocol frames at most 16 KiB. |
| Response JSON | UTF-8, finite JSON values, depth 64 and structural work bounded to 65,536 separators/string/container starts. |
| SSE | 64 KiB per frame and 8,192 frames, including comments; terminal `[DONE]` required. |

Authentication is loaded before admission or any helper/RPC. Credentials and
request data cross only private pipes; they are absent from the helper's
arguments and environment. A new requests Session disables environment proxy,
netrc and cookie inheritance, and redirects. The client requests identity
encoding and rejects compressed success responses, oversized or malformed
lengths, and malformed protocol data. Error response bodies are not consumed or
forwarded. Role-only chat deltas with null content remain valid.

The parent uses deadline-aware nonblocking IPC and a timer to kill/reap the
helper. The helper starts its own independent timer before third-party imports
and request reads, so caller death/recycling cannot remove its deadline. A
closed parent pipe can terminate it sooner. Stopped consumers cannot leave
workers waiting indefinitely. Explicit close, timeout and disconnect cleanup
are idempotent; admission returns only after process exit. If the OS cannot
finish reaping promptly, the slot stays reserved while a reaper waits. Scheduling
latency and uninterruptible kernel work are not claimed to be preemptible.
HTTP read/connect timeouts are additional guards, not the absolute deadline.

These limits protect the existing clients. They are not a global backend quota:
multiple caller processes each have four slots, and a compromised credential
holder can connect directly unless the backend/network separately enforces
admission. Model-file binding, server scheduling, accelerator qualification and
per-key limits remain independent acceptance work. Starting a helper for each
RPC also adds Python startup latency and bounded process/thread overhead.

The native UI uses required Landlock plus service syscall filtering; the native
agent currently has service syscall filtering without a Landlock wrapper.
Sandbox agent/UI use their configured container restrictions. The launcher now
masks directory-only rights from regular-file rules using the opened inode,
without granting additional rights or accepting a partial required policy.
Two exact Fedora ELF loader files are executable in the common policy:
`/usr/lib64/ld-linux-x86-64.so.2` and `/usr/lib/ld-linux-aarch64.so.1`.
The other architecture’s absent file is optional; library directories stay
read-only. This allows the locked Python and shell wrappers to start.
The actual generated UI wrapper reaches its health endpoint under required
Landlock in a private synthetic filesystem; this is not a complete Fedora unit boot.
The valid file/directory distinction follows the Linux
[Landlock filesystem rights contract](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags).

Tests distinguish adapter compatibility (`test_inference_clients.py`) from real
helper/socket limits (`test_inference_transport.py`). Qualification evidence
includes synthetic native and CPU container protocols, the actual packaged
agent runtime, slow headers/body, blocked request/output pipes, parent death,
concurrent close and admission release. Synthetic zero-weight completions prove
protocol handling, not useful model quality. The pinned CPU container backend
0.3.0-dev build 10795 differs from native 0.4.0 build 10809; this is not evidence
of identical backend hardening or accelerator behavior.
