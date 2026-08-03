"""Step executor — runs approved steps inside budget constraints (spec §8).

The executor dispatches each approved step to the appropriate handler:
file operations go through the storage gateway, tool invocations go
through the tool firewall, and online requests go through the airlock.
Results are returned through a narrow, logged interface.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import requests

from .models import (
    Budgets,
    CapabilityToken,
    Step,
    StepAction,
    StepStatus,
)
from .storage import StorageGateway

log = logging.getLogger("agent.executor")

# Service URLs (from environment, matching systemd service config)
_INFERENCE_URL = os.getenv("INFERENCE_URL", "http://127.0.0.1:8465")
_TOOL_FIREWALL_URL = os.getenv("TOOL_FIREWALL_URL", "http://127.0.0.1:8475")
_AIRLOCK_URL = os.getenv("AIRLOCK_URL", "http://127.0.0.1:8490")
_REGISTRY_URL = os.getenv("REGISTRY_URL", "http://127.0.0.1:8470")
_SEARCH_MEDIATOR_URL = os.getenv("SEARCH_MEDIATOR_URL", "http://127.0.0.1:8485")

# Timeout for internal service calls
_SERVICE_TIMEOUT = 30


def _service_headers(
    target: str,
    service_name: str = "agent",
) -> dict[str, str]:
    """Load the inter-service token for authenticated local API calls."""
    token_env = {
        "airlock": "AIRLOCK_TOKEN_PATH",
        "registry": "REGISTRY_TOKEN_PATH",
        "tool-firewall": "TOOL_FIREWALL_TOKEN_PATH",
    }.get(target, "SERVICE_TOKEN_PATH")
    token_path = os.getenv(token_env, "")
    try:
        token = Path(token_path).read_text(encoding="utf-8").strip()
    except OSError:
        token = ""
    headers = {"X-SecAI-Service": service_name}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


class Executor:
    """Runs approved steps with budget enforcement.

    Each step type dispatches to a specialised handler.  The executor
    tracks budget consumption and aborts if any limit is exceeded.
    """

    def __init__(self, storage: StorageGateway):
        self._storage = storage

    def execute(
        self,
        step: Step,
        cap: CapabilityToken,
        budgets: Budgets,
    ) -> Step:
        """Execute a single approved step.

        Mutates and returns the step with updated status and result.
        """
        # Budget check before execution
        budget_err = budgets.check()
        if budget_err:
            step.status = StepStatus.FAILED
            step.error = budget_err
            return step

        step.status = StepStatus.RUNNING
        budgets.steps_used += 1

        try:
            handler = self._get_handler(step.action)
            result = handler(step, cap, budgets)
            if not isinstance(result, dict):
                raise RuntimeError("step handler returned an invalid result")
            step.result = result
            if result.get("ok") is True:
                step.status = StepStatus.COMPLETED
                step.error = None
            else:
                step.status = StepStatus.FAILED
                raw_error = result.get("error", "step handler reported failure")
                step.error = str(raw_error)[:1024]
        except Exception as exc:
            log.error("step %s failed: %s", step.step_id, exc)
            step.status = StepStatus.FAILED
            step.error = str(exc)

        return step

    # --- handler dispatch --------------------------------------------------

    def _get_handler(self, action: StepAction):
        """Return the handler function for a step action."""
        handlers = {
            StepAction.LOCAL_SEARCH: self._handle_local_search,
            StepAction.SUMMARIZE: self._handle_summarize,
            StepAction.DRAFT: self._handle_draft,
            StepAction.CLASSIFY: self._handle_classify,
            StepAction.REPORT: self._handle_report,
            StepAction.EXPLAIN_SECURITY: self._handle_explain_security,
            StepAction.READ_FILE: self._handle_read_file,
            StepAction.WRITE_FILE: self._handle_write_file,
            StepAction.OVERWRITE_FILE: self._handle_write_file,
            StepAction.TOOL_INVOKE: self._handle_tool_invoke,
            StepAction.OUTBOUND_REQUEST: self._handle_outbound_request,
        }
        handler = handlers.get(action)
        if not handler:
            raise ValueError(f"no handler for action '{action.value}'")
        return handler

    # --- file handlers (via storage gateway) --------------------------------

    def _handle_read_file(
        self, step: Step, cap: CapabilityToken, budgets: Budgets
    ) -> dict:
        path = step.params.get("path", "")
        result = self._storage.read_file(path, cap)
        if result["ok"]:
            size = int(result.get("size", 0))
            if budgets.output_bytes_used + size > budgets.max_output_bytes:
                return {"ok": False, "error": "output-size budget would be exceeded"}
            budgets.files_touched += 1
            budgets.output_bytes_used += size
        return result

    def _handle_write_file(
        self, step: Step, cap: CapabilityToken, budgets: Budgets
    ) -> dict:
        path = step.params.get("path", "")
        content = step.params.get("content", "")
        overwrite = step.action == StepAction.OVERWRITE_FILE
        if budgets.files_touched >= budgets.max_files_touched:
            return {"ok": False, "error": "files-touched budget would be exceeded"}
        result = self._storage.write_file(path, content, cap, overwrite=overwrite)
        if result["ok"]:
            budgets.files_touched += 1
        return result

    # --- LLM-powered handlers (via inference worker) -----------------------

    def _handle_summarize(
        self, step: Step, cap: CapabilityToken, budgets: Budgets
    ) -> dict:
        """Summarize content using the local inference worker."""
        content = step.params.get("content", "")
        if isinstance(content, str) and content.strip() in {"...", "…"}:
            content = ""
        if not content:
            # If a path is given, read via storage gateway first
            path = step.params.get("path", "")
            if path:
                if budgets.files_touched >= budgets.max_files_touched:
                    return {"ok": False, "error": "files-touched budget would be exceeded"}
                read_result = self._storage.read_file(path, cap)
                if not read_result["ok"]:
                    return read_result
                content = read_result["content"]
                budgets.files_touched += 1

        if not content:
            return {"ok": False, "error": "no content to summarize"}

        prompt = f"Summarize the following content concisely:\n\n{content[:8000]}"
        result = self._inference_completion(prompt, budgets)
        return result

    def _handle_draft(
        self, step: Step, cap: CapabilityToken, budgets: Budgets
    ) -> dict:
        """Draft content using the local inference worker."""
        instruction = step.params.get("instruction", "")
        context = step.params.get("context", "")
        prompt = f"Draft the following:\n{instruction}"
        if context:
            prompt += f"\n\nContext:\n{context[:4000]}"
        result = self._inference_completion(prompt, budgets)

        # If an output path is specified, write the draft
        out_path = step.params.get("path", "")
        if out_path and result.get("ok"):
            if budgets.files_touched >= budgets.max_files_touched:
                return {"ok": False, "error": "files-touched budget would be exceeded"}
            write_result = self._storage.write_file(
                out_path, result.get("text", ""), cap
            )
            if not write_result["ok"]:
                return write_result
            budgets.files_touched += 1
            result["saved_to"] = out_path

        return result

    def _handle_classify(
        self, step: Step, cap: CapabilityToken, budgets: Budgets
    ) -> dict:
        """Classify/tag content using the local inference worker."""
        content = step.params.get("content", "")
        categories = step.params.get("categories", [])
        prompt = (
            f"Classify the following content into one of these categories: "
            f"{', '.join(categories) if categories else 'general, technical, personal, financial'}.\n"
            f"Respond with just the category name.\n\nContent:\n{content[:4000]}"
        )
        return self._inference_completion(prompt, budgets)

    def _handle_report(
        self, step: Step, cap: CapabilityToken, budgets: Budgets
    ) -> dict:
        """Generate a report using the local inference worker."""
        instruction = step.params.get("instruction", "")
        sources = step.params.get("sources", [])
        if not isinstance(sources, list) or any(
            not isinstance(source, str) for source in sources
        ):
            return {"ok": False, "error": "sources must be an array of paths"}

        # Gather source content via storage gateway
        gathered = []
        for src_path in sources[:5]:  # cap at 5 sources
            if budgets.files_touched >= budgets.max_files_touched:
                return {"ok": False, "error": "files-touched budget would be exceeded"}
            read_result = self._storage.read_file(src_path, cap)
            if read_result["ok"]:
                gathered.append(f"--- {src_path} ---\n{read_result['content'][:2000]}")
                budgets.files_touched += 1

        context = "\n\n".join(gathered) if gathered else ""
        prompt = f"Generate a report: {instruction}"
        if context:
            prompt += f"\n\nSources:\n{context}"

        result = self._inference_completion(prompt, budgets)

        out_path = step.params.get("path", "")
        if out_path and result.get("ok"):
            if budgets.files_touched >= budgets.max_files_touched:
                return {"ok": False, "error": "files-touched budget would be exceeded"}
            write_result = self._storage.write_file(
                out_path, result.get("text", ""), cap
            )
            if not write_result["ok"]:
                return write_result
            budgets.files_touched += 1
            result["saved_to"] = out_path

        return result

    def _handle_local_search(
        self, step: Step, cap: CapabilityToken, budgets: Budgets
    ) -> dict:
        """Search local files by listing directory contents."""
        scope = step.params.get("path", "")
        if not scope:
            scope = step.params.get("scope", "")
        if not scope:
            return {"ok": False, "error": "no search scope specified"}
        if budgets.files_touched >= budgets.max_files_touched:
            return {"ok": False, "error": "files-touched budget would be exceeded"}
        result = self._storage.list_files(scope, cap)
        if result["ok"]:
            budgets.files_touched += 1
        return result

    def _handle_explain_security(
        self, step: Step, cap: CapabilityToken, budgets: Budgets
    ) -> dict:
        """Explain a security decision in user-friendly language."""
        context = step.params.get("context", "")
        decision_type = step.params.get("decision_type", "general")
        prompt = (
            f"Explain the following {decision_type} security decision "
            f"in user-friendly language. Be concise and helpful.\n\n{context[:2000]}"
        )
        return self._inference_completion(prompt, budgets)

    # --- tool firewall handler ---------------------------------------------

    def _handle_tool_invoke(
        self, step: Step, cap: CapabilityToken, budgets: Budgets
    ) -> dict:
        """Invoke a tool through the tool firewall."""
        tool = step.params.get("tool", "")
        params = step.params.get("args", {})

        # First: evaluate via tool firewall
        try:
            resp = requests.post(
                f"{_TOOL_FIREWALL_URL}/v1/evaluate",
                json={"tool": tool, "params": params},
                headers=_service_headers("tool-firewall"),
                timeout=_SERVICE_TIMEOUT,
            )
            budgets.tool_calls_used += 1

            if resp.status_code != 200:
                return {
                    "ok": False,
                    "error": f"tool firewall denied: {resp.text}",
                }

            try:
                fw_result = resp.json()
            except (TypeError, ValueError):
                return {
                    "ok": False,
                    "error": "tool firewall returned a malformed decision",
                }
            if not isinstance(fw_result, dict) or type(fw_result.get("allowed")) is not bool:
                return {
                    "ok": False,
                    "error": "tool firewall returned a malformed decision",
                }
            if fw_result["allowed"] is not True:
                reason = fw_result.get("reason", "denied")
                if not isinstance(reason, str):
                    reason = "denied"
                return {
                    "ok": False,
                    "error": f"tool firewall: {reason}",
                }

        except requests.RequestException as exc:
            return {"ok": False, "error": f"tool firewall unreachable: {exc}"}

        return {
            "ok": False,
            "error": (
                "tool policy evaluation succeeded, but no production tool "
                "execution broker is configured"
            ),
        }

    # --- airlock handler ---------------------------------------------------

    def _handle_outbound_request(
        self, step: Step, cap: CapabilityToken, budgets: Budgets
    ) -> dict:
        """Route an outbound request through the airlock."""
        if not cap.allow_online:
            return {"ok": False, "error": "online access not permitted"}

        url = step.params.get("url", "")
        method = step.params.get("method", "GET")
        body = step.params.get("body", "")

        # Redact sensitive content from outbound body
        if body:
            body = self._storage.redact_for_export(body)

        headers = _service_headers("airlock")
        if "Authorization" not in headers:
            return {"ok": False, "error": "airlock service credential unavailable"}
        if budgets.tool_calls_used >= budgets.max_tool_calls:
            return {"ok": False, "error": "tool-call budget would be exceeded"}
        remaining_output = budgets.max_output_bytes - budgets.output_bytes_used
        if remaining_output <= 0:
            return {"ok": False, "error": "output-size budget would be exceeded"}

        resp = None
        try:
            resp = requests.post(
                f"{_AIRLOCK_URL}/v1/fetch",
                json={"destination": url, "method": method, "body": body},
                headers=headers,
                stream=True,
                allow_redirects=False,
                timeout=(5, _SERVICE_TIMEOUT),
            )
            budgets.tool_calls_used += 1

            if not 200 <= resp.status_code < 300:
                return {
                    "ok": False,
                    "error": f"airlock fetch failed with status {resp.status_code}",
                }
            declared = resp.headers.get("Content-Length") if hasattr(resp, "headers") else None
            if declared:
                try:
                    if int(declared) > remaining_output:
                        return {"ok": False, "error": "airlock response exceeds output budget"}
                except ValueError:
                    return {"ok": False, "error": "airlock returned invalid content length"}

            chunks: list[bytes] = []
            total = 0
            iterator = getattr(resp, "iter_content", None)
            if callable(iterator):
                for chunk in iterator(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > remaining_output:
                        return {"ok": False, "error": "airlock response exceeds output budget"}
                    chunks.append(chunk)
            raw = b"".join(chunks)
            budgets.output_bytes_used += len(raw)
            return {
                "ok": True,
                "status_code": resp.status_code,
                "content": raw.decode("utf-8", errors="replace"),
                "content_type": (
                    resp.headers.get("Content-Type", "")
                    if hasattr(resp, "headers")
                    else ""
                ),
                "size": len(raw),
            }

        except requests.RequestException as exc:
            return {"ok": False, "error": f"airlock unreachable: {exc}"}
        finally:
            if resp is not None and callable(getattr(resp, "close", None)):
                resp.close()

    # --- inference helper --------------------------------------------------

    def _inference_completion(
        self, prompt: str, budgets: Budgets
    ) -> dict:
        """Call the local inference worker for a completion."""
        remaining_tokens = budgets.max_tokens - budgets.tokens_used
        remaining_output = budgets.max_output_bytes - budgets.output_bytes_used
        if remaining_tokens <= 0:
            return {"ok": False, "error": "token budget would be exceeded"}
        if remaining_output <= 0:
            return {"ok": False, "error": "output-size budget would be exceeded"}
        try:
            resp = requests.post(
                f"{_INFERENCE_URL}/completion",
                json={
                    "prompt": prompt,
                    "n_predict": min(1024, remaining_tokens),
                    "temperature": 0.3,
                },
                timeout=60,
                allow_redirects=False,
            )

            if resp.status_code != 200:
                return {"ok": False, "error": f"inference error: {resp.status_code}"}

            data = resp.json()
            text = data.get("content", "")
            tokens = data.get("tokens_predicted", 0)
            if not isinstance(text, str):
                return {"ok": False, "error": "inference returned invalid content"}
            if (
                not isinstance(tokens, int)
                or isinstance(tokens, bool)
                or tokens < 0
                or tokens > remaining_tokens
            ):
                return {"ok": False, "error": "inference returned invalid token usage"}
            output_size = len(text.encode("utf-8"))
            if output_size > remaining_output:
                return {"ok": False, "error": "inference output exceeds output budget"}
            budgets.tokens_used += tokens
            budgets.output_bytes_used += output_size

            return {"ok": True, "text": text, "tokens": tokens}

        except requests.RequestException as exc:
            return {"ok": False, "error": f"inference unreachable: {exc}"}
