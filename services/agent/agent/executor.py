"""Step executor — runs approved steps inside budget constraints (spec §8).

The executor dispatches each approved step to the appropriate handler:
file operations go through the storage gateway, tool invocations go
through the tool firewall, and online requests go through the airlock.
Results are returned through a narrow, logged interface.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import requests

from .models import (
    Budgets,
    CapabilityToken,
    SessionMode,
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
            step.result = result
            step.status = StepStatus.COMPLETED
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
            budgets.files_touched += 1
            budgets.output_bytes_used += result.get("size", 0)
        return result

    def _handle_write_file(
        self, step: Step, cap: CapabilityToken, budgets: Budgets
    ) -> dict:
        path = step.params.get("path", "")
        content = step.params.get("content", "")
        overwrite = step.action == StepAction.OVERWRITE_FILE
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
        if not content:
            # If a path is given, read via storage gateway first
            path = step.params.get("path", "")
            if path:
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

        # Gather source content via storage gateway
        gathered = []
        for src_path in sources[:5]:  # cap at 5 sources
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
        args = step.params.get("args", {})

        # First: evaluate via tool firewall
        try:
            resp = requests.post(
                f"{_TOOL_FIREWALL_URL}/v1/evaluate",
                json={"tool": tool, "args": args},
                timeout=_SERVICE_TIMEOUT,
            )
            budgets.tool_calls_used += 1

            if resp.status_code != 200:
                return {
                    "ok": False,
                    "error": f"tool firewall denied: {resp.text}",
                }

            fw_result = resp.json()
            if fw_result.get("decision") != "allow":
                return {
                    "ok": False,
                    "error": f"tool firewall: {fw_result.get('reason', 'denied')}",
                }

        except requests.RequestException as exc:
            return {"ok": False, "error": f"tool firewall unreachable: {exc}"}

        return {"ok": True, "tool": tool, "firewall_decision": "allow"}

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

        try:
            resp = requests.post(
                f"{_AIRLOCK_URL}/v1/egress/check",
                json={"url": url, "method": method, "body": body},
                timeout=_SERVICE_TIMEOUT,
            )

            if resp.status_code != 200:
                return {"ok": False, "error": f"airlock denied: {resp.text}"}

            return {"ok": True, "airlock_decision": "allow", "url": url}

        except requests.RequestException as exc:
            return {"ok": False, "error": f"airlock unreachable: {exc}"}

    # --- inference helper --------------------------------------------------

    def _inference_completion(
        self, prompt: str, budgets: Budgets
    ) -> dict:
        """Call the local inference worker for a completion."""
        try:
            resp = requests.post(
                f"{_INFERENCE_URL}/completion",
                json={
                    "prompt": prompt,
                    "n_predict": 1024,
                    "temperature": 0.3,
                },
                timeout=60,
            )

            if resp.status_code != 200:
                return {"ok": False, "error": f"inference error: {resp.status_code}"}

            data = resp.json()
            text = data.get("content", "")
            tokens = data.get("tokens_predicted", 0)
            budgets.tokens_used += tokens
            budgets.output_bytes_used += len(text.encode("utf-8"))

            return {"ok": True, "text": text, "tokens": tokens}

        except requests.RequestException as exc:
            return {"ok": False, "error": f"inference unreachable: {exc}"}
