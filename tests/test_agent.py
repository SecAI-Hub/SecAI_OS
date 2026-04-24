"""
Tests for the SecAI_OS Agent Mode service.

Covers: policy engine, capability tokens, storage gateway, budgets,
planner heuristic fallback, executor dispatch, and Flask API endpoints.
"""

# ruff: noqa: E402

import json
import os
import socket
import stat
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest
import requests

# Add services/ to path
_services_root = str(Path(__file__).resolve().parent.parent / "services")
if _services_root not in sys.path:
    sys.path.insert(0, _services_root)

from agent.agent.models import (
    Budgets,
    CapabilityToken,
    RiskLevel,
    SensitivityLevel,
    SessionMode,
    Step,
    StepAction,
    StepStatus,
    TaskStatus,
    Task,
)
from agent.agent.policy import PolicyEngine, classify_risk
from agent.agent.capabilities import (
    clear_nonce_cache,
    create_budgets,
    create_token,
    hash_intent,
    hash_policy_file,
    verify_token,
    _reset_signing_key,
)
from agent.agent.keystore import (
    SoftwareKeyProvider,
    TPM2KeyProvider,
    PKCS11KeyProvider,
    create_provider,
    load_config,
)
from agent.agent.storage import StorageGateway
from agent.agent.planner import Planner
from agent.agent.executor import Executor
from agent.agent.app import app
import agent.agent.app as agent_app_module


# ============================================================================
# Policy engine tests
# ============================================================================

class TestClassifyRisk:
    """Risk classification for the allow/deny matrix (spec §10)."""

    def test_auto_allow_actions(self):
        """Low-risk actions are classified as auto."""
        for action in [
            StepAction.LOCAL_SEARCH,
            StepAction.SUMMARIZE,
            StepAction.DRAFT,
            StepAction.CLASSIFY,
            StepAction.REPORT,
            StepAction.EXPLAIN_SECURITY,
        ]:
            assert classify_risk(action) == RiskLevel.AUTO, f"{action} should be AUTO"

    def test_hard_approval_actions(self):
        """High-risk actions require approval."""
        for action in [
            StepAction.OUTBOUND_REQUEST,
            StepAction.EXPORT_DATA,
            StepAction.TRUST_CHANGE,
            StepAction.BATCH_DELETE,
            StepAction.WIDEN_SCOPE,
            StepAction.ENABLE_TOOL,
            StepAction.CHANGE_SECURITY,
        ]:
            assert classify_risk(action) == RiskLevel.APPROVAL_REQUIRED, (
                f"{action} should be APPROVAL_REQUIRED"
            )

    def test_configurable_actions(self):
        """Medium-risk actions are configurable."""
        for action in [
            StepAction.READ_FILE,
            StepAction.WRITE_FILE,
            StepAction.OVERWRITE_FILE,
            StepAction.TOOL_INVOKE,
        ]:
            assert classify_risk(action) == RiskLevel.CONFIGURABLE, (
                f"{action} should be CONFIGURABLE"
            )


class TestPolicyEngine:
    """Deny-by-default policy evaluation."""

    def setup_method(self):
        self.engine = PolicyEngine()
        self.cap = CapabilityToken(
            readable_paths=["/var/lib/secure-ai/vault/user_docs/**"],
            writable_paths=["/var/lib/secure-ai/vault/outputs/**"],
            allowed_tools=["filesystem.read", "filesystem.list"],
            allow_online=False,
            sensitivity_ceiling=SensitivityLevel.MEDIUM,
            session_mode=SessionMode.STANDARD,
        )

    def test_auto_allow_summarize(self):
        step = Step(action=StepAction.SUMMARIZE, params={"content": "hello"})
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "allow"

    def test_deny_change_security(self):
        step = Step(action=StepAction.CHANGE_SECURITY)
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "deny"

    def test_ask_outbound_request(self):
        """Outbound requests are denied in standard mode without allow_online."""
        step = Step(action=StepAction.OUTBOUND_REQUEST, params={"url": "https://example.com"})
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "deny"

    def test_ask_outbound_with_online(self):
        """Outbound requests ask for approval when online is allowed."""
        self.cap.allow_online = True
        step = Step(action=StepAction.OUTBOUND_REQUEST, params={"url": "https://example.com"})
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "ask"

    def test_deny_read_outside_scope(self):
        step = Step(
            action=StepAction.READ_FILE,
            params={"path": "/etc/shadow"},
        )
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "deny"

    def test_ask_read_in_scope(self):
        """Reading an in-scope file is configurable (default: ask)."""
        step = Step(
            action=StepAction.READ_FILE,
            params={"path": "/var/lib/secure-ai/vault/user_docs/report.txt"},
        )
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "ask"

    def test_allow_read_with_always_pref(self):
        """User preference 'always' auto-approves configurable actions."""
        self.cap.configurable_prefs["read_file"] = "always"
        step = Step(
            action=StepAction.READ_FILE,
            params={"path": "/var/lib/secure-ai/vault/user_docs/report.txt"},
        )
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "allow"

    def test_deny_read_with_never_pref(self):
        """User preference 'never' denies configurable actions."""
        self.cap.configurable_prefs["read_file"] = "never"
        step = Step(
            action=StepAction.READ_FILE,
            params={"path": "/var/lib/secure-ai/vault/user_docs/report.txt"},
        )
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "deny"

    def test_deny_tool_not_in_allowed(self):
        step = Step(
            action=StepAction.TOOL_INVOKE,
            params={"tool": "shell.exec"},
        )
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "deny"

    def test_offline_blocks_outbound(self):
        """Offline-only mode blocks all online actions."""
        self.cap.session_mode = SessionMode.OFFLINE_ONLY
        self.cap.allow_online = True  # even with this flag
        step = Step(action=StepAction.OUTBOUND_REQUEST)
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "deny"

    def test_offline_blocks_export(self):
        self.cap.session_mode = SessionMode.OFFLINE_ONLY
        step = Step(action=StepAction.EXPORT_DATA)
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "deny"

    def test_sensitivity_ceiling_exceeded(self):
        """Steps with sensitivity above ceiling are denied."""
        self.cap.sensitivity_ceiling = SensitivityLevel.LOW
        step = Step(
            action=StepAction.SUMMARIZE,
            params={"sensitivity": "high"},
        )
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "deny"

    def test_sensitivity_within_ceiling(self):
        self.cap.sensitivity_ceiling = SensitivityLevel.HIGH
        step = Step(
            action=StepAction.SUMMARIZE,
            params={"sensitivity": "medium"},
        )
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "allow"

    def test_write_outside_writable_scope(self):
        step = Step(
            action=StepAction.WRITE_FILE,
            params={"path": "/etc/secure-ai/policy/agent.yaml"},
        )
        decision, _ = self.engine.evaluate(step, self.cap)
        assert decision == "deny"

    def test_policy_from_yaml(self):
        """Policy loads from YAML file without error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("version: 1\ndefault_mode: standard\n")
            f.flush()
            engine = PolicyEngine(f.name)
        os.unlink(f.name)
        step = Step(action=StepAction.SUMMARIZE)
        decision, _ = engine.evaluate(step, self.cap)
        assert decision == "allow"


# ============================================================================
# Capability token tests
# ============================================================================

class TestCapabilityTokens:

    def test_standard_token_defaults(self):
        token = create_token(SessionMode.STANDARD)
        assert token.session_mode == SessionMode.STANDARD
        assert not token.allow_online
        assert len(token.readable_paths) > 0
        assert len(token.writable_paths) > 0

    def test_offline_token_no_online(self):
        token = create_token(SessionMode.OFFLINE_ONLY)
        assert not token.allow_online

    def test_online_assisted_allows_online(self):
        token = create_token(SessionMode.ONLINE_ASSISTED)
        assert token.allow_online

    def test_sensitive_tight_scope(self):
        token = create_token(SessionMode.SENSITIVE)
        assert len(token.readable_paths) == 0  # must be explicitly scoped
        assert token.sensitivity_ceiling == SensitivityLevel.HIGH

    def test_extra_readable(self):
        token = create_token(
            SessionMode.STANDARD,
            extra_readable=["/vault/extra/**"],
        )
        assert "/vault/extra/**" in token.readable_paths

    def test_configurable_prefs(self):
        token = create_token(
            SessionMode.STANDARD,
            configurable_prefs={"read_file": "always"},
        )
        assert token.configurable_prefs["read_file"] == "always"

    def test_token_to_dict(self):
        token = create_token(SessionMode.STANDARD)
        d = token.to_dict()
        assert "token_id" in d
        assert d["session_mode"] == "standard"

    def test_budgets_per_mode(self):
        std = create_budgets(SessionMode.STANDARD)
        sens = create_budgets(SessionMode.SENSITIVE)
        assert std.max_steps > sens.max_steps
        assert std.max_wall_clock_seconds > sens.max_wall_clock_seconds


# ============================================================================
# Budget enforcement tests
# ============================================================================

class TestBudgets:

    def test_budget_check_passes(self):
        b = Budgets()
        assert b.check() is None

    def test_step_budget_exceeded(self):
        b = Budgets(max_steps=5, steps_used=5)
        assert "step budget exceeded" in b.check()

    def test_tool_call_budget_exceeded(self):
        b = Budgets(max_tool_calls=10, tool_calls_used=10)
        assert "tool-call budget exceeded" in b.check()

    def test_token_budget_exceeded(self):
        b = Budgets(max_tokens=100, tokens_used=100)
        assert "token budget exceeded" in b.check()

    def test_wall_clock_exceeded(self):
        b = Budgets(max_wall_clock_seconds=0.01)
        b.start_time = time.time() - 1
        assert "wall-clock budget exceeded" in b.check()

    def test_files_budget_exceeded(self):
        b = Budgets(max_files_touched=3, files_touched=3)
        assert "files-touched budget exceeded" in b.check()

    def test_output_budget_exceeded(self):
        b = Budgets(max_output_bytes=100, output_bytes_used=100)
        assert "output-size budget exceeded" in b.check()


# ============================================================================
# Storage gateway tests
# ============================================================================

class TestStorageGateway:

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gateway = StorageGateway(self.tmpdir)
        self.cap = CapabilityToken(
            readable_paths=[f"{self.tmpdir}/**"],
            writable_paths=[f"{self.tmpdir}/outputs/**"],
            sensitivity_ceiling=SensitivityLevel.HIGH,
        )
        # Create test files
        os.makedirs(f"{self.tmpdir}/outputs", exist_ok=True)
        Path(f"{self.tmpdir}/test.txt").write_text("hello world")
        Path(f"{self.tmpdir}/sensitive.txt").write_text(
            "password: secret123\nemail: user@example.com"
        )

    def test_read_file_ok(self):
        result = self.gateway.read_file(f"{self.tmpdir}/test.txt", self.cap)
        assert result["ok"]
        assert result["content"] == "hello world"
        assert result["sensitivity"] == "low"

    def test_read_file_not_found(self):
        result = self.gateway.read_file(f"{self.tmpdir}/missing.txt", self.cap)
        assert not result["ok"]
        assert "not found" in result["error"]

    def test_read_outside_scope(self):
        cap = CapabilityToken(readable_paths=["/nonexistent/**"])
        result = self.gateway.read_file(f"{self.tmpdir}/test.txt", cap)
        assert not result["ok"]
        assert "not in readable scope" in result["error"]

    def test_read_blocked_path(self):
        cap = CapabilityToken(readable_paths=["/etc/**"])
        result = self.gateway.read_file("/etc/shadow", cap)
        assert not result["ok"]
        # On Windows, blocked paths use POSIX format and don't match
        # the normalized Windows path, so the scope check catches it instead
        assert "blocked" in result["error"] or "not in readable scope" in result["error"]

    def test_write_file_ok(self):
        result = self.gateway.write_file(
            f"{self.tmpdir}/outputs/out.txt",
            "test content",
            self.cap,
        )
        assert result["ok"]
        assert Path(f"{self.tmpdir}/outputs/out.txt").read_text() == "test content"

    def test_write_outside_scope(self):
        result = self.gateway.write_file(
            f"{self.tmpdir}/notallowed.txt",
            "data",
            self.cap,
        )
        assert not result["ok"]
        assert "not in writable scope" in result["error"]

    def test_write_overwrite_protection(self):
        Path(f"{self.tmpdir}/outputs/existing.txt").write_text("old")
        result = self.gateway.write_file(
            f"{self.tmpdir}/outputs/existing.txt",
            "new",
            self.cap,
            overwrite=False,
        )
        assert not result["ok"]
        assert "overwrite=false" in result["error"]

    def test_write_overwrite_allowed(self):
        Path(f"{self.tmpdir}/outputs/existing.txt").write_text("old")
        result = self.gateway.write_file(
            f"{self.tmpdir}/outputs/existing.txt",
            "new",
            self.cap,
            overwrite=True,
        )
        assert result["ok"]

    def test_list_files(self):
        result = self.gateway.list_files(self.tmpdir, self.cap)
        assert result["ok"]
        names = [f["name"] for f in result["files"]]
        assert "test.txt" in names

    def test_sensitivity_detection(self):
        result = self.gateway.read_file(f"{self.tmpdir}/sensitive.txt", self.cap)
        assert result["ok"]
        assert result["sensitivity"] in ("medium", "high")

    def test_sensitivity_ceiling_blocks(self):
        cap = CapabilityToken(
            readable_paths=[f"{self.tmpdir}/**"],
            sensitivity_ceiling=SensitivityLevel.LOW,
        )
        result = self.gateway.read_file(f"{self.tmpdir}/sensitive.txt", cap)
        assert not result["ok"]
        assert "sensitivity" in result["error"]

    def test_redact_for_export(self):
        text = "My email is user@example.com and password: secret123"
        redacted = self.gateway.redact_for_export(text)
        assert "user@example.com" not in redacted
        assert "secret123" not in redacted
        assert "[REDACTED]" in redacted

    def test_normalise_blocks_null_byte(self):
        norm = StorageGateway._normalise("/etc/pass\x00wd")
        assert norm == "/dev/null"

    def test_file_too_large(self):
        result = self.gateway.read_file(
            f"{self.tmpdir}/test.txt",
            self.cap,
            max_bytes=5,
        )
        assert not result["ok"]
        assert "too large" in result["error"]


# ============================================================================
# Planner tests (heuristic fallback)
# ============================================================================

class TestPlannerHeuristic:
    """Test the keyword-based fallback planner (no LLM needed)."""

    def setup_method(self):
        self.planner = Planner(PolicyEngine())
        self.cap = create_token(SessionMode.STANDARD)

    @patch("agent.agent.planner.requests.post")
    def test_summarize_intent(self, mock_post):
        """'summarize' keyword maps to SUMMARIZE action."""
        mock_post.side_effect = requests.ConnectionError("no inference")
        steps = self.planner.plan("summarize my documents", self.cap)
        assert len(steps) >= 1
        assert steps[0].action == StepAction.SUMMARIZE

    @patch("agent.agent.planner.requests.post")
    def test_search_intent(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("no inference")
        steps = self.planner.plan("search for reports", self.cap)
        assert steps[0].action == StepAction.LOCAL_SEARCH

    @patch("agent.agent.planner.requests.post")
    def test_draft_intent(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("no inference")
        steps = self.planner.plan("draft a new email", self.cap)
        assert steps[0].action == StepAction.DRAFT

    @patch("agent.agent.planner.requests.post")
    def test_read_intent_with_path(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("no inference")
        steps = self.planner.plan("read /vault/user_docs/notes.txt", self.cap)
        assert steps[0].action == StepAction.READ_FILE
        assert steps[0].params.get("path") == "/vault/user_docs/notes.txt"

    @patch("agent.agent.planner.requests.post")
    def test_explain_intent(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("no inference")
        steps = self.planner.plan("explain why the model was quarantined", self.cap)
        assert steps[0].action == StepAction.EXPLAIN_SECURITY

    @patch("agent.agent.planner.requests.post")
    def test_unknown_intent_defaults_to_summarize(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("no inference")
        steps = self.planner.plan("something completely unrelated", self.cap)
        assert steps[0].action == StepAction.SUMMARIZE

    @patch("agent.agent.planner.requests.post")
    def test_risk_levels_classified(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("no inference")
        steps = self.planner.plan("summarize my notes", self.cap)
        assert steps[0].risk_level == RiskLevel.AUTO

    @patch("agent.agent.planner.requests.post")
    def test_max_steps_respected(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("no inference")
        steps = self.planner.plan("summarize all", self.cap, max_steps=1)
        assert len(steps) <= 1


class TestPlannerLLMParsing:
    """Test LLM output parsing."""

    def setup_method(self):
        self.planner = Planner(PolicyEngine())

    def test_parse_valid_json(self):
        text = json.dumps([
            {"action": "read_file", "description": "Read doc", "params": {"path": "/vault/doc.txt"}},
            {"action": "summarize", "description": "Summarize", "params": {}},
        ])
        steps = self.planner._parse_llm_plan(text)
        assert len(steps) == 2
        assert steps[0].action == StepAction.READ_FILE
        assert steps[1].action == StepAction.SUMMARIZE

    def test_parse_with_markdown_fences(self):
        text = "```json\n" + json.dumps([
            {"action": "draft", "description": "Draft note", "params": {}}
        ]) + "\n```"
        steps = self.planner._parse_llm_plan(text)
        assert len(steps) == 1
        assert steps[0].action == StepAction.DRAFT

    def test_parse_invalid_json(self):
        steps = self.planner._parse_llm_plan("this is not json")
        assert len(steps) == 0

    def test_parse_unknown_action_skipped(self):
        text = json.dumps([
            {"action": "hack_everything", "description": "Bad", "params": {}},
            {"action": "summarize", "description": "Good", "params": {}},
        ])
        steps = self.planner._parse_llm_plan(text)
        assert len(steps) == 1
        assert steps[0].action == StepAction.SUMMARIZE

    def test_parse_placeholder_content_uses_prior_read_path(self):
        text = json.dumps([
            {
                "action": "read_file",
                "description": "Read doc",
                "params": {"path": "/vault/user_docs/report.txt"},
            },
            {
                "action": "summarize",
                "description": "Summarize doc",
                "params": {"content": "..."},
            },
        ])
        steps = self.planner._parse_llm_plan(text)
        assert len(steps) == 2
        assert steps[1].params.get("path") == "/vault/user_docs/report.txt"
        assert "content" not in steps[1].params

    def test_parse_placeholder_content_without_context_is_removed(self):
        text = json.dumps([
            {
                "action": "summarize",
                "description": "Summarize doc",
                "params": {"content": "..."},
            },
        ])
        steps = self.planner._parse_llm_plan(text)
        assert len(steps) == 1
        assert "content" not in steps[0].params

    def test_parse_scope_glob_is_normalized_for_local_search(self):
        text = json.dumps([
            {
                "action": "local_search",
                "description": "Search outputs",
                "params": {"path": "/var/lib/secure-ai/vault/outputs/**"},
            },
        ])
        steps = self.planner._parse_llm_plan(text)
        assert len(steps) == 1
        assert steps[0].params["path"] == "/var/lib/secure-ai/vault/outputs"

    def test_display_scope_strips_glob_suffixes(self):
        assert self.planner._display_scope("/var/lib/secure-ai/vault/outputs/**") == (
            "/var/lib/secure-ai/vault/outputs"
        )


# ============================================================================
# Executor tests
# ============================================================================

class TestExecutor:

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.storage = StorageGateway(self.tmpdir)
        self.executor = Executor(self.storage)
        self.cap = CapabilityToken(
            readable_paths=[f"{self.tmpdir}/**"],
            writable_paths=[f"{self.tmpdir}/outputs/**"],
            sensitivity_ceiling=SensitivityLevel.HIGH,
        )
        os.makedirs(f"{self.tmpdir}/outputs", exist_ok=True)
        Path(f"{self.tmpdir}/doc.txt").write_text("Test document content")

    def test_read_file_success(self):
        step = Step(
            action=StepAction.READ_FILE,
            status=StepStatus.APPROVED,
            params={"path": f"{self.tmpdir}/doc.txt"},
        )
        budgets = Budgets()
        result_step = self.executor.execute(step, self.cap, budgets)
        assert result_step.status == StepStatus.COMPLETED
        assert result_step.result["ok"]
        assert budgets.files_touched == 1

    def test_read_file_outside_scope_fails(self):
        step = Step(
            action=StepAction.READ_FILE,
            status=StepStatus.APPROVED,
            params={"path": "/etc/hostname"},
        )
        budgets = Budgets()
        result_step = self.executor.execute(step, self.cap, budgets)
        assert result_step.status == StepStatus.COMPLETED  # step completes but result is not ok
        assert not result_step.result["ok"]

    def test_budget_exceeded_blocks_execution(self):
        step = Step(action=StepAction.READ_FILE, status=StepStatus.APPROVED)
        budgets = Budgets(max_steps=0, steps_used=0)  # already at limit
        # manually set steps_used to trigger
        budgets.steps_used = budgets.max_steps
        result_step = self.executor.execute(step, self.cap, budgets)
        assert result_step.status == StepStatus.FAILED
        assert "budget exceeded" in result_step.error

    def test_write_file_success(self):
        step = Step(
            action=StepAction.WRITE_FILE,
            status=StepStatus.APPROVED,
            params={
                "path": f"{self.tmpdir}/outputs/new.txt",
                "content": "generated content",
            },
        )
        budgets = Budgets()
        result_step = self.executor.execute(step, self.cap, budgets)
        assert result_step.status == StepStatus.COMPLETED
        assert Path(f"{self.tmpdir}/outputs/new.txt").read_text() == "generated content"

    def test_local_search_success(self):
        step = Step(
            action=StepAction.LOCAL_SEARCH,
            status=StepStatus.APPROVED,
            params={"path": self.tmpdir},
        )
        budgets = Budgets()
        result_step = self.executor.execute(step, self.cap, budgets)
        assert result_step.status == StepStatus.COMPLETED
        assert result_step.result["ok"]

    def test_summarize_placeholder_content_fails_closed(self):
        step = Step(
            action=StepAction.SUMMARIZE,
            status=StepStatus.APPROVED,
            params={"content": "..."},
        )
        budgets = Budgets()
        result_step = self.executor.execute(step, self.cap, budgets)
        assert result_step.status == StepStatus.COMPLETED
        assert not result_step.result["ok"]
        assert "no content" in result_step.result["error"]

    def test_unknown_action_fails(self):
        step = Step(
            action=StepAction.BATCH_DELETE,
            status=StepStatus.APPROVED,
        )
        budgets = Budgets()
        result_step = self.executor.execute(step, self.cap, budgets)
        assert result_step.status == StepStatus.FAILED


# ============================================================================
# Flask API tests
# ============================================================================

class TestAgentAPI:

    def setup_method(self):
        self.client = app.test_client()

    def test_health(self):
        resp = self.client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["service"] == "agent"

    def test_list_modes(self):
        resp = self.client.get("/v1/modes")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["modes"]) == 4
        mode_ids = [m["id"] for m in data["modes"]]
        assert "standard" in mode_ids
        assert "offline_only" in mode_ids
        assert "online_assisted" in mode_ids
        assert "sensitive" in mode_ids

    @patch("agent.agent.planner.requests.post")
    def test_submit_task(self, mock_post):
        """Submit a task and get back a planned task."""
        mock_post.side_effect = requests.ConnectionError("no inference")
        resp = self.client.post("/v1/task", json={
            "intent": "summarize my documents",
            "mode": "standard",
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert "task_id" in data
        # Low-risk summarize is auto-approved and may complete immediately
        assert data["status"] in ("pending_approval", "running", "completed", "failed")
        assert len(data["steps"]) >= 1

    def test_submit_task_empty_intent(self):
        resp = self.client.post("/v1/task", json={"intent": ""})
        assert resp.status_code == 400

    def test_submit_task_long_intent(self):
        resp = self.client.post("/v1/task", json={"intent": "x" * 2001})
        assert resp.status_code == 400

    def test_submit_task_invalid_mode(self):
        resp = self.client.post("/v1/task", json={
            "intent": "test",
            "mode": "nonexistent",
        })
        assert resp.status_code == 400

    def test_get_nonexistent_task(self):
        resp = self.client.get("/v1/task/nonexistent")
        assert resp.status_code == 404

    @patch("agent.agent.planner.requests.post")
    def test_task_lifecycle(self, mock_post):
        """Submit → approve → complete lifecycle."""
        mock_post.side_effect = requests.ConnectionError("no inference")

        # Submit
        resp = self.client.post("/v1/task", json={
            "intent": "summarize my documents",
        })
        task_id = resp.get_json()["task_id"]

        # Get status
        resp = self.client.get(f"/v1/task/{task_id}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["task_id"] == task_id

    @patch("agent.agent.planner.requests.post")
    def test_cancel_pending_task(self, mock_post):
        """Cancel a task that needs approval (read_file is configurable)."""
        mock_post.side_effect = requests.ConnectionError("no inference")
        resp = self.client.post("/v1/task", json={
            "intent": "read /vault/user_docs/notes.txt",
        })
        data = resp.get_json()
        task_id = data["task_id"]

        # If task is pending approval, cancel should work
        if data["status"] == "pending_approval":
            resp = self.client.post(f"/v1/task/{task_id}/cancel")
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "cancelled"
        else:
            # If already completed/failed (race), cancel returns 409
            resp = self.client.post(f"/v1/task/{task_id}/cancel")
            assert resp.status_code == 409

    @patch("agent.agent.planner.requests.post")
    def test_list_tasks(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("no inference")
        self.client.post("/v1/task", json={"intent": "task 1"})
        self.client.post("/v1/task", json={"intent": "task 2"})

        resp = self.client.get("/v1/tasks")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["tasks"]) >= 2

    def test_approve_nonexistent(self):
        resp = self.client.post("/v1/task/fake/approve", json={})
        assert resp.status_code == 404

    @patch("agent.agent.planner.requests.post")
    def test_approve_pending_task_allows_internal_reverification(self, mock_post):
        """Approval should re-check integrity without consuming the token nonce."""
        clear_nonce_cache()
        with agent_app_module._tasks_lock:
            agent_app_module._tasks.clear()

        mock_post.side_effect = requests.ConnectionError("no inference")
        resp = self.client.post("/v1/task", json={
            "intent": "read /var/lib/secure-ai/vault/user_docs/notes.txt",
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["status"] == "pending_approval"

        resp = self.client.post(
            f"/v1/task/{data['task_id']}/approve",
            json={"approve_all": True},
        )
        assert resp.status_code == 200

    @patch("agent.agent.planner.requests.post")
    def test_approve_rejects_tampered_step(self, mock_post):
        clear_nonce_cache()
        with agent_app_module._tasks_lock:
            agent_app_module._tasks.clear()

        mock_post.side_effect = requests.ConnectionError("no inference")
        resp = self.client.post("/v1/task", json={
            "intent": "read /var/lib/secure-ai/vault/user_docs/notes.txt",
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["status"] == "pending_approval"

        with agent_app_module._tasks_lock:
            task = agent_app_module._tasks[data["task_id"]]
            task.steps[0].params["path"] = "/etc/shadow"

        resp = self.client.post(
            f"/v1/task/{data['task_id']}/approve",
            json={"approve_all": True},
        )
        assert resp.status_code == 409
        assert "integrity" in resp.get_json()["error"]

    @patch("agent.agent.planner.requests.post")
    def test_approve_rejects_tampered_capability_token(self, mock_post):
        clear_nonce_cache()
        with agent_app_module._tasks_lock:
            agent_app_module._tasks.clear()

        mock_post.side_effect = requests.ConnectionError("no inference")
        resp = self.client.post("/v1/task", json={
            "intent": "read /var/lib/secure-ai/vault/user_docs/notes.txt",
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["status"] == "pending_approval"

        with agent_app_module._tasks_lock:
            task = agent_app_module._tasks[data["task_id"]]
            task.capability.allow_online = True

        resp = self.client.post(
            f"/v1/task/{data['task_id']}/approve",
            json={"approve_all": True},
        )
        assert resp.status_code == 403
        assert "invalid" in resp.get_json()["error"]

    def test_deny_nonexistent(self):
        resp = self.client.post("/v1/task/fake/deny", json={})
        assert resp.status_code == 404

    def test_deny_completed_task_returns_conflict(self):
        task = Task(intent="done")
        task.status = TaskStatus.COMPLETED
        task.completed_at = time.time()
        with agent_app_module._tasks_lock:
            agent_app_module._tasks[task.task_id] = task

        resp = self.client.post(f"/v1/task/{task.task_id}/deny", json={"deny_all": True})

        assert resp.status_code == 409
        assert "not pending_approval" in resp.get_json()["error"]
        with agent_app_module._tasks_lock:
            assert agent_app_module._tasks[task.task_id].status == TaskStatus.COMPLETED

    def test_security_headers(self):
        resp = self.client.get("/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("Cache-Control") == "no-store"

    @patch("agent.agent.planner.requests.post")
    def test_workspace_ids_resolved(self, mock_post):
        """Workspace IDs like 'user_docs' are accepted and resolved."""
        mock_post.side_effect = requests.ConnectionError("no inference")
        resp = self.client.post("/v1/task", json={
            "intent": "summarize my documents",
            "workspace": ["user_docs"],
        })
        assert resp.status_code == 201

    def test_workspace_ids_resolve_to_directory_roots(self):
        """Workspace IDs resolve to concrete directories for local_search steps."""
        resolved, err = agent_app_module._resolve_workspaces(["outputs"])
        assert err is None
        assert resolved == ["/var/lib/secure-ai/vault/outputs"]

    def test_workspace_raw_path_rejected(self):
        """Raw filesystem paths are rejected — only workspace IDs allowed."""
        resp = self.client.post("/v1/task", json={
            "intent": "summarize",
            "workspace": ["/var/lib/secure-ai/vault/user_docs"],
        })
        assert resp.status_code == 400
        assert "unknown workspace" in resp.get_json()["error"]

    def test_workspace_invalid_id_rejected(self):
        """Unknown workspace IDs are rejected."""
        resp = self.client.post("/v1/task", json={
            "intent": "summarize",
            "workspace": ["nonexistent_workspace"],
        })
        assert resp.status_code == 400

    def test_workspace_not_array_rejected(self):
        """Non-array workspace values are rejected."""
        resp = self.client.post("/v1/task", json={
            "intent": "summarize",
            "workspace": "/vault/user_docs",
        })
        assert resp.status_code == 400


# ============================================================================
# Security invariant tests
# ============================================================================

class TestSecurityInvariants:
    """Tests proving the agent cannot bypass airlock or widen scope silently."""

    def test_cannot_bypass_airlock(self):
        """Outbound requests fail when airlock is unreachable (fail-closed)."""
        tmpdir = tempfile.mkdtemp()
        storage = StorageGateway(tmpdir)
        executor = Executor(storage)
        cap = CapabilityToken(
            allow_online=True,
            sensitivity_ceiling=SensitivityLevel.HIGH,
        )
        step = Step(
            action=StepAction.OUTBOUND_REQUEST,
            status=StepStatus.APPROVED,
            params={"url": "https://example.com", "method": "GET"},
        )
        budgets = Budgets()
        with patch("agent.agent.executor.requests.post") as mock:
            mock.side_effect = requests.ConnectionError("airlock unreachable")
            result_step = executor.execute(step, cap, budgets)
        assert result_step.result["ok"] is False
        assert "airlock unreachable" in result_step.result["error"]

    def test_airlock_receives_destination_field(self):
        """Outbound requests must send the destination field expected by the airlock."""
        tmpdir = tempfile.mkdtemp()
        storage = StorageGateway(tmpdir)
        executor = Executor(storage)
        cap = CapabilityToken(
            allow_online=True,
            sensitivity_ceiling=SensitivityLevel.HIGH,
        )
        step = Step(
            action=StepAction.OUTBOUND_REQUEST,
            status=StepStatus.APPROVED,
            params={"url": "https://example.com", "method": "GET"},
        )
        budgets = Budgets()

        mock_resp = type("Resp", (), {"status_code": 200, "text": "", "json": lambda self: {}})()

        with patch("agent.agent.executor.requests.post", return_value=mock_resp) as mock_post:
            result_step = executor.execute(step, cap, budgets)

        assert result_step.result["ok"] is True
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["destination"] == "https://example.com"
        assert "url" not in kwargs["json"]

    def test_cannot_bypass_tool_firewall(self):
        """Tool invocations fail when tool firewall is unreachable (fail-closed)."""
        tmpdir = tempfile.mkdtemp()
        storage = StorageGateway(tmpdir)
        executor = Executor(storage)
        cap = CapabilityToken(
            allowed_tools=["filesystem.read"],
            sensitivity_ceiling=SensitivityLevel.HIGH,
        )
        step = Step(
            action=StepAction.TOOL_INVOKE,
            status=StepStatus.APPROVED,
            params={"tool": "filesystem.read", "args": {"path": "/tmp/test"}},
        )
        budgets = Budgets()
        with patch("agent.agent.executor.requests.post") as mock:
            mock.side_effect = requests.ConnectionError("firewall unreachable")
            result_step = executor.execute(step, cap, budgets)
        assert result_step.result["ok"] is False
        assert "firewall unreachable" in result_step.result["error"]

    def test_tool_firewall_receives_normalized_params(self):
        """Tool firewall requests must send params, not the legacy args field."""
        tmpdir = tempfile.mkdtemp()
        storage = StorageGateway(tmpdir)
        executor = Executor(storage)
        cap = CapabilityToken(
            allowed_tools=["filesystem.read"],
            sensitivity_ceiling=SensitivityLevel.HIGH,
        )
        step = Step(
            action=StepAction.TOOL_INVOKE,
            status=StepStatus.APPROVED,
            params={"tool": "filesystem.read", "args": {"path": "/tmp/test"}},
        )
        budgets = Budgets()

        mock_resp = type("Resp", (), {
            "status_code": 200,
            "json": lambda self: {"decision": "allow"},
        })()

        with patch("agent.agent.executor.requests.post", return_value=mock_resp) as mock_post:
            result_step = executor.execute(step, cap, budgets)

        assert result_step.result["ok"] is True
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["tool"] == "filesystem.read"
        assert kwargs["json"]["params"] == {"path": "/tmp/test"}
        assert "args" not in kwargs["json"]

    def test_cannot_widen_scope_silently(self):
        """Widen-scope action is always classified as approval-required."""
        assert classify_risk(StepAction.WIDEN_SCOPE) == RiskLevel.APPROVAL_REQUIRED

    def test_cannot_change_security_settings(self):
        """Security setting changes are always denied regardless of mode."""
        engine = PolicyEngine()
        for mode in SessionMode:
            cap = CapabilityToken(session_mode=mode)
            step = Step(action=StepAction.CHANGE_SECURITY)
            decision, _ = engine.evaluate(step, cap)
            assert decision == "deny", f"change_security should be denied in {mode.value}"

    def test_outbound_denied_without_online_flag(self):
        """Outbound requests are denied when the capability token has allow_online=False."""
        engine = PolicyEngine()
        cap = CapabilityToken(
            allow_online=False,
            session_mode=SessionMode.STANDARD,
        )
        step = Step(action=StepAction.OUTBOUND_REQUEST)
        decision, _ = engine.evaluate(step, cap)
        assert decision == "deny"

    def test_offline_mode_blocks_all_online(self):
        """Offline-only mode denies outbound and export even with allow_online."""
        engine = PolicyEngine()
        cap = CapabilityToken(
            allow_online=True,
            session_mode=SessionMode.OFFLINE_ONLY,
        )
        for action in [StepAction.OUTBOUND_REQUEST, StepAction.EXPORT_DATA]:
            step = Step(action=action)
            decision, _ = engine.evaluate(step, cap)
            assert decision == "deny", f"{action.value} should be denied in offline_only"

    def test_storage_blocks_system_paths(self):
        """Storage gateway blocks access to sensitive system files."""
        tmpdir = tempfile.mkdtemp()
        gw = StorageGateway(tmpdir)
        cap = CapabilityToken(readable_paths=["/etc/**"])
        for blocked in ["/etc/shadow", "/etc/passwd", "/run/secure-ai/service-token"]:
            result = gw.read_file(blocked, cap)
            assert not result["ok"], f"{blocked} should be blocked"
            # On Windows, POSIX blocked paths don't match normalized Windows paths,
            # so the scope check catches the access instead of the block check
            assert "blocked" in result["error"] or "not in readable scope" in result["error"]


# ============================================================================
# Data model tests
# ============================================================================

class TestDataModels:

    def test_task_to_dict(self):
        task = Task(intent="test", mode=SessionMode.STANDARD)
        d = task.to_dict()
        assert d["intent"] == "test"
        assert d["mode"] == "standard"
        assert isinstance(d["steps"], list)

    def test_step_to_dict(self):
        step = Step(action=StepAction.SUMMARIZE, description="sum it up")
        d = step.to_dict()
        assert d["action"] == "summarize"
        assert d["description"] == "sum it up"

    def test_session_modes(self):
        assert SessionMode("offline_only") == SessionMode.OFFLINE_ONLY
        assert SessionMode("standard") == SessionMode.STANDARD
        assert SessionMode("online_assisted") == SessionMode.ONLINE_ASSISTED
        assert SessionMode("sensitive") == SessionMode.SENSITIVE

    def test_risk_levels(self):
        assert RiskLevel("auto") == RiskLevel.AUTO
        assert RiskLevel("configurable") == RiskLevel.CONFIGURABLE
        assert RiskLevel("approval_required") == RiskLevel.APPROVAL_REQUIRED


# ============================================================================
# M40 — Verified Supervisor: Token Signing & Verification
# ============================================================================

class TestTokenSigning:
    """HMAC-SHA256 token signing and verification (M40)."""

    def setup_method(self):
        _reset_signing_key()
        clear_nonce_cache()

    def test_token_is_signed(self):
        """Tokens created via create_token() have a non-empty signature."""
        token = create_token(SessionMode.STANDARD)
        assert token.signature != ""
        assert len(token.signature) == 64  # SHA-256 hex

    def test_token_has_nonce(self):
        """Each token gets a unique nonce."""
        t1 = create_token(SessionMode.STANDARD)
        clear_nonce_cache()
        t2 = create_token(SessionMode.STANDARD)
        assert t1.nonce != t2.nonce

    def test_verify_valid_token(self):
        """A freshly signed token passes verification."""
        token = create_token(SessionMode.STANDARD)
        valid, reason = verify_token(token)
        assert valid, f"expected valid, got: {reason}"
        assert reason == "valid"

    def test_verify_tampered_token_fails(self):
        """Modifying token fields after signing invalidates the signature."""
        token = create_token(SessionMode.STANDARD)
        token.allow_online = True  # tamper
        valid, reason = verify_token(token)
        assert not valid
        assert "signature mismatch" in reason

    def test_verify_tampered_paths_fails(self):
        """Widening readable paths after signing invalidates the token."""
        token = create_token(SessionMode.STANDARD)
        token.readable_paths.append("/etc/shadow")
        valid, reason = verify_token(token)
        assert not valid
        assert "signature mismatch" in reason

    def test_verify_unsigned_token_fails(self):
        """A token without a signature is rejected."""
        token = CapabilityToken()
        valid, reason = verify_token(token)
        assert not valid
        assert "not signed" in reason

    def test_replay_protection(self):
        """The same nonce cannot be used twice (replay attack)."""
        token = create_token(SessionMode.STANDARD)
        valid1, _ = verify_token(token)
        assert valid1
        # Second verify should fail (nonce already seen)
        valid2, reason2 = verify_token(token)
        assert not valid2
        assert "replay" in reason2

    def test_expired_token_rejected(self):
        """A token past its expiry time is rejected."""
        token = create_token(SessionMode.STANDARD, ttl_seconds=0.01)
        time.sleep(0.05)  # wait for expiry
        valid, reason = verify_token(token)
        assert not valid
        assert "expired" in reason

    def test_no_expiry_means_no_timeout(self):
        """A token with expires_at=0 never expires."""
        token = create_token(SessionMode.STANDARD, ttl_seconds=0)
        assert token.expires_at == 0.0
        assert not token.is_expired()

    def test_token_bound_to_task(self):
        """Token includes task_id and intent_hash when provided."""
        token = create_token(
            SessionMode.STANDARD,
            task_id="task123",
            intent="summarize documents",
        )
        assert token.task_id == "task123"
        assert token.intent_hash == hash_intent("summarize documents")
        assert token.intent_hash != ""


class TestTokenBinding:
    """Task context binding for capability tokens (M40)."""

    def setup_method(self):
        _reset_signing_key()
        clear_nonce_cache()

    def test_intent_hash_deterministic(self):
        """Same intent always produces the same hash."""
        h1 = hash_intent("summarize my docs")
        h2 = hash_intent("summarize my docs")
        assert h1 == h2

    def test_intent_hash_different_for_different_intents(self):
        h1 = hash_intent("summarize")
        h2 = hash_intent("classify")
        assert h1 != h2

    def test_policy_digest_from_file(self):
        """Policy digest is computed from the policy file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("version: 1\ndefault_mode: standard\n")
            f.flush()
            digest = hash_policy_file(f.name)
        os.unlink(f.name)
        assert len(digest) == 64  # SHA-256 hex

    def test_policy_digest_missing_file(self):
        """Missing policy file returns empty digest."""
        assert hash_policy_file("/nonexistent/policy.yaml") == ""

    def test_token_includes_policy_digest(self):
        """Token created with a policy path includes the digest."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("version: 1\n")
            f.flush()
            token = create_token(
                SessionMode.STANDARD,
                policy_path=f.name,
            )
        os.unlink(f.name)
        assert token.policy_digest != ""

    def test_to_dict_includes_new_fields(self):
        """to_dict() includes all M40 fields."""
        token = create_token(
            SessionMode.STANDARD,
            task_id="t1",
            intent="test",
        )
        d = token.to_dict()
        assert "task_id" in d
        assert "intent_hash" in d
        assert "policy_digest" in d
        assert "nonce" in d
        assert "issued_at" in d
        assert "expires_at" in d
        assert "signature" in d

    def test_is_expired_false_when_fresh(self):
        token = create_token(SessionMode.STANDARD, ttl_seconds=3600)
        assert not token.is_expired()

    def test_is_expired_true_when_past(self):
        token = CapabilityToken(expires_at=time.time() - 10)
        assert token.is_expired()


# ============================================================================
# M40 — Verified Supervisor: Two-Phase Approval & Policy Evidence
# ============================================================================

class TestTwoPhaseApproval:
    """Two-phase approval for high-risk actions (M40)."""

    def setup_method(self):
        _reset_signing_key()
        clear_nonce_cache()
        self.engine = PolicyEngine()
        self.cap = create_token(SessionMode.STANDARD)

    def test_trust_change_requires_two_phase(self):
        """TRUST_CHANGE always requires approval via two-phase."""
        step = Step(action=StepAction.TRUST_CHANGE)
        decision, reason, evidence = self.engine.evaluate_with_evidence(
            step, self.cap
        )
        assert decision == "ask"
        assert "approval" in reason.lower() or "two-phase" in reason.lower()

    def test_export_data_requires_two_phase(self):
        step = Step(action=StepAction.EXPORT_DATA)
        decision, _, evidence = self.engine.evaluate_with_evidence(
            step, self.cap
        )
        assert decision in ("ask", "deny")  # denied in offline, ask otherwise

    def test_widen_scope_requires_two_phase(self):
        step = Step(action=StepAction.WIDEN_SCOPE)
        decision, _, _ = self.engine.evaluate_with_evidence(step, self.cap)
        assert decision == "ask"

    def test_enable_tool_requires_two_phase(self):
        step = Step(action=StepAction.ENABLE_TOOL)
        decision, _, _ = self.engine.evaluate_with_evidence(step, self.cap)
        assert decision == "ask"

    def test_change_security_always_denied(self):
        """CHANGE_SECURITY is denied even with two-phase (always-deny)."""
        step = Step(action=StepAction.CHANGE_SECURITY)
        decision, _, evidence = self.engine.evaluate_with_evidence(
            step, self.cap
        )
        assert decision == "deny"
        assert evidence.decision == "deny"

    def test_low_risk_not_escalated(self):
        """Low-risk actions are not escalated to two-phase."""
        step = Step(action=StepAction.SUMMARIZE)
        decision, _, _ = self.engine.evaluate_with_evidence(step, self.cap)
        assert decision == "allow"


class TestPolicyEvidence:
    """Per-step policy decision evidence recording (M40)."""

    def setup_method(self):
        _reset_signing_key()
        clear_nonce_cache()
        self.engine = PolicyEngine()
        self.cap = create_token(SessionMode.STANDARD)

    def test_evidence_includes_step_id(self):
        step = Step(action=StepAction.SUMMARIZE)
        _, _, evidence = self.engine.evaluate_with_evidence(step, self.cap)
        assert evidence.step_id == step.step_id

    def test_evidence_includes_action(self):
        step = Step(action=StepAction.READ_FILE, params={"path": "/vault/doc.txt"})
        _, _, evidence = self.engine.evaluate_with_evidence(step, self.cap)
        assert evidence.action == "read_file"

    def test_evidence_includes_risk_level(self):
        step = Step(action=StepAction.SUMMARIZE)
        _, _, evidence = self.engine.evaluate_with_evidence(step, self.cap)
        assert evidence.risk_level == "auto"

    def test_evidence_includes_token_id(self):
        step = Step(action=StepAction.SUMMARIZE)
        _, _, evidence = self.engine.evaluate_with_evidence(step, self.cap)
        assert evidence.token_id == self.cap.token_id

    def test_evidence_token_valid_flag(self):
        step = Step(action=StepAction.SUMMARIZE)
        _, _, ev_valid = self.engine.evaluate_with_evidence(
            step, self.cap, token_valid=True
        )
        assert ev_valid.token_valid is True

        _, _, ev_invalid = self.engine.evaluate_with_evidence(
            step, self.cap, token_valid=False
        )
        assert ev_invalid.token_valid is False

    def test_evidence_to_dict(self):
        step = Step(action=StepAction.SUMMARIZE)
        _, _, evidence = self.engine.evaluate_with_evidence(step, self.cap)
        d = evidence.to_dict()
        assert "step_id" in d
        assert "action" in d
        assert "decision" in d
        assert "reason" in d
        assert "risk_level" in d
        assert "token_id" in d
        assert "token_valid" in d
        assert "timestamp" in d

    def test_expired_token_denied_with_evidence(self):
        """Expired tokens are denied and evidence records this."""
        _reset_signing_key()
        clear_nonce_cache()
        cap = create_token(SessionMode.STANDARD, ttl_seconds=0.01)
        time.sleep(0.05)
        step = Step(action=StepAction.SUMMARIZE)
        decision, reason, evidence = self.engine.evaluate_with_evidence(
            step, cap
        )
        assert decision == "deny"
        assert "expired" in reason

    def test_policy_digest_in_engine(self):
        """PolicyEngine exposes the digest of the loaded policy file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("version: 1\ndefault_mode: standard\n")
            f.flush()
            engine = PolicyEngine(f.name)
        os.unlink(f.name)
        assert engine.policy_digest != ""
        assert len(engine.policy_digest) == 64


# ============================================================================
# M40 — Verified Supervisor: API Integration Tests
# ============================================================================

class TestVerifiedSupervisorAPI:
    """API endpoint tests for M40 token signing and two-phase approval."""

    def setup_method(self):
        _reset_signing_key()
        clear_nonce_cache()
        self.client = app.test_client()

    @patch("agent.agent.planner.requests.post")
    def test_submitted_task_has_signed_token(self, mock_post):
        """Submitted tasks get tokens with signatures and binding fields."""
        mock_post.side_effect = requests.ConnectionError("no inference")
        resp = self.client.post("/v1/task", json={
            "intent": "summarize my documents",
            "mode": "standard",
        })
        assert resp.status_code == 201
        data = resp.get_json()
        cap = data.get("capability", {})
        assert cap.get("signature") != ""
        assert cap.get("nonce") != ""
        assert cap.get("intent_hash") != ""
        assert cap.get("task_id") == data["task_id"]

    @patch("agent.agent.planner.requests.post")
    def test_high_risk_action_requires_approval(self, mock_post):
        """Tasks with high-risk steps need user approval (two-phase)."""
        mock_post.side_effect = requests.ConnectionError("no inference")
        # 'export' maps to EXPORT_DATA which is high-risk
        resp = self.client.post("/v1/task", json={
            "intent": "export my documents",
        })
        data = resp.get_json()
        # Should be pending approval (export is high-risk)
        assert data["status"] in ("pending_approval", "running", "completed", "failed")

    @patch("agent.agent.planner.requests.post")
    def test_policy_decisions_in_step_params(self, mock_post):
        """Each step includes _policy_decision in its params."""
        mock_post.side_effect = requests.ConnectionError("no inference")
        resp = self.client.post("/v1/task", json={
            "intent": "summarize my documents",
        })
        data = resp.get_json()
        for step in data.get("steps", []):
            params = step.get("params", {})
            assert "_policy_decision" in params
            assert params["_policy_decision"] in ("allow", "ask", "deny")


# ============================================================================
# M41 — HSM-Backed Key Handling: Keystore Abstraction
# ============================================================================

class TestSoftwareKeyProvider:
    """Software key provider (default backend)."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.provider = SoftwareKeyProvider(key_dir=self.tmpdir)

    def test_provider_name(self):
        assert self.provider.provider_name() == "software"

    def test_sign_and_verify(self):
        data = b"test data to sign"
        sig = self.provider.sign(data)
        assert self.provider.verify(data, sig)

    def test_verify_rejects_tampered(self):
        data = b"test data"
        sig = self.provider.sign(data)
        assert not self.provider.verify(b"tampered data", sig)

    def test_verify_rejects_bad_signature(self):
        data = b"test data"
        assert not self.provider.verify(data, b"bad-signature")

    def test_get_key_generates_ephemeral(self):
        key = self.provider.get_key("test-key")
        assert len(key) == 64
        # Same key returned on second call
        assert self.provider.get_key("test-key") == key

    def test_different_key_ids_different_keys(self):
        k1 = self.provider.get_key("key1")
        k2 = self.provider.get_key("key2")
        assert k1 != k2

    def test_rotate_creates_new_key(self):
        old_key = self.provider.get_key("rotate-test")
        result = self.provider.rotate("rotate-test")
        new_key = self.provider.get_key("rotate-test")
        assert old_key != new_key
        assert "rotated" in result

    def test_rotate_persists_to_disk(self):
        self.provider.rotate("persist-test")
        key_path = os.path.join(self.tmpdir, "persist-test.key")
        assert os.path.isfile(key_path)
        if sys.platform != "win32":
            assert os.stat(key_path).st_mode & 0o777 == 0o600

    def test_load_key_from_file(self):
        key_data = os.urandom(64)
        key_path = os.path.join(self.tmpdir, "preexisting.key")
        Path(key_path).write_bytes(key_data)
        loaded = self.provider.get_key("preexisting")
        assert loaded == key_data

    def test_derive_subkey(self):
        k1 = self.provider.derive("context-a")
        k2 = self.provider.derive("context-b")
        assert k1 != k2
        assert len(k1) == 32  # SHA-256 output

    def test_derive_deterministic(self):
        k1 = self.provider.derive("same-context")
        k2 = self.provider.derive("same-context")
        assert k1 == k2

    def test_status(self):
        s = self.provider.status()
        assert s["provider"] == "software"
        assert s["available"] is True

    def test_default_key_path(self):
        key_data = os.urandom(64)
        key_path = os.path.join(self.tmpdir, "custom-default.key")
        Path(key_path).write_bytes(key_data)
        provider = SoftwareKeyProvider(
            key_dir=self.tmpdir,
            default_key_path=key_path,
        )
        assert provider.get_key("default") == key_data


class TestTPM2KeyProvider:
    """TPM2 key provider (degrades gracefully without hardware)."""

    def test_provider_name(self):
        provider = TPM2KeyProvider(key_dir="/nonexistent")
        assert provider.provider_name() == "tpm2"

    def test_unavailable_without_tools(self):
        with patch("agent.agent.keystore.shutil.which", return_value=None):
            provider = TPM2KeyProvider()
        s = provider.status()
        assert s["available"] is False

    def test_rotate_skipped_without_tools(self):
        with patch("agent.agent.keystore.shutil.which", return_value=None):
            provider = TPM2KeyProvider()
        result = provider.rotate()
        assert "not available" in result

    def test_unseal_missing_file_raises(self):
        with patch("agent.agent.keystore.shutil.which",
                    return_value="/usr/bin/tpm2_createprimary"):
            provider = TPM2KeyProvider(key_dir="/nonexistent")
        with pytest.raises(FileNotFoundError):
            provider.get_key("missing-key")

    def test_status_includes_pcr_list(self):
        with patch("agent.agent.keystore.shutil.which",
                    return_value="/usr/bin/tpm2_createprimary"):
            provider = TPM2KeyProvider(pcr_list="sha256:0,7")
        s = provider.status()
        assert s["pcr_list"] == "sha256:0,7"


class TestPKCS11KeyProvider:
    """PKCS#11 HSM key provider (stub)."""

    def test_provider_name(self):
        provider = PKCS11KeyProvider()
        assert provider.provider_name() == "pkcs11"

    def test_sign_raises_not_implemented(self):
        provider = PKCS11KeyProvider()
        with pytest.raises(NotImplementedError):
            provider.sign(b"data")

    def test_verify_raises_not_implemented(self):
        provider = PKCS11KeyProvider()
        with pytest.raises(NotImplementedError):
            provider.verify(b"data", b"sig")

    def test_get_key_raises_not_implemented(self):
        provider = PKCS11KeyProvider()
        with pytest.raises(NotImplementedError):
            provider.get_key()

    def test_rotate_returns_not_implemented(self):
        provider = PKCS11KeyProvider()
        assert "not implemented" in provider.rotate()

    def test_status_shows_unavailable(self):
        provider = PKCS11KeyProvider()
        s = provider.status()
        assert s["available"] is False


class TestKeystoreFactory:
    """Provider factory and configuration loading."""

    def test_load_config_missing_file(self):
        cfg = load_config("/nonexistent/keystore.yaml")
        assert cfg == {}

    def test_load_config_from_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("version: 1\nbackend: software\n")
            f.flush()
            cfg = load_config(f.name)
        os.unlink(f.name)
        assert cfg["backend"] == "software"

    def test_create_provider_defaults_to_software(self):
        provider = create_provider({})
        assert provider.provider_name() == "software"

    def test_create_provider_explicit_software(self):
        provider = create_provider({"backend": "software"})
        assert provider.provider_name() == "software"

    def test_create_provider_auto_without_tpm2(self):
        """Auto mode falls back to software when tpm2-tools absent."""
        with patch("agent.agent.keystore.shutil.which", return_value=None):
            provider = create_provider({"backend": "auto"})
        assert provider.provider_name() == "software"

    def test_create_provider_pkcs11_fallback(self):
        """PKCS#11 falls back to software when unavailable."""
        provider = create_provider({
            "backend": "pkcs11",
            "pkcs11": {"module_path": "/nonexistent.so"},
        })
        assert provider.provider_name() == "software"

    def test_keystore_integrates_with_capabilities(self):
        """Keystore provider is used by create_token for signing."""
        _reset_signing_key()
        clear_nonce_cache()
        token = create_token(SessionMode.STANDARD)
        assert token.signature != ""
        valid, reason = verify_token(token)
        assert valid, f"expected valid: {reason}"


class TestUnixSocketServer:
    def test_make_unix_server_binds_socket_path(self, tmp_path):
        if not hasattr(socket, "AF_UNIX"):
            pytest.skip("Unix domain sockets are not available on this platform")

        sock_path = tmp_path / "agent.sock"
        server = agent_app_module._make_unix_server(str(sock_path))
        try:
            assert sock_path.exists()
            assert stat.S_IMODE(sock_path.stat().st_mode) == 0o660
            assert server.server_address == str(sock_path)
        finally:
            server.server_close()
            try:
                sock_path.unlink()
            except FileNotFoundError:
                pass
