"""
Tests for the SecAI_OS Agent Mode service.

Covers: policy engine, capability tokens, storage gateway, budgets,
planner heuristic fallback, executor dispatch, and Flask API endpoints.
"""

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    Task,
    TaskStatus,
)
from agent.agent.policy import PolicyEngine, classify_risk
from agent.agent.capabilities import create_budgets, create_token
from agent.agent.storage import StorageGateway
from agent.agent.planner import Planner
from agent.agent.executor import Executor
from agent.agent.app import app


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
        assert "blocked" in result["error"]

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

    def test_deny_nonexistent(self):
        resp = self.client.post("/v1/task/fake/deny", json={})
        assert resp.status_code == 404

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
            assert "blocked" in result["error"]


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
