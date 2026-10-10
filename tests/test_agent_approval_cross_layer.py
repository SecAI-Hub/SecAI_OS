"""Actual UI proxy -> Unix HTTP -> agent handlers, with synthetic plans only."""
import os
from pathlib import Path
import sys
import tempfile
import threading
from unittest.mock import Mock

import pytest
from werkzeug.serving import make_server

os.environ.setdefault('AGENT_TASK_STATE_PATH', '')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'services/ui'))
from agent.agent import app as agent_api
from agent.agent.capabilities import clear_nonce_cache
from agent.agent.models import Step, StepAction, StepStatus
from agent.agent.planner import Planner
from agent.agent.task_store import TaskStore
from ui import app as ui

PROPOSED = '<script>synthetic & exact</script>\n<>&\u202e'
TARGET = '/var/lib/secure-ai/vault/outputs/exact&target.txt'


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_api, "_require_runtime_assurance", lambda: None)
    clear_nonce_cache()
    monkeypatch.setattr(agent_api, '_tasks', {})
    monkeypatch.setattr(agent_api, '_task_store', TaskStore(tmp_path / 'history.json'))
    monkeypatch.setattr(agent_api, '_audit', None)
    agent_api._containment_frozen.clear()
    token = tmp_path / 'synthetic-token'
    token.write_text('s' * 32)
    token.chmod(0o600)
    monkeypatch.setenv('AGENT_UI_TOKEN_PATH', str(token))
    monkeypatch.setenv('AGENT_TOKEN_PATH', str(token))
    monkeypatch.setattr(ui._auth, 'is_configured', lambda: True)
    monkeypatch.setattr(ui._auth, 'validate_session', lambda *args, **kwargs: True)
    monkeypatch.setattr(ui, '_ui_audit', ui.AuditChain(tmp_path / 'ui-audit.jsonl'))
    monkeypatch.setattr(agent_api._planner, 'plan', lambda *args, **kwargs: [Step(
        action=StepAction.OVERWRITE_FILE, description='Replace this concrete file',
        params={'path': TARGET, 'content': PROPOSED})])
    scheduled = []
    monkeypatch.setattr(agent_api, '_schedule_execution', lambda task: scheduled.append(task) or True)
    # No TCP listener, model call, production file operation or worker execution.
    with tempfile.TemporaryDirectory(prefix='agent-review-') as directory:
        socket_path = str(Path(directory) / 'agent.sock')
        server = make_server('unix://' + socket_path, 0, agent_api.app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        monkeypatch.setattr(ui, 'AGENT_SOCKET', socket_path)
        try:
            with ui.app.test_client() as client:
                client.environ_base['HTTP_AUTHORIZATION'] = 'Bearer synthetic-ui-session'
                yield client, scheduled
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            assert not thread.is_alive()


def submit(client):
    response = client.post('/api/agent/task', json={'intent': 'Overwrite the selected synthetic output', 'workspace': ['outputs']})
    assert response.status_code == 201, response.get_json()
    task = response.get_json()
    assert task['status'] == 'pending_approval'
    shown = client.get('/api/agent/task/' + task['task_id']).get_json()
    assert shown['steps'][0]['params']['content'] == PROPOSED
    assert shown['steps'][0]['params']['path'] == TARGET
    step_id = shown['steps'][0]['step_id']
    return shown, {'step_ids': [step_id], 'expected_plan_revision': shown['plan_revision'],
                   'step_hashes': {step_id: shown['step_hashes'][step_id]}}


def test_exact_review_reaches_real_handler_and_preserves_execution_binding(boundary):
    client, scheduled = boundary
    shown, decision = submit(client)
    response = client.post('/api/agent/task/' + shown['task_id'] + '/approve', json=decision)
    assert response.status_code == 200, response.get_json()
    assert len(scheduled) == 1
    task = scheduled[0]
    assert task.steps[0].status == StepStatus.APPROVED
    assert task.steps[0].params['content'] == PROPOSED
    assert task.steps[0].params['path'] == TARGET
    assert agent_api.verify_step_signature(task.steps[0], task.capability, task.steps[0].signature)[0]
    assert shown['approval_scope']['readable_paths'] == task.capability.readable_paths
    assert shown['approval_scope']['writable_paths'] == task.capability.writable_paths
    assert shown['approval_scope']['allow_online'] == task.capability.allow_online
    assert shown['approval_budgets'] == task.budgets.limits_dict() == task.capability.budget_limits
    assert client.post('/api/agent/task/' + shown['task_id'] + '/approve', json=decision).status_code == 409
    assert len(scheduled) == 1


@pytest.mark.parametrize('change', ['content', 'scope', 'budget'])
@pytest.mark.parametrize('action', ['approve', 'deny'])
def test_changed_review_rejected_across_real_http_boundary_without_scheduling(boundary, change, action):
    client, scheduled = boundary
    shown, decision = submit(client)
    task = agent_api._tasks[shown['task_id']]
    with task.runtime_lock:
        if change == 'content':
            task.steps[0].params['content'] = 'Changed proposed bytes'
        elif change == 'scope':
            task.capability.writable_paths.append('/different/scope')
        else:
            task.budgets.max_tokens += 1
    response = client.post('/api/agent/task/' + shown['task_id'] + '/' + action, json=decision)
    assert response.status_code == 409
    assert response.json['code'] == 'stale_review'
    assert task.steps[0].status == StepStatus.PENDING
    assert scheduled == []


def test_unsupported_task_and_history_empty_delete_use_actual_backend_contract(boundary, monkeypatch):
    client, scheduled = boundary
    planner = Planner(agent_api._policy)
    planner._plan_via_llm = Mock(side_effect=AssertionError('no inference for unavailable action'))
    monkeypatch.setattr(agent_api, '_planner', planner)
    response = client.post('/api/agent/task', json={'intent': 'invoke a tool'})
    assert response.status_code == 400
    planner._plan_via_llm.assert_not_called()
    assert scheduled == []
    modes = client.get('/api/agent/modes').json['modes']
    assert all('tool_invoke' not in [entry['action'] for entry in mode['actions']] for mode in modes)
    assert client.get('/api/agent/history/policy').json['storage_policy'] == 'metadata_only'
    deleted = client.delete('/api/agent/history')
    assert deleted.status_code == 200, deleted.json
    assert deleted.json['deleted'] == 0
