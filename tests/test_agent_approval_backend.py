"""Backend approval decisions are bound to the exact previously displayed plan."""
from __future__ import annotations

import copy
import os

import pytest

os.environ.setdefault('AGENT_TASK_STATE_PATH', '')
from agent.agent import app as api
from agent.agent.capabilities import clear_nonce_cache
from agent.agent.models import Step, StepAction, StepStatus, TaskStatus
from agent.agent.task_store import TaskStore


@pytest.fixture
def pending(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "_require_runtime_assurance", lambda: None)
    clear_nonce_cache()
    monkeypatch.setattr(api, '_tasks', {})
    monkeypatch.setattr(api, '_task_store', TaskStore(tmp_path / 'tasks.json'))
    monkeypatch.setattr(api, '_audit', None)
    api._containment_frozen.clear()
    token = tmp_path / 'token'
    token.write_text('u' * 32)
    token.chmod(0o600)
    monkeypatch.setenv('AGENT_UI_TOKEN_PATH', str(token))
    monkeypatch.setattr(api._planner, 'plan', lambda *args, **kwargs: [Step(
        action=StepAction.READ_FILE, description='Read the selected document',
        params={'path': '/var/lib/secure-ai/vault/user_docs/example.txt'})])
    client = api.app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = 'Bearer ' + 'u' * 32
    response = client.post('/v1/task', json={'intent': 'read a synthetic document', 'workspace': ['user_docs']})
    assert response.status_code == 201
    shown = response.get_json()
    assert shown['status'] == 'pending_approval'
    task = api._tasks[shown['task_id']]
    identifiers = [item['step_id'] for item in shown['steps']]
    body = {'step_ids': identifiers, 'expected_plan_revision': shown['plan_revision'],
            'step_hashes': {key: shown['step_hashes'][key] for key in identifiers}}
    calls = []
    monkeypatch.setattr(api, '_schedule_execution', lambda task: calls.append(task.task_id) or True)
    return client, task, body, calls


@pytest.mark.parametrize('method', ['approve', 'deny'])
@pytest.mark.parametrize('change', ['path', 'content', 'url', 'description', 'read_scope', 'write_scope', 'tools',
                                    'online', 'expiry', 'budget', 'cap_budget', 'preferences', 'policy_reason'])
def test_stale_material_plan_cannot_change_any_step_or_schedule(pending, method, change):
    client, task, body, calls = pending
    step = task.steps[0]
    if change in {'path', 'content', 'url'}:
        step.params[change] = 'changed-material-value'
    elif change == 'description':
        step.description = 'different operation'
    elif change == 'read_scope':
        task.capability.readable_paths.append('/new/read/scope')
    elif change == 'write_scope':
        task.capability.writable_paths.append('/new/write/scope')
    elif change == 'tools':
        task.capability.allowed_tools.append('new-tool')
    elif change == 'online':
        task.capability.allow_online = not task.capability.allow_online
    elif change == 'expiry':
        task.capability.expires_at += 1
    elif change == 'budget':
        task.budgets.max_steps += 1
    elif change == 'cap_budget':
        task.capability.budget_limits['max_steps'] += 1
    elif change == 'preferences':
        task.capability.configurable_prefs['read_file'] = 'always'
    else:
        step.params['_policy_reason'] = 'different policy basis'
    response = client.post(f'/v1/task/{task.task_id}/{method}', json=body)
    assert response.status_code == 409
    assert response.get_json()['code'] == 'stale_review'
    assert task.status == TaskStatus.PENDING_APPROVAL
    assert step.status == StepStatus.PENDING
    assert calls == []


@pytest.mark.parametrize('change,code', [('missing_revision', 409), ('missing_hashes', 409), ('wrong_hash', 409),
                                       ('extra_hash', 400), ('bad_revision', 400), ('empty_ids', 400),
                                       ('duplicate_ids', 400), ('legacy_all', 400)])
def test_missing_or_invalid_review_is_rejected_without_side_effects(pending, change, code):
    client, task, body, calls = pending
    if change == 'missing_revision':
        body.pop('expected_plan_revision')
    elif change == 'missing_hashes':
        body.pop('step_hashes')
    elif change == 'wrong_hash':
        body['step_hashes'][task.steps[0].step_id] = '0' * 64
    elif change == 'extra_hash':
        body['step_hashes']['f' * 12] = '0' * 64
    elif change == 'bad_revision':
        body['expected_plan_revision'] = True
    elif change == 'empty_ids':
        body['step_ids'] = []
    elif change == 'duplicate_ids':
        body['step_ids'] *= 2
    else:
        body['approve_all'] = True
    response = client.post(f'/v1/task/{task.task_id}/approve', json=body)
    assert response.status_code == code
    assert calls == []
    assert task.steps[0].status == StepStatus.PENDING


def test_exact_review_approves_once_and_preserves_signature_checks(pending):
    client, task, body, calls = pending
    response = client.post(f'/v1/task/{task.task_id}/approve', json=body)
    assert response.status_code == 200
    assert calls == [task.task_id]
    assert client.post(f'/v1/task/{task.task_id}/approve', json=body).status_code == 409
    assert calls == [task.task_id]


def test_fresh_snapshot_does_not_authorize_a_tampered_signature(pending):
    client, task, body, calls = pending
    task.steps[0].signature = '0' * 64
    response = client.post(f'/v1/task/{task.task_id}/approve', json=body)
    assert response.status_code == 409
    assert calls == []


def test_runtime_result_changes_do_not_invalidate_immutable_review(pending):
    client, task, body, calls = pending
    before = copy.deepcopy(body)
    task.steps[0].result = {'output': 'runtime diagnostic'}
    task.steps[0].error = 'runtime diagnostic'
    current = client.get(f'/v1/task/{task.task_id}').get_json()
    assert current['plan_revision'] == before['expected_plan_revision']
    assert current['steps'][0]['approval_hash'] == before['step_hashes'][task.steps[0].step_id]
    assert current['approval_scope']['readable_paths'] == task.capability.readable_paths
    assert current['approval_budgets'] == task.budgets.limits_dict()


def test_historical_metadata_cannot_be_approved_denied_or_cancelled(pending):
    client, task, body, calls = pending
    task.history_only = True
    for operation in ('approve', 'deny', 'cancel'):
        response = client.post(f'/v1/task/{task.task_id}/{operation}', json=body)
        assert response.status_code == 409
    assert calls == []
