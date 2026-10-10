"""Synthetic history privacy, retention, restart, fault and API contracts."""
from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

os.environ.setdefault('AGENT_TASK_STATE_PATH', '')
import agent.agent.task_store as history
from agent.agent import app as api
from agent.agent.models import (
    SessionMode,
    Step,
    StepAction,
    StepStatus,
    Task,
    TaskStatus,
)
from agent.agent.task_store import HistoryPolicy, TaskStore, history_policy_from_config


@pytest.fixture
def backend(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "_require_runtime_assurance", lambda: None)
    store = TaskStore(tmp_path / 'history' / 'tasks.json', ttl_seconds=3600)
    monkeypatch.setattr(api, '_task_store', store)
    monkeypatch.setattr(api, '_tasks', {})
    monkeypatch.setattr(api, '_audit', None)
    api._containment_frozen.clear()
    token = tmp_path / 'ui.token'
    token.write_text('u' * 32)
    token.chmod(0o600)
    other = tmp_path / 'containment.token'
    other.write_text('c' * 32)
    other.chmod(0o600)
    monkeypatch.setenv('AGENT_UI_TOKEN_PATH', str(token))
    monkeypatch.setenv('AGENT_CONTAINMENT_TOKEN_PATH', str(other))
    client = api.app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = 'Bearer ' + 'u' * 32
    return store, client


def finished(*, mode=SessionMode.STANDARD, age=0):
    secret = 'opaque-private-value-under-ordinary-keys'
    return Task(intent=secret, mode=mode, status=TaskStatus.COMPLETED,
                created_at=time.time() - age, completed_at=time.time() - age,
                steps=[Step(action=StepAction.READ_FILE, status=StepStatus.COMPLETED,
                            description=secret, params={secret: secret, 'instruction': secret, 'path': secret,
                                                       'sources': [{'url': secret}], '_policy_decision': 'allow'},
                            result={'output': {'arbitrary': [secret]}, 'file': secret}, error=secret)])


@pytest.mark.parametrize('mode', list(SessionMode))
@pytest.mark.parametrize('raw_enabled', [False, True])
def test_all_modes_and_logging_preferences_persist_only_metadata(tmp_path, mode, raw_enabled):
    store = TaskStore(tmp_path / 'tasks.json', policy=HistoryPolicy(store_raw_prompts=raw_enabled, store_raw_responses=raw_enabled))
    task = finished(mode=mode)
    original = task.to_dict()
    assert store.save([task])
    for path in tmp_path.iterdir():
        if path.is_file():
            assert b'opaque-private-value-under-ordinary-keys' not in path.read_bytes()
    assert task.to_dict()['steps'][0]['result'] == original['steps'][0]['result']
    record = json.loads(store.path.read_text())['tasks'][0]
    assert set(record) == history._TASK_FIELDS
    assert set(record['steps'][0]) == history._STEP_FIELDS
    assert record['steps'][0]['decision'] == 'allow'
    assert not {'intent', 'description', 'params', 'result', 'error', 'capability'} & set(record)
    restored = TaskStore(store.path).load()[task.task_id]
    assert restored.history_only is True
    assert restored.intent == ''
    assert restored.capability is None
    assert restored.steps[0].signature == ''
    assert restored.steps[0].result is None


def test_arbitrary_nested_keys_and_values_are_not_serialized(tmp_path):
    task = finished(mode=SessionMode.SENSITIVE)
    secret = 'nested-unrecognized-marker'
    nested = {secret: [{'url': secret, 'instruction': secret}]}
    for _ in range(30):
        nested = {secret: [nested]}
    task.steps[0].params = {'anything': nested}
    task.steps[0].result = {'anything': nested}
    store = TaskStore(tmp_path / 'tasks.json')
    assert store.save([task])
    assert secret.encode() not in store.path.read_bytes()


@pytest.mark.parametrize('status', [TaskStatus.PLANNING, TaskStatus.PENDING_APPROVAL, TaskStatus.RUNNING])
def test_restart_never_restores_executable_active_work(tmp_path, status):
    task = finished()
    task.status = status
    task.completed_at = None
    task.steps[0].status = StepStatus.APPROVED
    store = TaskStore(tmp_path / 'tasks.json')
    assert store.save([task])
    restored = TaskStore(store.path).load()[task.task_id]
    assert restored.status == TaskStatus.RECOVERY_REQUIRED
    assert restored.history_only and restored.capability is None
    assert restored.steps[0].status == StepStatus.FAILED
    assert api._schedule_execution(restored) is False
    assert api._verify_task_capability(restored)[0] is False


@pytest.mark.parametrize('version', [1, 99, True])
def test_legacy_or_unknown_schema_is_never_loaded_or_overwritten(tmp_path, version):
    path = tmp_path / 'tasks.json'
    raw = json.dumps({'version': version, 'tasks': [{'intent': 'old-raw-private-content'}]}).encode()
    path.write_bytes(raw)
    path.chmod(0o660)
    store = TaskStore(path)
    assert store.load() == {}
    assert store.blocked and not store.healthy
    assert not store.save([finished()])
    assert path.read_bytes() == raw
    assert not list(tmp_path.glob('*.bak'))


def test_version_two_unknown_content_fields_fail_before_exposure(tmp_path):
    store = TaskStore(tmp_path / 'tasks.json')
    assert store.save([finished()])
    payload = json.loads(store.path.read_text())
    payload['tasks'][0]['intent'] = 'injected-raw-private-content'
    store.path.write_text(json.dumps(payload))
    raw = store.path.read_bytes()
    fresh = TaskStore(store.path)
    assert fresh.load() == {}
    assert fresh.blocked
    assert not fresh.save([])
    assert store.path.read_bytes() == raw


def test_count_and_age_pruning_preserve_active_runtime_objects(backend):
    store, client = backend
    store.max_tasks = 1
    active = finished(age=7200)
    active.status = TaskStatus.RUNNING
    active.completed_at = None
    old = finished(age=7200)
    recent, newest = finished(age=100), finished()
    api._tasks.update({item.task_id: item for item in [active, old, recent, newest]})
    response = client.get('/v1/tasks').get_json()
    assert {item['task_id'] for item in response['tasks']} == {active.task_id, newest.task_id}
    assert api._tasks[active.task_id] is active
    records = json.loads(store.path.read_text())['tasks']
    assert len(records) == 1 and records[0]['task_id'] == newest.task_id


def test_startup_physically_prunes_expired_records(tmp_path, monkeypatch):
    store = TaskStore(tmp_path / 'tasks.json', ttl_seconds=60)
    task = finished()
    assert store.save([task])
    later = task.created_at + 61
    monkeypatch.setattr(history.time, 'time', lambda: later)
    fresh = TaskStore(store.path, ttl_seconds=60)
    assert fresh.load() == {}
    assert json.loads(store.path.read_text())['tasks'] == []
    assert task.task_id.encode() not in store.path.read_bytes()


@pytest.mark.parametrize(('saved_ttl', 'current_ttl'), [(60, 600), (600, 60)])
def test_restore_expiry_is_bounded_by_saved_expiry_and_current_policy(tmp_path, monkeypatch, saved_ttl, current_ttl):
    store = TaskStore(tmp_path / 'tasks.json', ttl_seconds=saved_ttl)
    task = finished()
    assert store.save([task])
    monkeypatch.setattr(history.time, 'time', lambda: task.created_at + 61)
    assert TaskStore(store.path, ttl_seconds=current_ttl).load() == {}


@pytest.mark.parametrize('jump', [-1000, float('nan'), float('inf'), 0])
def test_bad_or_reversed_clock_cannot_expose_old_history(tmp_path, monkeypatch, jump):
    store = TaskStore(tmp_path / 'tasks.json', ttl_seconds=60)
    task = finished()
    assert store.save([task])
    changed = task.created_at + jump if jump == -1000 else jump
    monkeypatch.setattr(history.time, 'time', lambda: changed)
    fresh = TaskStore(store.path)
    assert fresh.load() == {}
    assert not fresh.healthy


def test_small_clock_regression_never_reduces_persisted_high_water(tmp_path, monkeypatch):
    store = TaskStore(tmp_path / 'tasks.json')
    task = finished()
    assert store.save([task])
    first = json.loads(store.path.read_text())['updated_at']
    monkeypatch.setattr(history.time, 'time', lambda: first - 10)
    assert store.save([task])
    assert json.loads(store.path.read_text())['updated_at'] == first


@pytest.mark.parametrize('value', ['false', 0, 1, None, [], {}])
def test_logging_privacy_flags_must_be_actual_booleans(tmp_path, value):
    config = tmp_path / 'appliance.yaml'
    config.write_text(json.dumps({'logging': {'store_raw_prompts': value}}))
    config.chmod(0o644)
    with pytest.raises(ValueError):
        history_policy_from_config(config, environ={})


@pytest.mark.parametrize('variable,value', [('AGENT_TASK_HISTORY_LIMIT', '0'), ('AGENT_TASK_HISTORY_LIMIT', 'true'),
                                           ('AGENT_TASK_HISTORY_LIMIT', '5001'), ('AGENT_TASK_HISTORY_TTL_SECONDS', 'nan'),
                                           ('AGENT_TASK_HISTORY_TTL_SECONDS', '59'), ('AGENT_TASK_HISTORY_TTL_SECONDS', '2592001')])
def test_retention_environment_is_bounded_and_strict(tmp_path, variable, value):
    config = tmp_path / 'config.yaml'
    config.write_text('{}')
    config.chmod(0o644)
    with pytest.raises(ValueError):
        history_policy_from_config(config, environ={variable: value})


def test_explicit_missing_or_unsafe_configuration_does_not_fall_back(tmp_path):
    config = tmp_path / 'missing.yaml'
    with pytest.raises(ValueError):
        history_policy_from_config(config, environ={})
    config.write_text('{}')
    config.chmod(0o666)
    with pytest.raises(ValueError):
        history_policy_from_config(config, environ={})


def test_policy_api_describes_effective_history(backend):
    store, client = backend
    data = client.get('/v1/history/policy').get_json()
    assert data['storage_policy'] == 'metadata_only'
    assert data['raw_content_persisted'] is False
    assert data['ttl_seconds'] == 3600
    assert data['restart_behavior'] == 'metadata_only_not_executable'
    assert data['history_ready'] is True


def test_terminal_delete_is_durable_and_never_deletes_active_work(backend):
    store, client = backend
    active, done = finished(), finished()
    active.status = TaskStatus.PENDING_APPROVAL
    active.completed_at = None
    api._tasks.update({item.task_id: item for item in [active, done]})
    assert api._persist_tasks()
    assert client.delete(f'/v1/history/{active.task_id}').status_code == 409
    response = client.delete(f'/v1/history/{done.task_id}')
    assert response.status_code == 200
    assert response.get_json()['deleted'] == 1
    assert done.task_id not in api._tasks
    assert done.task_id not in TaskStore(store.path).load()
    assert active.task_id in api._tasks
    assert client.delete('/v1/history').get_json()['deleted'] == 0


def test_clear_history_excludes_terminal_task_with_running_step(backend):
    _, client = backend
    task = finished()
    task.steps[0].status = StepStatus.RUNNING
    api._tasks[task.task_id] = task
    assert client.delete('/v1/history').get_json() == {'deleted': 0, 'active_remaining': 1,
                                                     'external_backups_deleted': False, 'audit_evidence_deleted': False}
    assert task.task_id in api._tasks


def test_clear_history_drops_finished_memory_and_store(backend):
    store, client = backend
    tasks = [finished(), finished()]
    api._tasks.update({item.task_id: item for item in tasks})
    assert api._persist_tasks()
    response = client.delete('/v1/history')
    assert response.status_code == 200 and response.get_json()['deleted'] == 2
    assert api._tasks == {}
    assert TaskStore(store.path).load() == {}


@pytest.mark.parametrize('authorization', [None, 'Bearer wrong', 'Bearer ' + 'c' * 32])
def test_history_delete_requires_ui_task_control_credential(backend, authorization):
    _, _ = backend
    client = api.app.test_client()
    headers = {'Authorization': authorization} if authorization else {}
    assert client.delete('/v1/history', headers=headers).status_code == 401


def test_history_delete_requires_no_unvalidated_body_or_query(backend):
    _, client = backend
    assert client.delete('/v1/history', json={'active': True}).status_code == 400
    assert client.delete('/v1/history?all=true').status_code == 400


def test_delete_failure_never_claims_committed_deletion(backend, monkeypatch):
    store, client = backend
    task = finished()
    api._tasks[task.task_id] = task
    assert api._persist_tasks()
    monkeypatch.setattr(store, 'save', lambda _: False)
    response = client.delete(f'/v1/history/{task.task_id}')
    assert response.status_code == 503 and response.get_json()['deleted'] == 0
    assert api._tasks[task.task_id] is task


def test_inflight_snapshot_cannot_resurrect_a_successful_delete(backend, monkeypatch):
    store, client = backend
    task = finished()
    api._tasks[task.task_id] = task
    assert api._persist_tasks()
    entered, release = threading.Event(), threading.Event()
    original = store.save
    def pause(tasks):
        if threading.current_thread().name == 'old-save':
            entered.set()
            assert release.wait(5)
        return original(tasks)
    monkeypatch.setattr(store, 'save', pause)
    writer = threading.Thread(target=api._persist_tasks, name='old-save')
    writer.start()
    assert entered.wait(5)
    outcome = []
    deletion = threading.Thread(target=lambda: outcome.append(client.delete(f'/v1/history/{task.task_id}').status_code))
    deletion.start()
    release.set()
    writer.join(5)
    deletion.join(5)
    assert outcome == [200]
    assert not writer.is_alive() and not deletion.is_alive()
    assert TaskStore(store.path).load() == {}


@pytest.mark.parametrize('fault', ['file_fsync', 'replace', 'directory_fsync'])
def test_atomic_write_fault_preserves_valid_metadata_and_signals_failure(tmp_path, monkeypatch, fault):
    store = TaskStore(tmp_path / 'tasks.json')
    task = finished()
    assert store.save([task])
    with monkeypatch.context() as patch:
        def fail(*_args):
            raise OSError(errno.ENOSPC, 'synthetic write fault')
        if fault == 'replace':
            patch.setattr(history.os, 'replace', fail)
        else:
            original = history.os.fsync
            calls = []
            def fsync(fd):
                calls.append(fd)
                if fault == 'file_fsync' or len(calls) == 2:
                    fail()
                return original(fd)
            patch.setattr(history.os, 'fsync', fsync)
        assert store.save([]) is False
        assert not store.healthy
    payload = json.loads(store.path.read_text())
    assert payload['version'] == 2
    assert b'opaque-private-value' not in store.path.read_bytes()
    assert not list(tmp_path.glob('.*.tmp'))
    fresh = TaskStore(store.path)
    fresh.load()
    assert fresh.healthy


def test_external_history_replacement_is_not_silently_overwritten(tmp_path):
    store = TaskStore(tmp_path / 'tasks.json')
    assert store.save([finished()])
    store.path.write_text('{"version":1,"private":"preserve-this-raw-state"}')
    raw = store.path.read_bytes()
    assert not store.save([])
    assert store.path.read_bytes() == raw


@pytest.mark.parametrize('damage', ['symlink', 'hardlink', 'fifo', 'world_readable', 'truncated'])
def test_unsafe_or_corrupt_state_is_not_exposed(tmp_path, damage):
    store = TaskStore(tmp_path / 'tasks.json')
    assert store.save([finished()])
    if damage == 'world_readable':
        store.path.chmod(0o664)
    elif damage == 'truncated':
        store.path.write_text('{')
    elif damage == 'hardlink':
        os.link(store.path, tmp_path / 'alias')
    else:
        store.path.rename(tmp_path / 'saved')
        if damage == 'symlink':
            store.path.symlink_to(tmp_path / 'saved')
        else:
            os.mkfifo(store.path)
    fresh = TaskStore(store.path)
    assert fresh.load() == {}
    assert fresh.blocked


def test_abandoned_metadata_temporary_is_removed_but_raw_legacy_temp_is_preserved(tmp_path):
    store = TaskStore(tmp_path / 'tasks.json')
    assert store.save([finished()])
    temporary = tmp_path / ('.tasks.json.123.' + 'a' * 16 + '.tmp')
    temporary.write_bytes(store.path.read_bytes())
    temporary.chmod(0o660)
    assert TaskStore(store.path).load()
    assert not temporary.exists()
    temporary.write_text('{"version":1,"intent":"old-raw"}')
    temporary.chmod(0o660)
    fresh = TaskStore(store.path)
    assert fresh.load() == {}
    assert temporary.exists() and 'old-raw' in temporary.read_text()


def test_actual_process_restart_never_retrieves_content(tmp_path):
    store = TaskStore(tmp_path / 'tasks.json')
    task = finished(mode=SessionMode.SENSITIVE)
    assert store.save([task])
    program = '''import json, sys
from agent.agent.task_store import TaskStore
store = TaskStore(sys.argv[1])
print(json.dumps({key: value.to_dict() for key,value in store.load().items()}))
assert store.healthy
'''
    completed = subprocess.run([sys.executable, '-c', program, str(store.path)], env=dict(os.environ, PYTHONPATH='services'), capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    assert 'opaque-private-value' not in completed.stdout
    assert json.loads(completed.stdout)[task.task_id]['history_only'] is True


def test_application_backup_does_not_collect_agent_history():
    root = Path(__file__).resolve().parents[1]
    backup = (root / 'files/system/usr/libexec/secure-ai/secai-backup.sh').read_text()
    assert '"${SECURE_AI_ROOT}/agent"' not in backup
    assert 'tasks.json' not in backup


def test_idle_retention_worker_prunes_expired_history(backend):
    store, client = backend
    task = finished(age=7200)
    api._tasks[task.task_id] = task
    class Stop:
        count = 0
        def wait(self, interval):
            assert interval == 60
            self.count += 1
            return self.count > 1
    old = api._history_reaper_stop
    api._history_reaper_stop = Stop()
    try:
        api._history_retention_worker()
    finally:
        api._history_reaper_stop = old
    assert task.task_id not in api._tasks
    assert json.loads(store.path.read_text())['tasks'] == []


def test_retention_keeps_work_whose_step_is_still_running(backend):
    _, client = backend
    task = finished(age=7200)
    task.steps[0].status = StepStatus.RUNNING
    api._tasks[task.task_id] = task
    assert client.get(f'/v1/task/{task.task_id}').status_code == 200
    assert api._tasks[task.task_id] is task


def test_duplicate_generated_ids_cannot_create_an_unloadable_store(tmp_path):
    store = TaskStore(tmp_path / 'tasks.json')
    task = finished()
    assert not store.save([task, task])
    assert not store.path.exists()


def test_abrupt_exit_before_replace_leaves_only_metadata_and_no_deletion_ack(tmp_path):
    store = TaskStore(tmp_path / 'tasks.json')
    task = finished(mode=SessionMode.SENSITIVE)
    assert store.save([task])
    program = '''import os, sys
import agent.agent.task_store as history
store = history.TaskStore(sys.argv[1])
assert store.load()
def crash(*args):
    os._exit(73)
history.os.replace = crash
store.save([])
'''
    completed = subprocess.run([sys.executable, '-c', program, str(store.path)], env=dict(os.environ, PYTHONPATH='services'), capture_output=True, text=True, timeout=10)
    assert completed.returncode == 73
    assert list(tmp_path.glob('.*.tmp'))
    for path in tmp_path.iterdir():
        if path.is_file():
            assert b'opaque-private-value' not in path.read_bytes()
    fresh = TaskStore(store.path)
    assert task.task_id in fresh.load()
    assert not list(tmp_path.glob('.*.tmp'))
    assert fresh.healthy


def test_huge_timestamp_is_rejected_without_parser_crash(tmp_path):
    store = TaskStore(tmp_path / 'tasks.json')
    assert store.save([finished()])
    payload = json.loads(store.path.read_text())
    payload['updated_at'] = 10**1000
    store.path.write_text(json.dumps(payload))
    fresh = TaskStore(store.path)
    assert fresh.load() == {}
    assert not fresh.healthy


def test_long_running_task_gets_full_retention_when_it_finishes(backend):
    store, client = backend
    task = finished(age=7200)
    task.status = TaskStatus.RUNNING
    task.completed_at = None
    api._tasks[task.task_id] = task
    assert api._persist_tasks()
    assert task.task_id in api._tasks
    task.status = TaskStatus.COMPLETED
    task.completed_at = time.time()
    assert api._persist_tasks()
    shown = client.get(f'/v1/task/{task.task_id}').get_json()
    assert shown['content_available'] is True
    assert shown['steps'][0]['result'] == task.steps[0].result
    assert shown['history_expires_at'] >= task.completed_at + store.ttl_seconds
    assert task.task_id in TaskStore(store.path, ttl_seconds=store.ttl_seconds).load()


def test_fresh_agent_process_exposes_only_nonexecutable_history(tmp_path):
    store = TaskStore(tmp_path / 'tasks.json')
    task = finished(mode=SessionMode.SENSITIVE)
    assert store.save([task])
    token = tmp_path / 'token'
    token.write_text('u' * 32)
    token.chmod(0o600)
    program = '''import json, sys
from agent.agent import app as api
client = api.app.test_client()
client.environ_base['HTTP_AUTHORIZATION'] = 'Bearer ' + 'u' * 32
shown = client.get('/v1/tasks').get_json()
assert len(shown['tasks']) == 1
record = shown['tasks'][0]
assert record['history_only'] and record['content_available'] is False
for action in ('approve', 'deny', 'cancel'):
    assert client.post('/v1/task/' + record['task_id'] + '/' + action, json={}).status_code == 409
print(json.dumps(shown))
'''
    env = dict(os.environ, PYTHONPATH='services', AGENT_TASK_STATE_PATH=str(store.path),
               AUDIT_LOG_PATH=str(tmp_path / 'audit.jsonl'), AGENT_UI_TOKEN_PATH=str(token),
               AGENT_POLICY_PATH=str(tmp_path / 'policy.yaml'), VAULT_ROOT=str(tmp_path / 'vault'))
    completed = subprocess.run([sys.executable, '-c', program], env=env, capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    assert 'opaque-private-value' not in completed.stdout


@pytest.mark.parametrize('field', ['created_at', 'completed_at', 'expires_at'])
@pytest.mark.parametrize('value', [float('nan'), float('inf'), -1, 10**30])
def test_untrusted_nonfinite_or_out_of_range_timestamps_cannot_extend_history(tmp_path, field, value):
    store = TaskStore(tmp_path / 'tasks.json', ttl_seconds=60)
    assert store.save([finished()])
    payload = json.loads(store.path.read_text())
    payload['tasks'][0][field] = value
    store.path.write_text(json.dumps(payload))
    fresh = TaskStore(store.path, ttl_seconds=60)
    assert fresh.load() == {}
    assert fresh.blocked


@pytest.mark.parametrize('field', ['created_at', 'completed_at'])
def test_record_timestamp_cannot_be_later_than_its_persisted_observation(tmp_path, field):
    store = TaskStore(tmp_path / 'tasks.json', ttl_seconds=60)
    assert store.save([finished()])
    payload = json.loads(store.path.read_text())
    payload['tasks'][0][field] = payload['updated_at'] + 1
    store.path.write_text(json.dumps(payload))
    fresh = TaskStore(store.path, ttl_seconds=60)
    assert fresh.load() == {}
    assert fresh.blocked


@pytest.mark.parametrize('invalid_completion', ['before_creation', 'nonterminal'])
def test_inconsistent_completion_blocks_restore_without_replacing_state(tmp_path, invalid_completion):
    store = TaskStore(tmp_path / 'tasks.json', ttl_seconds=60)
    assert store.save([finished()])
    payload = json.loads(store.path.read_text())
    record = payload['tasks'][0]
    if invalid_completion == 'before_creation':
        record['completed_at'] = record['created_at'] - 1
    else:
        record['status'] = TaskStatus.RUNNING.value
    original = json.dumps(payload)
    store.path.write_text(original)
    fresh = TaskStore(store.path, ttl_seconds=60)
    assert fresh.load() == {}
    assert fresh.blocked
    assert not fresh.save([])
    assert store.path.read_text() == original


@pytest.mark.parametrize('invalid_completion', ['before_creation', 'nonterminal'])
def test_inconsistent_completion_cannot_be_saved(tmp_path, invalid_completion):
    store = TaskStore(tmp_path / 'tasks.json', ttl_seconds=60)
    assert store.save([finished()])
    original = store.path.read_bytes()
    task = finished()
    if invalid_completion == 'before_creation':
        task.completed_at = task.created_at - 1
    else:
        task.status = TaskStatus.RUNNING
    assert not store.save([task])
    assert not store.healthy
    assert store.path.read_bytes() == original


@pytest.mark.parametrize('status', [TaskStatus.COMPLETED, TaskStatus.CANCELLED, TaskStatus.FAILED])
def test_all_terminal_results_share_completion_retention(backend, status):
    store, client = backend
    task = finished(age=7200)
    task.status = status
    task.completed_at = time.time()
    api._tasks[task.task_id] = task
    assert api._persist_tasks()
    shown = client.get(f'/v1/task/{task.task_id}').get_json()
    assert shown['steps'][0]['result'] == task.steps[0].result
    assert shown['history_expires_at'] == task.completed_at + store.ttl_seconds
