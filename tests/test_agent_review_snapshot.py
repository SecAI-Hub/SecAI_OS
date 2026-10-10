"""Review identity and truthful action discovery, independent of HTTP handlers."""
import copy
import json
from unittest.mock import Mock

import pytest
import requests

from agent.agent import executor as executor_module
from agent.agent import planner as planner_module
from agent.agent.action_catalog import action_catalog, implemented_actions
from agent.agent.approval import approval_snapshot
from agent.agent.executor import Executor
from agent.agent.models import Budgets, CapabilityToken, SessionMode, Step, StepAction, StepStatus, Task
from agent.agent.planner import ActionUnavailable, Planner
from agent.agent.policy import PolicyEngine
from agent.agent.storage import StorageGateway


@pytest.fixture
def proposal():
    task = Task(intent='Replace a synthetic document')
    task.capability = CapabilityToken(readable_paths=['/synthetic/docs'], writable_paths=['/synthetic/outputs'],
                                     expires_at=2000000000, budget_limits=task.budgets.limits_dict())
    task.steps = [Step(action=StepAction.OVERWRITE_FILE, description='Save the summary',
                       params={'path': '/synthetic/outputs/a.txt', 'content': 'exact bytes & <markup>',
                               '_policy_decision': 'ask', '_policy_reason': 'Explicit review required'})]
    return task


@pytest.mark.parametrize('key', ['path', 'content', 'url', 'method', 'body', 'nested', '_policy_decision', '_policy_reason'])
def test_review_identity_binds_every_material_parameter(proposal, key):
    before = approval_snapshot(proposal)
    proposal.steps[0].params[key] = {'changed': ['a', 'b']} if key == 'nested' else 'changed'
    after = approval_snapshot(proposal)
    assert before['plan_revision'] != after['plan_revision']
    assert before['step_hashes'] != after['step_hashes']


@pytest.mark.parametrize('field', ['readable_paths', 'writable_paths', 'allowed_tools', 'allow_online',
                                   'expires_at', 'configurable_prefs', 'policy_digest', 'budget_limits'])
def test_review_identity_binds_effective_authority(proposal, field):
    before = approval_snapshot(proposal)
    cap = proposal.capability
    old = getattr(cap, field)
    new = old + ['/new/scope'] if isinstance(old, list) else {'changed': 1} if isinstance(old, dict) else not old if isinstance(old, bool) else old + 1 if isinstance(old, (int, float)) else old + 'changed'
    setattr(cap, field, new)
    after = approval_snapshot(proposal)
    assert before['plan_revision'] != after['plan_revision']
    assert before['step_hashes'] != after['step_hashes']


def test_review_identity_is_detached_from_runtime_and_never_publishes_authenticators(proposal):
    before = approval_snapshot(proposal)
    proposal.steps[0].status = StepStatus.COMPLETED
    proposal.steps[0].result = {'text': 'result'}
    proposal.steps[0].error = 'runtime error'
    proposal.steps[0].signature = 'internal-step-signature'
    proposal.capability.signature = 'internal-capability-signature'
    proposal.capability.nonce = 'internal-nonce'
    proposal.budgets.tokens_used += 3
    assert before == approval_snapshot(proposal)
    assert 'internal-' not in json.dumps(before)
    proposal.capability.readable_paths.append('/changed')
    assert before['approval_scope']['readable_paths'] == ['/synthetic/docs']


def test_same_description_cannot_hide_another_target_or_content(proposal):
    proposal.steps.append(Step(action=proposal.steps[0].action, description=proposal.steps[0].description,
                               params={'path': '/synthetic/outputs/b.txt', 'content': 'different bytes'}))
    snapshot = approval_snapshot(proposal)
    assert len(set(snapshot['step_hashes'].values())) == 2
    proposal.budgets.max_tokens += 1
    assert snapshot['plan_revision'] != approval_snapshot(proposal)['plan_revision']


def test_capability_session_mode_is_bound_independently_of_task_label(proposal):
    before = approval_snapshot(proposal)
    proposal.capability.session_mode = SessionMode.SENSITIVE
    assert before['plan_revision'] != approval_snapshot(proposal)['plan_revision']


@pytest.mark.parametrize('value', [float('nan'), float('inf'), object(), {1: 'non-string key'}])
def test_noncanonical_material_cannot_receive_an_approval_identity(proposal, value):
    proposal.steps[0].params['invalid'] = value
    with pytest.raises(ValueError):
        approval_snapshot(proposal)


def test_duplicate_ids_fail_closed(proposal):
    proposal.steps.append(copy.deepcopy(proposal.steps[0]))
    with pytest.raises(ValueError, match='duplicate'):
        approval_snapshot(proposal)


@pytest.mark.parametrize('intent', ['invoke the tool', 'run the shell command', 'use a tool', 'export documents', 'share this file', 'delete all files'])
def test_unavailable_workflow_is_rejected_before_model_planning(intent):
    planner = Planner(PolicyEngine())
    planner._plan_via_llm = Mock(side_effect=AssertionError('must not call inference'))
    with pytest.raises(ActionUnavailable):
        planner.plan(intent, CapabilityToken())
    planner._plan_via_llm.assert_not_called()


@pytest.mark.parametrize('action', sorted(set(StepAction) - implemented_actions(), key=lambda item: item.value))
def test_unexecutable_model_action_is_rejected_instead_of_advertised_or_run(action):
    planner = Planner(PolicyEngine())
    planner._plan_via_llm = Mock(return_value=[Step(action=action)])
    with pytest.raises(ActionUnavailable):
        planner.plan('A synthetic supported task', CapabilityToken())
    assert all(action.value not in [entry['action'] for entry in action_catalog(mode.value)] for mode in SessionMode)


def test_prompt_and_catalog_gate_network_and_omit_unavailable_tools(monkeypatch):
    prompts = []
    def completion(*args, **kwargs):
        prompts.append(kwargs['json']['prompt'])
        return object()
    monkeypatch.setattr(planner_module.inference_http, 'post', completion)
    monkeypatch.setattr(planner_module.inference_http, 'read_json', lambda response: {'content': '[]'})
    planner = Planner(PolicyEngine())
    for mode in SessionMode:
        cap = CapabilityToken(session_mode=mode, allow_online=mode == SessionMode.ONLINE_ASSISTED)
        planner._plan_via_llm('Summarize supplied text', cap, 5)
        prompt = prompts[-1]
        assert 'tool_invoke' not in prompt
        assert 'export_data' not in prompt
        assert ('outbound_request' in prompt) == cap.allow_online
        assert ('outbound_request' in [entry['action'] for entry in action_catalog(mode.value)]) == cap.allow_online


@pytest.mark.parametrize('action', sorted(implemented_actions(), key=lambda item: item.value))
def test_every_advertised_action_can_complete_its_executor_contract(tmp_path, monkeypatch, action):
    source = tmp_path / 'source.txt'
    source.write_text('Synthetic source text')
    destination = tmp_path / 'result.txt'
    if action == StepAction.OVERWRITE_FILE:
        destination.write_text('Previous synthetic bytes')
    cap = CapabilityToken(readable_paths=[str(tmp_path)], writable_paths=[str(tmp_path)], allow_online=True)
    executor = Executor(StorageGateway(vault_root=str(tmp_path)))
    prompts = []
    def infer(prompt, budgets):
        prompts.append(prompt)
        return {'ok': True, 'text': 'Synthetic generated result'}
    monkeypatch.setattr(executor, '_inference_completion', infer)
    reply = requests.Response()
    reply.status_code = 200
    reply._content = b'Synthetic network response'
    reply._content_consumed = True
    request = Mock(return_value=reply)
    monkeypatch.setattr(executor_module.requests, 'post', request)
    monkeypatch.setattr(executor_module, '_service_headers', lambda target: {'Authorization': 'Bearer synthetic-airlock'})
    params = {
        StepAction.LOCAL_SEARCH: {'path': str(tmp_path)},
        StepAction.SUMMARIZE: {'path': str(source)},
        StepAction.DRAFT: {'instruction': 'Draft synthetic text', 'path': str(destination)},
        StepAction.CLASSIFY: {'content': 'Synthetic technical content', 'categories': ['technical']},
        StepAction.REPORT: {'instruction': 'Report on source', 'sources': [str(source)], 'path': str(destination)},
        StepAction.EXPLAIN_SECURITY: {'context': 'A synthetic policy decision'},
        StepAction.READ_FILE: {'path': str(source)},
        StepAction.WRITE_FILE: {'path': str(destination), 'content': 'Exact proposed bytes'},
        StepAction.OVERWRITE_FILE: {'path': str(destination), 'content': 'Exact proposed bytes'},
        StepAction.OUTBOUND_REQUEST: {'url': 'https://example.invalid/synthetic', 'method': 'GET'},
    }[action]
    step = executor.execute(Step(action=action, params=params), cap, Budgets())
    assert step.status == StepStatus.COMPLETED, step.error
    assert step.result['ok'] is True
    if action in {StepAction.WRITE_FILE, StepAction.OVERWRITE_FILE}:
        assert destination.read_text() == 'Exact proposed bytes'
    elif action in {StepAction.DRAFT, StepAction.REPORT}:
        assert destination.read_text() == step.result['text'] == 'Synthetic generated result'
        assert step.result['saved_to'] == str(destination)
    elif action == StepAction.READ_FILE:
        assert step.result['content'] == 'Synthetic source text'
    elif action == StepAction.LOCAL_SEARCH:
        assert any(entry['name'] == source.name for entry in step.result['files'])
    elif action == StepAction.OUTBOUND_REQUEST:
        assert request.call_args.kwargs['json']['destination'] == 'https://example.invalid/synthetic'
        assert step.result['content'] == 'Synthetic network response'
    else:
        assert step.result['text'] == 'Synthetic generated result'
    if prompts and action in {StepAction.SUMMARIZE, StepAction.REPORT}:
        assert 'Synthetic source text' in prompts[0]
