"""Producer schema and authenticated-read boundaries for assurance display."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from unittest.mock import Mock

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'services/ui'))
from ui import app as ui
from ui import assurance

NOW = 1_800_000_000.0


def stamp(value=NOW):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


@pytest.mark.parametrize('field,value', [('schema_version', None), ('schema_version', 1), ('schema_version', True), ('gpu', None), ('gpu', {})])
def test_old_or_missing_gpu_bundle_cannot_display_trust(producers, field, value):
    producers['attestor']['bundle'][field] = value
    assert assurance.attestation(producers['attestor'], NOW)['passing'] is False


def test_gpu_scope_freshness_and_bootstrap_cannot_replace_runtime(producers):
    gpu = {'mode': 'required', 'policy_satisfied': True}
    for name in ('bootstrap', 'runtime'):
        gpu[name] = {'scope': name, 'status': 'verified', 'authenticated': True, 'verified': True,
                     'max_age_seconds': 600, 'max_cycle_seconds': 60,
                     'evidence': {'schema_version': 1, 'scope': name, 'availability': 'complete',
                                  'snapshot': {'started_at': stamp(NOW-10), 'completed_at': stamp(), 'verdict': 'healthy'}}}
    producers['attestor']['bundle']['gpu'] = gpu
    assert assurance.attestation(producers['attestor'], NOW)['passing'] is True
    gpu['runtime']['evidence']['snapshot']['started_at'] = stamp(NOW-601)
    assert assurance.attestation(producers['attestor'], NOW)['passing'] is False
    gpu['runtime'] = gpu['bootstrap']
    assert assurance.attestation(producers['attestor'], NOW)['passing'] is False


@pytest.mark.parametrize('field,value', [('mode', 'missing'), ('policy_satisfied', False), ('runtime', None)])
def test_cpu_enrollment_is_explicit_not_missing_gpu(producers, field, value):
    producers['attestor']['bundle']['gpu'][field] = value
    assert assurance.attestation(producers['attestor'], NOW)['passing'] is False


@pytest.fixture
def producers():
    bundle = {
        'schema_version': 2, 'state': 'attested', 'timestamp': stamp(), 'assurance_mode': 'hardware',
        'gpu': {'mode': 'no_gpu', 'policy_satisfied': True, **{
            name: {'scope': name, 'status': 'not_applicable', 'authenticated': False, 'verified': False, 'evidence': None}
            for name in ('bootstrap', 'runtime')}},
        'evidence_verified': True, 'deployment_verified': True, 'release_baseline_verified': True,
        'tpm_available': True, 'tpm_measurements_verified': True, 'tpm_quote_verified': True,
        'boot_measurements': {'secure_boot_enabled': True, 'measured_at': stamp()},
        'service_digests': {'service': 'a' * 64}, 'release_source_commit': 'b' * 40,
        'deployment_digest': 'c' * 64, 'policy_digest': 'd' * 64, 'registry_manifest_hash': 'e' * 64,
        'tpm_ak_public_key_sha256': 'f' * 64, 'bundle_hmac': '1' * 64,
    }
    return {
        'attestor': {'state': 'attested', 'bundle': bundle},
        'integrity_monitor': {'state': 'trusted', 'watched_files': 1, 'violation_count': 0, 'last_scan_at': stamp(),
                              'scan_count': 1, 'degraded_count': 0, 'recovery_count': 0},
        'incidents': {'total_incidents': 0, 'open_incidents': 0, 'contained_count': 0, 'resolved_count': 0,
                      'by_class': {}, 'open_by_severity': {}},
    }


@pytest.fixture
def client(monkeypatch, producers):
    monkeypatch.setattr(ui._auth, 'is_configured', lambda: True)
    monkeypatch.setattr(ui._auth, 'validate_session', lambda *args, **kwargs: True)
    monkeypatch.setattr(ui, '_is_sandbox_deployment', lambda: False)
    monkeypatch.setattr(ui.time, 'time', lambda: NOW)
    monkeypatch.setattr(ui, '_read_service_token', lambda target: 's' * 32)
    def fetch(url, token):
        assert token == 's' * 32
        name = 'attestor' if '/attest' in url else 'incidents' if '/stats' in url else 'integrity_monitor'
        return assurance.decode_json(json.dumps(producers[name]).encode())
    monkeypatch.setattr(assurance, 'authenticated_get', fetch)
    with ui.app.test_client() as client:
        client.environ_base['HTTP_AUTHORIZATION'] = 'Bearer synthetic-session'
        yield client


def test_positive_state_is_fresh_authenticated_producer_report_not_signature_verification(client):
    response = client.get('/api/observability/appliance-state')
    data = response.json
    assert response.status_code == 200
    assert data['appliance_state'] == 'reported_healthy'
    assert data['basis'] == 'authenticated_producer_reports'
    assert data['ui_verified_attestation_signature'] is False
    assert data['valid_until'] == NOW + 30
    assert all(item['authenticated_read'] is True and item['passing'] is True for item in data['evidence'].values())
    assert data['subsystems']['incidents']['total_open'] == 0
    assert 'no-store' in response.headers['Cache-Control']


@pytest.mark.parametrize('value', [None, [], {}, {'state': None}, {'state': []}, {'state': 'unexpected'},
                                   {'state': 'attested'}, {'state': 'trusted'}])
def test_missing_or_malformed_attestation_never_passes(client, producers, value):
    producers['attestor'] = value
    data = client.get('/api/observability/appliance-state').json
    assert data['appliance_state'] not in {'trusted', 'reported_healthy'}
    assert data['evidence']['attestor']['passing'] is False


@pytest.mark.parametrize('field,value', [
    ('timestamp', stamp(NOW-601)), ('timestamp', stamp(NOW+1)), ('timestamp', 'not a date'),
    ('assurance_mode', 'evaluation'), ('assurance_mode', 'future-mode'), ('evidence_verified', False),
    ('evidence_verified', 'true'), ('deployment_verified', None), ('release_baseline_verified', 1),
    ('tpm_quote_verified', False), ('tpm_measurements_verified', False), ('tpm_available', False),
    ('service_digests', {}), ('service_digests', {'service': 'bad'}), ('bundle_hmac', None),
    ('boot_measurements', {}), ('failures', ['known failure']), ('release_source_commit', 'a'*41),
])
def test_required_attestation_evidence_is_not_inferred(client, producers, field, value):
    producers['attestor']['bundle'][field] = value
    data = client.get('/api/observability/appliance-state').json
    assert data['appliance_state'] not in {'trusted', 'reported_healthy'}
    assert data['evidence']['attestor']['passing'] is False


@pytest.mark.parametrize('field,value', [
    ('state', None), ('state', 'future-state'), ('scan_count', 0), ('watched_files', 0),
    ('watched_files', True), ('scan_count', -1), ('last_scan_at', stamp(NOW-121)),
    ('last_scan_at', stamp(NOW+1)), ('violation_count', 1), ('active_violations', [{}]),
])
def test_integrity_requires_real_fresh_samples_without_violations(client, producers, field, value):
    producers['integrity_monitor'][field] = value
    data = client.get('/api/observability/appliance-state').json
    assert data['appliance_state'] not in {'trusted', 'reported_healthy'}
    assert data['evidence']['integrity_monitor']['passing'] is False


@pytest.mark.parametrize('payload', [
    {}, {'open_incidents': 0}, {'open_incidents': True, 'open_by_severity': {}},
    {'open_incidents': 1, 'open_by_severity': {}}, {'open_incidents': 0, 'open_by_severity': {'critical': 1}},
    {'open_incidents': 0, 'open_by_severity': {'future-severity': 0}},
    {'open_incidents': 0, 'open_by_severity': {'high': -1}},
])
def test_missing_incident_severities_are_zero_only_with_valid_total_relationship(client, producers, payload):
    producers['incidents'].update(payload)
    if not payload:
        producers['incidents'] = {}
    elif payload == {'open_incidents': 0}:
        producers['incidents'] = payload
    data = client.get('/api/observability/appliance-state').json
    assert data['evidence']['incidents']['passing'] is False
    assert data['evidence']['incidents'].get('total_open') is None


def test_decisive_integrity_failure_remains_visible_when_other_evidence_is_unavailable(client, producers):
    producers['attestor'] = {}
    producers['integrity_monitor']['state'] = 'recovery_required'
    data = client.get('/api/observability/appliance-state').json
    assert data['appliance_state'] == 'recovery_required'
    assert data['evidence']['integrity_monitor']['status'] == 'recovery_required'


def test_sandbox_cannot_claim_host_evidence_or_query_host_monitors(client, monkeypatch):
    monkeypatch.setattr(ui, '_is_sandbox_deployment', lambda: True)
    monkeypatch.setattr(assurance, 'authenticated_get', Mock(side_effect=AssertionError('no host probe')))
    data = client.get('/api/observability/appliance-state').json
    assert data['appliance_state'] == 'evaluation'
    assert all(item['passing'] is False for item in data['evidence'].values())


def test_snapshot_does_not_extend_nearly_expired_required_evidence(producers):
    producers['integrity_monitor']['last_scan_at'] = stamp(NOW-119)
    evidence = {'attestor': assurance.attestation(producers['attestor'], NOW),
                'integrity_monitor': assurance.integrity(producers['integrity_monitor'], NOW),
                'incidents': assurance.incidents(producers['incidents'], NOW)}
    for item in evidence.values():
        item['authenticated_read'] = True
    assert assurance.aggregate(evidence, NOW, sandbox=False)['valid_until'] == NOW+1
    assert assurance.aggregate(evidence, NOW+2, sandbox=False)['appliance_state'] == 'degraded'


@pytest.mark.parametrize('token', ['', 'short', 'a b'*12, 'é'*32, 'x'*513])
def test_unsafe_or_missing_credential_never_opens_an_http_session(monkeypatch, token):
    session = Mock(side_effect=AssertionError('no session'))
    monkeypatch.setattr(assurance.requests, 'Session', session)
    with pytest.raises(assurance.EvidenceUnavailable):
        assurance.authenticated_get('http://127.0.0.1:8505/api/v1/attest', token)
    session.assert_not_called()


@pytest.mark.parametrize('status', [200, 301, 302, 307, 401, 403, 500])
def test_authentication_redirect_and_body_validation_close_the_response(monkeypatch, status):
    response = requests.Response()
    response.status_code = status
    response.headers['Content-Type'] = 'application/json'
    response._content = b'{"state":"pending"}'
    response._content_consumed = True
    response.close = Mock()
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    session.get.return_value = response
    monkeypatch.setattr(assurance.requests, 'Session', lambda: session)
    if status == 200:
        assert assurance.authenticated_get('http://127.0.0.1:8505/api/v1/attest', 's'*32) == {'state': 'pending'}
    else:
        with pytest.raises(assurance.EvidenceUnavailable):
            assurance.authenticated_get('http://127.0.0.1:8505/api/v1/attest', 's'*32)
    assert session.trust_env is False
    assert session.get.call_args.kwargs['allow_redirects'] is False
    assert session.get.call_args.kwargs['headers']['Authorization'] == 'Bearer '+'s'*32
    response.close.assert_called_once()


@pytest.mark.parametrize('raw', [b'null', b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":"\\ud800"}', b'x'*(assurance.MAX_BYTES+1)])
def test_invalid_json_never_becomes_security_evidence(raw):
    with pytest.raises(assurance.EvidenceUnavailable):
        assurance.decode_json(raw)


@pytest.mark.parametrize('checked,status', [(0, 'no_samples'), (1, 'checked')])
def test_model_hash_report_does_not_turn_no_models_into_verified(checked, status):
    report = assurance.model_integrity({'status': 'ok', 'models_checked': checked, 'failures': 0, 'checked_at': stamp()}, NOW)
    assert report['status'] == status
    assert report['passing'] is (checked > 0)

BOOT = '12345678-1234-1234-1234-123456789abc'


def network_report(scope='offline'):
    return {'schema_version': 1, 'boot_id': BOOT, 'checked_at': stamp(), 'valid_until': stamp(NOW+30),
            'checked_monotonic': 100.0, 'valid_for_seconds': 30.0, 'status': 'verified', 'effective_scope': scope,
            'host_offline': scope == 'offline', 'ipv4_enforced': True, 'ipv6_enforced': True, 'arp_enforced': True,
            'lease_expires_at': None if scope == 'offline' else stamp(NOW+3600),
            'allowed_egress': list(assurance.NETWORK_EGRESS[scope]), 'automatic_network_tasks': False,
            'evidence_source': 'nftables_runtime'}


@pytest.mark.parametrize('scope', ['offline', 'research', 'full_lab', 'maintenance'])
def test_runtime_network_scope_requires_same_boot_and_actual_lease(scope):
    data = assurance.network(network_report(scope), BOOT, NOW, 101)
    assert data['status'] == 'verified'
    assert data['host_offline'] is (scope == 'offline')
    assert data['valid_until'] == NOW+29
    assert data['effective_scope'] == scope


@pytest.mark.parametrize('field,value', [
    ('schema_version', True), ('boot_id', 'another boot'), ('checked_at', stamp(NOW-31)),
    ('checked_at', stamp(NOW+1)), ('valid_until', stamp(NOW)), ('valid_until', stamp(NOW+31)),
    ('checked_monotonic', 200), ('checked_monotonic', 69), ('checked_monotonic', True),
    ('valid_for_seconds', None), ('valid_for_seconds', 31), ('valid_for_seconds', float('inf')),
    ('status', 'unknown'), ('status', None), ('host_offline', 'true'), ('effective_scope', 'offline_private'),
    ('ipv4_enforced', None), ('ipv6_enforced', False), ('arp_enforced', 'true'),
    ('automatic_network_tasks', True), ('lease_expires_at', stamp(NOW+10)),
    ('allowed_egress', ['arbitrary network destination']), ('evidence_source', 'selected_profile'),
])
def test_missing_stale_or_inconsistent_firewall_evidence_never_establishes_offline(field, value):
    data = network_report()
    data[field] = value
    result = assurance.network(data, BOOT, NOW, 100)
    assert result['passing'] is False
    assert result['host_offline'] is None


@pytest.mark.parametrize('scope', ['research', 'full_lab', 'maintenance'])
def test_expired_or_mismatched_network_lease_cannot_pass(scope):
    data = network_report(scope)
    data['lease_expires_at'] = stamp(NOW-1)
    assert assurance.network(data, BOOT, NOW, 100)['passing'] is False
    data = network_report(scope)
    data['allowed_egress'] = assurance.NETWORK_EGRESS['research'] if scope != 'research' else []
    assert assurance.network(data, BOOT, NOW, 100)['passing'] is False


def test_profile_label_alone_never_establishes_network_isolation(client, monkeypatch):
    monkeypatch.setattr(ui, '_read_active_profile', lambda: ('offline_private', False))
    monkeypatch.setattr(assurance, 'read_root_json', Mock(side_effect=assurance.EvidenceUnavailable('unavailable')))
    response = client.get('/api/profile')
    assert response.json['active'] == 'offline_private'
    assert response.json['network_assurance']['host_offline'] is None
    monkeypatch.setattr(ui, '_is_sandbox_deployment', lambda: True)
    assert client.get('/api/profile').json['network_assurance']['status'] == 'not_available'


def test_secure_boot_never_uses_untimestamped_presence_record(client, producers):
    data = client.get('/api/boot/secureboot/status').json
    assert data['enabled'] is True
    assert data['ui_verified_signature'] is False
    producers['attestor']['bundle']['boot_measurements'] = {}
    assert client.get('/api/boot/secureboot/status').json['enabled'] is None


def test_tpm_report_does_not_equate_enrollment_to_successful_hardware_unsealing(client, monkeypatch):
    report = {'schema_version': 1, 'checked_at': stamp(), 'tpm2_available': True, 'enrolled': True,
              'crypttab_tpm2_enabled': True, 'token_count': 1, 'keyslot_count': 2, 'pcr_binding': 'sha256:0,2,4,7', 'assurance': 'pcr_bound'}
    reader = Mock(return_value=report)
    monkeypatch.setattr(assurance, 'read_root_json', reader)
    data = client.get('/api/boot/tpm2/status').json
    assert reader.call_args.args[0] == Path('/run/secure-ai/tpm2-state.json')
    assert data['status'] == 'enrollment_reported'
    assert data['passing'] is False
    assert 'sealed' not in data
    report['checked_at'] = stamp(NOW-2101)
    assert client.get('/api/boot/tpm2/status').json['status'] == 'stale'


def test_audit_requires_authentic_file_and_real_nonempty_coverage(client, monkeypatch):
    reader = Mock(side_effect=assurance.EvidenceUnavailable('unsafe file'))
    monkeypatch.setattr(assurance, 'read_root_json', reader)
    assert client.get('/api/audit/status').json['passing'] is False
    reader.side_effect = None
    reader.return_value = {'status': 'ok', 'ready': True, 'checked_at': stamp(), 'logs_checked': 1, 'failures': 0,
                           'details': [{'valid': True, 'status': 'not_applicable', 'security_class': 'structured-only'}]}
    assert client.get('/api/audit/status').json['status'] == 'no_samples'
    reader.return_value['details'][0]['status'] = 'ok'
    assert client.get('/api/audit/status').json['passing'] is True
    reader.return_value['logs_checked'] = 0
    assert client.get('/api/audit/status').json['passing'] is False


def test_slo_api_never_claims_continuous_compliance_from_browser_samples(client, monkeypatch):
    monkeypatch.setattr(ui._slo_tracker, 'get_all_slos', lambda: [
        {'name': 'registry availability', 'current_value': 'N/A', 'compliant': True},
        {'name': 'web_ui availability', 'current_value': '100.0%', 'compliant': True}])
    data = client.get('/api/observability/slos').json
    assert data['continuous_compliance_verified'] is False
    assert data['slos'][0]['status'] == 'unknown'
    assert data['slos'][0]['observed_target_met'] is None
    assert data['slos'][1]['status'] == 'observation_only'
    assert all(item['compliant'] is None for item in data['slos'])


@pytest.mark.parametrize('headers', [
    {'Content-Encoding': 'gzip'}, {'Content-Encoding': 'br'}, {'Content-Type': 'text/html'},
    {'Content-Length': str(assurance.MAX_BYTES+1)}, {'Content-Length': '-1'},
])
def test_response_limits_apply_before_reading_or_decompressing(monkeypatch, headers):
    response = requests.Response()
    response.status_code = 200
    response.headers.update({'Content-Type': 'application/json', **headers})
    response.close = Mock()
    response.iter_content = Mock(side_effect=AssertionError('body must not be read'))
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    session.get.return_value = response
    monkeypatch.setattr(assurance.requests, 'Session', lambda: session)
    with pytest.raises(assurance.EvidenceUnavailable):
        assurance.authenticated_get('http://127.0.0.1:8505/api/v1/attest', 's'*32)
    assert session.get.call_args.kwargs['headers']['Accept-Encoding'] == 'identity'
    response.close.assert_called_once()
    response.iter_content.assert_not_called()


def test_network_allowances_match_pinned_native_producer():
    import ast
    source = Path(__file__).resolve().parents[1] / 'files/system/usr/libexec/secure-ai/network-profile.py'
    tree = ast.parse(source.read_text())
    values = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
              and isinstance(node.targets[0], ast.Name) and node.targets[0].id in {'ALLOWED', 'FRESHNESS'}}
    assert assurance.NETWORK_EGRESS == values['ALLOWED']
    assert assurance.SNAPSHOT_MAX_AGE == values['FRESHNESS']


def test_appliance_reads_use_distinct_target_credentials(client, monkeypatch, producers):
    tokens = {'attestor': 'a'*32, 'integrity-monitor': 'i'*32, 'incident-recorder': 'r'*32}
    seen = []
    monkeypatch.setattr(ui, '_read_service_token', tokens.__getitem__)
    def fetch(url, token):
        target = 'attestor' if '/attest' in url else 'incident-recorder' if '/stats' in url else 'integrity-monitor'
        seen.append(target)
        assert token == tokens[target]
        return producers[{'attestor':'attestor', 'integrity-monitor':'integrity_monitor', 'incident-recorder':'incidents'}[target]]
    monkeypatch.setattr(assurance, 'authenticated_get', fetch)
    assert client.get('/api/observability/appliance-state').json['appliance_state'] == 'reported_healthy'
    assert seen == ['attestor', 'integrity-monitor', 'incident-recorder']


def test_nonroot_owned_local_file_cannot_authenticate_evidence(tmp_path):
    import os
    if os.getuid() == 0:
        pytest.skip('This boundary requires an ordinary user-owned file; private-root positive coverage runs in the protocol smoke.')
    path = tmp_path / 'untrusted.json'
    path.write_text('{"status":"ok"}')
    path.chmod(0o644)
    with pytest.raises(assurance.EvidenceUnavailable):
        assurance.read_root_json(path)
