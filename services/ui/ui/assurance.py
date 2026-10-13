"""Strict interpretation of local producer reports, not signature verification.

Schemas come from runtime-attestor RuntimeStateBundle, integrity-monitor
StatusResponse, incident-recorder handleStats and integrity-check.sh. Keep
signing keys out of this service. Positive results describe what authenticated
producers report, never an independent verification of their signed evidence.
"""
from datetime import datetime
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from typing import TypeGuard
from urllib.parse import urlsplit

import requests

MAX_BYTES = 262_144
ATTESTATION_MAX_AGE = 600  # shipped producer refreshes every five minutes
INTEGRITY_MAX_AGE = 120  # shipped monitor scans every thirty seconds
MODEL_CHECK_MAX_AGE = 35 * 60
SNAPSHOT_MAX_AGE = 30
HEX64 = re.compile(r'[0-9a-f]{64}')
NETWORK_EGRESS = {
    'offline': [],
    'research': ['DHCP, ARP and IPv6 neighbor discovery', 'Tor service TCP'],
    'full_lab': ['DHCP, ARP and IPv6 neighbor discovery', 'Tor service TCP', 'Airlock service HTTPS and direct DNS'],
    'maintenance': ['DHCP, ARP and IPv6 neighbor discovery', 'Tor service TCP', 'Host HTTPS, DNS and NTP'],
}


class EvidenceUnavailable(ValueError):
    """A fixed public reason; never include a URL, token or exception payload."""


def read_root_json(path: Path) -> dict:
    """Read a root-owned report without following links or trusting its mtime."""
    if not path.is_absolute() or '..' in path.parts:
        raise EvidenceUnavailable('The local evidence path is invalid.')
    directory = None
    descriptor = None
    try:
        directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for component in path.parts[1:-1]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = following
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                or before.st_nlink != 1 or not 0 < before.st_size <= MAX_BYTES):
            raise EvidenceUnavailable('The local evidence file is not safely owned or readable.')
        chunks = []
        remaining = MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise EvidenceUnavailable('The local evidence changed during reading.')
        return decode_json(b''.join(chunks))
    except OSError as error:
        raise EvidenceUnavailable('The local evidence file is unavailable.') from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def decode_json(raw: bytes) -> dict:
    if len(raw) > MAX_BYTES:
        raise EvidenceUnavailable('Security service response exceeds the evidence limit.')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite number')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise EvidenceUnavailable('Security service returned invalid evidence JSON.') from error
    if not isinstance(data, dict):
        raise EvidenceUnavailable('Security service returned an invalid evidence object.')
    pending = [(data, 0)]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > 10_000 or depth > 16:
            raise EvidenceUnavailable('Security service evidence exceeds structural limits.')
        if isinstance(value, dict):
            pending.extend((part, depth + 1) for pair in value.items() for part in pair)
        elif isinstance(value, list):
            pending.extend((part, depth + 1) for part in value)
        elif isinstance(value, str):
            try:
                value.encode('utf-8')
            except UnicodeError as error:
                raise EvidenceUnavailable('Security service returned invalid evidence text.') from error
        elif isinstance(value, float) and not math.isfinite(value):
            raise EvidenceUnavailable('Security service returned invalid evidence numbers.')
    return data


def authenticated_get(url: str, token: str, *, array: bool = False) -> dict:
    """Read only fixed local service URLs with an explicit service credential."""
    parsed = urlsplit(url)
    if (parsed.scheme != 'http' or parsed.hostname not in {
            '127.0.0.1', '::1', 'localhost', 'registry', 'runtime-attestor',
            'integrity-monitor', 'incident-recorder'} or parsed.username or parsed.password or parsed.fragment):
        raise EvidenceUnavailable('The configured security service endpoint is unavailable.')
    if not isinstance(token, str) or not 16 <= len(token) <= 512 or not token.isascii() or any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in token):
        raise EvidenceUnavailable('Security service authentication is unavailable.')
    started = time.monotonic()
    try:
        with requests.Session() as session:
            session.trust_env = False
            with session.get(url, headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json', 'Accept-Encoding': 'identity'},
                             timeout=(2, 3), stream=True, allow_redirects=False) as response:
                if response.status_code != 200:
                    raise EvidenceUnavailable('Security service did not provide an authenticated successful response.')
                media_type = response.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
                if media_type != 'application/json':
                    raise EvidenceUnavailable('Security service returned an invalid evidence content type.')
                if response.headers.get('Content-Encoding', 'identity').strip().lower() != 'identity':
                    raise EvidenceUnavailable('Security service returned unsupported evidence compression.')
                length = response.headers.get('Content-Length')
                if length is not None and (not length.isdecimal() or int(length) > MAX_BYTES):
                    raise EvidenceUnavailable('Security service response exceeds the evidence limit.')
                content = bytearray()
                # A full-buffer iterator can wait indefinitely on a slow
                # trickle. Observe each byte so the elapsed-time check runs
                # even when the peer never fills a larger requested chunk.
                for chunk in response.iter_content(chunk_size=1):
                    if time.monotonic() - started > 5:
                        raise EvidenceUnavailable('Security service evidence read exceeded its deadline.')
                    content.extend(chunk)
                    if len(content) > MAX_BYTES:
                        raise EvidenceUnavailable('Security service response exceeds the evidence limit.')
                if array:
                    wrapped = decode_json(b'{"items":' + bytes(content) + b'}')
                    if not isinstance(wrapped.get('items'), list):
                        raise EvidenceUnavailable('Security service returned an invalid evidence inventory.')
                    return wrapped
                return decode_json(bytes(content))
    except requests.RequestException as error:
        raise EvidenceUnavailable('Security service evidence is unavailable.') from error


def timestamp(value: object) -> float | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        result = parsed.timestamp()
        return result if math.isfinite(result) else None
    except (ValueError, OverflowError, OSError):
        return None


def fresh(value: object, now: float, max_age: float) -> bool:
    parsed = timestamp(value)
    return parsed is not None and math.isfinite(now) and 0 <= now - parsed <= max_age


def count(value: object) -> TypeGuard[int]:
    return type(value) is int and 0 <= value <= 2**53 - 1


def finite_number(value: object) -> TypeGuard[int | float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def result(status: str, detail: str, *, observed_at=None, passing=False, **fields) -> dict:
    return {'status': status, 'passing': passing, 'detail': detail, 'observed_at': observed_at, **fields}


def _gpu_runtime_report_passes(gpu: object, now: float) -> bool:
    if not isinstance(gpu, dict) or gpu.get('policy_satisfied') is not True:
        return False
    mode = gpu.get('mode')
    if not isinstance(mode, str) or mode not in {'required', 'optional', 'no_gpu'}:
        return False
    for name in ('bootstrap', 'runtime'):
        scope = gpu.get(name)
        if not isinstance(scope, dict) or scope.get('scope') != name:
            return False
        if mode == 'no_gpu':
            if (scope.get('status') != 'not_applicable' or scope.get('authenticated') is not False
                    or scope.get('verified') is not False or scope.get('evidence', 'missing') is not None):
                return False
            continue
        if (scope.get('status') != 'verified' or scope.get('authenticated') is not True
                or scope.get('verified') is not True):
            return False
        evidence = scope.get('evidence')
        if (not isinstance(evidence, dict) or evidence.get('scope') != name
                or type(evidence.get('schema_version')) is not int or evidence['schema_version'] != 1
                or evidence.get('availability') != 'complete'):
            return False
        snapshot = evidence.get('snapshot')
        age = scope.get('max_age_seconds')
        duration = scope.get('max_cycle_seconds')
        if (not isinstance(snapshot, dict) or type(age) is not int or not 0 < age <= 600
                or type(duration) is not int or not 0 < duration <= age
                or snapshot.get('verdict') != 'healthy'
                or not fresh(snapshot.get('started_at'), now, age)
                or not fresh(snapshot.get('completed_at'), now, age)):
            return False
        start, end = timestamp(snapshot['started_at']), timestamp(snapshot['completed_at'])
        if start is None or end is None or not 0 <= end - start <= duration:
            return False
    return True


def attestation(data: dict, now: float) -> dict:
    state = data.get('state')
    if state == 'failed':
        return result('failed', 'The authenticated attestor reports a failure.')
    if not isinstance(state, str) or state not in {'attested', 'degraded', 'pending'}:
        return result('unknown', 'Attestor state is missing or invalid.')
    bundle = data.get('bundle')
    if not isinstance(bundle, dict) or bundle.get('state') != state:
        return result('unknown', 'Attestation bundle is absent or inconsistent.')
    if type(bundle.get('schema_version')) is not int or bundle['schema_version'] != 2:
        return result('unverified', 'Current runtime assurance schema is unavailable.')
    observed = bundle.get('timestamp')
    if not fresh(observed, now, ATTESTATION_MAX_AGE):
        return result('stale', 'No fresh attestation report is available.', observed_at=observed if isinstance(observed, str) else None)
    if state != 'attested':
        return result(state, 'The attestor has not reported passing checks.', observed_at=observed)
    if not _gpu_runtime_report_passes(bundle.get('gpu'), now):
        return result('unverified', 'Current GPU runtime policy evidence is unavailable.', observed_at=observed)
    if bundle.get('assurance_mode') == 'evaluation':
        return result('evaluation', 'Evaluation mode does not establish verified hardware evidence.', observed_at=observed)
    verified_flags = ['evidence_verified', 'deployment_verified', 'release_baseline_verified', 'tpm_available',
                      'tpm_measurements_verified', 'tpm_quote_verified']
    measurements = bundle.get('boot_measurements')
    digests = bundle.get('service_digests')
    hashes = ['deployment_digest', 'policy_digest', 'registry_manifest_hash', 'tpm_ak_public_key_sha256', 'bundle_hmac']
    if (bundle.get('assurance_mode') != 'hardware' or any(bundle.get(key) is not True for key in verified_flags)
            or not isinstance(measurements, dict) or measurements.get('secure_boot_enabled') is not True
            or not fresh(measurements.get('measured_at'), now, ATTESTATION_MAX_AGE)
            or not isinstance(digests, dict) or not digests
            or any(not isinstance(name, str) or not name or not isinstance(value, str) or not HEX64.fullmatch(value) for name, value in digests.items())
            or any(not isinstance(bundle.get(key), str) or not HEX64.fullmatch(bundle[key]) for key in hashes)
            or not isinstance(bundle.get('release_source_commit'), str) or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', bundle['release_source_commit'])
            or bundle.get('failures', []) != []):
        return result('unverified', 'Required hardware, deployment or baseline evidence was not reported verified.', observed_at=observed)
    gpu_detail = ('The enrolled CPU policy makes GPU assurance not applicable.' if bundle['gpu']['mode'] == 'no_gpu'
                  else 'The enrolled bootstrap and runtime GPU checks are reported verified.')
    return result('attested', 'The authenticated attestor reports current hardware, deployment and baseline verification. ' + gpu_detail + ' The UI does not independently verify its bundle signature.',
                  observed_at=observed, passing=True, basis='authenticated_producer_report', ui_verified_signature=False)


def integrity(data: dict, now: float) -> dict:
    state = data.get('state')
    if state == 'recovery_required':
        return result('recovery_required', 'The authenticated integrity monitor reports required recovery.')
    if state == 'degraded':
        return result('degraded', 'The authenticated integrity monitor reports degraded integrity.')
    fields = ['watched_files', 'violation_count', 'scan_count', 'degraded_count', 'recovery_count']
    if state != 'trusted' or any(not count(data.get(key)) for key in fields):
        return result('unknown', 'Integrity monitor state or counters are invalid.')
    if data['violation_count'] != 0 or data.get('active_violations', []) != []:
        return result('degraded', 'The integrity report contains violations.')
    if data['watched_files'] == 0 or data['scan_count'] == 0:
        return result('unverified', 'No completed integrity scan with watched files was reported.')
    observed = data.get('last_scan_at')
    if not fresh(observed, now, INTEGRITY_MAX_AGE):
        return result('stale', 'No fresh integrity scan is available.', observed_at=observed if isinstance(observed, str) else None)
    return result('checked', 'The authenticated integrity monitor reports a recent scan without violations.', observed_at=observed, passing=True)


def incidents(data: dict, now: float) -> dict:
    severities = data.get('open_by_severity')
    total = data.get('open_incidents')
    if (not isinstance(severities, dict) or set(severities) - {'critical', 'high', 'medium', 'low'}
            or not count(total) or any(not count(value) for value in severities.values())
            or sum(severities.values()) != total
            or any(not count(data.get(key)) for key in ['total_incidents', 'contained_count', 'resolved_count'])
            or data['total_incidents'] < total):
        return result('unknown', 'Incident counts are missing or inconsistent.', available=False)
    critical, high = severities.get('critical', 0), severities.get('high', 0)
    state = 'recovery_required' if critical else 'degraded' if total else 'checked'
    return result(state, 'Current counts from an authenticated live incident service read; the producer supplies no event timestamp.',
                  passing=total == 0, available=True, total_open=total, open_critical=critical, open_high=high,
                  retrieved_at=now, freshness_basis='live_authenticated_read')


def model_integrity(data: dict, now: float) -> dict:
    status = data.get('status')
    checked, failures = data.get('models_checked'), data.get('failures')
    if status == 'failed' or (count(failures) and failures > 0):
        return result('failed', 'The registry reports model integrity failures.', models_checked=checked if count(checked) else None, failures=failures if count(failures) else None)
    if status != 'ok' or not count(checked) or not count(failures) or failures != 0:
        return result('unknown', 'The model integrity report is unavailable or invalid.')
    if checked == 0:
        return result('no_samples', 'No models were checked; model integrity is not established.', models_checked=0, failures=0)
    observed = data.get('checked_at')
    if not fresh(observed, now, MODEL_CHECK_MAX_AGE):
        return result('stale', 'No fresh model integrity report is available.')
    return result('checked', 'The authenticated registry reports a recent model hash check without failures.',
                  passing=True, observed_at=observed, models_checked=checked, failures=0)


def network(data: dict, boot_id: str, now: float, monotonic_now: float) -> dict:
    """Validate the short-lived same-boot native firewall report, never a profile label."""
    unknown = result('unknown', 'Fresh same-boot runtime firewall evidence is unavailable.', host_offline=None, effective_scope='unknown')
    if (type(data.get('schema_version')) is not int or data['schema_version'] != 1
            or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot_id)
            or data.get('boot_id') != boot_id or data.get('status') != 'verified'
            or data.get('evidence_source') != 'nftables_runtime' or data.get('automatic_network_tasks') is not False):
        return unknown
    checked = timestamp(data.get('checked_at'))
    expires = timestamp(data.get('valid_until'))
    elapsed_start, valid_for = data.get('checked_monotonic'), data.get('valid_for_seconds')
    if (checked is None or expires is None or not 0 <= now - checked <= 30 or not now < expires <= checked + 30
            or not finite_number(elapsed_start) or not finite_number(valid_for)
            or not 0 < valid_for <= 30 or not 0 <= monotonic_now - elapsed_start < valid_for):
        return unknown
    scope = data.get('effective_scope')
    if scope not in ('offline', 'research', 'full_lab', 'maintenance') or any(data.get(key) is not True for key in ('ipv4_enforced', 'ipv6_enforced', 'arp_enforced')):
        return unknown
    destinations = data.get('allowed_egress')
    if destinations != NETWORK_EGRESS[scope]:
        return unknown
    lease = data.get('lease_expires_at')
    if scope == 'offline':
        if data.get('host_offline') is not True or lease is not None or destinations:
            return unknown
        detail = 'Current native firewall rules report host egress blocked; no live egress lease was found.'
    else:
        lease_expiry = timestamp(lease)
        if data.get('host_offline') is not False or lease_expiry is None or not now < expires <= lease_expiry or not destinations:
            return unknown
        detail = 'A finite native egress lease is active. This device is not offline.'
    # A wall clock adjustment must not extend the monotonic lifetime.
    effective_expiry = min(expires, now + valid_for - (monotonic_now - elapsed_start))
    return result('verified', detail, observed_at=data['checked_at'], passing=True,
                  host_offline=data['host_offline'], effective_scope=scope, valid_until=effective_expiry,
                  lease_expires_at=lease, allowed_egress=destinations, basis='root_owned_same_boot_runtime_report')


def audit(data: dict, now: float) -> dict:
    if data.get('status') == 'failed' or data.get('valid') is False or (count(data.get('failures')) and data['failures'] > 0):
        return result('failed', 'The local audit verifier reports failed evidence. Inspect the local report.')
    if data.get('status') == 'checking':
        return result('checking', 'Audit evidence verification is in progress; readiness is not established.')
    details = data.get('details')
    if (data.get('status') != 'ok' or data.get('ready') is not True
            or not count(data.get('logs_checked')) or not count(data.get('failures')) or data['failures'] != 0
            or not isinstance(details, list) or not details or data['logs_checked'] != len(details)):
        return result('unknown', 'Audit verification schema or coverage is incomplete.')
    coverage = {key: 0 for key in ('keyed-tamper-evident', 'unkeyed-hash-linked', 'structured-only', 'not_applicable')}
    for item in details:
        if isinstance(item, dict) and item.get('valid') is False:
            return result('failed', 'The local verifier reports unresolved audit evidence.')
        if not isinstance(item, dict) or item.get('valid') is not True:
            return result('unknown', 'Audit evidence has unresolved coverage.')
        if item.get('status') == 'not_applicable' and item.get('security_class') in coverage:
            coverage['not_applicable'] += 1
        elif item.get('status') == 'ok' and item.get('security_class') in coverage and item['security_class'] != 'not_applicable':
            coverage[item['security_class']] += 1
        else:
            return result('unknown', 'Audit evidence contains an unknown verification or assurance class.')
    if sum(value for key, value in coverage.items() if key != 'not_applicable') == 0:
        return result('no_samples', 'No applicable audit evidence was verified.')
    if not fresh(data.get('checked_at'), now, MODEL_CHECK_MAX_AGE):
        return result('stale', 'No current audit verification report is available. Reports expire after 35 minutes.')
    return result('checked', 'Local verification completed. Syntax and unkeyed linkage do not prove authenticity.',
                  passing=True, observed_at=data['checked_at'], coverage=coverage)


def tpm_enrollment(data: dict, now: float) -> dict:
    """Enrollment is not proof that this boot unsealed a hardware-bound key."""
    fields = ('tpm2_available', 'enrolled', 'crypttab_tpm2_enabled')
    if (type(data.get('schema_version')) is not int or data['schema_version'] != 1
            or any(type(data.get(key)) is not bool for key in fields)
            or any(not count(data.get(key)) for key in ('token_count', 'keyslot_count'))
            or data.get('assurance') not in ('platform_unknown', 'virtual_tpm_host_controlled', 'secure_boot_not_verified', 'pcr_bound', 'not_enrolled')):
        return result('unknown', 'TPM enrollment evidence is missing or invalid.')
    if not fresh(data.get('checked_at'), now, MODEL_CHECK_MAX_AGE):
        return result('stale', 'No recent TPM enrollment inspection is available.')
    if data['assurance'] == 'pcr_bound' and all(data[key] is True for key in fields) and data['token_count'] > 0 and data['keyslot_count'] > 0 and data.get('pcr_binding') == 'sha256:0,2,4,7':
        return result('enrollment_reported', 'The root-owned inspection reports SHA-256 PCR 0, 2, 4, 7 enrollment. This is not proof of successful hardware unsealing on this boot.',
                      observed_at=data['checked_at'], passing=False)
    detail = {'platform_unknown': 'The host type could not be established; hardware TPM assurance is unavailable.',
              'virtual_tpm_host_controlled': 'A virtual TPM is controlled by its host; hardware isolation is not established.',
              'secure_boot_not_verified': 'The enrollment inspection did not verify Secure Boot.',
              'not_enrolled': 'The inspection reports no usable TPM enrollment.'}
    return result('unverified', detail.get(data['assurance'], 'TPM enrollment fields are inconsistent.'), observed_at=data['checked_at'])


def aggregate(evidence: dict, now: float, *, sandbox: bool) -> dict:
    required = ('attestor', 'integrity_monitor', 'incidents')
    evidence = {name: dict(value) for name, value in evidence.items()}
    # Browser clocks expose milliseconds. Rounding down avoids a report
    # appearing to come from the future during same-millisecond local reads.
    snapshot_time = math.floor(now * 1000) / 1000
    valid_until = snapshot_time + SNAPSHOT_MAX_AGE
    for name, age in [('attestor', ATTESTATION_MAX_AGE), ('integrity_monitor', INTEGRITY_MAX_AGE)]:
        item = evidence.get(name, {})
        if item.get('passing') is True:
            observed = timestamp(item.get('observed_at'))
            if observed is None or not 0 <= now - observed <= age:
                item.update(passing=False, status='stale', detail='The producer report is no longer fresh.')
            else:
                valid_until = min(valid_until, observed + age)
    statuses = [evidence.get(name, {}).get('status') for name in required]
    if any(state in {'failed', 'recovery_required'} for state in statuses):
        state = 'recovery_required'
    elif sandbox or 'evaluation' in statuses:
        state = 'evaluation'
    elif all(evidence.get(name, {}).get('passing') is True and evidence[name].get('authenticated_read') is True for name in required):
        state = 'reported_healthy'
    else:
        state = 'degraded'
    return {'schema_version': 1, 'appliance_state': state, 'evidence': evidence,
            'timestamp': snapshot_time, 'valid_until': valid_until,
            'basis': 'authenticated_producer_reports', 'ui_verified_attestation_signature': False,
            'subsystems': {'attestor': evidence.get('attestor', {}).get('status', 'unknown'),
                           'integrity_monitor': evidence.get('integrity_monitor', {}).get('status', 'unknown'),
                           'incidents': evidence.get('incidents', {})}}
