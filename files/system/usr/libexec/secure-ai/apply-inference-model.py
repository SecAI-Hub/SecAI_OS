#!/usr/bin/python3
"""Apply one authenticated-UI model request; only the inference unit is controlled.

The `resolve` mode is read-only and is shared by the inference launcher. Runtime
requests cannot choose filesystem paths, commands, units, or shell arguments.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT_UID = 0
UNIT = 'secure-ai-inference.service'
NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class SelectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class Paths:
    requests: Path = Path('/run/secure-ai-ui')
    control: Path = Path('/run/secure-ai/inference-control')
    selection: Path = Path('/var/lib/secure-ai/inference/selection.json')
    manifest: Path = Path('/var/lib/secure-ai/registry/manifest.json')
    models: Path = Path('/var/lib/secure-ai/vault/models')


def _decode(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SelectionError('duplicate JSON field')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _v: (_ for _ in ()).throw(SelectionError('nonfinite JSON value')))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise SelectionError('invalid JSON') from exc


def filename(value) -> str:
    if (not isinstance(value, str) or not value or value != value.strip()
            or value.startswith('.') or len(value.encode('utf-8')) > 255
            or any(c in value for c in '/\\,') or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or not value.lower().endswith('.gguf')):
        raise SelectionError('an exact GGUF filename is required')
    return value


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _read_regular(path: Path, limit: int, *, owner=None, trusted=True) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit
                or (owner is not None and before.st_uid != owner)
                or (trusted and before.st_mode & 0o022) or (not trusted and before.st_mode & 0o007)):
            raise SelectionError('unsafe or oversized control file')
        with os.fdopen(descriptor, 'rb', closefd=False) as handle:
            raw = handle.read(limit + 1)
        if len(raw) != before.st_size or _identity(before) != _identity(os.fstat(descriptor)):
            raise SelectionError('control file changed while reading')
        return raw
    finally:
        os.close(descriptor)


def _directory(path: Path) -> int:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    info = os.fstat(descriptor)
    if info.st_uid != ROOT_UID or info.st_mode & 0o022:
        os.close(descriptor)
        raise SelectionError('control directory is not root-owned and protected')
    return descriptor


def gpu_layers(policy: Path, requested: str) -> str:
    """An explicitly enrolled CPU release cannot offload to an autodetected GPU."""
    if requested not in {'0', '-1'}:
        raise SelectionError('invalid GPU offload configuration')

    class UniqueLoader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            keys = [self.construct_object(key, deep=deep) for key, _value in node.value]
            try:
                if len(keys) != len(set(keys)):
                    raise SelectionError('duplicate GPU assurance policy field')
            except TypeError as exc:
                raise SelectionError('invalid GPU assurance policy field') from exc
            return super().construct_mapping(node, deep=deep)

    try:
        value = yaml.load(_read_regular(policy, 1024**2, owner=ROOT_UID), Loader=UniqueLoader)
        if not isinstance(value, dict) or type(value.get('version')) is not int or value['version'] != 1:
            raise SelectionError('invalid GPU assurance policy')
        gpu = value.get('gpu')
        if not isinstance(gpu, dict) or gpu.get('mode') not in {'required', 'optional', 'no_gpu'}:
            raise SelectionError('GPU assurance mode is not explicitly enrolled')
        if gpu['mode'] == 'no_gpu':
            if set(gpu) != {'mode'}:
                raise SelectionError('CPU-only policy cannot contain GPU scopes')
            return '0'
        if not isinstance(gpu.get('bootstrap'), dict) or not isinstance(gpu.get('runtime'), dict):
            raise SelectionError('GPU assurance scopes are not explicitly enrolled')
        return requested
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        raise SelectionError('invalid GPU assurance policy') from exc


def _atomic_json(path: Path, value) -> None:
    parent = _directory(path.parent)
    if not os.fstat(parent).st_mode & stat.S_ISGID:
        os.close(parent)
        raise SelectionError('control directory must inherit its reader group')
    name = '.inference-' + uuid.uuid4().hex
    descriptor = -1
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o640, dir_fd=parent)
        os.fchmod(descriptor, 0o640)
        with os.fdopen(descriptor, 'wb', closefd=False) as handle:
            handle.write((json.dumps(value, separators=(',', ':')) + '\n').encode())
            handle.flush()
            os.fsync(descriptor)
        os.rename(name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(name, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def _models(manifest: Path) -> list[dict]:
    data = _decode(_read_regular(manifest, 16 * 1024**2))
    if not isinstance(data, dict) or not isinstance(data.get('models'), list) or len(data['models']) > 10_000:
        raise SelectionError('invalid trusted registry manifest')
    return data['models']


def verified_model(models: Path, manifest: Path, name: str, expected: str | None = None) -> tuple[Path, str]:
    filename(name)
    candidates = [entry for entry in _models(manifest) if isinstance(entry, dict) and entry.get('filename') == name]
    if len(candidates) != 1 or candidates[0].get('format') != 'gguf' or candidates[0].get('blocked', False) is not False:
        raise SelectionError('selected model is not one unblocked promoted GGUF')
    digest = candidates[0].get('sha256')
    if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest) or (expected is not None and digest != expected):
        raise SelectionError('selected model identity changed in the registry')
    directory = os.open(models, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    descriptor = -1
    try:
        descriptor = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=directory)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
            raise SelectionError('selected model is not a nonempty regular file')
        actual = hashlib.sha256()
        remaining = before.st_size
        deadline = time.monotonic() + 120
        while remaining:
            if time.monotonic() > deadline:
                raise SelectionError('selected model verification timed out')
            chunk = os.read(descriptor, min(1024**2, remaining))
            if not chunk:
                raise SelectionError('selected model changed while hashing')
            actual.update(chunk)
            remaining -= len(chunk)
        if (_identity(before) != _identity(os.fstat(descriptor)) or actual.hexdigest() != digest
                or _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != _identity(before)):
            raise SelectionError('selected model hash or file identity changed')
        return models / name, digest
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def resolve_model(paths: Paths) -> Path:
    try:
        paths.selection.lstat()
    except FileNotFoundError:
        # Preserve initial startup's first-valid behavior only when no selection exists.
        for entry in _models(paths.manifest):
            if isinstance(entry, dict) and entry.get('format') == 'gguf':
                try:
                    return verified_model(paths.models, paths.manifest, entry.get('filename'))[0]
                except (OSError, SelectionError):
                    continue
        raise SelectionError('no verified GGUF model is available')
    parent = _directory(paths.selection.parent)
    os.close(parent)
    selected = _decode(_read_regular(paths.selection, 4096, owner=ROOT_UID))
    if (not isinstance(selected, dict) or set(selected) != {'version', 'request_id', 'model_filename', 'sha256'}
            or type(selected['version']) is not int or selected['version'] != 1
            or not isinstance(selected['request_id'], str) or not re.fullmatch('[0-9a-f]{32}', selected['request_id'])
            or not isinstance(selected['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', selected['sha256'])):
        raise SelectionError('invalid explicit model selection')
    return verified_model(paths.models, paths.manifest, selected['model_filename'], selected['sha256'])[0]


def systemctl(action: str) -> bool:
    if action not in {'restart', 'is-active', 'stop'}:
        raise SelectionError('unsupported inference service action')
    try:
        result = subprocess.run(['/usr/bin/systemctl', '--no-pager', '--quiet', action, UNIT],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, timeout=125 if action == 'restart' else 30)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def apply_request(paths: Paths = Paths(), action=systemctl) -> bool:
    control = _directory(paths.control)
    processing = _directory(paths.control / 'processing')
    lock = os.open('control.lock', os.O_RDWR | os.O_CREAT | NOFOLLOW, 0o600, dir_fd=control)
    claim = uuid.uuid4().hex + '.json'
    request = None
    claimed = False
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o077:
            raise SelectionError('unsafe inference control lock')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False  # Leave a queued request for the path unit after the active broker finishes.
        inbox = os.open(paths.requests, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
        try:
            info = os.fstat(inbox)
            if info.st_uid != ROOT_UID or info.st_mode & 0o007:
                raise SelectionError('unsafe inference request directory')
            try:
                os.rename('inference-model-request', claim, src_dir_fd=inbox, dst_dir_fd=processing)
            except FileNotFoundError:
                return True
            claimed = True
        finally:
            os.close(inbox)
        raw = _decode(_read_regular(paths.control / 'processing' / claim, 4096, trusted=False))
        # Retain a valid correlation identity for truthful rejection feedback.
        if (isinstance(raw, dict) and isinstance(raw.get('request_id'), str)
                and re.fullmatch('[0-9a-f]{32}', raw['request_id'])):
            request = {'version': 1, 'request_id': raw['request_id'], 'model_filename': filename(raw.get('model_filename'))}
        if (request is None or set(raw) != {'version', 'request_id', 'model_filename'}
                or type(raw['version']) is not int or raw['version'] != 1):
            raise SelectionError('invalid model-selection request schema')
        _, digest = verified_model(paths.models, paths.manifest, request['model_filename'])
        _atomic_json(paths.control / 'result.json', {**request, 'status': 'pending', 'detail': 'Restarting inference with the verified selection.'})
        _atomic_json(paths.selection, {**request, 'sha256': digest})
        if not action('restart') or not action('is-active'):
            stopped = action('stop')
            detail = ('Inference restart failed; explicit selection retained and service stopped.' if stopped else
                      'Inference restart failed; explicit selection retained; service stop could not be confirmed.')
            raise SelectionError(detail)
        _atomic_json(paths.control / 'result.json', {**request, 'status': 'succeeded',
                     'detail': 'Inference service restarted. Verify the backend model alias before chatting.'})
        return True
    except (OSError, SelectionError) as exc:
        if request is not None:
            _atomic_json(paths.control / 'result.json', {**request, 'status': 'failed', 'detail': str(exc)[:400]})
        return False
    finally:
        if claimed:
            try:
                os.unlink(claim, dir_fd=processing)
            except FileNotFoundError:
                pass
            except IsADirectoryError:
                # Never recurse through an untrusted directory request. Preserve
                # a nonempty rejected object for local repair rather than walk it.
                try:
                    os.rmdir(claim, dir_fd=processing)
                except OSError:
                    print('Rejected non-file request retained in protected processing directory.', file=sys.stderr)
        os.close(lock)
        os.close(processing)
        os.close(control)


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == 'gpu-layers':
        try:
            # EnvironmentFile is hardware observation, never policy authority.
            print(gpu_layers(Path('/etc/secure-ai/policy/attestation.yaml'), sys.argv[2]))
            return 0
        except (OSError, SelectionError) as exc:
            print(f'[select-model] {exc}', file=sys.stderr)
            return 1
    if sys.argv[1:] == ['resolve']:
        paths = Paths(models=Path(os.getenv('REGISTRY_DIR', str(Paths.models))),
                      manifest=Path(os.getenv('REGISTRY_MANIFEST_PATH', str(Paths.manifest))),
                      selection=Path(os.getenv('INFERENCE_SELECTION_PATH', str(Paths.selection))))
        try:
            print(resolve_model(paths))
            return 0
        except (OSError, SelectionError) as exc:
            print(f'[select-model] {exc}', file=sys.stderr)
            return 1
    if sys.argv[1:] or os.geteuid() != ROOT_UID:
        raise SystemExit('root broker takes no arguments')
    return 0 if apply_request() else 1


if __name__ == '__main__':
    raise SystemExit(main())
