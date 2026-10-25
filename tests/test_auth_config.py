"""Configuration/key permissions and nonce state fail closed."""
import concurrent.futures
import json
import os
import sqlite3
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from http_ctl import auth


@pytest.mark.parametrize('value', ['http://a.example', 'https://a.example/', 'https://a.example/path', 'https://a.example?x', 'https://a.example#x', 'https://user:a@a.example', 'https://A.example', 'https://a.example ', 'https://é.example', 'https://a.example:bad', 'https://a.example:65536', None])
def test_origin_validation(value):
    with pytest.raises((ValueError, TypeError)):
        auth.origin(value)


@pytest.mark.parametrize('value', ['https://a.example', 'https://a.example:8443', 'https://[::1]:8443'])
def test_origin_valid_values(value):
    assert auth.origin(value) == value


@pytest.mark.parametrize('raw', [b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}'])
def test_json_duplicate_and_nonfinite_values_rejected(raw):
    with pytest.raises(ValueError):
        auth.strict_json(raw)


def test_protected_read_permissions_symlink_and_size(tmp_path):
    target = tmp_path / 'config'
    target.write_bytes(b'12345')
    target.chmod(0o600)
    assert auth.protected_read(str(target)) == b'12345'
    with pytest.raises(ValueError):
        auth.protected_read(str(target), limit=4)
    target.chmod(0o644)
    with pytest.raises(ValueError):
        auth.protected_read(str(target))
    target.chmod(0o600)
    alias = tmp_path / 'alias'
    alias.symlink_to(target)
    with pytest.raises(OSError):
        auth.protected_read(str(alias))


@pytest.mark.parametrize('mutation', ['world_readable', 'no_keys', 'bad_key_id', 'bad_scope', 'scope_not_list', 'revoked_not_boolean', 'root_missing', 'root_relative', 'root_all', 'root_noncanonical', 'root_without_scope', 'unknown_config_key', 'unknown_key_field', 'serial_injection'])
def test_invalid_config_rejected_at_startup(service, mutation):
    item = service.data['keys']['test-key']
    if mutation == 'world_readable':
        service.config_path.chmod(0o644)
    elif mutation == 'no_keys':
        service.data['keys'] = {}
    elif mutation == 'bad_key_id':
        service.data['keys']['bad key'] = item
    elif mutation == 'bad_scope':
        item['scopes'] = ['everything']
    elif mutation == 'scope_not_list':
        item['scopes'] = 'health:read'
    elif mutation == 'revoked_not_boolean':
        item['revoked'] = 'false'
    elif mutation == 'root_missing':
        del item['file_root']
    elif mutation == 'root_relative':
        item['file_root'] = 'relative'
    elif mutation == 'root_all':
        item['file_root'] = '/'
    elif mutation == 'root_noncanonical':
        item['file_root'] += '/..'
    elif mutation == 'root_without_scope':
        item['scopes'] = ['health:read']
    elif mutation == 'unknown_config_key':
        service.data['unsafe'] = True
    elif mutation == 'unknown_key_field':
        item['unknown'] = 1
    else:
        service.data['adb_serial'] = 'localhost;id'
    if mutation != 'world_readable':
        service.write_config()
    with pytest.raises((ValueError, KeyError, TypeError)):
        auth.Config(str(service.config_path))


def test_config_rejects_other_key_algorithms(service):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service.data['keys']['test-key']['public_key_pem'] = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    service.write_config()
    with pytest.raises(ValueError, match='Ed25519'):
        auth.Config(str(service.config_path))


def test_replay_store_private_files_and_restart(tmp_path):
    state = tmp_path / 'state'
    path = state / 'replay.sqlite3'
    store = auth.ReplayStore(str(path))
    assert state.stat().st_mode & 0o777 == 0o700
    assert path.stat().st_mode & 0o777 == 0o600
    expires = int(time.time()) + 30
    store.consume('test-key', 'test-nonce', expires)
    other = auth.ReplayStore(str(path))
    with pytest.raises(auth.AuthError):
        other.consume('test-key', 'test-nonce', expires)
    other.consume('other-key', 'test-nonce', expires)  # Nonce identity is per key.


def test_replay_store_two_instances_concurrent_unique_commit(tmp_path):
    path = str(tmp_path / 'state' / 'replay.sqlite3')
    stores = [auth.ReplayStore(path), auth.ReplayStore(path)]
    expires = int(time.time()) + 30
    def commit(i):
        try:
            stores[i % 2].consume('key', 'concurrent-nonce', expires)
            return True
        except auth.AuthError:
            return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(commit, range(8))) == 1


@pytest.mark.parametrize('kind', ['directory_permissions', 'file_permissions', 'file_symlink', 'directory_symlink'])
def test_replay_store_unsafe_state_rejected(tmp_path, kind):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    path = state / 'replay.sqlite3'
    if kind == 'directory_permissions':
        state.chmod(0o755)
    elif kind == 'file_permissions':
        path.touch(mode=0o644)
        path.chmod(0o644)
    elif kind == 'file_symlink':
        outside = tmp_path / 'outside'
        outside.touch(mode=0o600)
        path.symlink_to(outside)
    else:
        alias = tmp_path / 'alias'
        alias.symlink_to(state, target_is_directory=True)
        path = alias / 'replay.sqlite3'
    with pytest.raises((ValueError, OSError)):
        auth.ReplayStore(str(path))


def test_replay_store_clock_rollback_fails_closed(tmp_path, monkeypatch):
    store = auth.ReplayStore(str(tmp_path / 'state' / 'replay.sqlite3'))
    now = time.time()
    monkeypatch.setattr(auth, 'time', SimpleNamespace(time=lambda: now - 60))
    with pytest.raises(auth.AuthError, match='authentication failed') as error:
        store.consume('key', 'nonce', int(now + 30))
    assert error.value.code == 'clock_rollback'


def test_replay_store_database_failure_fails_closed(service, monkeypatch):
    def unavailable():
        raise sqlite3.OperationalError('simulated disk failure')
    monkeypatch.setattr(service.server.replay, '_connect', unavailable)
    assert service.request().status == 401


def test_database_failure_never_runs_mocked_operation(service, monkeypatch):
    def unavailable():
        raise sqlite3.OperationalError('simulated disk failure')
    monkeypatch.setattr(service.server.replay, '_connect', unavailable)
    assert service.request('POST', '/ui', b'{"action":"keyevent","key":"HOME"}').status == 401


def test_replay_retained_across_allowed_five_second_rollback_and_pruning(tmp_path, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(auth, 'time', SimpleNamespace(time=lambda: now[0]))
    store = auth.ReplayStore(str(tmp_path / 'state' / 'replay.sqlite3'))
    store.consume('key', 'captured', 1001)
    # Signature expired six seconds ago: outside its acceptance window now,
    # but still eligible after the maximum allowed five-second rollback.
    now[0] = 1007.0
    store.consume('key', 'advance-clock-and-prune', 1060)
    now[0] = 1002.0
    with pytest.raises(auth.AuthError, match='authentication failed') as error:
        store.consume('key', 'captured', 1001)
    assert error.value.code == 'replay_rejected'


def test_replay_prunes_only_after_full_skew_retention_window(tmp_path, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(auth, 'time', SimpleNamespace(time=lambda: now[0]))
    store = auth.ReplayStore(str(tmp_path / 'state' / 'replay.sqlite3'))
    store.consume('key', 'expired', 1001)
    now[0] = 1011.0
    store.consume('key', 'at-boundary', 1060)
    with sqlite3.connect(store.path) as con:
        assert con.execute("SELECT COUNT(*) FROM nonces WHERE nonce='expired'").fetchone()[0] == 1
    now[0] = 1011.1
    store.consume('key', 'past-boundary', 1060)
    with sqlite3.connect(store.path) as con:
        assert con.execute("SELECT COUNT(*) FROM nonces WHERE nonce='expired'").fetchone()[0] == 0
