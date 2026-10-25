"""Real loopback HTTP integration tests; device actions use explicit local mocks."""
import concurrent.futures
import json
import threading
import time

import pytest

from http_ctl import auth, server as server_module


def test_authenticated_health(service):
    result = service.request()
    assert result.status == 200
    assert result.json()['ok'] is True
    assert result.json()['version'] == 2
    assert result.headers['Cache-Control'] == 'no-store'
    assert result.headers['Connection'] == 'close'
    assert result.headers['X-Content-Type-Options'] == 'nosniff'
    assert 'Server' not in result.headers


def test_missing_signature_and_legacy_token_fail_closed(service):
    headers = {'Content-Length': '0', 'Content-Type': 'application/octet-stream'}
    assert service.request(headers=headers).status == 401
    headers['Authorization'] = 'Bearer obsolete-token'
    assert service.request(headers=headers).status == 400


@pytest.mark.parametrize('mutation', ['body', 'digest', 'method', 'target', 'query_encoding', 'content_type'])
def test_covered_fields_cannot_be_tampered(service, mutation):
    body = b'original'
    target = '/upload?path=safe.txt'
    headers = service.headers('POST', target, body)
    method = 'POST'
    if mutation == 'body':
        body = b'modified'  # Equal length isolates digest validation.
    elif mutation == 'digest':
        headers['Content-Digest'] = auth.digest(b'anything')
    elif mutation == 'method':
        method, target, body = 'GET', '/download?path=safe.txt', b''
        headers['Content-Length'] = '0'
        headers['Content-Digest'] = auth.digest(body)
    elif mutation == 'target':
        target = '/upload?path=else.txt'
    elif mutation == 'query_encoding':
        target = '/upload?path=%73afe.txt'
    elif mutation == 'content_type':
        headers = service.headers('POST', target, body, content_type='text/plain')
        headers['Content-Type'] = 'application/octet-stream'
    assert service.request(method, target, body, headers=headers).status == 401
    assert list(service.root.iterdir()) == []


def test_method_covered_independently(service):
    # Both actual path and body are unchanged; only the signed method is wrong.
    headers = service.headers('POST', '/health')
    assert service.request(headers=headers).status == 401


@pytest.mark.parametrize('kind', ['wrong_material', 'unknown_id', 'wrong_known_id'])
def test_unknown_or_wrong_signing_key(service, kind):
    key_id = 'unknown' if kind == 'unknown_id' else ('other-key' if kind == 'wrong_known_id' else 'test-key')
    private = service.other_private if kind == 'wrong_material' else service.private
    assert service.request(key_id=key_id, private=private).status == 401


def test_replay_rejected_and_survives_restart(service):
    headers = service.headers()
    assert service.request(headers=headers).status == 200
    assert service.request(headers=headers).status == 401
    service.restart()
    assert service.request(headers=headers).status == 401
    assert service.request().status == 200


def test_concurrent_replay_accepts_exactly_once(service):
    headers = service.headers()
    barrier = threading.Barrier(6)
    def request_once(_):
        barrier.wait(timeout=3)
        return service.request(headers=headers).status
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(request_once, range(6)))
    assert results.count(200) == 1
    assert results.count(401) == 5


def test_invalid_signature_does_not_burn_nonce(service):
    headers = service.headers()
    tampered = dict(headers, **{'Content-Digest': auth.digest(b'bad')})
    assert service.request(headers=tampered).status == 401
    assert service.request(headers=headers).status == 200


@pytest.mark.parametrize(('created_offset', 'expires_offset'), [(-100, -40), (60, 100), (-100, 10), (0, 120), (0, 0), (0, -1)])
def test_invalid_timestamps(service, created_offset, expires_offset):
    now = int(time.time())
    headers = service.headers(created=now + created_offset, expires=now + expires_offset)
    assert service.request(headers=headers).status == 401


def test_live_revocation_without_restart(service):
    assert service.request().status == 200
    service.data['keys']['test-key']['revoked'] = True
    service.write_config()
    assert service.request().status == 401
    assert service.request(key_id='health-only').status == 200


def test_removing_key_revokes_without_restart(service):
    del service.data['keys']['test-key']
    service.write_config()
    assert service.request().status == 401


def test_invalid_reloaded_config_fails_closed(service):
    service.data['external_origin'] = 'https://changed.example.test'
    service.write_config()
    assert service.request().status == 401


def test_scope_denied_before_operation(service):
    body = json.dumps({'cmd': 'not executed'}).encode()
    result = service.request('POST', '/exec', body, key_id='health-only')
    assert result.status == 403
    assert result.json() == {'error': 'scope denied'}


@pytest.mark.parametrize('components', [('@method', '@target-uri', 'content-type'), ('@method', '@target-uri', 'content-digest', 'content-type'), ('@method', 'content-type', 'content-digest'), ('@method', '@target-uri', 'content-type', 'content-digest', 'content-length')])
def test_incomplete_extra_or_reordered_components(service, components):
    assert service.request(components=components).status == 401


@pytest.mark.parametrize('mutation', ['algorithm', 'tag', 'nonce_short', 'missing_nonce', 'duplicate_parameter', 'duplicate_input_label', 'duplicate_signature_label', 'extra_label', 'signature_parameter', 'signature_short', 'component_parameter', 'noncanonical_spacing'])
def test_restricted_signature_profile(service, mutation):
    headers = service.headers()
    value = headers['X-Http-Ctl-Signature-Input']
    if mutation == 'algorithm':
        headers['X-Http-Ctl-Signature-Input'] = value.replace('alg="ed25519"', 'alg="rsa-pss-sha512"')
    elif mutation == 'tag':
        headers['X-Http-Ctl-Signature-Input'] = value.replace('tag="http-ctl-v2"', 'tag="other"')
    elif mutation == 'nonce_short':
        node = auth._structured(value)
        node['ctl'].params['nonce'] = 'short'
        headers['X-Http-Ctl-Signature-Input'] = str(node)
    elif mutation == 'missing_nonce':
        node = auth._structured(value)
        del node['ctl'].params['nonce']
        headers['X-Http-Ctl-Signature-Input'] = str(node)
    elif mutation == 'duplicate_parameter':
        headers['X-Http-Ctl-Signature-Input'] += ';alg="ed25519"'
    elif mutation == 'duplicate_input_label':
        headers['X-Http-Ctl-Signature-Input'] += ', ' + value
    elif mutation == 'duplicate_signature_label':
        headers['X-Http-Ctl-Signature'] += ', ' + headers['X-Http-Ctl-Signature']
    elif mutation == 'extra_label':
        headers['X-Http-Ctl-Signature'] += ', other=:AA==:'
    elif mutation == 'signature_parameter':
        headers['X-Http-Ctl-Signature'] += ';x=1'
    elif mutation == 'signature_short':
        headers['X-Http-Ctl-Signature'] = 'ctl=:AA==:'
    elif mutation == 'component_parameter':
        headers['X-Http-Ctl-Signature-Input'] = value.replace('"@method"', '"@method";x=1')
    elif mutation == 'noncanonical_spacing':
        headers['X-Http-Ctl-Signature-Input'] = value.replace('"@method" ', '"@method"  ')
    assert service.request(headers=headers).status == 401


def test_origin_cannot_be_spoofed_with_host_or_forwarding(service):
    headers = service.headers(origin='https://attacker.example.test')
    headers.update({'Host': 'attacker.example.test', 'Forwarded': 'host=attacker.example.test;proto=https', 'X-Forwarded-Host': 'attacker.example.test', 'X-Forwarded-Proto': 'https', 'X-Original-URL': '/health'})
    assert service.request(headers=headers).status == 401
    valid = service.headers()
    valid.update({'Host': 'attacker.example.test', 'X-Forwarded-Host': 'attacker.example.test'})
    assert service.request(headers=valid).status == 200  # Configured origin, not proxy headers, is authoritative.


def test_forwarded_target_cannot_authorize_different_route(service):
    headers = service.headers('GET', '/health')
    headers['X-Original-URL'] = '/health'
    headers['X-Rewrite-URL'] = '/health'
    assert service.request('GET', '/screenshot', headers=headers).status == 401


def test_nonce_commit_precedes_mocked_action(service, monkeypatch):
    calls = []
    def mocked_run(argv, timeout, **kwargs):
        calls.append((argv, timeout, kwargs))
        return 0, b'local mock output', b'', False, False
    monkeypatch.setattr(server_module, 'run_bounded', mocked_run)
    body = b'{"action":"tap","x":10,"y":20}'
    headers = service.headers('POST', '/ui', body)
    assert service.request('POST', '/ui', body, headers=headers).status == 200
    assert service.request('POST', '/ui', body, headers=headers).status == 401
    assert calls == [(['/test-only/adb-not-executed', '-s', 'test-device-never-used', 'shell', 'input', 'tap', '10', '20'], 10, {})]


def test_mocked_screenshot_never_contacts_device(service, monkeypatch):
    image = b'\x89PNG\r\n\x1a\n' + b'test-only-not-a-real-screenshot'
    calls = []
    def mocked_run(argv, timeout, **kwargs):
        calls.append((argv, timeout, kwargs))
        return 0, image, b'', False, False
    monkeypatch.setattr(server_module, 'run_bounded', mocked_run)
    result = service.request('GET', '/screenshot')
    assert result.status == 200
    assert result.body == image
    assert result.headers['Content-Type'] == 'image/png'
    assert calls == [(['/test-only/adb-not-executed', '-s', 'test-device-never-used', 'exec-out', 'screencap', '-p'], 30, {'output_limit': 16 * 1024 * 1024})]


def test_mocked_shell_output_flags_and_timeout(service, monkeypatch):
    calls = []
    def mocked_run(argv, timeout, **kwargs):
        calls.append((argv, timeout, kwargs))
        return -9, b'mock\xff', b'bounded', True, True
    monkeypatch.setattr(server_module, 'run_bounded', mocked_run)
    result = service.request('POST', '/exec', b'{"cmd":"test-only-command","timeout":7}')
    assert result.status == 200
    assert result.json() == {'exit': -9, 'stdout': 'mock\ufffd', 'stderr': 'bounded', 'timed_out': True, 'truncated': True}
    assert calls == [(['/test-only/bash-not-executed', '-c', 'test-only-command'], 7, {})]


@pytest.mark.parametrize('body', [b'{"cmd":"a","cmd":"b"}', b'{"cmd":"a","timeout":NaN}', b'{"cmd":"a","timeout":true}', b'{"cmd":"a","timeout":301}', b'{"cmd":"a","unknown":1}', b'[]'])
def test_invalid_command_json_never_runs(service, body):
    assert service.request('POST', '/exec', body).status == 400


def test_mocked_failure_does_not_leak_sensitive_command(service, monkeypatch, capsys):
    marker = 'PRIVATE-COMMAND-DO-NOT-LOG'
    monkeypatch.setattr(server_module, 'run_bounded', lambda *a, **kw: (1, b'PRIVATE-OUTPUT', b'PRIVATE-ERROR', False, False))
    headers = service.headers('POST', '/exec', json.dumps({'cmd': marker}).encode())
    response = service.request('POST', '/exec', json.dumps({'cmd': marker}).encode(), headers=headers)
    assert response.status == 200
    output = capsys.readouterr().out
    assert marker not in output
    assert 'PRIVATE-OUTPUT' not in output
    assert 'PRIVATE-ERROR' not in output
    assert headers['X-Http-Ctl-Signature'] not in output
    assert headers['X-Http-Ctl-Signature-Input'] not in output
