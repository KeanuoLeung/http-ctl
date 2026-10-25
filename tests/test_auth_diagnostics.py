"""Fixed local-only auth classifications, without request or exception leakage."""
import json
import sqlite3
import threading
import time

import pytest

from http_ctl import auth, server

EXPECTED_CODES = frozenset({
    'missing_signature_input', 'missing_signature', 'missing_content_digest',
    'structured_invalid', 'structured_noncanonical', 'profile_invalid',
    'time_invalid', 'digest_mismatch', 'key_unavailable',
    'configuration_unavailable', 'signature_invalid', 'replay_rejected',
    'replay_unavailable', 'clock_rollback', 'internal',
})
PRIVATE_KEY_ID = 'PRIVATE-TEST-KEY-ID'
PRIVATE_NONCE = 'PRIVATE_TEST_NONCE_12345678901234567890'
PRIVATE_PATH = 'PRIVATE-FILE-NAME.txt'
PRIVATE_BODY = b'PRIVATE-REQUEST-BODY-DO-NOT-LOG'
PRIVATE_EXCEPTION = 'PRIVATE-EXCEPTION-PATH-DETAILS-DO-NOT-LOG'


@pytest.fixture
def audit_capture(monkeypatch):
    messages = []
    ready = threading.Event()
    def capture(*args, **kwargs):
        messages.append(' '.join(str(value) for value in args))
        ready.set()
    monkeypatch.setattr(server, 'print', capture, raising=False)
    return messages, ready


def assert_private_audit(response, expected, audit_capture, headers):
    messages, ready = audit_capture
    assert ready.wait(2), 'expected one local audit record'
    assert response.status == 401
    assert response.json() == {'error': 'unauthorized'}
    assert expected not in response.body.decode()
    assert len(messages) == 1
    audit = json.loads(messages[0])
    assert set(audit) == {'route', 'status', 'duration_ms', 'auth_failure'}
    assert audit['auth_failure'] == expected
    assert audit['auth_failure'] in EXPECTED_CODES
    assert audit['route'] == '/upload'
    assert audit['status'] == 401
    assert type(audit['duration_ms']) is int
    combined = '\n'.join(messages) + response.body.decode()
    for value in [PRIVATE_KEY_ID, PRIVATE_NONCE, PRIVATE_PATH, PRIVATE_BODY.decode(), PRIVATE_EXCEPTION, headers.get('X-Http-Ctl-Signature'), headers.get('X-Http-Ctl-Signature-Input'), headers.get('Content-Digest')]:
        if value:
            assert value not in combined
    assert 'Traceback' not in combined
    assert 'PRIVATE KEY' not in combined


@pytest.mark.parametrize('code', sorted(EXPECTED_CODES))
def test_each_fixed_auth_diagnostic_is_local_only_and_secret_free(service, monkeypatch, audit_capture, code):
    service.data['keys'][PRIVATE_KEY_ID] = service.key_record(service.private, sorted(auth.SCOPES))
    service.write_config()
    target = '/upload?path=' + PRIVATE_PATH
    headers = service.headers('POST', target, PRIVATE_BODY, key_id=PRIVATE_KEY_ID, nonce=PRIVATE_NONCE)
    if code.startswith('missing_'):
        missing = {'missing_signature_input': 'X-Http-Ctl-Signature-Input', 'missing_signature': 'X-Http-Ctl-Signature', 'missing_content_digest': 'Content-Digest'}[code]
        del headers[missing]
    elif code == 'structured_invalid':
        headers['X-Http-Ctl-Signature-Input'] = 'ctl=(:'
    elif code == 'structured_noncanonical':
        headers['X-Http-Ctl-Signature-Input'] = headers['X-Http-Ctl-Signature-Input'].replace('"@method" ', '"@method"  ')
    elif code == 'profile_invalid':
        headers['X-Http-Ctl-Signature-Input'] = headers['X-Http-Ctl-Signature-Input'].replace('alg="ed25519"', 'alg="rsa-pss-sha512"')
    elif code == 'time_invalid':
        now = int(time.time())
        headers = service.headers('POST', target, PRIVATE_BODY, key_id=PRIVATE_KEY_ID, nonce=PRIVATE_NONCE, created=now - 100, expires=now - 40)
    elif code == 'digest_mismatch':
        headers['Content-Digest'] = auth.digest(b'not the actual request body')
    elif code == 'key_unavailable':
        del service.data['keys'][PRIVATE_KEY_ID]
        service.write_config()
    elif code == 'configuration_unavailable':
        def fail_config():
            raise ValueError(PRIVATE_EXCEPTION)
        monkeypatch.setattr(service.server.config, 'keys', fail_config)
    elif code == 'signature_invalid':
        headers = service.headers('POST', target, PRIVATE_BODY, key_id=PRIVATE_KEY_ID, nonce=PRIVATE_NONCE, private=service.other_private)
    elif code == 'replay_rejected':
        # Preconsume the nonce directly so no endpoint operation is performed.
        service.server.replay.consume(PRIVATE_KEY_ID, PRIVATE_NONCE, int(time.time()) + 60)
    elif code == 'replay_unavailable':
        def fail_database():
            raise sqlite3.OperationalError(PRIVATE_EXCEPTION)
        monkeypatch.setattr(service.server.replay, '_connect', fail_database)
    elif code == 'clock_rollback':
        # A durable highwater ahead of current time exercises the actual store's
        # rollback check without changing global wall clock or signature time.
        with sqlite3.connect(service.server.replay.path) as con:
            con.execute('UPDATE clock SET highwater = ?', (time.time() + 60,))
    elif code == 'internal':
        def unexpected_error(*args):
            raise RuntimeError(PRIVATE_EXCEPTION)
        monkeypatch.setattr(service.server.replay, 'consume', unexpected_error)
    response = service.request('POST', target, PRIVATE_BODY, headers=headers)
    assert_private_audit(response, code, audit_capture, headers)
    assert list(service.root.iterdir()) == []


def test_allowed_diagnostic_codes_are_explicit_and_fixed():
    assert auth.AUTH_FAILURE_CODES == EXPECTED_CODES
    for code in EXPECTED_CODES:
        error = auth.AuthError(code)
        assert error.code == code
        assert str(error) == 'authentication failed'
        assert error.args == ('authentication failed',)


@pytest.mark.parametrize('untrusted', [PRIVATE_EXCEPTION, 'PRIVATE\nINJECTED-LOG', '', None, 123])
def test_unknown_auth_error_text_cannot_become_log_code(untrusted):
    error = auth.AuthError(untrusted)
    assert error.code == 'internal'
    assert str(error) == 'authentication failed'
    if str(untrusted):
        assert str(untrusted) not in str(error)


def test_success_has_no_auth_failure_diagnostic(service, audit_capture):
    response = service.request()
    messages, ready = audit_capture
    assert ready.wait(2)
    assert response.status == 200
    assert len(messages) == 1
    assert set(json.loads(messages[0])) == {'route', 'status', 'duration_ms'}


def test_scope_denial_remains_403_without_auth_diagnostic(service, audit_capture):
    response = service.request('POST', '/upload?path=' + PRIVATE_PATH, PRIVATE_BODY, key_id='health-only')
    messages, ready = audit_capture
    assert ready.wait(2)
    assert response.status == 403
    assert response.json() == {'error': 'scope denied'}
    assert len(messages) == 1
    assert set(json.loads(messages[0])) == {'route', 'status', 'duration_ms'}
    assert PRIVATE_PATH not in messages[0]
    assert PRIVATE_BODY.decode() not in messages[0]
