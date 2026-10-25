"""Exec CLI status and sanitized diagnostics; no external network or credentials."""
import http.client
import io
import json
import urllib.error

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from http_ctl import client


@pytest.fixture(autouse=True)
def credentials(monkeypatch):
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    monkeypatch.setenv('CTL_BASE_URL', 'https://ctl.example.test')
    monkeypatch.setenv('CTL_KEY_ID', 'test-key')
    monkeypatch.setattr(client, 'protected_read', lambda _: pem)


def response(**changes):
    result = dict(exit=0, stdout='hello\n', stderr='', timed_out=False, truncated=False)
    result.update(changes)
    return json.dumps(result).encode()


@pytest.mark.parametrize('changes,status', [
    ({}, 0), ({'exit': 1}, 1), ({'exit': 42}, 42), ({'exit': 255}, 255),
    ({'exit': -9}, 137), ({'exit': -15}, 143), ({'exit': -127}, 255),
    ({'timed_out': True, 'exit': -9}, 124),
    ({'truncated': True}, 125),
    ({'timed_out': True, 'truncated': True}, 124),
])
def test_exec_exit_and_unchanged_json(changes, status, monkeypatch, capsys):
    data = response(**changes)
    calls = []
    def request(*args):
        calls.append(args)
        return data
    monkeypatch.setattr(client, 'request', request)
    assert client.main(['exec', 'example', '7']) == status
    out = capsys.readouterr()
    assert out.out == data.decode() + '\n'
    assert ('remote execution' in out.err) == bool(status)
    assert len(calls) == 1
    assert json.loads(calls[0][-1]) == {'cmd': 'example', 'timeout': 7}


def test_raw_separate_streams_no_extra_newlines(monkeypatch, capsys):
    monkeypatch.setattr(client, 'request', lambda *a: response(stdout='hello 中', stderr='warning'))
    assert client.main(['exec', '--raw', 'example']) == 0
    captured = capsys.readouterr()
    assert captured.out == 'hello 中'
    assert captured.err == 'warning'


@pytest.mark.parametrize('data', [
    b'not JSON', b'[]', b'null', b'{}', b'\xff',
    response(exit=True), response(exit=1.0), response(exit=None), response(exit=256),
    response(exit=-128), response(stdout=[]), response(stderr=None),
    response(timed_out=1), response(truncated='false'), response(stdout='\ud800'),
    response().replace(b'"exit": 0', b'"exit": 0, "exit": 1'),
])
def test_bad_exec_schema_never_prints_remote_body(data, monkeypatch, capsys):
    monkeypatch.setattr(client, 'request', lambda *a: data)
    assert client.main(['exec', 'secret-command']) == 255
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'transport/protocol' in captured.err
    assert 'secret-command' not in captured.err


@pytest.mark.parametrize('code,phrase', [(401, 'authentication'), (403, 'authorization'),
    (429, 'limit'), (503, 'unavailable'), (500, 'rejected')])
def test_http_diagnostics_static_and_no_retries(code, phrase, monkeypatch, capsys):
    body = io.BytesIO(b'SECRET BODY')
    error = urllib.error.HTTPError('https://SECRET_URL', code, 'SECRET REASON',
                                   {'SECRET HEADER': 'SECRET'}, body)
    calls = []
    def fail(*args):
        calls.append(args)
        raise error
    monkeypatch.setattr(client, 'request', fail)
    assert client.main(['exec', 'SECRET COMMAND']) == 255
    assert len(calls) == 1
    captured = capsys.readouterr()
    assert captured.out == ''
    assert str(code) in captured.err and phrase in captured.err
    assert 'SECRET' not in captured.err
    assert 'no automatic retry' in captured.err
    assert body.closed


@pytest.mark.parametrize('error', [urllib.error.URLError('SECRET'), TimeoutError('SECRET'),
    ConnectionResetError('SECRET'), OSError('SECRET'), http.client.IncompleteRead(b'SECRET'),
    client.ResponseError('SECRET')])
def test_transport_distinguished_from_remote_failure(error, monkeypatch, capsys):
    calls = []
    def fail(*args):
        calls.append(args)
        raise error
    monkeypatch.setattr(client, 'request', fail)
    assert client.main(['exec', 'example']) == 255
    captured = capsys.readouterr()
    assert len(calls) == 1 and captured.out == ''
    assert 'outcome may be unknown' in captured.err
    assert 'SECRET' not in captured.err


def test_exec_help_documents_statuses(capsys):
    with pytest.raises(SystemExit) as error:
        client.main(['exec', '--help'])
    assert error.value.code == 0
    help_text = capsys.readouterr().out
    for phrase in ('128+N', '124', '125', '255', '--raw', 'overlap'):
        assert phrase in help_text
