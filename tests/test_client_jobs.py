"""Jobs CLI contract tests: in-memory responses only, no external credentials."""
import base64
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


def status(**changes):
    result = dict(id='stable-1', state='running', exit=None, timeout=3600,
                  created_at=1.0, finished_at=None, stdout_bytes=0,
                  stderr_bytes=0, output_limit=1048576)
    result.update(changes)
    return json.dumps(result).encode()


def logs(**changes):
    result = dict(id='stable-1', state='exited', stream='stdout', cursor=0,
                  next_cursor=3, data_b64=base64.b64encode(b'\x00\xff\n').decode(), eof=True)
    result.update(changes)
    return json.dumps(result).encode()


@pytest.mark.parametrize('action', ['submit', 'status', 'cancel', 'logs'])
def test_jobs_wire_contract(action, monkeypatch, capsys):
    calls = []
    def request(*args, **kwargs):
        calls.append((args, kwargs))
        return logs() if action == 'logs' else status()
    monkeypatch.setattr(client, 'request', request)
    argv = ['jobs', action] + (['--id', 'stable-1', 'secret command'] if action == 'submit' else ['stable-1'])
    assert client.main(argv) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)['id'] == 'stable-1'
    assert 'secret command' not in out.err
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[1:3] == ('POST', '/jobs/' + action)
    assert args[3]['Content-Type'] == 'application/json'
    body = json.loads(args[4])
    assert body['id'] == 'stable-1'
    assert kwargs == ({'expected_statuses': (200, 202)} if action == 'submit' else {})
    if action == 'submit':
        assert body == dict(id='stable-1', cmd='secret command', timeout=3600)
        assert 'job id: stable-1' in out.err
    if action == 'logs':
        assert body == dict(id='stable-1', stream='stdout', cursor=0, limit=65536)


def test_raw_binary_selected_stream(monkeypatch):
    monkeypatch.setattr(client, 'request', lambda *a: logs(stream='stderr'))
    output = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
    monkeypatch.setattr(client.sys, 'stdout', output)
    assert client.main(['jobs', 'logs', 'stable-1', '--stream', 'stderr', '--raw']) == 0
    assert output.buffer.getvalue() == b'\x00\xff\n'


@pytest.mark.parametrize('argv', [
    ['submit', '--id', '../bad', 'cmd'], ['status', 'a\n'],
    ['submit', '--id', 'stable-1', ''], ['submit', '--id', 'stable-1', 'x\0y'],
    ['submit', '--id', 'stable-1', 'x' * 16385],
    ['submit', '--id', 'stable-1', '中' * 16000],
    ['submit', '--id', 'stable-1', 'cmd', '--timeout', '0'],
    ['submit', '--id', 'stable-1', 'cmd', '--timeout', '3601'],
    ['logs', 'stable-1', '--cursor', '-1'], ['logs', 'stable-1', '--cursor', '1048577'],
    ['logs', 'stable-1', '--limit', '0'], ['logs', 'stable-1', '--limit', '65537'],
])
def test_invalid_arguments_not_transmitted(argv, monkeypatch, capsys):
    def unexpected(*a, **kw):
        pytest.fail('invalid request transmitted')
    monkeypatch.setattr(client, 'request', unexpected)
    assert client.main(['jobs'] + argv) == 1
    assert not capsys.readouterr().out


@pytest.mark.parametrize('data', [b'{}', b'[]', b'\xff', status(id='other'), status(state='bogus'),
    status(exit=True), status(exit=256), status(timeout=True), status(timeout=0),
    status(created_at=float('nan')), status(created_at=True), status(finished_at=1),
    status(stdout_bytes=-1), status(stdout_bytes=1048576, stderr_bytes=1),
    status(state='exited', finished_at=2), status(state='failed'),
    status(extra='secret'), status().replace(b'"id":', b'"id":"duplicate", "id":'),
])
def test_bad_status_sanitized(data, monkeypatch, capsys):
    monkeypatch.setattr(client, 'request', lambda *a: data)
    assert client.main(['jobs', 'status', 'stable-1']) == 255
    captured = capsys.readouterr()
    assert not captured.out
    assert 'transport/protocol failure' in captured.err
    assert 'secret' not in captured.err


@pytest.mark.parametrize('changes', [dict(stream='stderr'), dict(cursor=True), dict(cursor=1),
    dict(next_cursor=4), dict(next_cursor=True), dict(data_b64='%%%'), dict(data_b64=None),
    dict(eof='true'), dict(state='running'), dict(extra=1)])
def test_bad_logs_sanitized(changes, monkeypatch, capsys):
    monkeypatch.setattr(client, 'request', lambda *a: logs(**changes))
    assert client.main(['jobs', 'logs', 'stable-1']) == 255
    assert not capsys.readouterr().out


@pytest.mark.parametrize('state', ['exited', 'cancelled', 'timed_out', 'output_limit', 'failed', 'interrupted'])
def test_status_query_success_not_remote_exit(state, monkeypatch, capsys):
    monkeypatch.setattr(client, 'request', lambda *a: status(state=state, exit=-9, finished_at=2))
    assert client.main(['jobs', 'status', 'stable-1']) == 0
    assert json.loads(capsys.readouterr().out)['exit'] == -9


def test_submit_unknown_outcome_prints_id_before_single_attempt(monkeypatch, capsys):
    calls = []
    def request(*args, **kwargs):
        assert 'job id: stable-1' in capsys.readouterr().err
        calls.append(1)
        raise OSError('secret error')
    monkeypatch.setattr(client, 'request', request)
    assert client.main(['jobs', 'submit', '--id', 'stable-1', 'secret command']) == 255
    captured = capsys.readouterr()
    assert 'outcome may be unknown' in captured.err
    assert 'secret' not in captured.err
    assert calls == [1]


@pytest.mark.parametrize('code', [404, 409, 503])
def test_job_http_failures_never_retry(code, monkeypatch, capsys):
    calls = []
    def request(*args, **kwargs):
        calls.append(1)
        raise urllib.error.HTTPError('url', code, 'secret', {}, io.BytesIO(b'secret'))
    monkeypatch.setattr(client, 'request', request)
    assert client.main(['jobs', 'submit', '--id', 'stable-1', 'secret command']) == 255
    out = capsys.readouterr()
    assert 'HTTP ' + str(code) in out.err
    assert 'secret' not in out.err
    assert calls == [1]


@pytest.mark.parametrize('accepted', [False, True])
def test_request_accepts_202_only_when_explicit(monkeypatch, accepted):
    class Response:
        status = 202
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def getheader(self, name): return '2'
        def read(self, size): return b'{}'
    class Opener:
        def open(self, *a, **kw): return Response()
    monkeypatch.setattr(client.urllib.request, 'build_opener', lambda *a: Opener())
    kwargs = {'expected_statuses': (200, 202)} if accepted else {}
    if accepted:
        assert client.request('https://ctl.example.test', 'POST', '/jobs/submit', {}, b'{}', **kwargs) == b'{}'
    else:
        with pytest.raises(urllib.error.HTTPError):
            client.request('https://ctl.example.test', 'POST', '/jobs/submit', {}, b'{}', **kwargs)
