"""Actual signed HTTPS client -> local proxy -> jobs -> local shell, no phone."""
import base64
import json
import shlex
import shutil
import time
import urllib.error

from cryptography.hazmat.primitives import serialization

from http_ctl import client, server
from test_client import local_https_proxy  # Reuse isolated TLS/CONNECT fixture.


def configure(service, monkeypatch):
    # Daemon and client share this test process, unlike production streams.
    monkeypatch.setattr(server, 'print', lambda *a, **k: None, raising=False)
    pem = service.private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    monkeypatch.setattr(client, 'protected_read', lambda _: pem)
    monkeypatch.setenv('CTL_BASE_URL', 'https://ctl.example.test')
    monkeypatch.setenv('CTL_KEY_ID', 'test-key')
    service.server.bash = shutil.which('bash')


def invoke(capsys, *argv):
    code = client.main(list(argv))
    output = capsys.readouterr()
    return code, json.loads(output.out) if output.out else None


def await_finished(capsys, job_id):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        code, state = invoke(capsys, 'jobs', 'status', job_id)
        assert code == 0
        if state['state'] not in ('starting', 'running'):
            return state
        time.sleep(0.01)
    raise AssertionError('local job did not finish')


def test_https_job_lifecycle_and_binary_pages(local_https_proxy, monkeypatch, capsys):
    service, connects, _ = local_https_proxy
    configure(service, monkeypatch)
    command = 'head -c 150000 /dev/zero; printf done >&2; exit 7'
    code, admitted = invoke(capsys, 'jobs', 'submit', '--id', 'https-job', command)
    assert code == 0 and admitted['id'] == 'https-job'
    state = await_finished(capsys, 'https-job')
    assert state['state'] == 'exited' and state['exit'] == 7
    assert state['stdout_bytes'] == 150000
    cursor, result = 0, bytearray()
    while True:
        code, page = invoke(capsys, 'jobs', 'logs', 'https-job', '--cursor', str(cursor))
        assert code == 0
        result.extend(base64.b64decode(page['data_b64'], validate=True))
        cursor = page['next_cursor']
        if page['eof']:
            break
    assert result == b'\0' * 150000
    code, page = invoke(capsys, 'jobs', 'logs', 'https-job', '--stream', 'stderr')
    assert code == 0 and base64.b64decode(page['data_b64']) == b'done'
    assert connects and all(target == 'ctl.example.test:443' for target in connects)


def test_lost_submit_response_queries_original_not_duplicate(local_https_proxy, monkeypatch, capsys, tmp_path):
    service, _, _ = local_https_proxy
    configure(service, monkeypatch)
    marker = tmp_path / 'executions'
    command = 'printf x >> ' + shlex.quote(str(marker))
    real_request = client.request
    def lost_response(*args, **kwargs):
        real_request(*args, **kwargs)  # Server accepted; caller never receives it.
        raise urllib.error.URLError('test-only dropped response')
    monkeypatch.setattr(client, 'request', lost_response)
    code, result = invoke(capsys, 'jobs', 'submit', '--id', 'lost-response', command)
    assert code == 255 and result is None
    monkeypatch.setattr(client, 'request', real_request)
    state = await_finished(capsys, 'lost-response')
    assert state['state'] == 'exited' and state['exit'] == 0
    assert marker.read_bytes() == b'x'
    code, existing = invoke(capsys, 'jobs', 'submit', '--id', 'lost-response', command)
    assert code == 0 and existing['state'] == 'exited'
    assert marker.read_bytes() == b'x'
