"""Local commands only; no phones, network, or persistent credentials."""
import base64
import concurrent.futures
import json
import os
import shutil
import time

import pytest

from http_ctl import jobs


@pytest.fixture
def store(tmp_path):
    instance = jobs.JobStore(str(tmp_path / 'jobs'))
    yield instance
    instance.close()


def submit(store, command='printf hello; printf error >&2', job_id='job', owner='key', timeout=5):
    return store.submit(owner, {'id': job_id, 'cmd': command, 'timeout': timeout}, shutil.which('bash'))


def finished(store, job_id='job', owner='key'):
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        status = store.status(owner, job_id)
        if status['state'] not in jobs.ACTIVE:
            return status
        time.sleep(0.01)
    pytest.fail('job failed to finish')


def output(store, stream='stdout', job_id='job', owner='key'):
    cursor, result = 0, bytearray()
    while True:
        page = store.logs(owner, dict(id=job_id, stream=stream, cursor=cursor, limit=1777))
        result.extend(base64.b64decode(page['data_b64']))
        cursor = page['next_cursor']
        if page['eof']:
            return bytes(result)


def test_streams_exit_and_cursor(store):
    assert submit(store, 'printf hello; printf error >&2; exit 7')[0]
    status = finished(store)
    assert status['state'] == 'exited' and status['exit'] == 7
    assert output(store) == b'hello'
    assert output(store, 'stderr') == b'error'
    page = store.logs('key', dict(id='job', stream='stdout', cursor=2, limit=2))
    assert base64.b64decode(page['data_b64']) == b'll'
    assert page['next_cursor'] == 4 and not page['eof']
    assert 'owner' not in status and 'fingerprint' not in status


def test_idempotency_concurrent_and_conflict(store, tmp_path):
    marker = tmp_path / 'count'
    command = 'printf x >> ' + str(marker)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: submit(store, command), range(8)))
    assert sum(created for created, _ in results) == 1
    finished(store)
    assert marker.read_bytes() == b'x'
    with pytest.raises(jobs.JobError) as exc:
        submit(store, 'printf different')
    assert exc.value.status == 409
    store.close()
    restarted = jobs.JobStore(store.path)
    try:
        assert not submit(restarted, command)[0]
        assert marker.read_bytes() == b'x'
    finally:
        restarted.close()


def test_owner_isolation(store):
    submit(store)
    finished(store)
    for operation in [lambda: store.status('other', 'job'), lambda: store.cancel('other', 'job'),
                      lambda: store.logs('other', {'id': 'job', 'stream': 'stdout'})]:
        with pytest.raises(jobs.JobError) as exc:
            operation()
        assert exc.value.status == 404
    assert submit(store, owner='other')[0]
    finished(store, owner='other')


def test_large_logs_are_not_short_exec_limit(store):
    submit(store, 'head -c 250000 /dev/zero; printf done >&2')
    status = finished(store)
    assert status['state'] == 'exited' and status['exit'] == 0
    assert len(output(store)) == 250000
    assert output(store, 'stderr') == b'done'


def test_output_quota_and_runtime(store):
    submit(store, 'yes noisy')
    status = finished(store)
    assert status['state'] == 'output_limit'
    assert status['stdout_bytes'] + status['stderr_bytes'] == jobs.MAX_OUTPUT
    submit(store, 'sleep 10', job_id='timeout', timeout=1)
    assert finished(store, 'timeout')['state'] == 'timed_out'


def test_cancel_idempotent_and_active_limit(store):
    submit(store, 'sleep 10')
    submit(store, 'sleep 10', job_id='second')
    with pytest.raises(jobs.JobError) as exc:
        submit(store, job_id='third')
    assert exc.value.status == 503
    assert not submit(store, 'sleep 10')[0]
    store.cancel('key', 'job')
    assert finished(store)['state'] == 'cancelled'
    assert store.cancel('key', 'job')['state'] == 'cancelled'
    store.cancel('key', 'second')
    finished(store, 'second')


def test_retained_limit_never_prunes_ids(store, monkeypatch):
    monkeypatch.setattr(jobs, 'MAX_JOBS', 1)
    submit(store)
    finished(store)
    assert not submit(store)[0]
    with pytest.raises(jobs.JobError) as exc:
        submit(store, job_id='second')
    assert exc.value.status == 503


def test_restart_marks_reserved_job_interrupted_without_spawn(store):
    submit(store)
    finished(store)
    token = store._token('key', 'job')
    store.records[token]['state'] = 'starting'
    store.records[token]['exit'] = None
    store._save(token)
    store.close()
    restarted = jobs.JobStore(store.path)
    try:
        assert restarted.status('key', 'job')['state'] == 'interrupted'
        assert not submit(restarted)[0]
        assert output(restarted) == b'hello'
    finally:
        restarted.close()


def test_single_manager_lock_and_private_files(store):
    with pytest.raises(OSError):
        jobs.JobStore(store.path)
    submit(store)
    finished(store)
    for name in os.listdir(store.path):
        assert os.stat(os.path.join(store.path, name)).st_mode & 0o077 == 0


@pytest.mark.parametrize('req', [None, [], {}, {'id': '../x', 'cmd': 'x'}, {'id': 'x', 'cmd': ''},
    {'id': 'x', 'cmd': 'x', 'timeout': True}, {'id': 'x', 'cmd': 'x', 'timeout': 3601},
    {'id': 'x', 'cmd': 'x', 'timeout': 0}, {'id': 'x', 'cmd': 'x\0'}, {'id': 'x', 'cmd': 'x', 'extra': 1}])
def test_invalid_submit(store, req):
    with pytest.raises(ValueError):
        store.submit('key', req, '/bin/bash')
    assert not store.records


def test_invalid_log_cursor(store):
    submit(store)
    finished(store)
    for extra in [{'stream': '../x'}, {'cursor': True}, {'cursor': -1}, {'cursor': 6}, {'limit': 65537}, {'limit': 0}]:
        with pytest.raises(ValueError):
            store.logs('key', {'id': 'job', 'stream': 'stdout', **extra})


def test_http_auth_scope_revocation_and_requests(service):
    service.server.bash = shutil.which('bash')
    def request(action, req, **kwargs):
        return service.request('POST', '/jobs/' + action, json.dumps(req).encode(), content_type='application/json', **kwargs)
    body = {'id': 'httpjob', 'cmd': 'printf hello', 'timeout': 5}
    assert request('submit', body, key_id='health-only').status == 403
    assert request('submit', body).status == 202
    assert request('submit', body).status == 200
    assert request('submit', {**body, 'cmd': 'different'}).status == 409
    finished(service.server.jobs, 'httpjob', 'test-key')
    assert request('status', {'id': 'httpjob'}).json()['state'] == 'exited'
    assert request('logs', {'id': 'httpjob', 'stream': 'stdout'}).json()['data_b64'] == 'aGVsbG8='
    assert request('status', {'id': 'missing'}).status == 404
    assert request('status', {'id': 'httpjob', 'extra': True}).status == 400
    service.data['keys']['test-key']['revoked'] = True
    service.write_config()
    for action, req in [('submit', body), ('status', {'id': 'httpjob'}), ('cancel', {'id': 'httpjob'}), ('logs', {'id': 'httpjob', 'stream': 'stdout'})]:
        assert request(action, req).status == 401


def test_command_environment_and_stdin_are_not_service_secrets(store, monkeypatch):
    monkeypatch.setenv('HTTP_CTL_TEST_SECRET', 'must-not-leak')
    monkeypatch.setenv('BASH_ENV', '/nonexistent/startup-hook')
    submit(store, 'printf "%s:%s" "${HTTP_CTL_TEST_SECRET-unset}" "${BASH_ENV-unset}"; cat')
    assert finished(store)['exit'] == 0
    assert output(store) == b'unset:unset'


def test_close_kills_process_group_and_marks_interrupted(store, tmp_path):
    marker = tmp_path / 'child-done'
    submit(store, '(sleep 1; printf bad > ' + str(marker) + ') & wait')
    deadline = time.monotonic() + 2
    while store.status('key', 'job')['state'] == 'starting' and time.monotonic() < deadline:
        time.sleep(0.01)
    store.close()
    assert store.status('key', 'job')['state'] == 'interrupted'
    time.sleep(1.1)
    assert not marker.exists()


def test_shutdown_does_not_wait_for_background_pipe(store):
    submit(store, 'sleep 100 & printf done')
    assert finished(store)['state'] == 'exited'
    assert output(store) == b'done'


def test_reservation_is_durable_before_spawn_failure(store, monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError('cannot spawn')
    monkeypatch.setattr(jobs.subprocess, 'Popen', unavailable)
    assert submit(store)[0]
    assert finished(store)['state'] == 'failed'
    assert not submit(store)[0]


def test_long_timeout_and_status_when_operation_slots_busy(service):
    service.server.bash = shutil.which('bash')
    assert service.server.operation_slots.acquire(False)
    assert service.server.operation_slots.acquire(False)
    try:
        response = service.request('POST', '/jobs/submit', b'{"id":"long","cmd":"printf ok","timeout":3600}', content_type='application/json')
        assert response.status == 202
        assert response.json()['timeout'] == 3600
        finished(service.server.jobs, 'long', 'test-key')
        assert service.request('POST', '/jobs/status', b'{"id":"long"}', content_type='application/json').status == 200
    finally:
        service.server.operation_slots.release()
        service.server.operation_slots.release()


def test_http_other_shell_key_and_duplicate_json(service):
    service.server.bash = shutil.which('bash')
    service.data['keys']['other-key']['scopes'] = ['shell:exec']
    service.write_config()
    assert service.request('POST', '/jobs/submit', b'{"id":"same","cmd":"true"}', content_type='application/json').status == 202
    for action, payload in [('status', b'{"id":"same"}'), ('cancel', b'{"id":"same"}'), ('logs', b'{"id":"same","stream":"stdout"}')]:
        assert service.request('POST', '/jobs/' + action, payload, content_type='application/json', key_id='other-key', private=service.other_private).status == 404
    assert service.request('POST', '/jobs/submit', b'{"id":"a","id":"b","cmd":"true"}', content_type='application/json').status == 400
    assert service.request('POST', '/jobs/status?x=1', b'{"id":"same"}', content_type='application/json').status == 400


def test_unsafe_temp_hardlink_is_not_truncated(store, tmp_path):
    victim = tmp_path / 'victim'
    victim.write_bytes(b'preserved')
    victim.chmod(0o600)
    token = store._token('key', 'job')
    os.link(victim, os.path.join(store.path, token + '.tmp'))
    with pytest.raises(ValueError):
        submit(store)
    assert victim.read_bytes() == b'preserved'


def test_deep_json_is_bad_request(service):
    body = b'{"id":"deep","cmd":' + b'[' * 1500 + b'0' + b']' * 1500 + b'}'
    assert service.request('POST', '/jobs/submit', body, content_type='application/json').status == 400


def test_main_sigterm_reaches_server_close(monkeypatch):
    import signal
    from http_ctl import server
    closed = []
    class FakeServer:
        def __init__(self, *args):
            pass
        def serve_forever(self):
            os.kill(os.getpid(), signal.SIGTERM)
        def server_close(self):
            closed.append(True)
    monkeypatch.setattr(server, 'Config', lambda _: object())
    monkeypatch.setattr(server, 'Server', FakeServer)
    previous = signal.getsignal(signal.SIGTERM)
    old_umask = os.umask(0o077)
    try:
        server.main()
    finally:
        signal.signal(signal.SIGTERM, previous)
        os.umask(old_umask)
    assert closed == [True]


def test_admission_persistence_failure_never_spawns_or_stays_running(store, monkeypatch):
    def unavailable(_token):
        raise OSError('disk unavailable')
    monkeypatch.setattr(store, '_save', unavailable)
    with pytest.raises(OSError):
        submit(store)
    assert store.status('key', 'job')['state'] == 'failed'
    assert not store.workers
    assert not submit(store)[0]
    with pytest.raises(jobs.JobError) as exc:
        submit(store, job_id='new')
    assert exc.value.status == 503


def test_actual_process_crash_between_reservation_and_spawn(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    directory = str(tmp_path / 'crashed-jobs')
    script = '''
import os, sys
from http_ctl.jobs import JobStore
import http_ctl.jobs as jobs
store = JobStore(sys.argv[1])
jobs.threading.Thread.start = lambda self: os._exit(23)
store.submit('key', {'id': 'reserved', 'cmd': 'printf never', 'timeout': 5}, '/bin/bash')
'''
    result = subprocess.run([sys.executable, '-c', script, directory], cwd=str(Path(__file__).resolve().parents[1]), timeout=5)
    assert result.returncode == 23
    restarted = jobs.JobStore(directory)
    try:
        assert restarted.status('key', 'reserved')['state'] == 'interrupted'
        created, status = submit(restarted, 'printf never', job_id='reserved')
        assert not created and status['state'] == 'interrupted'
        assert output(restarted, job_id='reserved') == b''
    finally:
        restarted.close()
