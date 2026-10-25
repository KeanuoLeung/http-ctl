"""Failure-window tests for the reviewed Termux helper, WITHOUT running it.

Only Python imports/function definitions are AST-extracted from its heredoc.
main(), phone checks, shell launcher, subprocesses, service changes, package
installation, and network operations are never executed. Files are test-local;
all run/Popen/probe/socket interactions below are explicit mocks.
"""
import ast
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from http_ctl import auth, rollout


@pytest.fixture
def deployment(service, tmp_path):
    script = Path(__file__).resolve().parents[1] / 'examples/termux-phone-deploy.sh'
    source = script.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
    tree = ast.parse(source, filename=str(script))
    definitions = ast.Module(body=[node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))], type_ignores=[])
    ns = {'__name__': 'test_only_deployment_definitions'}
    exec(compile(definitions, str(script), 'exec'), ns)
    old_umask = os.umask(0o077)
    state, service_dir = tmp_path / 'migration', tmp_path / 'mock-service'
    state.mkdir(mode=0o700)
    service_dir.mkdir(mode=0o700)
    original = b'#!/test-only/sh\n# legacy marker, NEVER EXECUTED\n'
    production = b'#!/test-only/sh\n# v2 marker, NEVER EXECUTED\n'
    (service_dir / 'run').write_bytes(original)
    (service_dir / 'run').chmod(0o700)
    (state / 'legacy-run').write_bytes(original)
    (state / 'launch-production').write_bytes(production)
    (state / 'launch-stage').write_bytes(b'stage marker')
    (state / 'deploy.sh').write_bytes(b'deployment marker')
    probe_path = state / 'test-only-probe.json'
    probe_path.write_bytes(b'{}')
    config = {'external_origin': 'https://ctl.example.test', 'replay_db': str(state / 'replay.sqlite3'), 'keys': {'health-key': service.key_record(service.private, ['health:read'])}}
    (state / 'server.json').write_text(json.dumps(config))
    calls, probes, popens, connections, events = [], [], [], [], []
    controls = {'watchdog': 'ready', 'probe_error': False, 'run_error': None, 'listener_results': [0], 'listener_default': 0}
    ns.update(STATE=state, SERVICE=service_dir, HOME=tmp_path, PREFIX=tmp_path / 'mock-termux', SOURCE=script.parents[1])
    ns['fingerprint'] = lambda: 'reviewed-test-fingerprint'
    ns['rollout_api'] = lambda: rollout
    ns['service_status'] = lambda: 'run: mocked-service: (pid test) 1s'
    def run(args, **kwargs):
        args = [str(a) for a in args]
        calls.append((args, kwargs))
        events.append(('run', args[3] if len(args) > 3 else tuple(args)))
        if controls['run_error'] and controls['run_error'](args):
            raise RuntimeError('simulated service operation failure')
        return SimpleNamespace(stdout='run: mocked-service')
    ns['run'] = run
    def probe(path, port):
        probes.append((path, port))
        events.append(('probe', port))
        if controls['probe_error']:
            raise RuntimeError('simulated local signed probe failure')
    ns['probe'] = probe
    class SocketMock:
        def __init__(self, *args, **kwargs):
            pass
        def settimeout(self, timeout):
            assert 0 < timeout <= 15
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def connect_ex(self, address):
            assert address[0] == '127.0.0.1'
            connections.append(address)
            if address[1] == 18082:
                return 111
            assert address[1] == 18081
            # sv up is only a supervisor state, not proof the listener exists.
            assert calls and calls[-1][0][3] == 'up'
            assert probes == []
            assert (service_dir / 'run').read_bytes() == production
            result = controls['listener_results'].pop(0) if controls['listener_results'] else controls['listener_default']
            events.append(('tcp', result))
            return result
    import socket
    ns['socket'] = SimpleNamespace(socket=SocketMock, AF_INET=socket.AF_INET, SOCK_STREAM=socket.SOCK_STREAM)
    class PopenMock:
        pid = 123456
        def __init__(self, args, **kwargs):
            popens.append((args, kwargs))
            # At the exact moment the independent watchdog is launched, the
            # live run file must still be legacy and no sv stop may have run.
            assert (service_dir / 'run').read_bytes() == original
            assert calls == []
            if controls['watchdog'] in ('ready', 'bad-marker'):
                data = ns['record']()
                marker = {'pid': self.pid, 'id': data['rollout_id'], 'deadline': data['rollout_deadline']}
                if controls['watchdog'] == 'bad-marker':
                    marker['id'] = 'wrong'
                rollout.atomic_json(str(state / 'watchdog-ready.json'), marker)
        def poll(self):
            return 1 if controls['watchdog'] == 'exited' else None
    import subprocess
    ns['subprocess'] = SimpleNamespace(Popen=PopenMock, DEVNULL=subprocess.DEVNULL, STDOUT=subprocess.STDOUT)
    import time
    monotonic_start, elapsed = time.monotonic(), [0.0]
    def advance(seconds):
        elapsed[0] += seconds
    ns['time'] = SimpleNamespace(time=time.time, monotonic=lambda: monotonic_start + elapsed[0], sleep=advance)
    data = {'service': str(service_dir), 'phase': 'verified', 'verified_at': int(time.time()), 'created': int(time.time()), 'original_sha256': ns['digest'](service_dir / 'run'), 'original_mode': 0o700, 'rollout_id': '0123456789abcdef0123456789abcdef', 'fingerprint': 'reviewed-test-fingerprint'}
    ns['write_record'](data)
    try:
        yield SimpleNamespace(ns=ns, state=state, service=service_dir, original=original, production=production, calls=calls, probes=probes, popens=popens, controls=controls, probe=probe_path, connections=connections, events=events, elapsed=elapsed)
    finally:
        os.umask(old_umask)


def cutover(deployment):
    deployment.ns['cutover'](deployment.probe, True, 'health-key', 300)


@pytest.mark.parametrize('watchdog', ['absent', 'exited', 'bad-marker'])
def test_cutover_never_stops_legacy_without_independent_watchdog_ready(deployment, watchdog):
    deployment.controls['watchdog'] = watchdog
    with pytest.raises(RuntimeError, match='watchdog did not confirm readiness'):
        cutover(deployment)
    assert deployment.calls == []
    assert deployment.probes == []
    assert (deployment.service / 'run').read_bytes() == deployment.original
    assert (deployment.state / 'legacy-run').read_bytes() == deployment.original
    assert deployment.ns['record']()['phase'] == 'rollout-arming'


def test_cutover_local_probe_failure_restores_only_legacy_run_once(deployment):
    deployment.controls['probe_error'] = True
    unrelated = deployment.service / 'unrelated-log'
    unrelated.write_bytes(b'logs must remain')
    with pytest.raises(RuntimeError, match='simulated local signed probe failure'):
        cutover(deployment)
    assert (deployment.service / 'run').read_bytes() == deployment.original
    assert (deployment.state / 'legacy-run').read_bytes() == deployment.original
    assert unrelated.read_bytes() == b'logs must remain'
    assert [args[3] for args, _ in deployment.calls] == ['down', 'up', 'down', 'up']
    assert deployment.probes == [(deployment.probe, 18081)]
    assert deployment.ns['record']()['phase'] == 'rolled-back'
    assert rollout.read_state(str(deployment.state))['status'] == 'rolled-back'
    config = json.loads((deployment.state / 'server.json').read_text())
    assert 'rollout' not in config
    assert config['keys']['health-key']['scopes'] == ['health:read']
    deployment.ns['perform_rollback'](deployment.ns['record']())
    assert len(deployment.calls) == 4  # No second service restore.


def test_cutover_success_is_pending_until_signed_external_confirmation(deployment):
    cutover(deployment)
    assert (deployment.service / 'run').read_bytes() == deployment.production
    assert [args[3] for args, _ in deployment.calls] == ['down', 'up']
    assert deployment.ns['record']()['phase'] == 'rollout-awaiting-confirm'
    assert rollout.read_state(str(deployment.state))['status'] == 'pending'
    assert not (deployment.state / 'rollout-ack.json').exists()
    assert len(deployment.popens) == 1
    _, kwargs = deployment.popens[0]
    assert kwargs['start_new_session'] is True
    assert kwargs['close_fds'] is True


def test_cutover_requires_explicit_rollback_guard(deployment):
    with pytest.raises(RuntimeError, match='requires --rollback-on-failure'):
        deployment.ns['cutover'](deployment.probe, False, 'health-key', 300)
    assert deployment.calls == []
    assert deployment.popens == []
    assert (deployment.service / 'run').read_bytes() == deployment.original


def test_cutover_refuses_independently_modified_run_file(deployment):
    (deployment.service / 'run').write_bytes(b'independently changed')
    with pytest.raises(RuntimeError, match='changed since the backup'):
        cutover(deployment)
    assert deployment.calls == []
    assert deployment.popens == []
    assert (deployment.service / 'run').read_bytes() == b'independently changed'


def test_rollback_refuses_changed_backup_and_changed_live_file(deployment):
    data = deployment.ns['record']()
    (deployment.state / 'legacy-run').write_bytes(b'changed backup')
    with pytest.raises(RuntimeError, match='backup no longer matches'):
        deployment.ns['rollback'](data)
    assert deployment.calls == []
    (deployment.state / 'legacy-run').write_bytes(deployment.original)
    (deployment.service / 'run').write_bytes(b'unknown live run')
    with pytest.raises(RuntimeError, match='changed outside this migration'):
        deployment.ns['rollback'](data)
    assert deployment.calls == []


@pytest.mark.parametrize('crash_phase', ['cutover-started', 'cutover-start-pending', 'rollout-awaiting-confirm'])
def test_signed_confirmation_watchdog_retires_temporary_access(deployment, crash_phase):
    cutover(deployment)
    ns = deployment.ns
    # Run the real watchdog state machine with a mocked external confirmation
    # arriving just after its arming check, not a service or network operation.
    data = ns['record']()
    data['phase'] = 'rollout-arming'
    ns['write_record'](data)
    original_record = ns['record']
    reads = [0]
    def record_with_confirmation():
        reads[0] += 1
        current = original_record()
        if reads[0] == 2:
            config = auth.Config(str(deployment.state / 'server.json'))
            assert rollout.confirm(config, current['rollout_id']) == current['rollout_id']
            current['phase'] = crash_phase
            ns['write_record'](current)
        return current
    ns['record'] = record_with_confirmation
    ns['watch_rollout']()
    assert original_record()['phase'] == 'complete'
    assert rollout.read_state(str(deployment.state))['status'] == 'confirmed'
    config = json.loads((deployment.state / 'server.json').read_text())
    assert 'rollout' not in config
    assert config['keys']['health-key']['scopes'] == ['health:read']
    assert len(deployment.calls) == 2  # No rollback after acceptance.
    assert (deployment.service / 'run').read_bytes() == deployment.production


def test_expired_watchdog_restores_once_and_removes_grant(deployment):
    cutover(deployment)
    ns = deployment.ns
    data = ns['record']()
    data['phase'] = 'rollout-arming'
    ns['write_record'](data)
    state = rollout.read_state(str(deployment.state))
    state['deadline_monotonic'] = 0
    rollout.write_state(str(deployment.state), state)
    ns['watch_rollout']()
    assert ns['record']()['phase'] == 'rolled-back'
    assert rollout.read_state(str(deployment.state))['status'] == 'rolled-back'
    assert (deployment.service / 'run').read_bytes() == deployment.original
    assert len(deployment.calls) == 4
    ns['perform_rollback'](ns['record']())
    assert len(deployment.calls) == 4
    assert 'rollout' not in json.loads((deployment.state / 'server.json').read_text())


def test_automatic_rollback_cannot_override_confirmed_state(deployment):
    cutover(deployment)
    config = auth.Config(str(deployment.state / 'server.json'))
    rollout.confirm(config, deployment.ns['record']()['rollout_id'])
    assert deployment.ns['perform_rollback'](deployment.ns['record']()) is False
    assert len(deployment.calls) == 2
    assert (deployment.service / 'run').read_bytes() == deployment.production


def test_operation_flock_exclusion_and_release(deployment):
    first = deployment.ns['operation_lock']()
    try:
        with pytest.raises(RuntimeError, match='Another live operation'):
            deployment.ns['operation_lock']()
    finally:
        os.close(first)
    second = deployment.ns['operation_lock']()
    os.close(second)
    assert (deployment.state / '.operation-lock').exists()  # Existing file is not a stale lock.


def _hold_operation_file(path, ready, release):
    import fcntl
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ready.set()
        release.wait(5)
    finally:
        os.close(fd)


def test_dead_cutover_process_releases_operation_lock(deployment):
    import multiprocessing
    context = multiprocessing.get_context('spawn')
    ready, release = context.Event(), context.Event()
    process = context.Process(target=_hold_operation_file, args=(str(deployment.state / '.operation-lock'), ready, release))
    process.start()
    try:
        assert ready.wait(3)
        with pytest.raises(RuntimeError, match='Another live operation'):
            deployment.ns['operation_lock']()
        process.kill()
        process.join(timeout=3)
        assert not process.is_alive()
        fd = deployment.ns['operation_lock']()
        os.close(fd)
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=3)


def test_watchdog_can_recover_crash_before_live_run_replacement(deployment):
    cutover(deployment)
    ns = deployment.ns
    # Reconstruct the crash window after watchdog arming but before replace_run.
    (deployment.service / 'run').write_bytes(deployment.original)
    deployment.calls.clear()
    data = ns['record']()
    data['phase'] = 'rollout-arming'
    ns['write_record'](data)
    state = rollout.read_state(str(deployment.state))
    state['deadline_monotonic'] = 0
    rollout.write_state(str(deployment.state), state)
    ns['watch_rollout']()
    assert ns['record']()['phase'] == 'rolled-back'
    assert (deployment.service / 'run').read_bytes() == deployment.original
    assert len(deployment.calls) == 2


def test_delayed_listener_readiness_never_consumes_probe_before_bind(deployment):
    deployment.controls['listener_results'] = [111, 111, 111, 0]
    cutover(deployment)
    assert deployment.connections == [('127.0.0.1', 18082)] + [('127.0.0.1', 18081)] * 4
    assert deployment.events == [('run', 'down'), ('run', 'up'), ('tcp', 111), ('tcp', 111), ('tcp', 111), ('tcp', 0), ('probe', 18081)]
    assert deployment.probes == [(deployment.probe, 18081)]
    assert deployment.elapsed[0] > 0
    assert deployment.ns['record']()['phase'] == 'rollout-awaiting-confirm'
    assert (deployment.service / 'run').read_bytes() == deployment.production


def test_listener_startup_timeout_rolls_back_without_any_signed_probe(deployment):
    deployment.controls['listener_results'] = []
    deployment.controls['listener_default'] = 111
    with pytest.raises(RuntimeError):
        cutover(deployment)
    assert deployment.probes == []
    assert deployment.elapsed[0] == pytest.approx(15, abs=0.001)
    assert [args[3] for args, _ in deployment.calls] == ['down', 'up', 'down', 'up']
    assert (deployment.service / 'run').read_bytes() == deployment.original
    assert deployment.ns['record']()['phase'] == 'rolled-back'
    assert rollout.read_state(str(deployment.state))['status'] == 'rolled-back'
    assert 'rollout' not in json.loads((deployment.state / 'server.json').read_text())


def test_ready_listener_does_not_retry_failed_one_use_probe(deployment):
    deployment.controls['listener_results'] = [111, 0]
    deployment.controls['probe_error'] = True
    with pytest.raises(RuntimeError, match='simulated local signed probe failure'):
        cutover(deployment)
    assert deployment.probes == [(deployment.probe, 18081)]
    assert deployment.events == [('run', 'down'), ('run', 'up'), ('tcp', 111), ('tcp', 0), ('probe', 18081), ('run', 'down'), ('run', 'up')]
    assert (deployment.service / 'run').read_bytes() == deployment.original
    assert deployment.ns['record']()['phase'] == 'rolled-back'
