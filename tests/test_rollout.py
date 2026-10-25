"""Migration confirmation tests. Rollback is a state-claim simulation only.

No deployment, service restart script, shell command, phone, or production state
is touched. All keys/state and the extra-process lock target are test fixtures.
"""
import concurrent.futures
import json
import multiprocessing
import os
import threading
import time

import pytest

from http_ctl import auth, client, rollout

ROLLOUT_ID = '0123456789abcdef0123456789abcdef'


@pytest.fixture
def pending_rollout(service):
    deadline = int(time.time()) + 120
    service.data['rollout'] = {'id': ROLLOUT_ID, 'deadline': deadline, 'ack_file': str(service.state / 'rollout-ack.json')}
    service.data['keys']['migration-only'] = service.key_record(service.private, ['migration:confirm'])
    service.write_config()
    state = {'id': ROLLOUT_ID, 'deadline': deadline, 'deadline_monotonic': time.monotonic() + 120, 'boot_id': rollout.boot_id(), 'status': 'pending'}
    rollout.write_state(str(service.state), state)
    return service, state


def confirm_request(service, rollout_id=ROLLOUT_ID, *, headers=None, key_id='migration-only', body=None):
    body = json.dumps({'rollout_id': rollout_id}, separators=(',', ':')).encode() if body is None else body
    return service.request('POST', '/migration/confirm', body, headers=headers, key_id=key_id)


def test_signed_confirmation_records_private_ack_and_confirmed_state(pending_rollout):
    service, state = pending_rollout
    response = confirm_request(service)
    assert response.status == 200
    assert response.json() == {'ok': True, 'rollout_id': ROLLOUT_ID}
    ack = service.state / 'rollout-ack.json'
    assert json.loads(ack.read_text()) == {'id': ROLLOUT_ID, 'deadline': state['deadline']}
    assert ack.stat().st_mode & 0o777 == 0o600
    assert rollout.read_state(str(service.state)) == dict(state, status='confirmed')
    assert (service.state / 'rollout-state.json').stat().st_mode & 0o777 == 0o600
    assert (service.state / '.rollout-lock').stat().st_mode & 0o777 == 0o600
    assert not list(service.state.glob('.rollout-*.[0-9a-f]*'))


def test_confirmation_key_has_no_shell_files_or_device_scope(pending_rollout):
    service, _ = pending_rollout
    assert service.request(key_id='migration-only').status == 403
    assert service.request('POST', '/exec', b'{"cmd":"not run"}', key_id='migration-only').status == 403
    assert service.request('POST', '/upload?path=x', b'no', key_id='migration-only').status == 403
    assert service.request('GET', '/screenshot', key_id='migration-only').status == 403
    assert confirm_request(service).status == 200


def test_health_scope_cannot_confirm_rollout(pending_rollout):
    service, _ = pending_rollout
    assert confirm_request(service, key_id='health-only').status == 403
    assert rollout.read_state(str(service.state))['status'] == 'pending'
    assert not (service.state / 'rollout-ack.json').exists()


def test_confirmation_replay_rejected_but_fresh_retry_is_idempotent(pending_rollout):
    service, _ = pending_rollout
    body = json.dumps({'rollout_id': ROLLOUT_ID}, separators=(',', ':')).encode()
    headers = service.headers('POST', '/migration/confirm', body, key_id='migration-only')
    assert confirm_request(service, body=body, headers=headers).status == 200
    assert confirm_request(service, body=body, headers=headers).status == 401
    assert confirm_request(service).status == 200


@pytest.mark.parametrize('kind', ['wrong_id', 'wrong_id_type', 'wall_expired', 'monotonic_expired', 'missing_state', 'different_boot', 'rolling_back', 'rolled_back', 'wrong_state_id', 'wrong_state_deadline', 'bad_monotonic_type', 'state_symlink'])
def test_unavailable_rollout_cannot_be_confirmed(pending_rollout, kind, tmp_path):
    service, state = pending_rollout
    requested_id = ROLLOUT_ID
    if kind == 'wrong_id':
        requested_id = 'f' * 32
    elif kind == 'wrong_id_type':
        requested_id = 123
    elif kind == 'wall_expired':
        service.data['rollout']['deadline'] = int(time.time()) - 1
        service.write_config()
        state['deadline'] = service.data['rollout']['deadline']
    elif kind == 'monotonic_expired':
        state['deadline_monotonic'] = time.monotonic() - 1
    elif kind == 'missing_state':
        (service.state / 'rollout-state.json').unlink()
    elif kind == 'different_boot':
        state['boot_id'] = 'another-boot'
    elif kind == 'rolling_back':
        state['status'] = 'rolling_back'
    elif kind == 'rolled_back':
        state['status'] = 'rolled_back'
    elif kind == 'wrong_state_id':
        state['id'] = 'f' * 32
    elif kind == 'wrong_state_deadline':
        state['deadline'] += 1
    elif kind == 'bad_monotonic_type':
        state['deadline_monotonic'] = True
    elif kind == 'state_symlink':
        outside = tmp_path / 'outside-state'
        outside.write_text(json.dumps(state))
        outside.chmod(0o600)
        (service.state / 'rollout-state.json').unlink()
        (service.state / 'rollout-state.json').symlink_to(outside)
    if kind not in ('missing_state', 'state_symlink'):
        rollout.write_state(str(service.state), state)
    assert confirm_request(service, requested_id).status == 409
    assert not (service.state / 'rollout-ack.json').exists()


def test_confirmation_without_configured_rollout_rejected(service):
    assert confirm_request(service, key_id='test-key').status == 409


@pytest.mark.parametrize('body', [b'{}', b'[]', b'{"rollout_id":"x","unexpected":1}', b'{"rollout_id":"x","rollout_id":"y"}'])
def test_confirmation_requires_exact_unique_json_body(pending_rollout, body):
    service, _ = pending_rollout
    assert confirm_request(service, body=body).status == 400


@pytest.mark.parametrize('mutation', ['bad_id', 'bad_deadline_type', 'unbounded_deadline', 'wrong_ack_path', 'extra_field'])
def test_rollout_config_bounded_and_ack_confined(pending_rollout, mutation):
    service, _ = pending_rollout
    value = service.data['rollout']
    if mutation == 'bad_id':
        value['id'] = 'X' * 32
    elif mutation == 'bad_deadline_type':
        value['deadline'] = True
    elif mutation == 'unbounded_deadline':
        value['deadline'] = int(time.time()) + 901
    elif mutation == 'wrong_ack_path':
        value['ack_file'] = str(service.root / 'elsewhere')
    else:
        value['extra'] = True
    service.write_config()
    with pytest.raises(ValueError):
        auth.Config(str(service.config_path))


def _hold_test_lock(directory, ready, release):
    with rollout.locked_state(directory):
        ready.set()
        release.wait(5)


def test_other_process_lock_fails_fast_without_confirmation(pending_rollout):
    service, _ = pending_rollout
    context = multiprocessing.get_context('spawn')
    ready, release = context.Event(), context.Event()
    process = context.Process(target=_hold_test_lock, args=(str(service.state), ready, release))
    process.start()
    try:
        assert ready.wait(3)
        started = time.monotonic()
        assert confirm_request(service).status == 409
        assert time.monotonic() - started < 2
        assert rollout.read_state(str(service.state))['status'] == 'pending'
        assert not (service.state / 'rollout-ack.json').exists()
    finally:
        release.set()
        process.join(timeout=3)
        if process.is_alive():
            process.terminate()
            process.join(timeout=3)
    assert process.exitcode == 0
    assert confirm_request(service).status == 200


@pytest.mark.parametrize('iteration', range(10))
def test_confirmation_and_simulated_rollback_claim_are_mutually_exclusive(pending_rollout, iteration):
    service, _ = pending_rollout
    barrier = threading.Barrier(2)
    def confirm():
        barrier.wait(timeout=3)
        try:
            rollout.confirm(service.server.config, ROLLOUT_ID)
            return 'confirmed'
        except (rollout.RolloutUnavailable, OSError):
            return 'lost'
    def simulated_rollback_claim():
        # Models only the watchdog's lock/state claim. This test never invokes
        # rollback commands or changes services.
        barrier.wait(timeout=3)
        try:
            with rollout.locked_state(str(service.state)):
                current = rollout.read_state(str(service.state))
                if current['status'] != 'pending':
                    return 'lost'
                current['status'] = 'rolling_back'
                rollout.write_state(str(service.state), current)
                return 'rolling_back'
        except (rollout.RolloutUnavailable, OSError):
            return 'lost'
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(confirm)
        b = pool.submit(simulated_rollback_claim)
        results = [a.result(timeout=3), b.result(timeout=3)]
    assert results.count('lost') == 1
    winner = next(item for item in results if item != 'lost')
    assert rollout.read_state(str(service.state))['status'] == winner
    assert (service.state / 'rollout-ack.json').exists() == (winner == 'confirmed')


def test_confirmation_atomically_replaces_symlink_ack(pending_rollout, tmp_path):
    service, _ = pending_rollout
    outside = tmp_path / 'outside-ack'
    outside.write_bytes(b'preserve')
    ack = service.state / 'rollout-ack.json'
    ack.symlink_to(outside)
    assert confirm_request(service).status == 200
    assert not ack.is_symlink()
    assert outside.read_bytes() == b'preserve'


def test_cli_migration_confirm_signs_only_exact_id(pending_rollout, monkeypatch, tmp_path, capsys):
    from cryptography.hazmat.primitives import serialization
    service, _ = pending_rollout
    path = tmp_path / 'migration-test-only.pem'
    path.write_bytes(service.private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.chmod(0o600)
    monkeypatch.setenv('CTL_BASE_URL', 'https://ctl.example.test')
    monkeypatch.setenv('CTL_KEY_ID', 'migration-only')
    monkeypatch.setenv('CTL_PRIVATE_KEY_FILE', str(path))
    calls = []
    def local_request(base, method, target, headers, body):
        calls.append((base, method, target, json.loads(body)))
        response = service.request(method, target, body, headers=headers)
        assert response.status == 200
        return response.body
    monkeypatch.setattr(client, 'request', local_request)
    assert client.main(['migration-confirm', ROLLOUT_ID]) == 0
    assert calls == [('https://ctl.example.test', 'POST', '/migration/confirm', {'rollout_id': ROLLOUT_ID})]
    assert rollout.read_state(str(service.state))['status'] == 'confirmed'


@pytest.mark.parametrize('body', [b'{"rollout_id":"0123456789abcdef0123456789abcdef","path":"/arbitrary"}', b'{"rollout_id":"0123456789abcdef0123456789abcdef","duration":900}'])
def test_confirmation_never_accepts_client_paths_or_durations(pending_rollout, body):
    service, _ = pending_rollout
    assert confirm_request(service, body=body).status == 400


def test_killed_lock_holder_does_not_leave_persistent_flock(pending_rollout):
    service, _ = pending_rollout
    context = multiprocessing.get_context('spawn')
    ready, release = context.Event(), context.Event()
    process = context.Process(target=_hold_test_lock, args=(str(service.state), ready, release))
    process.start()
    try:
        assert ready.wait(3)
        assert confirm_request(service).status == 409
        process.kill()
        process.join(timeout=3)
        assert not process.is_alive()
        assert confirm_request(service).status == 200
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=3)


@pytest.mark.parametrize('malformed', [[], None, 'not a state', 7])
def test_malformed_rollout_state_fails_closed_with_controlled_response(pending_rollout, malformed):
    service, _ = pending_rollout
    rollout.atomic_json(str(service.state / 'rollout-state.json'), malformed)
    assert confirm_request(service).status == 409
    assert not (service.state / 'rollout-ack.json').exists()


def test_unsigned_confirmation_never_changes_state(pending_rollout):
    service, _ = pending_rollout
    body = json.dumps({'rollout_id': ROLLOUT_ID}).encode()
    headers = {'Content-Type': 'application/json', 'Content-Length': str(len(body))}
    assert confirm_request(service, body=body, headers=headers).status == 401
    assert rollout.read_state(str(service.state))['status'] == 'pending'
    assert not (service.state / 'rollout-ack.json').exists()
