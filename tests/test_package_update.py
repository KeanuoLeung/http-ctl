"""Local-filesystem and mocked-supervisor tests, never phone operations."""
import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def updater():
    path = Path(__file__).resolve().parents[1] / 'examples/termux-package-update.py'
    spec = importlib.util.spec_from_file_location('package_updater', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def packages(tmp_path):
    release, stage = tmp_path / 'release', tmp_path / 'stage'
    for root, marker in ((release, 'previous signed v2'), (stage, 'new signed v2')):
        package = root / 'http_ctl'
        package.mkdir(parents=True)
        (package / '__init__.py').write_text('')
        (package / 'server.py').write_text(marker)
    return release, stage


def test_success_retains_previous_package(updater, packages, monkeypatch):
    release, stage = packages
    calls = []
    monkeypatch.setattr(updater, 'sv', lambda service, command: calls.append(command))
    monkeypatch.setattr(updater, 'readiness', lambda *a, **kw: calls.append(('ready', kw)))
    backup = updater.cutover(release, stage, Path('/fake/service'), lambda: None)
    assert (backup / 'server.py').read_text() == 'previous signed v2'
    assert (release / 'http_ctl/server.py').read_text() == 'new signed v2'
    assert calls == ['down', 'up', ('ready', {'hierarchy': True})]


def test_failed_readiness_restores_signed_v2_once(updater, packages, monkeypatch):
    release, stage = packages
    calls = []
    monkeypatch.setattr(updater, 'sv', lambda service, command: calls.append(command))
    def ready(port, hierarchy=False):
        if hierarchy:
            raise RuntimeError('missing hierarchy')
    monkeypatch.setattr(updater, 'readiness', ready)
    with pytest.raises(RuntimeError, match='previous signed-v2 package is running'):
        updater.cutover(release, stage, Path('/fake/service'), lambda: None)
    assert calls == ['down', 'up', 'down', 'up']
    assert (release / 'http_ctl/server.py').read_text() == 'previous signed v2'
    assert (stage / 'failed-http_ctl/server.py').read_text() == 'new signed v2'


def test_recovery_failure_does_not_loop(updater, packages, monkeypatch):
    release, stage = packages
    calls = []
    monkeypatch.setattr(updater, 'sv', lambda service, command: calls.append(command))
    monkeypatch.setattr(updater, 'readiness', lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('offline')))
    with pytest.raises(RuntimeError, match='one signed-v2 recovery attempt also failed'):
        updater.cutover(release, stage, Path('/fake/service'), lambda: None)
    assert calls == ['down', 'up', 'down', 'up']
    assert (release / 'http_ctl/server.py').read_text() == 'previous signed v2'


def test_stop_failure_does_not_swap(updater, packages, monkeypatch):
    release, stage = packages
    calls = []
    def sv(service, command):
        calls.append(command)
        if command == 'down':
            raise RuntimeError('stop failed')
    monkeypatch.setattr(updater, 'sv', sv)
    monkeypatch.setattr(updater, 'readiness', lambda *a, **kw: None)
    with pytest.raises(RuntimeError):
        updater.cutover(release, stage, Path('/fake/service'), lambda: None)
    assert calls == ['down', 'up']
    assert (release / 'http_ctl/server.py').read_text() == 'previous signed v2'
    assert not (stage / 'previous-http_ctl').exists()


def test_symlink_package_rejected(updater, packages):
    release, stage = packages
    (stage / 'http_ctl/linked.py').symlink_to(release / 'http_ctl/server.py')
    with pytest.raises(RuntimeError, match='Expected an owned'):
        updater.package_digest(stage / 'http_ctl')


def test_noncode_package_rejected(updater, packages):
    _, stage = packages
    (stage / 'http_ctl/private.pem').write_text('not a real key')
    with pytest.raises(RuntimeError, match='Unexpected package content'):
        updater.package_digest(stage / 'http_ctl')


def test_configuration_drift_during_stop_restores_only_service(updater, packages, monkeypatch):
    release, stage = packages
    calls, validations = [], []
    monkeypatch.setattr(updater, 'sv', lambda service, command: calls.append(command))
    monkeypatch.setattr(updater, 'readiness', lambda *a, **kw: None)
    def validate():
        validations.append(1)
        if len(validations) == 2:
            raise RuntimeError('config drift')
    with pytest.raises(RuntimeError):
        updater.cutover(release, stage, Path('/fake/service'), validate)
    assert calls == ['down', 'up']
    assert (release / 'http_ctl/server.py').read_text() == 'previous signed v2'


def test_real_loopback_readiness_no_adb(updater, service):
    updater.readiness(service.server.server_address[1], hierarchy=True, timeout=1)


def test_real_loopback_missing_route_is_not_ready(updater, service, monkeypatch):
    from http_ctl import server
    monkeypatch.delitem(server.ROUTES, ('GET', '/ui/hierarchy'))
    with pytest.raises(RuntimeError, match='readiness failed'):
        updater.readiness(service.server.server_address[1], hierarchy=True, timeout=0.05)


def test_exited_sidecar_not_ready(updater):
    class Exited:
        def poll(self):
            return 1
    with pytest.raises(RuntimeError, match='sidecar exited'):
        updater.readiness(1, hierarchy=True, process=Exited(), timeout=1)


def test_sidecar_exit_during_probe_is_not_ready(updater, service):
    class ExitsDuringProbe:
        def __init__(self):
            self.polls = 0
        def poll(self):
            self.polls += 1
            return None if self.polls == 1 else 1
    with pytest.raises(RuntimeError, match='sidecar exited'):
        updater.readiness(service.server.server_address[1], hierarchy=True, process=ExitsDuringProbe(), timeout=1)


def test_sidecar_configuration_deep_copies_and_revokes_all_keys(updater):
    import copy
    original = {'replay_db': '/production/nonces', 'keys': {
        'active': {'scopes': ['ui:control'], 'revoked': False},
        'implicit': {'scopes': ['health:read']},
        'retired': {'scopes': [], 'revoked': True},
    }}
    before = copy.deepcopy(original)
    candidate = updater.sidecar_configuration(original, '/isolated/nonces')
    assert original == before
    assert candidate['replay_db'] == '/isolated/nonces'
    assert all(key['revoked'] is True for key in candidate['keys'].values())
    candidate['keys']['active']['scopes'].append('health:read')
    assert original == before


def test_production_signed_ui_cannot_execute_or_replay_on_sidecar(updater, service, tmp_path, monkeypatch):
    import http.client
    import json
    import sqlite3
    import threading
    from http_ctl import auth, server
    production_config_bytes = service.config_path.read_bytes()
    side_state = tmp_path / 'sidecar-state'
    side_state.mkdir(mode=0o700)
    config_path = side_state / 'sidecar.json'
    replay = side_state / 'nonces.sqlite3'
    config_path.write_text(json.dumps(updater.sidecar_configuration(service.data, replay)))
    config_path.chmod(0o600)
    calls = []
    def operation(*args, **kwargs):
        calls.append(args)
        return (0, b'', b'', False, False)
    monkeypatch.setattr(server, 'run_bounded', operation)
    body = b'{"action":"keyevent","key":"HOME"}'
    headers = service.headers('POST', '/ui', body)
    # Prove the exact signed request is valid and has executed once at production.
    result = service.request('POST', '/ui', body, headers=headers)
    assert result.status == 200
    assert len(calls) == 1
    sidecar = server.Server(('127.0.0.1', 0), auth.Config(str(config_path)))
    sidecar.adb = '/test-only/adb-not-executed'
    thread = threading.Thread(target=sidecar.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
    thread.start()
    conn = http.client.HTTPConnection('127.0.0.1', sidecar.server_address[1], timeout=2)
    try:
        updater.readiness(sidecar.server_address[1], hierarchy=True, timeout=1)
        conn.request('POST', '/ui', body=body, headers=headers)
        response = conn.getresponse()
        assert response.status == 401
        assert response.read() == b'{"error": "unauthorized"}'
        assert len(calls) == 1  # No second execution on the independent replay DB.
        with sqlite3.connect(replay) as database:
            assert database.execute('SELECT count(*) FROM nonces').fetchone()[0] == 0
        assert service.config_path.read_bytes() == production_config_bytes
    finally:
        conn.close()
        sidecar.shutdown()
        sidecar.server_close()
        thread.join(timeout=3)
