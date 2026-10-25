#!/usr/bin/env python3
"""Local-only, package-only update of an already migrated signed-v2 service.

No installs, credentials, legacy fallback, remote transport, or run-file edits.
See termux-package-update.md. Run explicitly from a reviewed source checkout.
"""
import argparse
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import shlex
import stat
import subprocess
import tempfile
import time


def checked_path(path, directory=False):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise RuntimeError(f"Expected an owned, non-writable-by-others {'directory' if directory else 'file'}: {path}")


def package_digest(package):
    checked_path(package, directory=True)
    digest = hashlib.sha256()
    count = 0
    for item in sorted(package.rglob('*')):
        if '__pycache__' in item.parts:
            continue
        checked_path(item, directory=item.is_dir())
        if item.is_file():
            if item.suffix != '.py':
                raise RuntimeError(f'Unexpected package content: {item.name}')
            digest.update(item.relative_to(package).as_posix().encode() + b'\0')
            digest.update(item.read_bytes() + b'\0')
            count += 1
    if not count or not (package / 'server.py').is_file() or not (package / '__init__.py').is_file():
        raise RuntimeError('Incomplete package')
    return digest.hexdigest()


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, timeout=20, **kwargs)


def sv(service, command):
    run(['sv', '-w', '10', command, service], stdout=subprocess.DEVNULL)


def readiness(port, hierarchy=False, process=None, timeout=12):
    """Require signed-v2's denial response; never bypass auth or perform a UI action."""
    deadline = time.monotonic() + timeout
    paths = ['/health', '/ui/hierarchy'] if hierarchy else ['/health']
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError('Candidate sidecar exited')
        passed = True
        for path in paths:
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
            try:
                conn.request('GET', path, headers={'Content-Type': 'application/octet-stream'})
                response = conn.getresponse()
                passed = passed and response.status == 401 and response.getheader('Cache-Control') == 'no-store' and response.getheader('X-Content-Type-Options') == 'nosniff' and response.read(1024) == b'{"error": "unauthorized"}'
            except (OSError, http.client.HTTPException):
                passed = False
            finally:
                conn.close()
        if passed:
            if process is not None and process.poll() is not None:
                raise RuntimeError('Candidate sidecar exited')
            return
        time.sleep(0.2)
    raise RuntimeError('Signed-v2 listener readiness failed')


def stop_sidecar(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def cutover(release, stage, service, validate):
    """Retain old package, restore it exactly once on a caught update failure."""
    active, candidate = release / 'http_ctl', stage / 'http_ctl'
    backup, failed = stage / 'previous-http_ctl', stage / 'failed-http_ctl'
    before = package_digest(active)
    moved = False
    try:
        validate()
        sv(service, 'down')
        validate()
        active.rename(backup)
        moved = True
        candidate.rename(active)
        sv(service, 'up')
        readiness(18081, hierarchy=True)
        validate()
    except BaseException as error:
        # If stop failed before swapping, only restore the prior supervisor state.
        # If code moved, this is the one and only attempt to restore signed v2.
        try:
            if moved:
                if package_digest(backup) != before:
                    raise RuntimeError('Previous package backup changed; refusing restoration')
                sv(service, 'down')
                if active.exists():
                    active.rename(failed)
                backup.rename(active)
            sv(service, 'up')
            readiness(18081)
        except BaseException as recovery_error:
            raise RuntimeError(f'Update failed; the one signed-v2 recovery attempt also failed. Retained state: {stage}. Open Termux locally; do not use legacy rollback.') from recovery_error
        raise RuntimeError(f'Update failed; previous signed-v2 package is running. Retained state: {stage}') from error
    return backup


def sidecar_configuration(production, replay_db):
    """Clone without active keys: sidecar is only an unsigned rejection probe.

    An independent replay DB must never accept production-signed requests.
    Revoking every copied key prevents a second replay domain and UI execution.
    """
    candidate = json.loads(json.dumps(production))
    candidate['replay_db'] = str(replay_db)
    for key in candidate['keys'].values():
        key['revoked'] = True
    return candidate


def update(source, release, config_path, service, expected_run_sha256):
    state = release.parent
    python = release / '.venv/bin/python'
    for directory in (source, state, release, service):
        checked_path(directory, directory=True)
        if directory != directory.resolve():
            raise RuntimeError('Symlinked paths are not supported')
    for file in (source / 'requirements.txt', release / 'requirements.txt', config_path, state / 'launch-production', service / 'run'):
        checked_path(file)
    if not python.is_file():
        raise RuntimeError('Existing virtual environment is missing; no installation attempted')
    if (source / 'requirements.txt').read_bytes() != (release / 'requirements.txt').read_bytes():
        raise RuntimeError('Requirements changed; this package-only updater refuses dependency changes')
    if hashlib.sha256((service / 'run').read_bytes()).hexdigest() != expected_run_sha256:
        raise RuntimeError('Service run file differs from the operator-reviewed SHA-256')
    if (service / 'run').read_bytes() != (state / 'launch-production').read_bytes():
        raise RuntimeError('Service run file is not the existing signed-v2 production launcher')
    launcher = (state / 'launch-production').read_text()
    required_lines = {'export CTL_HOST=127.0.0.1', 'export CTL_PORT=18081', 'export CTL_CONFIG_FILE=' + shlex.quote(str(config_path)), 'cd ' + shlex.quote(str(release)), 'exec ' + shlex.quote(str(python)) + ' -m http_ctl.server'}
    if not required_lines.issubset(set(launcher.splitlines())):
        raise RuntimeError('Unexpected production launcher')
    config = json.loads((config_path).read_text())
    if config.get('rollout') is not None:
        raise RuntimeError('An unfinished migration is present; do not update it')
    status = run(['sv', 'status', service], capture_output=True, text=True).stdout
    if not status.startswith('run:'):
        raise RuntimeError('Existing production supervisor is not running')
    readiness(18081)
    watched = [config_path, state / 'launch-production', service / 'run', release / 'requirements.txt']
    snapshots = {p: (p.read_bytes(), p.stat().st_mode) for p in watched}
    def validate():
        for path, original in snapshots.items():
            checked_path(path)
            if (path.read_bytes(), path.stat().st_mode) != original:
                raise RuntimeError('Configuration or launcher changed during update; refusing to overwrite it')
    expected = package_digest(source / 'http_ctl')
    package_digest(release / 'http_ctl')
    stage = Path(tempfile.mkdtemp(prefix='package-update-', dir=state))
    shutil.copytree(source / 'http_ctl', stage / 'http_ctl', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    if package_digest(stage / 'http_ctl') != expected:
        raise RuntimeError('Staged package copy differs')
    # The sidecar has NO active keys and cannot accept/replay production requests.
    # Production configuration and replay history are never modified or reset.
    config = sidecar_configuration(config, stage / 'sidecar-replay.sqlite3')
    sideconfig = stage / 'sidecar.json'
    sideconfig.write_text(json.dumps(config))
    sideconfig.chmod(0o600)
    inherited = {key: value for key, value in os.environ.items() if not key.startswith('PYTHON')}
    env = dict(inherited, PYTHONPATH=str(stage), PYTHONDONTWRITEBYTECODE='1', CTL_CONFIG_FILE=str(sideconfig), CTL_HOST='127.0.0.1', CTL_PORT='18082')
    # Bind before launching to refuse an occupied sidecar port, never kill its owner.
    import socket
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 18082))
    run([python, '-c', 'import http_ctl.server; assert ("GET", "/ui/hierarchy") in http_ctl.server.ROUTES'], cwd=stage, env=env)
    with (stage / 'sidecar.log').open('xb') as log:
        process = subprocess.Popen([str(python), '-m', 'http_ctl.server'], cwd=stage, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        try:
            readiness(18082, hierarchy=True, process=process)
        finally:
            stop_sidecar(process)
    validate()
    backup = cutover(release, stage, service, validate)
    print('Package updated; configuration, keys, scopes, replay database, virtual environment and runit files were not replaced.')
    print(f'Previous signed-v2 package retained at: {backup}')
    print('Local authentication rejection passed. Signed public health and hierarchy acceptance are still required.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='Reviewed, unpacked source checkout')
    parser.add_argument('--release', type=Path, required=True, help='Existing signed-v2 release containing .venv and http_ctl')
    parser.add_argument('--config', type=Path, required=True, help='Existing production server JSON; never replaced')
    parser.add_argument('--service', type=Path, required=True, help='Existing ctl-server runit directory')
    parser.add_argument('--expected-run-sha256', required=True, help='SHA-256 of the reviewed existing run file')
    parser.add_argument('--confirm-local-package-update', action='store_true', required=True)
    args = parser.parse_args()
    prefix = Path(os.environ.get('PREFIX', '/data/data/com.termux/files/usr'))
    if str(prefix) != '/data/data/com.termux/files/usr' or not (prefix / 'bin/sh').is_file() or not Path('/system/bin').is_dir() or os.geteuid() == 0:
        parser.error('Run locally as the normal Termux user, not root or proot')
    release, config_path, service = args.release.absolute(), args.config.absolute(), args.service.absolute()
    if service != prefix / 'var/service/ctl-server':
        parser.error('Only the existing ctl-server service is supported')
    state = release.parent
    os.umask(0o077)
    checked_path(state, directory=True)
    lockfd = os.open(state / 'package-update.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        update(args.source.absolute(), release, config_path, service, args.expected_run_sha256)
    finally:
        os.close(lockfd)


if __name__ == '__main__':
    main()
