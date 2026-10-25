"""One bounded migration acknowledgement, mutually exclusive with rollback."""
from contextlib import contextmanager
import fcntl
import hmac
import json
import os
from pathlib import Path
import stat
import tempfile
import time
from .auth import protected_read, strict_json


class RolloutUnavailable(Exception):
    pass


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


@contextmanager
def locked_state(directory):
    st = os.lstat(directory)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise RolloutUnavailable('private rollout directory required')
    fd = os.open(os.path.join(directory, '.rollout-lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise RolloutUnavailable('invalid rollout lock')
        # A stuck deployment operation must not block all request threads.
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def read_state(directory):
    state = strict_json(protected_read(os.path.join(directory, 'rollout-state.json'), 4096))
    if not isinstance(state, dict):
        raise RolloutUnavailable('invalid rollout state')
    return state


def atomic_json(path, value):
    parent = os.path.dirname(path)
    fd, temporary = tempfile.mkstemp(prefix='.rollout-', dir=parent)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_state(directory, state):
    atomic_json(os.path.join(directory, 'rollout-state.json'), state)


def confirm(config, rollout_id):
    rollout = config.rollout()
    if rollout is None or type(rollout_id) is not str or not hmac.compare_digest(rollout_id, rollout['id']):
        raise RolloutUnavailable('no matching rollout')
    directory = os.path.dirname(config.replay_db)
    with locked_state(directory):
        state = read_state(directory)
        if state.get('id') != rollout['id'] or state.get('deadline') != rollout['deadline'] or state.get('boot_id') != boot_id() or state.get('status') not in ('pending', 'confirmed'):
            raise RolloutUnavailable('rollout no longer pending')
        if type(state.get('deadline_monotonic')) not in (float, int) or time.time() >= rollout['deadline'] or time.monotonic() >= state['deadline_monotonic']:
            raise RolloutUnavailable('rollout expired')
        state['status'] = 'confirmed'
        write_state(directory, state)
        atomic_json(rollout['ack_file'], {'id': rollout['id'], 'deadline': rollout['deadline']})
    return rollout['id']
