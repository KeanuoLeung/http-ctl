"""Bounded, key-owned asynchronous commands with durable at-most-once admission.

A committed reservation is never rerun, even if a crash happened before spawn.
Restarted jobs are interrupted (execution outcome unknown), not resumed. This is
not a sandbox: shell:exec already grants the daemon account's shell privileges.
"""
import base64
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import threading
import time

MAX_RUNTIME = 3600
MAX_OUTPUT = 1024 * 1024
MAX_JOBS = 128
MAX_ACTIVE = 2
ACTIVE = {'starting', 'running'}
ID = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')


class JobError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def _private_file(path, flags):
    fd = os.open(path, (flags & ~os.O_TRUNC) | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077 or st.st_nlink != 1:
        os.close(fd)
        raise ValueError('unsafe job state')
    if flags & os.O_TRUNC:
        os.ftruncate(fd, 0)
    return fd


class JobStore:
    def __init__(self, path):
        self.path = path
        os.makedirs(path, mode=0o700, exist_ok=True)
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise ValueError('unsafe job directory')
        self.lock_fd = _private_file(os.path.join(path, 'lock'), os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            os.close(self.lock_fd)
            raise
        self.lock = threading.RLock()
        self.records = {}
        self.workers = {}
        self.closed = False
        self._close_called = False
        try:
            with os.scandir(path) as entries:
                for count, entry in enumerate(entries):
                    if count > MAX_JOBS * 4 + 1:
                        raise ValueError('job state capacity exceeded')
                    if not re.fullmatch(r'[a-f0-9]{64}\.json', entry.name):
                        continue
                    with os.fdopen(_private_file(entry.path, os.O_RDONLY), 'rb') as f:
                        raw = f.read(4097)
                    if len(raw) > 4096:
                        raise ValueError('oversized job metadata')
                    record = json.loads(raw)
                    token = entry.name[:-5]
                    if self._token(record['owner'], record['id']) != token or len(self.records) >= MAX_JOBS:
                        raise ValueError('invalid job metadata')
                    self.records[token] = record
                    if record['state'] in ACTIVE:
                        record.update(state='interrupted', exit=None, finished_at=time.time())
                        self._save(token)
        except Exception:
            os.close(self.lock_fd)
            raise

    @staticmethod
    def _token(owner, job_id):
        if not isinstance(job_id, str) or not ID.fullmatch(job_id):
            raise ValueError('invalid job id')
        return hashlib.sha256((owner + '\0' + job_id).encode()).hexdigest()

    def _save(self, token):
        temporary = os.path.join(self.path, token + '.tmp')
        with os.fdopen(_private_file(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC), 'wb') as f:
            f.write(json.dumps(self.records[token], separators=(',', ':')).encode())
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, os.path.join(self.path, token + '.json'))
        fd = os.open(self.path, os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _get(self, owner, job_id):
        token = self._token(owner, job_id)
        if token not in self.records:
            raise JobError(404, 'job not found')
        return token, self.records[token]

    def _size(self, token, stream):
        try:
            fd = _private_file(os.path.join(self.path, token + '.' + stream), os.O_RDONLY)
        except FileNotFoundError:
            return 0
        try:
            return os.fstat(fd).st_size
        finally:
            os.close(fd)

    def _status(self, token):
        record = self.records[token]
        return {**{k: v for k, v in record.items() if k not in ('owner', 'fingerprint')},
                'stdout_bytes': self._size(token, 'stdout'), 'stderr_bytes': self._size(token, 'stderr'),
                'output_limit': MAX_OUTPUT}

    def submit(self, owner, req, bash):
        if not isinstance(req, dict) or set(req) - {'id', 'cmd', 'timeout'}:
            raise ValueError('invalid job request')
        token = self._token(owner, req.get('id'))
        cmd, timeout = req.get('cmd'), req.get('timeout', MAX_RUNTIME)
        if not isinstance(cmd, str) or not cmd or len(cmd) > 16384 or '\0' in cmd:
            raise ValueError('invalid command')
        if type(timeout) is not int or not 1 <= timeout <= MAX_RUNTIME:
            raise ValueError('invalid timeout')
        fingerprint = hashlib.sha256(json.dumps([cmd, timeout], ensure_ascii=True).encode()).hexdigest()
        with self.lock:
            if token in self.records:
                if self.records[token]['fingerprint'] != fingerprint:
                    raise JobError(409, 'job id already used with different command or timeout')
                return False, self._status(token)
            if self.closed or len(self.workers) >= MAX_ACTIVE or len(self.records) >= MAX_JOBS:
                raise JobError(503, 'job capacity exhausted')
            if not bash:
                raise JobError(501, 'bash unavailable')
            self.records[token] = dict(id=req['id'], owner=owner, fingerprint=fingerprint,
                                       state='starting', exit=None, timeout=timeout,
                                       created_at=time.time(), finished_at=None)
            # Persist BEFORE spawn. Never delete this reservation on any error.
            try:
                self._save(token)
            except (OSError, ValueError):
                self.records[token].update(state='failed', finished_at=time.time())
                self.closed = True
                raise
            cancel = threading.Event()
            worker = threading.Thread(target=self._run, args=(token, bash, cmd, timeout, cancel), daemon=True)
            self.workers[token] = (worker, cancel)
            try:
                worker.start()
            except Exception:
                self.workers.pop(token)
                self.records[token].update(state='failed', finished_at=time.time())
                self._save(token)
                raise
            return True, self._status(token)

    def status(self, owner, job_id):
        with self.lock:
            token, _ = self._get(owner, job_id)
            return self._status(token)

    def cancel(self, owner, job_id):
        with self.lock:
            token, _ = self._get(owner, job_id)
            if token in self.workers:
                self.workers[token][1].set()
            return self._status(token)

    def logs(self, owner, req):
        if not isinstance(req, dict) or set(req) - {'id', 'stream', 'cursor', 'limit'}:
            raise ValueError('invalid logs request')
        stream, cursor, limit = req.get('stream'), req.get('cursor', 0), req.get('limit', 65536)
        if stream not in ('stdout', 'stderr') or type(cursor) is not int or not 0 <= cursor <= MAX_OUTPUT or type(limit) is not int or not 1 <= limit <= 65536:
            raise ValueError('invalid cursor')
        with self.lock:
            token, record = self._get(owner, req.get('id'))
            size = self._size(token, stream)
            if cursor > size:
                raise ValueError('cursor beyond available output')
            data = b''
            if size:
                with os.fdopen(_private_file(os.path.join(self.path, token + '.' + stream), os.O_RDONLY), 'rb') as f:
                    f.seek(cursor)
                    data = f.read(min(limit, size - cursor))
            return dict(id=record['id'], stream=stream, cursor=cursor, next_cursor=cursor + len(data),
                        data_b64=base64.b64encode(data).decode(), state=record['state'],
                        eof=record['state'] not in ACTIVE and cursor + len(data) >= size)

    @staticmethod
    def _kill(proc):
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def _run(self, token, bash, cmd, timeout, cancel):
        proc = None
        files = {}
        selector = selectors.DefaultSelector()
        state = 'failed'
        try:
            for stream in ('stdout', 'stderr'):
                files[stream] = os.fdopen(_private_file(os.path.join(self.path, token + '.' + stream), os.O_WRONLY | os.O_CREAT | os.O_EXCL), 'wb', buffering=0)
            if cancel.is_set():
                state = 'interrupted' if self.closed else 'cancelled'
                return
            # Drop secrets and shell startup hooks from the service environment.
            env = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'LANG', 'TMPDIR', 'PREFIX', 'LD_LIBRARY_PATH')}
            proc = subprocess.Popen([bash, '-c', cmd], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, start_new_session=True, close_fds=True, env=env)
            deadline = time.monotonic() + timeout
            with self.lock:
                self.records[token]['state'] = 'running'
                self._save(token)
            for stream in files:
                pipe = getattr(proc, stream)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, stream)
            total = 0
            state = 'exited'
            exited_at = None
            while selector.get_map() or proc.poll() is None:
                if cancel.is_set():
                    state = 'interrupted' if self.closed else 'cancelled'
                    break
                if time.monotonic() >= deadline:
                    state = 'timed_out'
                    break
                if proc.poll() is not None:
                    # Do not leave background children holding pipes after shell exit.
                    if exited_at is None:
                        exited_at = time.monotonic()
                        self._kill(proc)
                    elif time.monotonic() - exited_at > 0.5:
                        break
                for key, _ in selector.select(0.05):
                    chunk = os.read(key.fd, 16384)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    remaining = MAX_OUTPUT - total
                    if files[key.data].write(chunk[:remaining]) != min(len(chunk), remaining):
                        raise OSError('short log write')
                    total += min(len(chunk), remaining)
                    if len(chunk) > remaining:
                        state = 'output_limit'
                        break
                if state == 'output_limit':
                    break
        except Exception:
            state = 'failed'
        finally:
            self._kill(proc)
            if proc is not None:
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    state = 'interrupted'
                proc.stdout.close()
                proc.stderr.close()
            selector.close()
            for f in files.values():
                try:
                    os.fsync(f.fileno())
                except OSError:
                    state = 'failed'
                f.close()
            with self.lock:
                self.records[token].update(state=state, exit=None if proc is None else proc.returncode, finished_at=time.time())
                try:
                    self._save(token)
                except OSError:
                    # Disk failure must neither rerun a reservation nor admit
                    # more work. Durable starting/running becomes interrupted.
                    self.closed = True
                finally:
                    self.workers.pop(token, None)

    def close(self):
        with self.lock:
            if self._close_called:
                return
            self._close_called = True
            self.closed = True
            workers = list(self.workers.values())
            for _, cancel in workers:
                cancel.set()
        for worker, _ in workers:
            worker.join(timeout=4)
        # Never release ownership while a worker could still mutate state.
        if all(not worker.is_alive() for worker, _ in workers):
            os.close(self.lock_fd)
