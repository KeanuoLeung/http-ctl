"""Bounded subprocesses and descriptor-relative file access."""
import os
import selectors
import shlex
import signal
import stat
import subprocess
import time
import uuid

MAX_FILE = 50 * 1024 * 1024
MAX_OUTPUT = 100_000


def run_bounded(argv, timeout, output_limit=MAX_OUTPUT, env=None):
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env=env, close_fds=True)
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    selector = selectors.DefaultSelector()
    for name, pipe in [('stdout', proc.stdout), ('stderr', proc.stderr)]:
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ, name)
    deadline = time.monotonic() + timeout
    timed_out = truncated = False
    killed = False
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                timed_out = True
                break
            for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buf = buffers[key.data]
                remaining = output_limit - len(buf)
                buf.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    # Stop noisy processes immediately rather than unbounded draining.
                    killed = True
                    break
            if killed:
                break
        if timed_out or killed:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=2)
    finally:
        selector.close()
        proc.stdout.close()
        proc.stderr.close()
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=2)
    return proc.returncode, bytes(buffers['stdout']), bytes(buffers['stderr']), timed_out, truncated


def _directory(path):
    """Open every component without symlinks, including trusted root ancestors."""
    if not os.path.isabs(path) or os.path.normpath(path) != path or path == '/':
        raise ValueError('invalid root')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.split('/')[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nxt
        st = os.fstat(fd)
        if st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise ValueError('file root must be owned by daemon and not writable by other users')
        return fd
    except Exception:
        os.close(fd)
        raise


def parent_fd(root, relative):
    if not isinstance(relative, str) or not relative or len(relative) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in relative) or '\\' in relative:
        raise ValueError('invalid relative path')
    parts = relative.split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('relative path must not contain traversal')
    fd = _directory(root)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd, parts[-1]
    except Exception:
        os.close(fd)
        raise


def download(root, relative):
    parent, name = parent_fd(root, relative)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, 'rb') as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ValueError('regular file with one link required')
            if st.st_size > MAX_FILE:
                raise OverflowError()
            data = f.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise OverflowError()
            return data
    finally:
        os.close(parent)


def upload(root, relative, data):
    parent, name = parent_fd(root, relative)
    temporary = '.http-ctl-' + uuid.uuid4().hex
    try:
        try:
            st = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ValueError('regular file with one link required')
        except FileNotFoundError:
            pass
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # Atomic replace replaces a raced-in symlink itself; it never follows it.
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def ui_arguments(req):
    if not isinstance(req, dict):
        raise ValueError()
    action = req.get('action')
    def integer(name, low, high):
        value = req.get(name)
        if type(value) is not int or not low <= value <= high:
            raise ValueError()
        return str(value)
    if action == 'tap' and set(req) == {'action', 'x', 'y'}:
        return ['input', 'tap', integer('x', 0, 10000), integer('y', 0, 10000)]
    if action == 'swipe' and set(req) == {'action', 'x1', 'y1', 'x2', 'y2', 'duration_ms'}:
        return ['input', 'swipe', *(integer(k, 0, 10000) for k in ('x1', 'y1', 'x2', 'y2')), integer('duration_ms', 1, 5000)]
    if action == 'keyevent' and set(req) == {'action', 'key'}:
        keys = {'HOME': '3', 'BACK': '4', 'APP_SWITCH': '187', 'ENTER': '66', 'DEL': '67', 'VOLUME_UP': '24', 'VOLUME_DOWN': '25'}
        if req.get('key') not in keys:
            raise ValueError()
        return ['input', 'keyevent', keys[req['key']]]
    if action == 'text' and set(req) == {'action', 'text'}:
        value = req.get('text')
        # adb shell concatenates argv remotely. Keep an explicit safe alphabet;
        # Unicode/quotes/metacharacters belong in a separately reviewed input path.
        import re
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9 .,!?@_+:/=-]{1,500}', value):
            raise ValueError()
        # No quotes: encoded spaces; shell metacharacters are excluded above.
        return ['input', 'text', shlex.quote(value.replace(' ', '%s'))]
    raise ValueError('unsupported UI action')
