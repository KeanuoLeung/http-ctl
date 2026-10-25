"""Bounded subprocesses and descriptor-relative file access."""
import os
import re
import selectors
import shlex
import signal
import stat
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET

MAX_FILE = 50 * 1024 * 1024
MAX_OUTPUT = 100_000
MAX_HIERARCHY = 1024 * 1024


def validate_hierarchy(data):
    """Accept only bounded UTF-8 UIAutomator XML, never DTDs or entities."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_HIERARCHY:
        raise ValueError('invalid hierarchy')
    text = data.decode('utf-8', 'strict')
    # UIAutomator emits neither declarations other than XML nor comments.
    # Reject before parsing so entity expansion/external resolution is impossible.
    if '<!' in text or '\x00' in text:
        raise ValueError('invalid hierarchy')
    remaining = text.removeprefix('\ufeff')
    if remaining.startswith('<?xml '):
        declaration, separator, remaining = remaining.partition('?>')
        if not separator or len(declaration) > 256:
            raise ValueError('invalid hierarchy')
        encoding = re.search(r'\bencoding\s*=\s*([\"\'])(.*?)\1', declaration)
        if encoding and encoding[2].lower() != 'utf-8':
            raise ValueError('invalid hierarchy')
    if '<?' in remaining:
        raise ValueError('invalid hierarchy')
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError):
        raise ValueError('invalid hierarchy') from None
    if root.tag != 'hierarchy':
        raise ValueError('invalid hierarchy')
    pending = [(root, 0)]
    count = 0
    redacted = False
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > 10000 or depth > 100 or (node is not root and node.tag != 'node'):
            raise ValueError('invalid hierarchy')
        if (node.text and node.text.strip()) or (node.tail and node.tail.strip()):
            raise ValueError('invalid hierarchy')
        if any('{' in name or ':' in name for name in node.attrib):
            raise ValueError('invalid hierarchy')
        if node.get('password', '').lower() == 'true':
            for name in ('text', 'content-desc'):
                if node.get(name):
                    node.set(name, '')
                    redacted = True
        pending.extend((child, depth + 1) for child in node)
    if redacted:
        data = ET.tostring(root, encoding='utf-8', xml_declaration=True)
        if len(data) > MAX_HIERARCHY:
            raise ValueError('invalid hierarchy')
    return data


def ui_hierarchy(adb):
    """Read the active Android hierarchy using one fixed, bounded operation.

    No request content enters the script or path. Private remote temporary files
    are cleaned by a trap and an independent, bounded cleanup attempt. An ADB
    outage may prevent cleanup; an operator can remove the private residue later.
    """
    directory = '/data/local/tmp/http-ctl-ui-' + uuid.uuid4().hex
    marker = '.owned-' + uuid.uuid4().hex
    # exec-out handles multiple argv differently across ADB versions. Supply
    # one complete shell command, with the fixed script quoted exactly once.
    argv = [adb, '-s', 'localhost:5555', 'exec-out']
    # Android's sh/timeout/uiautomator are existing system tools, not installers.
    # Do not apply RLIMIT_FSIZE to ART: it also limits runtime cache/memfd
    # files and prevents startup. XML is checked before reading and bounded
    # on capture, but temporary disk usage while the trusted producer writes
    # is bounded by runtime/cleanup, not a hard per-file quota.
    script = '\n'.join([
        'umask 077', 'd=' + shlex.quote(directory), 'marker=' + shlex.quote(marker),
        'mkdir -m 700 "$d" || exit 1',
        '(set -C; : > "$d/$marker") || exit 1',
        'cleanup() { rm -f "$d/hierarchy.xml" "$d/$marker"; rmdir "$d"; }',
        'trap cleanup EXIT', "trap 'exit 1' HUP INT TERM",
        'timeout -s KILL 20 uiautomator dump --compressed "$d/hierarchy.xml" >/dev/null 2>/dev/null || exit 1',
        'test -f "$d/hierarchy.xml" && test ! -L "$d/hierarchy.xml" || exit 1',
        'size=$(stat -c %s "$d/hierarchy.xml") || exit 1',
        "case $size in ''|*[!0-9]*) exit 1 ;; esac",
        'test "$size" -gt 0 && test "$size" -le 1048576 || exit 1',
        'cat "$d/hierarchy.xml"',
    ])
    cleanup = '\n'.join([
        'd=' + shlex.quote(directory), 'marker=' + shlex.quote(marker),
        'if test -d "$d" && test ! -L "$d"; then',
        '  test -f "$d/$marker" && test ! -L "$d/$marker" || exit 1',
        '  rm -f "$d/hierarchy.xml" "$d/$marker" && rmdir "$d"',
        'else test ! -e "$d" && test ! -L "$d"; fi || exit 1',
        "printf 'HTTP_CTL_UI_CLEANUP_OK\\n'",
    ])
    try:
        code, out, _, timed, truncated = run_bounded(argv + ['sh -c ' + shlex.quote(script)], 25, output_limit=MAX_HIERARCHY)
        if code or timed or truncated:
            raise ValueError('hierarchy unavailable')
        result = validate_hierarchy(out)
    finally:
        code, cleaned, _, timed, truncated = run_bounded(argv + ['sh -c ' + shlex.quote(cleanup)], 5, output_limit=4096)
        # exec-out can return host status zero for a failed remote command.
        if code or timed or truncated or cleaned != b'HTTP_CTL_UI_CLEANUP_OK\n':
            raise ValueError('hierarchy cleanup unavailable')
    return result


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
