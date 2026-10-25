"""Loopback-only signed control daemon. See SECURITY.md before enabling scopes."""
import io
import json
import os
import re
import shutil
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .auth import AuthError, Config, ReplayStore, authenticate, strict_json
from .rollout import confirm, RolloutUnavailable
from .operations import MAX_FILE, download, upload, run_bounded, ui_arguments

ROUTES = {
    ('GET', '/health'): ('health:read', 0, 'application/octet-stream'),
    ('GET', '/screenshot'): ('screenshot:read', 0, 'application/octet-stream'),
    ('GET', '/download'): ('files:read', 0, 'application/octet-stream'),
    ('POST', '/upload'): ('files:write', MAX_FILE, 'application/octet-stream'),
    ('POST', '/exec'): ('shell:exec', 65536, 'application/json'),
    ('POST', '/ui'): ('ui:control', 4096, 'application/json'),
    ('POST', '/migration/confirm'): ('migration:confirm', 512, 'application/json'),
}

class Bucket:
    def __init__(self, rate, burst):
        self.rate, self.burst = rate, burst
        self.tokens, self.updated = burst, time.monotonic()
        self.lock = threading.Lock()

    def take(self):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens < 1:
                return False
            self.tokens -= 1
            return True


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, address, config):
        if address[0] != '127.0.0.1':
            raise ValueError('only literal 127.0.0.1 is allowed')
        self.config = config
        self.replay = ReplayStore(config.replay_db)
        self.slots = threading.BoundedSemaphore(8)
        self.operation_slots = threading.BoundedSemaphore(2)
        self.bucket = Bucket(10, 30)
        self.key_buckets = {}
        self.key_bucket_lock = threading.Lock()
        self.started = time.monotonic()
        self.adb = shutil.which('adb')
        self.bash = shutil.which('bash')
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # No traceback, command, path, headers or body ever enter service logs.
        print('http-ctl request_error', flush=True)

    def key_limit(self, key_id):
        with self.key_bucket_lock:
            if key_id not in self.key_buckets:
                if len(self.key_buckets) >= 64:
                    self.key_buckets.clear()
                self.key_buckets[key_id] = Bucket(5, 15)
            bucket = self.key_buckets[key_id]
        return bucket.take()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'http-ctl/2'
    sys_version = ''

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def handle_one_request(self):
        self.close_connection = True
        self._start = time.monotonic()
        self._route = 'invalid'
        self.requestline = ''
        self.request_version = 'HTTP/1.1'
        self.command = None
        try:
            self._deadline = time.monotonic() + 10
            self.raw_requestline = self._readline(8193)
            if not self.raw_requestline:
                return
            if len(self.raw_requestline) > 8192:
                return self._json(414, {'error': 'request rejected'})
            # Strict syntax before BaseHTTPRequestHandler can normalize a target.
            match = re.fullmatch(rb'(GET|POST) ([!-~]+) HTTP/1\.[01]\r\n', self.raw_requestline)
            if not match:
                return self._json(400, {'error': 'request rejected'})
            raw_target = match[2].decode('ascii')
            if not raw_target.startswith('/') or raw_target.startswith('//') or '#' in raw_target or '\\' in raw_target or re.search(r'%(?![0-9a-fA-F]{2})', raw_target):
                return self._json(400, {'error': 'request rejected'})
            # Bound aggregate headers, reject obsolete folding/duplicates/controls.
            header_bytes = bytearray()
            seen = set()
            for _ in range(65):
                line = self._readline(8193)
                header_bytes.extend(line)
                if len(header_bytes) > 16384 or not line.endswith(b'\r\n'):
                    return self._json(400, {'error': 'request rejected'})
                if line == b'\r\n':
                    break
                if b':' not in line:
                    return self._json(400, {'error': 'request rejected'})
                name, value = line[:-2].split(b':', 1)
                if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or any(c < 32 or c > 126 for c in value):
                    return self._json(400, {'error': 'request rejected'})
                name = name.lower()
                if name in seen:
                    return self._json(400, {'error': 'request rejected'})
                seen.add(name)
            else:
                return self._json(400, {'error': 'request rejected'})
            original = self.rfile
            try:
                self.rfile = io.BytesIO(header_bytes)
                if not self.parse_request():
                    return
            finally:
                self.rfile = original
            self.path = raw_target
            self.close_connection = True
            self._dispatch()
        except (TimeoutError, socket.timeout):
            self._json(408, {'error': 'request timed out'})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._json(500, {'error': 'request failed'})
        finally:
            self.close_connection = True

    def _set_read_timeout(self):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        self.connection.settimeout(remaining)

    def _readline(self, limit):
        # Read one bounded byte at a time for an absolute deadline, not a sliding
        # per-socket timeout vulnerable to an endless drip of headers.
        data = bytearray()
        while len(data) < limit:
            self._set_read_timeout()
            byte = self.rfile.read(1)
            if not byte:
                break
            data += byte
            if byte == b'\n':
                break
        return bytes(data)

    def _read_body(self, length):
        data = bytearray()
        while len(data) < length:
            self._set_read_timeout()
            # read1 performs at most one underlying read, so the deadline is
            # rechecked between chunks even if the peer continuously drips data.
            chunk = self.rfile.read1(min(65536, length - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def handle_expect_100(self):
        self._json(400, {'error': 'request rejected'})
        return False

    def send_error(self, code, message=None, explain=None):
        self.close_connection = True
        self._json(code, {'error': 'request rejected'})

    def _send(self, code, data, content_type):
        self.send_response_only(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        try:
            self.wfile.write(data)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        # Route is constant server-owned text; never output user-controlled data.
        audit = {'route': self._route, 'status': code, 'duration_ms': int((time.monotonic() - self._start) * 1000)}
        if getattr(self, '_auth_failure', None):
            audit['auth_failure'] = self._auth_failure
        print(json.dumps(audit), flush=True)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode(), 'application/json')

    def _dispatch(self):
        if not self.server.bucket.take():
            return self._json(429, {'error': 'rate limited'})
        if any(name in self.headers for name in ('Transfer-Encoding', 'Content-Encoding', 'Authorization', 'Expect')):
            return self._json(400, {'error': 'request rejected'})
        if 'Host' not in self.headers:
            return self._json(400, {'error': 'request rejected'})
        parsed = urlsplit(self.path)
        route = ROUTES.get((self.command, parsed.path))
        if route is None:
            return self._json(404, {'error': 'not found'})
        self._route = parsed.path
        scope, limit, content_type = route
        try:
            query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=2, encoding='utf-8', errors='strict')
        except (ValueError, UnicodeError):
            return self._json(400, {'error': 'invalid query'})
        if parsed.path in ('/download', '/upload'):
            if set(query) != {'path'} or len(query['path']) != 1 or not query['path'][0]:
                return self._json(400, {'error': 'one relative path required'})
        elif parsed.query or '?' in self.path:
            return self._json(400, {'error': 'unexpected query'})
        length = self.headers.get('Content-Length', '0' if self.command == 'GET' else '')
        if not re.fullmatch(r'0|[1-9][0-9]{0,8}', length):
            return self._json(400, {'error': 'invalid content length'})
        length = int(length)
        if length > limit:
            return self._json(413, {'error': 'body too large'})
        if self.headers.get('Content-Type') != content_type:
            return self._json(400, {'error': 'invalid content type'})
        body = self._read_body(length)
        self.connection.settimeout(10)
        if len(body) != length:
            return self._json(400, {'error': 'incomplete body'})
        try:
            key_id, key = authenticate(self.server.config, self.server.replay, self.command, self.path, self.headers, body, scope)
        except PermissionError:
            return self._json(403, {'error': 'scope denied'})
        except AuthError as exc:
            self._auth_failure = exc.code
            return self._json(401, {'error': 'unauthorized'})
        if not self.server.key_limit(key_id):
            return self._json(429, {'error': 'rate limited'})
        if parsed.path == '/health':
            return self._json(200, {'ok': True, 'service': 'http-ctl', 'version': 2, 'uptime_s': int(time.monotonic() - self.server.started)})
        if not self.server.operation_slots.acquire(blocking=False):
            return self._json(503, {'error': 'busy'})
        try:
            self._operation(parsed.path, query, body, key)
        except (ValueError, UnicodeError, TypeError, KeyError):
            self._json(400, {'error': 'invalid operation'})
        except OverflowError:
            self._json(413, {'error': 'file too large'})
        except OSError:
            self._json(400, {'error': 'operation unavailable'})
        finally:
            self.server.operation_slots.release()

    def _operation(self, path, query, body, key):
        if path == '/migration/confirm':
            req = strict_json(body)
            if not isinstance(req, dict) or set(req) != {'rollout_id'}:
                raise ValueError('invalid rollout request')
            try:
                rollout_id = confirm(self.server.config, req['rollout_id'])
            except (RolloutUnavailable, OSError, ValueError, KeyError):
                return self._json(409, {'error': 'rollout unavailable or no longer pending'})
            return self._json(200, {'ok': True, 'rollout_id': rollout_id})
        if path == '/download':
            return self._send(200, download(key.file_root, query['path'][0]), 'application/octet-stream')
        if path == '/upload':
            upload(key.file_root, query['path'][0], body)
            return self._json(200, {'ok': True, 'bytes': len(body)})
        if path == '/exec':
            req = strict_json(body)
            if not isinstance(req, dict) or set(req) - {'cmd', 'timeout'} or not isinstance(req.get('cmd'), str) or not req['cmd'] or len(req['cmd']) > 16384:
                raise ValueError()
            timeout = req.get('timeout', 60)
            if type(timeout) is not int or not 1 <= timeout <= 300:
                raise ValueError()
            if not self.server.bash:
                return self._json(501, {'error': 'bash unavailable'})
            result = run_bounded([self.server.bash, '-c', req['cmd']], timeout)
        else:
            if not self.server.adb:
                return self._json(501, {'error': 'adb unavailable'})
            argv = [self.server.adb, '-s', self.server.config.adb_serial]
            if path == '/screenshot':
                code, out, _, timed, truncated = run_bounded(argv + ['exec-out', 'screencap', '-p'], 30, output_limit=16 * 1024 * 1024)
                if code or timed or truncated or not out.startswith(b'\x89PNG\r\n\x1a\n'):
                    return self._json(502, {'error': 'screenshot failed'})
                return self._send(200, out, 'image/png')
            result = run_bounded(argv + ['shell'] + ui_arguments(strict_json(body)), 10)
        code, out, err, timed, truncated = result
        if path == '/ui':
            return self._json(200 if code == 0 and not timed and not truncated else 502, {'ok': code == 0 and not timed and not truncated})
        self._json(200, {'exit': code, 'stdout': out.decode('utf-8', 'replace'), 'stderr': err.decode('utf-8', 'replace'), 'timed_out': timed, 'truncated': truncated})


def main():
    os.umask(0o077)
    try:
        config = Config(os.environ.get('CTL_CONFIG_FILE', '~/.config/http-ctl/server.json'))
        server = Server((os.environ.get('CTL_HOST', '127.0.0.1'), int(os.environ.get('CTL_PORT', '18081'))), config)
    except Exception:
        raise SystemExit('http-ctl: invalid configuration or unavailable listener/state; refusing to start')
    print('http-ctl v2 listening on loopback; signatures required', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
