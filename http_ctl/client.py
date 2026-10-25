"""No credential transmission, redirects, automatic retries or response logging."""
import argparse
import http.client
import json
import os
import pathlib
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .auth import protected_read, signed_headers, origin
from .operations import MAX_FILE

MAX_RESPONSE = MAX_FILE + 65536


def atomic_output(path, body):
    path = pathlib.Path(path).absolute()
    fd, temporary = tempfile.mkstemp(prefix='.http-ctl-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('redirect refused')


def request(base_url, method, target, headers, body):
    """Single request only; honors standard HTTPS proxy environment configuration."""
    url = origin(base_url) + target
    # urllib uses this exact ASCII URL; do not requote or normalize after signing.
    outgoing = urllib.request.Request(url, data=body, headers=headers, method=method)
    if outgoing.full_url != url or outgoing.selector != target:
        raise ValueError('URL changed after signing')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(), urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    with opener.open(outgoing, timeout=315) as response:
        length = response.getheader('Content-Length')
        if length is None or not length.isascii() or not length.isdecimal() or int(length) > MAX_RESPONSE:
            raise ValueError('invalid response length')
        data = response.read(int(length) + 1)
        if len(data) != int(length):
            raise ValueError('incomplete response')
        if response.status != 200:
            raise ValueError('server rejected request; request was not retried')
        return data


def parser():
    p = argparse.ArgumentParser(description='Signed HTTP control; TLS required; operations are never retried automatically')
    sub = p.add_subparsers(dest='operation', required=True)
    sub.add_parser('health')
    confirm = sub.add_parser('migration-confirm', help='confirm one active rollout only after external validation')
    confirm.add_argument('rollout_id')
    probe = sub.add_parser('health-probe', help='write a 60-second one-use signed health probe, not a private key')
    probe.add_argument('output')
    exe = sub.add_parser('exec')
    exe.add_argument('command')
    exe.add_argument('timeout', nargs='?', type=int, default=60)
    shot = sub.add_parser('screenshot')
    shot.add_argument('output', nargs='?', default='screenshot.png')
    down = sub.add_parser('download')
    down.add_argument('remote', help='relative to the key file root')
    down.add_argument('output', nargs='?')
    up = sub.add_parser('upload')
    up.add_argument('source')
    up.add_argument('remote', help='relative to the key file root')
    ui = sub.add_parser('ui')
    actions = ui.add_subparsers(dest='action', required=True)
    tap = actions.add_parser('tap')
    tap.add_argument('x', type=int)
    tap.add_argument('y', type=int)
    swipe = actions.add_parser('swipe')
    for name in ('x1', 'y1', 'x2', 'y2', 'duration_ms'):
        swipe.add_argument(name, type=int)
    key = actions.add_parser('keyevent')
    key.add_argument('key', choices=['HOME', 'BACK', 'APP_SWITCH', 'ENTER', 'DEL', 'VOLUME_UP', 'VOLUME_DOWN'])
    text = actions.add_parser('text')
    text.add_argument('text')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        base = origin(os.environ['CTL_BASE_URL'])
        key_id = os.environ['CTL_KEY_ID']
        pem = protected_read(os.environ.get('CTL_PRIVATE_KEY_FILE', '~/.config/http-ctl/client-key.pem'))
        private = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise ValueError('Ed25519 private key required')
        operation = args.operation
        method, target, body, content_type = 'GET', '/' + operation, b'', 'application/octet-stream'
        output = None
        if operation == 'health-probe':
            target = '/health'
        elif operation == 'migration-confirm':
            method, target, content_type = 'POST', '/migration/confirm', 'application/json'
            body = json.dumps({'rollout_id': args.rollout_id}, separators=(',', ':')).encode()
        elif operation == 'exec':
            method, content_type = 'POST', 'application/json'
            body = json.dumps({'cmd': args.command, 'timeout': args.timeout}, separators=(',', ':')).encode()
        elif operation == 'ui':
            method, content_type = 'POST', 'application/json'
            values = vars(args).copy()
            del values['operation']
            body = json.dumps(values, separators=(',', ':')).encode()
        elif operation in ('download', 'upload'):
            target += '?path=' + quote(args.remote, safe='')
            if operation == 'upload':
                method = 'POST'
                with open(args.source, 'rb') as f:
                    body = f.read(MAX_FILE + 1)
                if len(body) > MAX_FILE:
                    raise ValueError('file too large')
            else:
                output = args.output or pathlib.PurePosixPath(args.remote).name
        elif operation == 'screenshot':
            output = args.output
        headers = signed_headers(private, key_id, base, method, target, body, content_type)
        if operation == 'health-probe':
            # Use exclusive creation so no accidental overwrite of key/config files.
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump({'method': method, 'target': target, 'headers': headers}, f)
            print('Saved one-use health probe; valid for 60 seconds.')
            return 0
        data = request(base, method, target, headers, body)
        if output:
            if operation == 'screenshot' and not data.startswith(b'\x89PNG\r\n\x1a\n'):
                raise ValueError('invalid screenshot response')
            atomic_output(output, data)
            print('Saved response (%d bytes).' % len(data))
        else:
            # stdout is explicitly requested command result, not a service log.
            print(data.decode('utf-8'))
        return 0
    except (OSError, ValueError, KeyError, http.client.HTTPException, urllib.error.URLError):
        # No private-key paths, request headers/body, tokens, remote body, or
        # low-level library exception text printed on failure.
        print('ctl: request/configuration failed; no automatic retry. Verify state before repeating a write.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
