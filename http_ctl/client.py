"""No credential transmission, redirects, automatic retries or response logging."""
import argparse
import base64
import math
import re
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
from .operations import MAX_FILE, validate_hierarchy

MAX_RESPONSE = MAX_FILE + 65536


class ResponseError(ValueError):
    """Invalid remote protocol data, never include its contents in diagnostics."""


def exec_result(data):
    """Validate exec's wire schema and return (result, shell-compatible status).

    Exit 0..255 is preserved; POSIX -N maps to 128+N (N=1..127).
    Timeout (124) takes precedence over truncation (125), then remote exit.
    HTTP/transport/protocol failures use 255; local configuration failures use 1.
    These codes can also be genuine remote exits: stderr diagnostics and JSON
    distinguish their origin. Raw output is decoded text, not a binary channel.
    """
    try:
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate field')
                result[key] = value
            return result
        result = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object)
        if not isinstance(result, dict):
            raise ValueError('object required')
        for field in ('stdout', 'stderr'):
            if not isinstance(result[field], str):
                raise ValueError('text required')
            result[field].encode('utf-8')
        for field in ('timed_out', 'truncated'):
            if type(result[field]) is not bool:
                raise ValueError('boolean required')
        code = result['exit']
        if type(code) is not int or not -127 <= code <= 255:
            raise ValueError('invalid exit status')
    except (ValueError, KeyError, TypeError, RecursionError) as error:
        raise ResponseError('invalid exec response') from error
    if result['timed_out']:
        status = 124
    elif result['truncated']:
        status = 125
    else:
        status = code if code >= 0 else 128 - code
    return result, status


JOB_STATES = {'starting', 'running', 'exited', 'cancelled', 'timed_out',
              'output_limit', 'interrupted', 'failed'}
JOB_MAX_OUTPUT = 1024 * 1024


def job_request(args):
    """Validate locally before signing or transmitting a job request."""
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', args.id):
        raise ValueError('invalid job id')
    result = {'id': args.id}
    if args.job_action == 'submit':
        if not args.command or len(args.command) > 16384 or '\0' in args.command:
            raise ValueError('invalid command')
        args.command.encode('utf-8')
        if not 1 <= args.timeout <= 3600:
            raise ValueError('invalid timeout')
        result.update(cmd=args.command, timeout=args.timeout)
    elif args.job_action == 'logs':
        if not 0 <= args.cursor <= JOB_MAX_OUTPUT or not 1 <= args.limit <= 65536:
            raise ValueError('invalid log bounds')
        result.update(stream=args.stream, cursor=args.cursor, limit=args.limit)
    return result


def job_result(data, args):
    """Reject malformed or mismatched job replies before emitting any output."""
    try:
        def unique_object(pairs):
            obj = {}
            for key, value in pairs:
                if key in obj:
                    raise ValueError('duplicate field')
                obj[key] = value
            return obj
        result = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object)
        if not isinstance(result, dict) or result['id'] != args.id or result['state'] not in JOB_STATES:
            raise ValueError('invalid job')
        if args.job_action == 'logs':
            if set(result) != {'id', 'stream', 'cursor', 'next_cursor', 'data_b64', 'eof', 'state'}:
                raise ValueError('invalid fields')
            if result['stream'] != args.stream or type(result['cursor']) is not int or result['cursor'] != args.cursor:
                raise ValueError('mismatched cursor')
            if type(result['next_cursor']) is not int or type(result['eof']) is not bool:
                raise ValueError('invalid cursor or eof')
            if not isinstance(result['data_b64'], str):
                raise ValueError('invalid data')
            raw = base64.b64decode(result['data_b64'], validate=True)
            if base64.b64encode(raw).decode() != result['data_b64']:
                raise ValueError('noncanonical data')
            if len(raw) > args.limit or result['next_cursor'] != args.cursor + len(raw) or result['next_cursor'] > JOB_MAX_OUTPUT:
                raise ValueError('invalid data length')
            if result['eof'] and result['state'] in ('starting', 'running'):
                raise ValueError('active eof')
            return result, raw
        if set(result) != {'id', 'state', 'exit', 'timeout', 'created_at', 'finished_at',
                           'stdout_bytes', 'stderr_bytes', 'output_limit'}:
            raise ValueError('invalid fields')
        for field, lower, upper in (('timeout', 1, 3600), ('stdout_bytes', 0, JOB_MAX_OUTPUT),
                                    ('stderr_bytes', 0, JOB_MAX_OUTPUT), ('output_limit', 1, JOB_MAX_OUTPUT)):
            if type(result[field]) is not int or not lower <= result[field] <= upper:
                raise ValueError('invalid bound')
        if result['stdout_bytes'] + result['stderr_bytes'] > result['output_limit']:
            raise ValueError('invalid output size')
        if result['exit'] is not None and (type(result['exit']) is not int or not -127 <= result['exit'] <= 255):
            raise ValueError('invalid exit')
        for field in ('created_at', 'finished_at'):
            value = result[field]
            if field == 'finished_at' and value is None:
                continue
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError('invalid timestamp')
        active = result['state'] in ('starting', 'running')
        if active and (result['finished_at'] is not None or result['exit'] is not None):
            raise ValueError('invalid active status')
        if not active and result['finished_at'] is None:
            raise ValueError('missing finish timestamp')
        if result['state'] == 'exited' and result['exit'] is None:
            raise ValueError('missing exit')
        return result, None
    except (ValueError, KeyError, TypeError, RecursionError, OverflowError) as error:
        raise ResponseError('invalid job response') from error


def http_error_message(status):
    """Static status-only diagnostics; never trust reason, headers or body."""
    category = {
        401: 'authentication rejected; check key, clock and signed origin',
        403: 'authorization denied; check key capabilities and policy',
        429: 'rate or concurrency limit reached',
        503: 'service temporarily unavailable',
    }.get(status, 'server rejected request')
    # Only allow integer HTTP status codes into user-visible diagnostics.
    code = str(status) if type(status) is int and 100 <= status <= 599 else 'unknown'
    return 'ctl: HTTP ' + code + ': ' + category + '; no automatic retry. Verify state before repeating a write.'



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


def request(base_url, method, target, headers, body, *, expected_statuses=(200,)):
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
            raise ResponseError('invalid response length')
        data = response.read(int(length) + 1)
        if len(data) != int(length):
            raise ResponseError('incomplete response')
        if response.status not in expected_statuses:
            raise urllib.error.HTTPError(url, response.status, 'server rejected request', None, None)
        return data


def parser():
    p = argparse.ArgumentParser(description='Signed HTTP control; TLS required; operations are never retried automatically')
    sub = p.add_subparsers(dest='operation', required=True)
    sub.add_parser('health')
    confirm = sub.add_parser('migration-confirm', help='confirm one active rollout only after external validation')
    confirm.add_argument('rollout_id')
    probe = sub.add_parser('health-probe', help='write a 60-second one-use signed health probe, not a private key')
    probe.add_argument('output')
    exe = sub.add_parser('exec', description=(
        'Exit: remote 0..255; signal -N maps to 128+N; timeout 124; '
        'truncation 125; HTTP/transport/protocol failure 255; configuration 1. '
        'Timeout takes precedence over truncation. Reserved codes may overlap '
        'remote exits; JSON and stderr diagnostics distinguish the cause.'))
    exe.add_argument('--raw', action='store_true', help='write decoded remote stdout/stderr separately without JSON (not binary-safe)')
    exe.add_argument('command')
    exe.add_argument('timeout', nargs='?', type=int, default=60)
    jobs = sub.add_parser('jobs', help='submit, inspect, read or cancel bounded durable commands')
    actions = jobs.add_subparsers(dest='job_action', required=True)
    submit = actions.add_parser('submit', help='submit once with a caller-chosen stable ID; never automatically retried')
    submit.add_argument('--id', required=True)
    submit.add_argument('command')
    submit.add_argument('--timeout', type=int, default=3600)
    for action in ('status', 'cancel'):
        actions.add_parser(action).add_argument('id')
    logs = actions.add_parser('logs')
    logs.add_argument('id')
    logs.add_argument('--stream', choices=('stdout', 'stderr'), default='stdout')
    logs.add_argument('--cursor', type=int, default=0)
    logs.add_argument('--limit', type=int, default=65536)
    logs.add_argument('--raw', action='store_true', help='write selected stream bytes to stdout, without JSON or newline')
    shot = sub.add_parser('screenshot')
    shot.add_argument('output', nargs='?', default='screenshot.png')
    hierarchy = sub.add_parser('hierarchy', help='read the active Android accessibility hierarchy without navigation')
    hierarchy.add_argument('output', nargs='?', default='hierarchy.xml')
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
        elif operation == 'jobs':
            method, target, content_type = 'POST', '/jobs/' + args.job_action, 'application/json'
            body = json.dumps(job_request(args), separators=(',', ':')).encode()
            if len(body) > 65536:
                raise ValueError('job request too large')
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
        elif operation == 'hierarchy':
            if not args.output:
                raise ValueError('hierarchy output required')
            target, output = '/ui/hierarchy', args.output
        headers = signed_headers(private, key_id, base, method, target, body, content_type)
        if operation == 'health-probe':
            # Use exclusive creation so no accidental overwrite of key/config files.
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump({'method': method, 'target': target, 'headers': headers}, f)
            print('Saved one-use health probe; valid for 60 seconds.')
            return 0
        try:
            if operation == 'jobs' and args.job_action == 'submit':
                print('ctl: job id: ' + args.id + '; if outcome is unknown, use jobs status with this ID before resubmitting.', file=sys.stderr, flush=True)
                data = request(base, method, target, headers, body, expected_statuses=(200, 202))
            else:
                data = request(base, method, target, headers, body)
        except urllib.error.HTTPError:
            raise
        except OSError as error:
            raise ResponseError('transport failure') from error
        if operation == 'jobs':
            result, raw = job_result(data, args)
            if args.job_action == 'logs' and args.raw:
                sys.stdout.buffer.write(raw)
                sys.stdout.buffer.flush()
            else:
                print(json.dumps(result, separators=(',', ':')))
            return 0
        if operation == 'exec':
            result, status = exec_result(data)
            if args.raw:
                sys.stdout.write(result['stdout'])
                sys.stderr.write(result['stderr'])
            else:
                # Preserve the server JSON text and historical trailing newline.
                print(data.decode('utf-8'))
            if result['timed_out']:
                print('ctl: remote execution timed out (exit 124).', file=sys.stderr)
            elif result['truncated']:
                print('ctl: remote execution output truncated (exit 125).', file=sys.stderr)
            elif status:
                print('ctl: remote execution failed (exit %d).' % status, file=sys.stderr)
            return status
        if output:
            if operation == 'screenshot' and not data.startswith(b'\x89PNG\r\n\x1a\n'):
                raise ValueError('invalid screenshot response')
            if operation == 'hierarchy':
                data = validate_hierarchy(data)
            atomic_output(output, data)
            print('Saved response (%d bytes).' % len(data))
        else:
            # stdout is explicitly requested command result, not a service log.
            print(data.decode('utf-8'))
        return 0
    except urllib.error.HTTPError as error:
        print(http_error_message(error.code), file=sys.stderr)
        error.close()
        return 255
    except (ResponseError, http.client.HTTPException, urllib.error.URLError, TimeoutError, ConnectionError):
        print('ctl: transport/protocol failure; remote outcome may be unknown; no automatic retry. Verify state before repeating a write.', file=sys.stderr)
        return 255
    except (OSError, ValueError, KeyError):
        # No private-key paths, request headers/body, tokens, remote body, or
        # low-level library exception text printed on failure.
        print('ctl: request/configuration failed; no automatic retry. Verify state before repeating a write.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
