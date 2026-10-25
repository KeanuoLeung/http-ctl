"""Isolated test fixtures. No production credentials, phones, or external networks."""
import http.client
import json
import os
import socket
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from http_ctl import auth, server as server_module

ORIGIN = 'https://ctl.example.test'


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes

    def json(self):
        return json.loads(self.body)


class TestService:
    __test__ = False

    def __init__(self, directory):
        self.directory = directory
        self.root = directory / 'files'
        self.root.mkdir(mode=0o700)
        self.state = directory / 'state'
        self.state.mkdir(mode=0o700)
        # Ephemeral, test-only in-memory private keys. Never persisted or logged.
        self.private = Ed25519PrivateKey.generate()
        self.other_private = Ed25519PrivateKey.generate()
        self.config_path = directory / 'server.json'
        self.data = {
            'external_origin': ORIGIN,
            'replay_db': str(self.state / 'replay.sqlite3'),
            'adb_serial': 'test-device-never-used',
            'keys': {
                'test-key': self.key_record(self.private, sorted(auth.SCOPES)),
                'health-only': self.key_record(self.private, ['health:read']),
                'other-key': self.key_record(self.other_private, ['health:read']),
            },
        }
        self.write_config()
        self.start()

    def key_record(self, private, scopes):
        record = {
            'public_key_pem': private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode('ascii'),
            'scopes': scopes,
        }
        if {'files:read', 'files:write'}.intersection(scopes):
            record['file_root'] = str(self.root)
        return record

    def write_config(self):
        temporary = self.config_path.with_suffix('.new')
        temporary.write_text(json.dumps(self.data), encoding='utf-8')
        temporary.chmod(0o600)
        os.replace(temporary, self.config_path)

    def start(self):
        self.server = server_module.Server(('127.0.0.1', 0), auth.Config(str(self.config_path)))
        # Deterministic stress tests are not rate-limit tests. Rate limits get
        # their own explicit tests rather than masking signature failures.
        self.server.bucket = server_module.Bucket(100000, 100000)
        self.server.key_limit = lambda _key: True
        self.server.adb = '/test-only/adb-not-executed'
        self.server.bash = '/test-only/bash-not-executed'
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive()

    def restart(self):
        self.stop()
        self.start()

    def headers(self, method='GET', target='/health', body=b'', *, key_id='test-key', private=None, origin=ORIGIN, content_type=None, **kwargs):
        content_type = content_type or ('application/json' if target.split('?')[0] in ('/exec', '/ui', '/migration/confirm') else 'application/octet-stream')
        return auth.signed_headers(private or self.private, key_id, origin, method, target, body, content_type, **kwargs)

    def request(self, method='GET', target='/health', body=b'', *, headers=None, sign_method=None, sign_target=None, **kwargs):
        if headers is None:
            headers = self.headers(sign_method or method, sign_target or target, body, **kwargs)
        pairs = list(headers.items()) if isinstance(headers, dict) else list(headers)
        if not any(name.lower() == 'host' for name, _ in pairs):
            pairs.insert(0, ('Host', '127.0.0.1'))
        pairs.append(('Connection', 'close'))
        wire = (method + ' ' + target + ' HTTP/1.1\r\n').encode('ascii')
        wire += b''.join(name.encode('ascii') + b': ' + value.encode('ascii') + b'\r\n' for name, value in pairs)
        return self.raw(wire + b'\r\n' + body)

    def raw(self, wire, *, shutdown_write=True):
        with socket.create_connection(self.server.server_address, timeout=4) as connection:
            connection.settimeout(4)
            connection.sendall(wire)
            if shutdown_write:
                connection.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(connection)
            response.begin()
            return Response(response.status, dict(response.getheaders()), response.read())


@pytest.fixture
def service(tmp_path, monkeypatch):
    def forbid_unmocked_subprocess(*args, **kwargs):
        raise AssertionError('server subprocesses must be explicitly mocked; never use real ADB')
    monkeypatch.setattr(server_module, 'run_bounded', forbid_unmocked_subprocess)
    instance = TestService(tmp_path)
    try:
        yield instance
    finally:
        instance.stop()
