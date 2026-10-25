"""Client proxy/TLS tests use local servers and fresh, short-lived test certs."""
import datetime as dt
import http.server
import json
import os
import select
import socket
import ssl
import threading
import urllib.error

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from http_ctl import auth, client, server as server_module


@pytest.fixture
def local_https_proxy(service, tmp_path, monkeypatch):
    # Self-signed CA and private key exist only in this test's temporary directory.
    tls_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ctl.example.test')])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(tls_private.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('ctl.example.test')]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(tls_private, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'test-only-cert.pem', tmp_path / 'test-only-tls-key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(tls_private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    # Restart serving the same loopback listener with TLS. The public origin
    # remains ctl.example.test:443, mapped only by our in-process CONNECT proxy.
    service.server.shutdown()
    service.thread.join(timeout=3)
    service.server.socket = context.wrap_socket(service.server.socket, server_side=True)
    service.thread = threading.Thread(target=service.server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
    service.thread.start()
    connects = []

    class ConnectProxy(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args):
            pass
        def do_CONNECT(self):
            connects.append(self.path)
            # Never resolve or connect to a host supplied over the network.
            if self.path != 'ctl.example.test:443':
                self.send_error(403)
                return
            with socket.create_connection(service.server.server_address, timeout=3) as upstream:
                self.send_response_only(200)
                self.end_headers()
                self.wfile.flush()
                peers = [self.connection, upstream]
                while peers:
                    ready, _, _ = select.select(peers, [], [], 3)
                    if not ready:
                        return
                    for source in ready:
                        try:
                            chunk = source.recv(65536)
                            if not chunk:
                                return
                            target = upstream if source is self.connection else self.connection
                            target.sendall(chunk)
                        except OSError:
                            # Expected when a client rejects our untrusted TLS cert.
                            return

    proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), ConnectProxy)
    proxy.daemon_threads = True
    thread = threading.Thread(target=proxy.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
    thread.start()
    for name in list(os.environ):
        if name.lower().endswith('_proxy'):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('https_proxy', 'http://127.0.0.1:' + str(proxy.server_address[1]))
    monkeypatch.setenv('no_proxy', '')
    monkeypatch.setenv('SSL_CERT_FILE', str(cert_path))
    try:
        yield service, connects, cert_path
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=3)


def test_https_connect_proxy_preserves_signed_ascii_target(local_https_proxy):
    service, connects, _ = local_https_proxy
    (service.root / 'a b+中.txt').write_bytes(b'proxy round trip')
    target = '/download?path=a%20b%2B%E4%B8%AD.txt'
    headers = service.headers('GET', target)
    assert client.request('https://ctl.example.test', 'GET', target, headers, b'') == b'proxy round trip'
    assert connects == ['ctl.example.test:443']
    # It reached real authentication and the durable replay store, not a mock.
    with pytest.raises(urllib.error.HTTPError) as error:
        client.request('https://ctl.example.test', 'GET', target, headers, b'')
    assert error.value.code == 401
    assert connects == ['ctl.example.test:443'] * 2


def test_https_connect_proxy_keeps_certificate_verification(local_https_proxy, monkeypatch):
    service, connects, _ = local_https_proxy
    # Deliberately replace the trusted test CA with the normal system store.
    monkeypatch.delenv('SSL_CERT_FILE')
    with pytest.raises(urllib.error.URLError) as error:
        client.request('https://ctl.example.test', 'GET', '/health', service.headers(), b'')
    assert isinstance(error.value.reason, ssl.SSLCertVerificationError)
    assert connects == ['ctl.example.test:443']


def test_client_refuses_redirect_without_replaying_signature(local_https_proxy, monkeypatch):
    service, connects, _ = local_https_proxy
    seen = []
    original = server_module.Handler._dispatch
    def redirect(self):
        seen.append(self.path)
        if self.path == '/health':
            self.send_response_only(307)
            self.send_header('Location', 'https://ctl.example.test/screenshot')
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()
            return
        return original(self)
    monkeypatch.setattr(server_module.Handler, '_dispatch', redirect)
    with pytest.raises(ValueError, match='redirect refused'):
        client.request('https://ctl.example.test', 'GET', '/health', service.headers(), b'')
    assert seen == ['/health']
    assert connects == ['ctl.example.test:443']


@pytest.fixture
def cli_credentials(service, tmp_path, monkeypatch):
    key_file = tmp_path / 'test-only-client.pem'
    key_file.write_bytes(service.private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_file.chmod(0o600)
    monkeypatch.setenv('CTL_BASE_URL', 'https://ctl.example.test')
    monkeypatch.setenv('CTL_KEY_ID', 'test-key')
    monkeypatch.setenv('CTL_PRIVATE_KEY_FILE', str(key_file))
    return key_file


def test_cli_health_probe_is_private_valid_one_use_and_non_overwriting(service, cli_credentials, tmp_path, capsys):
    output = tmp_path / 'probe.json'
    assert client.main(['health-probe', str(output)]) == 0
    assert output.stat().st_mode & 0o777 == 0o600
    probe = json.loads(output.read_text())
    assert set(probe) == {'method', 'target', 'headers'}
    assert probe['method'] == 'GET'
    assert probe['target'] == '/health'
    assert service.request(headers=probe['headers']).status == 200
    assert service.request(headers=probe['headers']).status == 401
    original = output.read_bytes()
    assert client.main(['health-probe', str(output)]) == 1
    assert output.read_bytes() == original
    logs = capsys.readouterr()
    assert 'PRIVATE KEY' not in output.read_text()
    assert probe['headers']['X-Http-Ctl-Signature'] not in logs.out + logs.err


def test_cli_health_probe_rejects_symlink(service, cli_credentials, tmp_path):
    real = tmp_path / 'real'
    real.write_bytes(b'preserve')
    symlink = tmp_path / 'probe'
    symlink.symlink_to(real)
    assert client.main(['health-probe', str(symlink)]) == 1
    assert real.read_bytes() == b'preserve'


def test_cli_health_mock_preserves_signed_request(service, cli_credentials, monkeypatch, capsys):
    calls = []
    def local_request(base, method, target, headers, body):
        calls.append((base, method, target, body))
        response = service.request(method, target, body, headers=headers)
        assert response.status == 200
        return response.body
    monkeypatch.setattr(client, 'request', local_request)
    assert client.main(['health']) == 0
    assert calls == [('https://ctl.example.test', 'GET', '/health', b'')]
    assert '"ok": true' in capsys.readouterr().out


def test_cli_error_is_generic_and_never_retries(service, cli_credentials, monkeypatch, capsys):
    calls = []
    def fail(*args):
        calls.append(args)
        raise ValueError('sensitive remote output and credential location')
    monkeypatch.setattr(client, 'request', fail)
    assert client.main(['exec', 'private-command']) == 1
    assert len(calls) == 1
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'sensitive' not in captured.err
    assert 'private-command' not in captured.err
    assert 'no automatic retry' in captured.err


@pytest.mark.parametrize('value', ['http://ctl.example.test', 'https://ctl.example.test/', 'https://USER@ctl.example.test', 'https://CTL.example.test', 'https://ctl.example.test?x=y'])
def test_client_requires_exact_https_origin(value):
    with pytest.raises(ValueError):
        client.request(value, 'GET', '/health', {}, b'')


def test_atomic_download_output_private_and_no_follow(tmp_path):
    target = tmp_path / 'target'
    outside = tmp_path / 'outside'
    outside.write_bytes(b'preserve')
    target.symlink_to(outside)
    client.atomic_output(target, b'response')
    assert not target.is_symlink()
    assert target.read_bytes() == b'response'
    assert target.stat().st_mode & 0o777 == 0o600
    assert outside.read_bytes() == b'preserve'
