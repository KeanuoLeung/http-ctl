"""Native OpenSSH over authenticated WSS, entirely isolated on loopback.

Requires local OpenSSH binaries; creates and destroys only ephemeral test keys.
No user ssh config, production credentials, external services, or system edits.
"""
import contextlib
import datetime
import hashlib
import ipaddress
import json
import os
import pwd
import select
import signal
import shlex
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_port(number, process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f'test daemon exited with {process.returncode}')
        try:
            with socket.create_connection(('127.0.0.1', number), timeout=.2):
                return
        except OSError:
            time.sleep(.03)
    raise RuntimeError('test daemon did not listen')


def pem_key(path, key):
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    path.chmod(0o600)


class ThreadServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TLSTunnel(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with self.server.tls.wrap_socket(self.request, server_side=True) as downstream:
                with socket.create_connection(('127.0.0.1', self.server.target)) as upstream:
                    endpoints = [downstream, upstream]
                    while endpoints:
                        readable, _, _ = select.select(endpoints, [], [], 20)
                        if not readable:
                            return
                        for src in readable:
                            data = src.recv(65536)
                            if not data:
                                return
                            (upstream if src is downstream else downstream).sendall(data)
        except (OSError, ssl.SSLError):
            pass


@pytest.fixture(scope='module')
def native_ssh():
    for command in ('ssh', 'sshd', 'ssh-keygen', 'scp', 'sftp'):
        if not shutil.which(command):
            pytest.skip(f'isolated native SSH integration requires {command}')
    if not (ROOT / 'http_ctl/ssh_bridge.py').exists():
        pytest.skip('optional SSH bridge not installed')
    # StrictModes checks the complete authorized-key path; /tmp is world
    # writable on hosted runners. Keep the private fixture inside the checkout
    # instead of weakening sshd ownership checks or changing system modes.
    with tempfile.TemporaryDirectory(prefix='.http-ctl-openssh-', dir=ROOT) as directory:
        d = Path(directory)
        processes = []
        logs = []
        tls_server = None
        try:
            for name in ('host', 'identity', 'wrong-host'):
                subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(d / name)], check=True)
            ssh_port, bridge_port = port(), port()
            config = d / 'sshd_config'
            config.write_text(f'''ListenAddress 127.0.0.1
Port {ssh_port}
HostKey {d}/host
PidFile {d}/sshd.pid
AuthorizedKeysFile {d}/identity.pub
StrictModes yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AllowUsers {pwd.getpwuid(os.getuid()).pw_name}
AllowTcpForwarding local
GatewayPorts no
PermitTunnel no
X11Forwarding no
Subsystem sftp internal-sftp
LogLevel VERBOSE
''')
            def start(args, logfile):
                log = open(d / logfile, 'wb')
                logs.append(log)
                proc = subprocess.Popen(args, cwd=ROOT, stdout=log, stderr=log)
                processes.append(proc)
                return proc
            sshd = start([shutil.which('sshd'), '-D', '-e', '-f', str(config)], 'sshd.log')
            wait_port(ssh_port, sshd)

            # CA trust is confined to this child's environment. TLS verification
            # stays enabled; this certificate has an explicit loopback IP SAN.
            tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'http-ctl isolated test CA')])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(minutes=1))
                    .not_valid_after(now + datetime.timedelta(hours=1))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                    .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                    .sign(tls_key, hashes.SHA256()))
            pem_key(d / 'tls.key', tls_key)
            (d / 'ca.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(d / 'ca.pem', d / 'tls.key')
            tls_server = ThreadServer(('127.0.0.1', 0), TLSTunnel)
            tls_server.tls, tls_server.target = tls, bridge_port
            threading.Thread(target=tls_server.serve_forever, daemon=True).start()
            origin = f'https://127.0.0.1:{tls_server.server_address[1]}'
            signing = ed25519.Ed25519PrivateKey.generate()
            pem_key(d / 'signing.pem', signing)
            data = {'external_origin': origin, 'replay_db': str(d / 'state/replay.sqlite3'),
                    'keys': {'test-ssh': {'public_key_pem': signing.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(), 'scopes': ['ssh:connect']}}}
            (d / 'bridge.json').write_text(json.dumps(data))
            (d / 'bridge.json').chmod(0o600)
            bridge = start([sys.executable, '-m', 'http_ctl.ssh_bridge', '--config', str(d / 'bridge.json'), '--listen-port', str(bridge_port), '--ssh-port', str(ssh_port)], 'bridge.log')
            wait_port(bridge_port, bridge)
            proxy = shlex.join([sys.executable, '-m', 'http_ctl.ssh_proxy', '--origin', origin, '--key-id', 'test-ssh', '--private-key', str(d / 'signing.pem')])
            known = d / 'known_hosts'
            known.write_text('isolated-http-ctl ' + (d / 'host.pub').read_text())
            client_config = d / 'ssh_config'
            client_config.write_text(f'''Host test-target
  HostName isolated-http-ctl
  HostKeyAlias isolated-http-ctl
  User {pwd.getpwuid(os.getuid()).pw_name}
  IdentityFile {d}/identity
  IdentitiesOnly yes
  IdentityAgent none
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  BatchMode yes
  ConnectTimeout 8
  ProxyCommand {proxy}
''')
            env = dict(os.environ, SSL_CERT_FILE=str(d / 'ca.pem'), PYTHONPATH=str(ROOT))
            def run(command, *, input=None, timeout=30, extra=()):
                args = ['ssh', '-F', str(client_config), *extra, 'test-target', command]
                proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=ROOT, start_new_session=True)
                try:
                    stdout, stderr = proc.communicate(input=input, timeout=timeout)
                    if proc.returncode == 255:
                        stderr += b"\nIsolated test sshd diagnostics:\n" + (d / "sshd.log").read_bytes()[-16000:]
                    return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)
                finally:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
            yield {'run': run, 'directory': d, 'config': client_config, 'env': env}
        finally:
            for proc in reversed(processes):
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            if tls_server:
                tls_server.shutdown()
                tls_server.server_close()
            for log in logs:
                log.close()
            # Captured by pytest; displayed only for failed tests. Keep output
            # bounded and limited to this ephemeral, loopback-only daemon.
            sshd_log = d / 'sshd.log'
            if sshd_log.exists():
                print('\nIsolated test sshd diagnostics:\n' + sshd_log.read_text(errors='replace')[-16000:])



def test_native_ssh_exit_status(native_ssh):
    result = native_ssh['run']("printf test-ok; printf test-error >&2; exit 7")
    assert result.returncode == 7, result.stderr.decode(errors='replace')
    assert result.stdout == b'test-ok'
    assert b'test-error' in result.stderr


def test_native_ssh_large_binary_stdout(native_ssh):
    result = native_ssh['run']("python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256))*16384)'")
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    assert hashlib.sha256(result.stdout).digest() == hashlib.sha256(bytes(range(256)) * 16384).digest()


def test_native_ssh_stdin_eof_tail(native_ssh):
    payload = bytes(range(256)) * 8192
    result = native_ssh['run']("python3 -c 'import sys; d=sys.stdin.buffer.read(); sys.stdout.buffer.write(d+b\"EOF-TAIL\")'", input=payload)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    assert result.stdout == payload + b'EOF-TAIL'


def test_native_ssh_pty_allocation(native_ssh):
    try:
        result = native_ssh['run']("test -t 0 && test -t 1 && printf PTY-OK", extra=('-tt',), input=b'', timeout=8)
    except subprocess.TimeoutExpired:
        if 'Attempt to write login records by non-root user' in (native_ssh['directory'] / 'sshd.log').read_text():
            pytest.skip('local sshd cannot allocate PTY: non-root login records prohibited; resize untested')
        raise
    if result.returncode != 0 and 'Attempt to write login records by non-root user' in (native_ssh['directory'] / 'sshd.log').read_text():
        pytest.skip('local sshd cannot allocate PTY: non-root login records prohibited; resize untested')
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    assert b'PTY-OK' in result.stdout


@pytest.mark.parametrize('program', ['scp', 'sftp'])
def test_native_file_roundtrip(native_ssh, program):
    d = native_ssh['directory']
    payload = bytes(range(256)) * 4096
    source, remote, returned = [d / f'{program}-{part}' for part in ('source', 'remote', 'returned')]
    source.write_bytes(payload)
    base = [program, '-F', str(native_ssh['config'])]
    kwargs = dict(env=native_ssh['env'], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if program == 'scp':
        for args in ([str(source), 'test-target:' + str(remote)], ['test-target:' + str(remote), str(returned)]):
            result = subprocess.run(base + args, **kwargs)
            assert result.returncode == 0, result.stderr.decode(errors='replace')
    else:
        result = subprocess.run(base + ['-b', '-', 'test-target'], input=f'put {source} {remote}\nget {remote} {returned}\n'.encode(), **kwargs)
        assert result.returncode == 0, result.stderr.decode(errors='replace')
    assert returned.read_bytes() == payload


def test_native_hostkey_mismatch_rejected(native_ssh):
    d = native_ssh['directory']
    wrong = d / 'wrong_known_hosts'
    wrong.write_text('isolated-http-ctl ' + (d / 'wrong-host.pub').read_text())
    result = native_ssh['run']('printf MUST-NOT-RUN', extra=('-o', f'UserKnownHostsFile={wrong}'))
    assert result.returncode == 255
    assert b'MUST-NOT-RUN' not in result.stdout
    assert b'HOST IDENTIFICATION HAS CHANGED' in result.stderr


def test_native_local_forward(native_ssh):
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            while True:
                chunk = self.request.recv(65536)
                if not chunk:
                    return
                self.request.sendall(chunk)
    with ThreadServer(('127.0.0.1', 0), Echo) as echo:
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        local_port = port()
        proc = subprocess.Popen(['ssh', '-F', str(native_ssh['config']), '-N', '-o', 'ExitOnForwardFailure=yes', '-L', f'127.0.0.1:{local_port}:127.0.0.1:{echo.server_address[1]}', 'test-target'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=native_ssh['env'], cwd=ROOT)
        try:
            wait_port(local_port, proc)
            payload = os.urandom(131072)
            with socket.create_connection(('127.0.0.1', local_port), timeout=10) as sock:
                sock.sendall(payload)
                received = bytearray()
                while len(received) < len(payload):
                    chunk = sock.recv(65536)
                    assert chunk
                    received.extend(chunk)
                assert bytes(received) == payload
        finally:
            proc.terminate()
            proc.communicate(timeout=10)
            echo.shutdown()


def test_native_slow_stdout_consumer_no_tail_loss(native_ssh):
    command = "python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256))*16384+b\"FINAL-TAIL\")'"
    proc = subprocess.Popen(['ssh', '-F', str(native_ssh['config']), 'test-target', command], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=native_ssh['env'], cwd=ROOT)
    output = bytearray()
    deadline = time.monotonic() + 30
    try:
        while True:
            assert time.monotonic() < deadline, 'slow-consumer SSH timed out'
            readable, _, _ = select.select([proc.stdout], [], [], 1)
            if not readable:
                continue
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                break
            output.extend(chunk)
            time.sleep(.002)
        assert proc.wait(timeout=10) == 0, proc.stderr.read().decode(errors='replace')
        assert output == bytes(range(256)) * 16384 + b'FINAL-TAIL'
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        proc.stderr.close()


def test_native_tls_untrusted_ca_rejected(native_ssh):
    empty_ca_directory = native_ssh['directory'] / 'empty-ca-directory'
    empty_ca_directory.mkdir()
    env = dict(native_ssh['env'], SSL_CERT_FILE='/dev/null', SSL_CERT_DIR=str(empty_ca_directory))
    result = subprocess.run(['ssh', '-F', str(native_ssh['config']), 'test-target', 'printf MUST-NOT-RUN'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=ROOT, timeout=15)
    assert result.returncode == 255
    assert b'MUST-NOT-RUN' not in result.stdout
    assert b'SSH transport failed' in result.stderr
