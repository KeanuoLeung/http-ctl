"""Local-only optional SSH transport regression tests; no deployment."""
import asyncio
import json
import os

import pytest
pytest.importorskip('websockets')
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus, ConnectionClosed

from http_ctl.auth import Config, ReplayStore, signed_headers as _signed_headers
from http_ctl.ssh_bridge import Bridge, SUBPROTOCOL, CHUNK


def signed_headers(*args, **kwargs):
    headers = _signed_headers(*args, **kwargs)
    headers.pop('Content-Length')
    return headers


def setup(tmp_path, scopes=None):
    tmp_path.chmod(0o700)
    key = Ed25519PrivateKey.generate()
    data = {'external_origin':'https://example.test', 'replay_db':str(tmp_path / 'replay.db'),
            'keys':{'test':{'public_key_pem':key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(), 'scopes': ['ssh:connect'] if scopes is None else scopes}}}
    path = tmp_path / 'config.json'
    path.write_text(json.dumps(data)); path.chmod(0o600)
    config = Config(str(path))
    return key, config, ReplayStore(config.replay_db), path, data


def test_roundtrip_halfclose_binary(tmp_path):
    async def scenario():
        key, config, replay, _, _ = setup(tmp_path)
        async def echo(reader, writer):
            while data := await reader.read(CHUNK):
                writer.write(data); await writer.drain()
            writer.write(b'after-eof'); await writer.drain()
            writer.write_eof(); writer.close(); await writer.wait_closed()
        tcp = await asyncio.start_server(echo, '127.0.0.1', 0)
        bridge = Bridge(config, replay, ssh_port=tcp.sockets[0].getsockname()[1])
        try:
            async with bridge.serve(0) as server:
                uri = 'ws://127.0.0.1:' + str(server.sockets[0].getsockname()[1]) + '/ssh'
                headers = signed_headers(key, 'test', config.external_origin, 'GET', '/ssh')
                async with connect(uri, proxy=None, additional_headers=headers, subprotocols=[SUBPROTOCOL], compression=None) as ws:
                    body = bytes(range(256)) * 300
                    for i in range(0, len(body), CHUNK):
                        await ws.send(b'\0' + body[i:i+CHUNK])
                    await ws.send(b'\1')
                    output = b''
                    while (data := await ws.recv()) != b'\1':
                        assert data[0] == 0
                        output += data[1:]
                    assert output == body + b'after-eof'
        finally:
            tcp.close(); await tcp.wait_closed()
    asyncio.run(scenario())


@pytest.mark.parametrize('mode', ['unsigned', 'scope', 'path', 'replay', 'protocol', 'duplicate'])
def test_rejected_before_dial(tmp_path, mode):
    async def scenario():
        key, config, replay, _, _ = setup(tmp_path, [] if mode == 'scope' else None)
        calls = []
        async def target(reader, writer):
            calls.append(True); writer.close(); await writer.wait_closed()
        tcp = await asyncio.start_server(target, '127.0.0.1', 0)
        bridge = Bridge(config, replay, ssh_port=tcp.sockets[0].getsockname()[1])
        try:
            async with bridge.serve(0) as server:
                uri = 'ws://127.0.0.1:' + str(server.sockets[0].getsockname()[1]) + ('/wrong' if mode == 'path' else '/ssh')
                h = signed_headers(key, 'test', config.external_origin, 'GET', '/ssh')
                if mode == 'unsigned': h = {}
                if mode == 'duplicate': h = list(h.items()) + [('Content-Digest', h['Content-Digest'])]
                if mode == 'replay':
                    from http_ctl.auth import authenticate
                    authenticate(config, replay, 'GET', '/ssh', h, b'', 'ssh:connect')
                with pytest.raises(InvalidStatus):
                    async with connect(uri, proxy=None, additional_headers=h, subprotocols=[] if mode == 'protocol' else [SUBPROTOCOL]):
                        pass
                assert not calls
        finally:
            tcp.close(); await tcp.wait_closed()
    asyncio.run(scenario())


@pytest.mark.parametrize('message', ['text', b'', b'\x02', b'\x00', b'\x01extra', b'\0' + b'x' * (CHUNK + 1)], ids=['text','empty','opcode','empty-data','bad-eof','oversize'])
def test_bad_message_closes_without_forwarding(tmp_path, message):
    async def scenario():
        key, config, replay, _, _ = setup(tmp_path)
        got = []
        async def target(reader, writer):
            got.append(await reader.read()); writer.close(); await writer.wait_closed()
        tcp = await asyncio.start_server(target, '127.0.0.1', 0)
        bridge = Bridge(config, replay, ssh_port=tcp.sockets[0].getsockname()[1])
        try:
            async with bridge.serve(0) as server:
                headers = signed_headers(key, 'test', config.external_origin, 'GET', '/ssh')
                async with connect('ws://127.0.0.1:%d/ssh' % server.sockets[0].getsockname()[1], proxy=None, additional_headers=headers, subprotocols=[SUBPROTOCOL]) as ws:
                    await ws.send(message)
                    with pytest.raises(ConnectionClosed): await ws.recv()
                await asyncio.sleep(.01)
                assert got == [b'']
        finally:
            tcp.close(); await tcp.wait_closed()
    asyncio.run(scenario())


@pytest.mark.parametrize('change', ['revoke', 'scope', 'replace', 'invalid'])
def test_revocation_closes_established(tmp_path, monkeypatch, change):
    import http_ctl.ssh_bridge as module
    monkeypatch.setattr(module, 'REVALIDATE_SECONDS', .02)
    async def scenario():
        key, config, replay, path, data = setup(tmp_path)
        async def target(reader, writer):
            await reader.read(); writer.close(); await writer.wait_closed()
        tcp = await asyncio.start_server(target, '127.0.0.1', 0)
        bridge = Bridge(config, replay, ssh_port=tcp.sockets[0].getsockname()[1])
        try:
            async with bridge.serve(0) as server:
                headers = signed_headers(key, 'test', config.external_origin, 'GET', '/ssh')
                async with connect('ws://127.0.0.1:%d/ssh' % server.sockets[0].getsockname()[1], proxy=None, additional_headers=headers, subprotocols=[SUBPROTOCOL]) as ws:
                    if change == 'revoke': data['keys']['test']['revoked'] = True
                    elif change == 'scope': data['keys']['test']['scopes'] = []
                    elif change == 'replace': data['keys']['test']['public_key_pem'] = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                    path.write_text('invalid' if change == 'invalid' else json.dumps(data))
                    with pytest.raises(ConnectionClosed): await asyncio.wait_for(ws.recv(), 1)
        finally:
            tcp.close(); await tcp.wait_closed()
    asyncio.run(scenario())


def test_connection_quota_and_cleanup(tmp_path, monkeypatch):
    import http_ctl.ssh_bridge as module
    monkeypatch.setattr(module, 'MAX_CONNECTIONS', 1)
    async def scenario():
        _, config, replay, _, _ = setup(tmp_path)
        bridge = Bridge(config, replay)
        async with bridge.serve(0) as server:
            port = server.sockets[0].getsockname()[1]
            r1, w1 = await asyncio.open_connection('127.0.0.1', port)
            r2, w2 = await asyncio.open_connection('127.0.0.1', port)
            assert await asyncio.wait_for(r2.read(), 1) == b''
            assert len(bridge.connections) == 1
            w1.close(); w2.close()
            await w1.wait_closed(); await w2.wait_closed()
            await asyncio.sleep(.01)
            assert not bridge.connections
    asyncio.run(scenario())


def test_thread_admission_survives_socket_cancellation(tmp_path, monkeypatch):
    import threading
    import http_ctl.ssh_bridge as module
    monkeypatch.setattr(module, 'MAX_CONNECTIONS', 1)
    async def scenario():
        _, config, replay, _, _ = setup(tmp_path)
        bridge = Bridge(config, replay)
        release = threading.Event()
        task = asyncio.create_task(bridge.disk_check(release.wait, 2))
        await asyncio.sleep(.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        with pytest.raises(PermissionError): await bridge.disk_check(lambda: None)
        release.set()
        await asyncio.sleep(.05)
        assert await bridge.disk_check(lambda: 42) == 42
    asyncio.run(scenario())
