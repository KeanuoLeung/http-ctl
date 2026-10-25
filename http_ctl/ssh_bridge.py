"""Optional loopback-only WebSocket transport for a separately secured sshd.

Wire v1: binary 0x00 + 1..32768 raw bytes; binary 0x01 = directional
EOF. No SSH parsing, target selection, text, compression, or credentials.
External TLS termination must forward only the configured exact path here.
"""
import argparse
import asyncio
import contextlib
import logging
import re
import sys
from http import HTTPStatus

from cryptography.hazmat.primitives import serialization
from websockets.asyncio.server import ServerConnection, serve

from .auth import Config, ReplayStore, authenticate

SUBPROTOCOL = 'http-ctl-ssh-v1'
CHUNK = 32768
MAX_CONNECTIONS = 16
REVALIDATE_SECONDS = 5
HALF_CLOSE_TIMEOUT = 30
OPTIONS = dict(compression=None, max_size=CHUNK + 1, max_queue=4,
               write_limit=CHUNK, ping_interval=20, ping_timeout=20,
               close_timeout=5, open_timeout=10)
# Never expose signed headers through websockets' DEBUG handshake logging.
LOGGER = logging.Logger('http_ctl.ssh_transport', level=logging.CRITICAL + 1)
LOGGER.addHandler(logging.NullHandler())


def path_value(value):
    if not re.fullmatch(r'/[A-Za-z0-9/_-]{1,127}', value):
        raise ValueError('invalid bridge path')
    return value


def port_value(value):
    value = int(value)
    if not 1 <= value <= 65535:
        raise ValueError('invalid port')
    return value


async def relay(ws, reader, writer):
    """Bounded full duplex; EOF drains the opposite direction for up to 30s."""
    async def upload():
        while True:
            data = await reader.read(CHUNK)
            if not data:
                await ws.send(b'\x01')
                return
            await ws.send(b'\x00' + data)

    async def download():
        while True:
            data = await ws.recv()
            if not isinstance(data, bytes) or not data:
                raise ValueError('invalid transport message')
            if data == b'\x01':
                # Previous data was drained; pipe EOF closes its transport.
                writer.write_eof()
                return
            if data[0] != 0 or not 2 <= len(data) <= CHUNK + 1:
                raise ValueError('invalid transport message')
            writer.write(data[1:])
            await writer.drain()

    tasks = [asyncio.create_task(upload()), asyncio.create_task(download())]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        if pending:
            await asyncio.wait_for(asyncio.gather(*pending), HALF_CLOSE_TIMEOUT)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class Bridge:
    def __init__(self, config, replay, *, path='/ssh', ssh_port=8022):
        self.config, self.replay = config, replay
        self.path, self.ssh_port = path_value(path), port_value(ssh_port)
        self.connections = set()
        self.auth_slots = asyncio.Semaphore(MAX_CONNECTIONS)

    async def disk_check(self, function, *args):
        # Retain admission until the thread finishes, even if the socket closes.
        # Otherwise churned handshakes could queue unbounded executor work.
        if self.auth_slots.locked():
            raise PermissionError('authentication busy')
        await self.auth_slots.acquire()
        task = asyncio.create_task(asyncio.to_thread(function, *args))
        def finished(task):
            self.auth_slots.release()
            if not task.cancelled():
                task.exception()
        task.add_done_callback(finished)
        return await asyncio.shield(task)

    def connection(self, *args, **kwargs):
        owner = self
        class LimitedConnection(ServerConnection):
            def connection_made(self, transport):
                super().connection_made(transport)
                if len(owner.connections) >= MAX_CONNECTIONS:
                    transport.close()
                else:
                    owner.connections.add(self)
            def connection_lost(self, exc):
                owner.connections.discard(self)
                super().connection_lost(exc)
        return LimitedConnection(*args, **kwargs)

    async def request(self, connection, request):
        try:
            if request.path != self.path:
                return connection.respond(HTTPStatus.NOT_FOUND, 'not found\n')
            # Require exactly our protocol; no downgrade or alternate target.
            if request.headers.get_all('Sec-WebSocket-Protocol') != [SUBPROTOCOL]:
                raise ValueError('protocol required')
            if request.headers.get_all('Content-Length') not in ([], ['0']) or request.headers.get_all('Transfer-Encoding'):
                raise ValueError('body forbidden')
            # raw_items preserves duplicates for the signing profile to reject.
            class Headers:
                def items(self):
                    return request.headers.raw_items()
            connection.identity = await self.disk_check(
                authenticate, self.config, self.replay, 'GET',
                self.path, Headers(), b'', 'ssh:connect')
        except Exception:
            return connection.respond(HTTPStatus.FORBIDDEN, 'access denied\n')

    async def revalidate(self, identity):
        key_id, initial = identity
        encoded = initial.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        while True:
            await asyncio.sleep(REVALIDATE_SECONDS)
            current = (await self.disk_check(self.config.keys)).get(key_id)
            if (current is None or current.revoked or 'ssh:connect' not in current.scopes
                    or current.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) != encoded):
                raise PermissionError('access denied')

    async def handle(self, ws):
        writer = None
        tasks = []
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', self.ssh_port, limit=CHUNK), 5)
            tasks = [asyncio.create_task(relay(ws, reader, writer)),
                     asyncio.create_task(self.revalidate(ws.identity))]
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        except Exception:
            await ws.close(code=1011, reason='transport ended')
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(writer.wait_closed(), 5)

    def serve(self, port=18083, **kwargs):
        """Local integration tests may pass ssl= and port=0; CLI is loopback only."""
        return serve(self.handle, '127.0.0.1', port, subprotocols=[SUBPROTOCOL],
                     process_request=self.request, create_connection=self.connection,
                     logger=LOGGER, **OPTIONS, **kwargs)


async def run(args):
    config = Config(args.config)
    bridge = Bridge(config, ReplayStore(config.replay_db), path=args.path, ssh_port=args.ssh_port)
    async with bridge.serve(args.listen_port):
        await asyncio.Future()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--path', type=path_value, default='/ssh')
    parser.add_argument('--listen-port', type=port_value, default=18083)
    parser.add_argument('--ssh-port', type=port_value, default=8022)
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        return 0
    except Exception:
        print('SSH bridge failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
