"""Linux OpenSSH ProxyCommand: authenticated WSS to stdin/stdout raw bytes.

SSH host-key verification and SSH login remain entirely OpenSSH's job.
Never use this program as a shell, and never disable StrictHostKeyChecking.
"""
import argparse
import asyncio
import ssl
import sys
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from websockets.asyncio.client import connect

from .auth import origin, protected_read, signed_headers
from .ssh_bridge import CHUNK, HALF_CLOSE_TIMEOUT, LOGGER, OPTIONS, SUBPROTOCOL, path_value, relay


class OutputProtocol(asyncio.streams.FlowControlMixin):
    """Wait for all pipe bytes to flush before asyncio.run closes the loop."""
    def __init__(self, loop):
        super().__init__(loop=loop)
        self.closed = loop.create_future()

    def connection_lost(self, exc):
        super().connection_lost(exc)
        if not self.closed.done():
            if exc is None:
                self.closed.set_result(None)
            else:
                self.closed.set_exception(exc)

    def _get_close_waiter(self, stream):
        return self.closed


class NoRedirectConnect(connect):
    def process_redirect(self, exc):
        # Never send a signed upgrade to a redirected origin/path.
        return exc


async def run(args):
    base = origin(args.origin)
    path = path_value(args.path)
    key = serialization.load_pem_private_key(protected_read(args.private_key, 16384), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('Ed25519 required')
    proxy = args.proxy if args.proxy is not None else True
    if isinstance(proxy, str):
        p = urlsplit(proxy)
        if p.scheme not in ('http', 'https') or not p.hostname:
            raise ValueError('HTTP proxy required')
    headers = signed_headers(key, args.key_id, base, 'GET', path)
    # websockets rejects even Content-Length: 0; this field isn't signed.
    headers.pop('Content-Length')
    context = ssl.create_default_context()
    async with NoRedirectConnect('wss://' + base[len('https://'):] + path,
            additional_headers=headers, subprotocols=[SUBPROTOCOL],
            ssl=context, proxy=proxy, logger=LOGGER, **OPTIONS) as ws:
        if ws.subprotocol != SUBPROTOCOL:
            raise ValueError('protocol mismatch')
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=CHUNK)
        rtransport, _ = await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
        wtransport = None
        try:
            protocol = OutputProtocol(loop)
            wtransport, _ = await loop.connect_write_pipe(lambda: protocol, sys.stdout.buffer)
            writer = asyncio.StreamWriter(wtransport, protocol, None, loop)
            await relay(ws, reader, writer)
        finally:
            rtransport.close()
            if wtransport is not None:
                wtransport.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), HALF_CLOSE_TIMEOUT)
                except BaseException:
                    wtransport.abort()
                    raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', required=True, type=origin)
    parser.add_argument('--path', default='/ssh', type=path_value)
    parser.add_argument('--private-key', required=True)
    parser.add_argument('--key-id', required=True)
    parser.add_argument('--proxy', help='HTTP(S) CONNECT proxy; otherwise system proxy settings apply')
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        print('SSH transport failed', file=sys.stderr)
        return 255


if __name__ == '__main__':
    sys.exit(main())
