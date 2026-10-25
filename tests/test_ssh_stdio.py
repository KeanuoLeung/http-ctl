"""Regression for final stdout bytes under ProxyCommand pipe backpressure."""
import subprocess
import sys
import time
from pathlib import Path

import pytest
pytest.importorskip('websockets')


def test_proxy_flushes_pipe_before_successful_exit():
    # Exercise the actual run() cleanup with a deterministic in-memory WSS peer;
    # the OS stdout pipe is real and deliberately smaller than one data frame.
    script = r'''
import asyncio
from types import SimpleNamespace
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import http_ctl.ssh_proxy as module
key = Ed25519PrivateKey.generate()
pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
module.protected_read = lambda *args: pem
class Peer:
    subprotocol = module.SUBPROTOCOL
    def __init__(self):
        self.messages = iter([b'\0' + bytes(range(256))*128] + [b'\0FINAL-TAIL', b'\1'])
    async def send(self, data): pass
    async def recv(self): return next(self.messages)
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
module.NoRedirectConnect = lambda *args, **kwargs: Peer()
asyncio.run(module.run(SimpleNamespace(origin='https://example.test', path='/ssh', private_key='unused', key_id='test', proxy=None)))
'''
    root = Path(__file__).resolve().parents[1]
    process = subprocess.Popen([sys.executable, '-c', script], cwd=root,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, pipesize=4096)
    process.stdin.close()
    process.stdin = None
    try:
        time.sleep(.15)
        output, errors = process.communicate(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    assert process.returncode == 0, errors.decode(errors='replace')
    assert output == bytes(range(256))*128 + b'FINAL-TAIL'
    assert errors == b''
