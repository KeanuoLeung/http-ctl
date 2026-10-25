"""Deterministic rate, concurrency and absolute input-deadline coverage."""
import io
import time
from types import SimpleNamespace

import pytest

from http_ctl import server


def test_bucket_burst_refill_and_cap(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(server, 'time', SimpleNamespace(monotonic=lambda: now[0]))
    bucket = server.Bucket(2, 3)
    assert [bucket.take() for _ in range(4)] == [True, True, True, False]
    now[0] += 0.5
    assert bucket.take() is True
    assert bucket.take() is False
    now[0] += 100
    assert [bucket.take() for _ in range(4)] == [True, True, True, False]


def test_global_limit_before_auth_does_not_consume_nonce(service):
    headers = service.headers()
    service.server.bucket = server.Bucket(0, 0)
    assert service.request(headers=headers).status == 429
    service.server.bucket = server.Bucket(100, 100)
    assert service.request(headers=headers).status == 200


def test_per_key_rate_limit_blocks_operation(service):
    service.server.key_limit = lambda _: False
    assert service.request('POST', '/ui', b'{"action":"keyevent","key":"HOME"}').status == 429


def test_operation_capacity_returns_busy_without_execution(service):
    assert service.server.operation_slots.acquire(blocking=False)
    assert service.server.operation_slots.acquire(blocking=False)
    try:
        assert service.request('POST', '/ui', b'{"action":"keyevent","key":"HOME"}').status == 503
        assert service.request().status == 200  # Health does not occupy an operation slot.
    finally:
        service.server.operation_slots.release()
        service.server.operation_slots.release()


@pytest.mark.parametrize('part', ['headers', 'body'])
def test_absolute_socket_deadline_rejects_stalled_input(service, monkeypatch, part):
    original = server.Handler._set_read_timeout
    def shorter_deadline(self):
        if not getattr(self, '_test_short_deadline', False):
            self._deadline = time.monotonic() + 0.1
            self._test_short_deadline = True
        return original(self)
    monkeypatch.setattr(server.Handler, '_set_read_timeout', shorter_deadline)
    if part == 'headers':
        wire = b'GET /health HTTP/1.1\r\nHost: incomplete'
    else:
        headers = service.headers('POST', '/upload?path=x', b'abc')
        wire = b'POST /upload?path=x HTTP/1.1\r\nHost: local.test\r\n' + b''.join(f'{k}: {v}\r\n'.encode() for k, v in headers.items()) + b'\r\na'
    started = time.monotonic()
    assert service.raw(wire, shutdown_write=False).status == 408
    assert time.monotonic() - started < 2
    assert list(service.root.iterdir()) == []


@pytest.mark.parametrize('method', ['line', 'body'])
def test_absolute_deadline_not_extended_by_continuous_drip(monkeypatch, method):
    # Simulated always-readable input demonstrates deadline progress independently
    # of an idle socket timeout, without a ten-second timing-sensitive test.
    now = [0.0]
    def tick():
        now[0] += 0.04
        return now[0]
    monkeypatch.setattr(server, 'time', SimpleNamespace(monotonic=tick))
    handler = object.__new__(server.Handler)
    handler._deadline = 0.1
    timeouts = []
    handler.connection = SimpleNamespace(settimeout=timeouts.append)
    class Drip:
        def read(self, _):
            return b'a'
        read1 = read
    handler.rfile = Drip()
    with pytest.raises(TimeoutError):
        handler._readline(100) if method == 'line' else handler._read_body(100)
    assert len(timeouts) == 2
    assert timeouts[0] > timeouts[1] > 0


@pytest.mark.parametrize('address', [('0.0.0.0', 0), ('localhost', 0), ('::1', 0), ('192.0.2.1', 0)])
def test_server_refuses_non_literal_loopback_listener(service, address):
    with pytest.raises(ValueError, match='127.0.0.1'):
        server.Server(address, service.server.config)
