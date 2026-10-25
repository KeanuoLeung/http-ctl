"""Raw-wire parser tests, including duplicate headers that HTTP clients hide."""
import pytest


def raw_request(service, *, target='/health', method='GET', headers=None, body=b'', version='HTTP/1.1'):
    pairs = list(service.headers().items()) if headers is None else headers
    return service.raw((f'{method} {target} {version}\r\nHost: local.test\r\n').encode() + b''.join(f'{name}: {value}\r\n'.encode() for name, value in pairs) + b'\r\n' + body)


@pytest.mark.parametrize('name', ['Host', 'Content-Length', 'Content-Type', 'Content-Digest', 'X-Http-Ctl-Signature', 'X-Http-Ctl-Signature-Input'])
def test_duplicate_header_names_rejected_case_insensitively(service, name):
    pairs = list(service.headers().items())
    original = dict(pairs).get(name, 'local.test')
    pairs.append((name.swapcase(), original))
    assert raw_request(service, headers=pairs).status == 400


@pytest.mark.parametrize(('name', 'value'), [('Transfer-Encoding', 'chunked'), ('Content-Encoding', 'gzip'), ('Authorization', 'Bearer old'), ('Expect', '100-continue')])
def test_unsupported_transport_or_auth_headers_rejected(service, name, value):
    headers = service.headers()
    headers[name] = value
    assert service.request(headers=headers).status == 400


@pytest.mark.parametrize('length', ['', '00', '01', '-1', '+1', '1.0', '0, 0', ' 0', '0 ', '1000000000'])
def test_noncanonical_content_length_rejected(service, length):
    headers = service.headers()
    headers['Content-Length'] = length
    result = service.request(headers=headers)
    # HTTP allows optional whitespace before a field value and the parser strips
    # it; the protocol's canonical check applies to the parsed field value.
    assert result.status == (200 if length == ' 0' else 400)


def test_get_missing_length_accepted_after_proxy_strips_zero(service):
    headers = service.headers()
    del headers['Content-Length']
    assert service.request(headers=headers).status == 200


def test_post_missing_length_rejected(service):
    headers = service.headers('POST', '/upload?path=x')
    del headers['Content-Length']
    assert service.request('POST', '/upload?path=x', headers=headers).status == 400


def test_get_body_and_oversized_upload_rejected_without_reading_body(service):
    headers = service.headers()
    headers['Content-Length'] = '1'
    assert service.request(headers=headers).status == 413
    headers = service.headers('POST', '/upload?path=x')
    headers['Content-Length'] = str(50 * 1024 * 1024 + 1)
    assert service.request('POST', '/upload?path=x', headers=headers).status == 413


def test_incomplete_body_rejected(service):
    headers = service.headers('POST', '/upload?path=x', b'abc')
    assert service.request('POST', '/upload?path=x', b'a', headers=headers).status == 400
    assert list(service.root.iterdir()) == []


@pytest.mark.parametrize('target', ['//health', 'https://ctl.example.test/health', '/health#fragment', '/health\\x', '/health%ZZ', '/health%', '/health?'])
def test_non_origin_or_invalid_request_targets_rejected(service, target):
    assert raw_request(service, target=target).status == 400


@pytest.mark.parametrize('target', ['/download?path=a&path=b', '/download?path=', '/download?path=a&extra=b', '/download?path=a&x=b&y=c', '/download?path=%FF', '/download?path', '/health?ignored=1'])
def test_invalid_or_duplicate_query_parameters(service, target):
    headers = service.headers('GET', target)
    assert service.request('GET', target, headers=headers).status == 400


@pytest.mark.parametrize('line', [b'X-Bad : x\r\n', b'X-Bad:\tx\r\n', b' folded: x\r\n', b'X-Bad: x\x00\r\n', b'X-Bad: x\x7f\r\n', b'X-Bad: \xff\r\n', b'X-Bad: x\n'])
def test_header_folding_controls_and_invalid_names_rejected(service, line):
    assert service.raw(b'GET /health HTTP/1.1\r\nHost: local.test\r\n' + line + b'\r\n').status == 400


def test_header_count_and_aggregate_size_bounded(service):
    pairs = [('X-Test-' + str(i), 'x') for i in range(65)]
    assert raw_request(service, headers=pairs).status == 400
    assert raw_request(service, headers=[('X-A', 'x' * 8000), ('X-B', 'x' * 8000), ('X-C', 'x' * 1000)]).status == 400


def test_request_line_size_bounded(service):
    assert service.raw(b'GET /' + b'x' * 8200 + b' HTTP/1.1\r\n\r\n').status == 414


def test_pipelined_second_request_never_executes(service):
    # An exact-length first message is processed once; surplus bytes cannot be
    # interpreted as another operation on this connection.
    def wire(headers):
        return b'GET /health HTTP/1.1\r\nHost: local.test\r\n' + b''.join(f'{k}: {v}\r\n'.encode() for k, v in headers.items()) + b'\r\n'
    first, second = service.headers(), service.headers()
    assert service.raw(wire(first) + wire(second)).status == 200
    assert service.request(headers=first).status == 401
    assert service.request(headers=second).status == 200


def test_unknown_route_never_redirects(service):
    result = raw_request(service, target='/health/')
    assert result.status == 404
    assert 'Location' not in result.headers
