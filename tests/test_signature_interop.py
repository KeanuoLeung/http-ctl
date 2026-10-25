"""Signature-base checks independent of HTTPMessageSigner's implementation.

These tests construct the RFC 9421 application-profile base explicitly and use
cryptography's raw Ed25519 sign/verify API, not the HTTP signature library's
base builder. The deterministic seed below is PUBLIC TEST DATA, never a secret
or a key suitable for a deployed service.
"""
import base64
import hashlib
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from http_ctl import auth


def independent_headers(private, *, method='GET', target='/health', body=b'', created=None, parameter_as_token=None):
    created = int(time.time()) if created is None else created
    fields = {
        'keyid': 'test-key', 'alg': 'ed25519',
        'nonce': 'independent_nonce_1234567890', 'tag': 'http-ctl-v2',
    }
    params = '("@method" "@target-uri" "content-type" "content-digest")'
    params += f';created={created};keyid="test-key";alg="ed25519";expires={created + 60};nonce="{fields["nonce"]}";tag="http-ctl-v2"'
    if parameter_as_token:
        value = fields[parameter_as_token]
        params = params.replace(f';{parameter_as_token}="{value}"', f';{parameter_as_token}={value}')
    content_digest = 'sha-256=:' + base64.b64encode(hashlib.sha256(body).digest()).decode() + ':'
    base = (
        f'"@method": {method}\n'
        f'"@target-uri": https://ctl.example.test{target}\n'
        '"content-type": application/octet-stream\n'
        f'"content-digest": {content_digest}\n'
        f'"@signature-params": {params}'
    ).encode('ascii')
    signature = private.sign(base)
    # Raw verification explicitly confirms invalid-type negative fixtures have
    # valid Ed25519 signatures rather than failing due to a mere byte mutation.
    private.public_key().verify(signature, base)
    return {
        'Content-Type': 'application/octet-stream',
        'Content-Length': str(len(body)),
        'Content-Digest': content_digest,
        'X-Http-Ctl-Signature-Input': 'ctl=' + params,
        'X-Http-Ctl-Signature': 'ctl=:' + base64.b64encode(signature).decode() + ':',
    }, base


def test_library_signature_matches_independently_assembled_expected_base():
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))  # PUBLIC TEST FIXTURE.
    expected, base = independent_headers(private, method='POST', target='/upload?path=a%20b.txt', body=b'hello\n', created=1700000000)
    actual = auth.signed_headers(private, 'test-key', 'https://ctl.example.test', 'POST', '/upload?path=a%20b.txt', b'hello\n', created=1700000000, expires=1700000060, nonce='independent_nonce_1234567890')
    assert actual == expected
    assert base.splitlines()[0] == b'"@method": POST'
    assert base.splitlines()[1] == b'"@target-uri": https://ctl.example.test/upload?path=a%20b.txt'
    assert not base.endswith(b'\n')
    assert expected['Content-Digest'] == 'sha-256=:WJG1tSLV3whtD/CxEPvZ0hu0/HFjrzTQgoai6Eb2vgM=:'


def test_server_accepts_independently_signed_profile(service):
    headers, _ = independent_headers(service.private)
    assert service.request(headers=headers).status == 200


@pytest.mark.parametrize('field', ['keyid', 'alg', 'nonce', 'tag'])
def test_structured_field_tokens_not_interchangeable_with_strings(service, field):
    headers, _ = independent_headers(service.private, parameter_as_token=field)
    node = auth._structured(headers['X-Http-Ctl-Signature-Input'])
    assert type(node['ctl'].params[field]) is not str
    assert isinstance(node['ctl'].params[field], str)  # Token is a str subclass.
    assert service.request(headers=headers).status == 401
