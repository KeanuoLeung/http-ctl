"""Only application-namespaced signature transport can authorize a request.

The signature-base format, required components, Ed25519 verification, nonce
consumption, scope checks, and generic public error remain unchanged.
"""
import base64

import pytest

from http_ctl import auth

APP_SIGNATURE = 'X-Http-Ctl-Signature'
APP_INPUT = 'X-Http-Ctl-Signature-Input'


def test_signer_emits_only_application_signature_transport(service):
    headers = service.headers()
    assert auth.SIGNATURE_HEADER == APP_SIGNATURE
    assert auth.SIGNATURE_INPUT_HEADER == APP_INPUT
    assert APP_SIGNATURE in headers
    assert APP_INPUT in headers
    assert 'Signature' not in headers
    assert 'Signature-Input' not in headers
    assert service.request(headers=headers).status == 200


def test_standard_signature_headers_alone_cannot_authorize(service):
    headers = service.headers()
    headers['Signature'] = headers.pop(APP_SIGNATURE)
    headers['Signature-Input'] = headers.pop(APP_INPUT)
    response = service.request(headers=headers)
    assert response.status == 401
    assert response.json() == {'error': 'unauthorized'}


def test_valid_application_signature_ignores_unrelated_standard_headers(service):
    headers = service.headers()
    headers['Signature'] = 'proxy-owned-not-an-application-signature'
    headers['Signature-Input'] = 'proxy-owned-not-an-application-signature-input'
    assert service.request(headers=headers).status == 200


def test_invalid_application_signature_never_falls_back_to_valid_standard_signature(service):
    headers = service.headers()
    headers['Signature'] = headers[APP_SIGNATURE]
    headers['Signature-Input'] = headers[APP_INPUT]
    headers[APP_SIGNATURE] = 'ctl=:' + base64.b64encode(bytes(64)).decode() + ':'
    response = service.request(headers=headers)
    assert response.status == 401
    assert response.json() == {'error': 'unauthorized'}


@pytest.mark.parametrize(('app_name', 'ordinary_name'), [(APP_SIGNATURE, 'Signature'), (APP_INPUT, 'Signature-Input')])
def test_missing_application_half_cannot_be_filled_from_standard_headers(service, app_name, ordinary_name):
    headers = service.headers()
    headers[ordinary_name] = headers.pop(app_name)
    assert service.request(headers=headers).status == 401


def test_application_header_names_are_case_insensitive(service):
    headers = service.headers()
    headers[APP_SIGNATURE.swapcase()] = headers.pop(APP_SIGNATURE)
    headers[APP_INPUT.lower()] = headers.pop(APP_INPUT)
    assert service.request(headers=headers).status == 200


@pytest.mark.parametrize('name', [APP_SIGNATURE, APP_INPUT])
def test_duplicate_application_header_case_variants_rejected(service, name):
    headers = service.headers()
    pairs = list(headers.items())
    pairs.append((name.swapcase(), headers[name]))
    assert service.request(headers=pairs).status == 400


def test_unrelated_standard_signature_cannot_change_application_replay_identity(service):
    headers = service.headers()
    headers['Signature'] = 'proxy-first'
    headers['Signature-Input'] = 'proxy-first'
    assert service.request(headers=headers).status == 200
    headers['Signature'] = 'proxy-second'
    headers['Signature-Input'] = 'proxy-second'
    assert service.request(headers=headers).status == 401
