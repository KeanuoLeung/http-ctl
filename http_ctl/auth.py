"""Narrow RFC 9421 / RFC 9530 application profile. No custom crypto."""
import base64
from contextlib import contextmanager
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass
from types import SimpleNamespace
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from http_message_signatures import HTTPMessageSigner, HTTPMessageVerifier, HTTPSignatureKeyResolver, algorithms
from http_message_signatures import http_sfv

COMPONENTS = ('@method', '@target-uri', 'content-type', 'content-digest')
TAG = 'http-ctl-v2'
LABEL = 'ctl'
# Application-owned transport avoids collisions with intermediary HTTP signatures.
# The cryptographic signature base remains the RFC 9421 application profile.
SIGNATURE_HEADER = 'X-Http-Ctl-Signature'
SIGNATURE_INPUT_HEADER = 'X-Http-Ctl-Signature-Input'
MAX_AGE = 60
SKEW = 5
SCOPES = frozenset({'health:read', 'screenshot:read', 'ui:control', 'files:read', 'files:write', 'shell:exec', 'migration:confirm'})
KEY_ID = re.compile(r'[A-Za-z0-9._-]{1,64}\Z')
NONCE = re.compile(r'[A-Za-z0-9_-]{22,128}\Z')

AUTH_FAILURE_CODES = frozenset({
    'missing_signature_input', 'missing_signature', 'missing_content_digest',
    'structured_invalid', 'structured_noncanonical', 'profile_invalid',
    'time_invalid', 'digest_mismatch', 'key_unavailable',
    'configuration_unavailable', 'signature_invalid', 'replay_rejected',
    'replay_unavailable', 'clock_rollback', 'internal',
})


class AuthError(Exception):
    def __init__(self, code='profile_invalid'):
        # Only fixed server-owned classifications may reach the audit log.
        self.code = code if code in AUTH_FAILURE_CODES else 'internal'
        super().__init__('authentication failed')


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def origin(value):
    if not isinstance(value, str) or not value.isascii() or any(c.isspace() for c in value):
        raise ValueError('external_origin must be an ASCII HTTPS origin')
    parts = urlsplit(value)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.path or parts.query or parts.fragment:
        raise ValueError('external_origin must be HTTPS, without path or credentials')
    if parts.netloc != parts.netloc.lower() or value != 'https://' + parts.netloc:
        raise ValueError('external_origin must be canonical lowercase')
    _ = parts.port
    return value


def digest(body):
    return 'sha-256=:' + base64.b64encode(hashlib.sha256(body).digest()).decode('ascii') + ':'


def protected_read(path, limit=65536):
    fd = os.open(os.path.expanduser(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise ValueError('configuration/key file must be owned by this user and mode 600')
        data = f.read(limit + 1)
        if len(data) > limit:
            raise ValueError('configuration/key file too large')
        return data


@dataclass(frozen=True)
class Key:
    public_key: Ed25519PublicKey
    scopes: frozenset
    file_root: str | None
    revoked: bool


class Config:
    def __init__(self, path):
        self.path = os.path.abspath(os.path.expanduser(path))
        data = self._read()
        self.external_origin = origin(data['external_origin'])
        self.replay_db = os.path.abspath(os.path.expanduser(data.get('replay_db', '~/.local/state/http-ctl/replay.sqlite3')))
        self.adb_serial = data.get('adb_serial', 'localhost:5555')
        if not isinstance(self.adb_serial, str) or not re.fullmatch(r'[A-Za-z0-9.:_-]{1,128}', self.adb_serial):
            raise ValueError('invalid adb_serial')
        self.rollout()
        self.keys()  # Fail at startup, not only on the first request.

    def _read(self):
        data = strict_json(protected_read(self.path))
        if not isinstance(data, dict) or set(data) - {'external_origin', 'replay_db', 'adb_serial', 'keys', 'rollout'}:
            raise ValueError('invalid configuration')
        return data

    def rollout(self):
        value = self._read().get('rollout')
        if value is None:
            return None
        if not isinstance(value, dict) or set(value) != {'id', 'deadline', 'ack_file'}:
            raise ValueError('invalid rollout')
        if type(value['id']) is not str or not re.fullmatch(r'[a-f0-9]{32}', value['id']) or type(value['deadline']) is not int or value['deadline'] > time.time() + 900:
            raise ValueError('rollout must be bounded to at most 15 minutes')
        expected = os.path.join(os.path.dirname(self.replay_db), 'rollout-ack.json')
        if value['ack_file'] != expected:
            raise ValueError('rollout acknowledgement must be beside private replay state')
        return value

    def keys(self):
        data = self._read()  # Atomic replace gives live revocation, never stale fail-open cache.
        if origin(data['external_origin']) != self.external_origin or os.path.abspath(os.path.expanduser(data.get('replay_db', '~/.local/state/http-ctl/replay.sqlite3'))) != self.replay_db or data.get('adb_serial', 'localhost:5555') != self.adb_serial:
            raise ValueError('origin, replay path or adb target changed; restart required')
        raw = data['keys']
        if not isinstance(raw, dict) or not 1 <= len(raw) <= 64:
            raise ValueError('expected 1 to 64 keys')
        result = {}
        for key_id, item in raw.items():
            if not KEY_ID.fullmatch(key_id) or not isinstance(item, dict) or set(item) - {'public_key_pem', 'scopes', 'file_root', 'revoked'}:
                raise ValueError('invalid key entry')
            scopes = item.get('scopes', [])
            if not isinstance(scopes, list) or any(not isinstance(s, str) or s not in SCOPES for s in scopes):
                raise ValueError('invalid scopes')
            revoked = item.get('revoked', False)
            if type(revoked) is not bool:
                raise ValueError('revoked must be boolean')
            pem = item['public_key_pem']
            if not isinstance(pem, str) or len(pem) > 1024:
                raise ValueError('invalid public key')
            public_key = serialization.load_pem_public_key(pem.encode('ascii'))
            if not isinstance(public_key, Ed25519PublicKey):
                raise ValueError('Ed25519 required')
            root = item.get('file_root')
            if {'files:read', 'files:write'} & set(scopes):
                if not isinstance(root, str) or not os.path.isabs(root) or os.path.normpath(root) != root or root == '/':
                    raise ValueError('file scopes need an absolute dedicated file_root, not /')
            elif root is not None:
                raise ValueError('file_root needs a file scope')
            result[key_id] = Key(public_key, frozenset(scopes), root, revoked)
        return result


class Resolver(HTTPSignatureKeyResolver):
    def __init__(self, key_id, key):
        self.key_id, self.key = key_id, key

    def resolve_public_key(self, key_id):
        if key_id != self.key_id:
            raise AuthError()
        return self.key

    resolve_private_key = resolve_public_key


class ReplayStore:
    """One committed nonce globally, across worker threads, processes and restarts."""
    def __init__(self, path):
        self.path = path
        parent = os.path.dirname(path)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        st = os.lstat(parent)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise ValueError('replay directory must be owned by this user and mode 700')
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        st = os.fstat(fd)
        os.close(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise ValueError('replay database must be owned by this user and mode 600')
        with self._connect() as con:
            con.execute('CREATE TABLE IF NOT EXISTS nonces (key_id TEXT NOT NULL, nonce TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(key_id, nonce))')
            con.execute('CREATE TABLE IF NOT EXISTS clock (id INTEGER PRIMARY KEY CHECK(id=1), highwater REAL NOT NULL)')
            con.execute('INSERT OR IGNORE INTO clock VALUES (1, ?)', (time.time(),))

    @contextmanager
    def _connect(self):
        con = sqlite3.connect(self.path, timeout=2)
        try:
            con.execute('PRAGMA synchronous=FULL')
            with con:
                yield con
        finally:
            con.close()

    def consume(self, key_id, nonce, expires):
        try:
            with self._connect() as con:
                con.execute('BEGIN IMMEDIATE')
                now = time.time()
                highwater = con.execute('SELECT highwater FROM clock WHERE id=1').fetchone()[0]
                if now + SKEW < highwater:
                    raise AuthError('clock_rollback')
                con.execute('UPDATE clock SET highwater=MAX(highwater, ?) WHERE id=1', (now,))
                con.execute('DELETE FROM nonces WHERE expires < ?', (now - 2 * SKEW,))
                con.execute('INSERT INTO nonces VALUES (?, ?, ?)', (key_id, nonce, expires))
                # Context manager commits before returning to the endpoint.
        except sqlite3.IntegrityError as exc:
            raise AuthError('replay_rejected') from exc
        except sqlite3.Error as exc:
            raise AuthError('replay_unavailable') from exc


def _structured(value):
    node = http_sfv.Dictionary()
    try:
        node.parse(value.encode('ascii'))
    except Exception as exc:
        raise AuthError('structured_invalid') from exc
    # Restrict to canonical encoding: this rejects duplicate dictionary members or
    # parameters that generic SF parsers otherwise silently overwrite.
    if str(node) != value:
        raise AuthError('structured_noncanonical')
    return node


def authenticate(config, replay, method, target, headers, body, scope):
    try:
        incoming_headers = headers
        def single(name, missing_code='profile_invalid'):
            values = [value for field, value in incoming_headers.items() if field.lower() == name.lower()]
            if not values:
                raise AuthError(missing_code)
            if len(values) != 1:
                raise AuthError('profile_invalid')
            return values[0]
        # Do not copy the original mapping: standard Signature fields may belong
        # to the egress/tunnel infrastructure. Only this app's exact values may
        # enter the verifier. There is deliberately NO standard-header fallback.
        headers = {
            'Signature-Input': single(SIGNATURE_INPUT_HEADER, 'missing_signature_input'),
            'Signature': single(SIGNATURE_HEADER, 'missing_signature'),
            'Content-Digest': single('Content-Digest', 'missing_content_digest'),
            'Content-Type': single('Content-Type'),
        }
        inputs = _structured(headers['Signature-Input'])
        signatures = _structured(headers['Signature'])
        if list(inputs) != [LABEL] or list(signatures) != [LABEL]:
            raise AuthError()
        sig_input = inputs[LABEL]
        if not isinstance(sig_input, http_sfv.InnerList) or tuple(item.value for item in sig_input) != COMPONENTS or any(item.params or type(item.value) is not str for item in sig_input):
            raise AuthError()
        params = sig_input.params
        if set(params) != {'created', 'expires', 'keyid', 'nonce', 'alg', 'tag'}:
            raise AuthError()
        if any(type(params[p]) is not str for p in ('alg', 'tag', 'keyid', 'nonce')) or params['alg'] != 'ed25519' or params['tag'] != TAG or not isinstance(params['keyid'], str) or not KEY_ID.fullmatch(params['keyid']) or not isinstance(params['nonce'], str) or not NONCE.fullmatch(params['nonce']):
            raise AuthError()
        created, expires = params['created'], params['expires']
        now = time.time()
        if type(created) is not int or type(expires) is not int or not created < expires <= created + MAX_AGE or created > now + SKEW or created < now - MAX_AGE - SKEW or expires < now - SKEW:
            raise AuthError('time_invalid')
        sig = signatures[LABEL]
        if not isinstance(sig, http_sfv.Item) or sig.params or not isinstance(sig.value, bytes) or len(sig.value) != 64:
            raise AuthError()
        if not hmac.compare_digest(headers['Content-Digest'], digest(body)):
            raise AuthError('digest_mismatch')
        try:
            key = config.keys().get(params['keyid'])
        except Exception as exc:
            raise AuthError('configuration_unavailable') from exc
        if key is None or key.revoked:
            raise AuthError('key_unavailable')
        message = SimpleNamespace(method=method, url=config.external_origin + target, headers=headers)
        verifier = HTTPMessageVerifier(signature_algorithm=algorithms.ED25519, key_resolver=Resolver(params['keyid'], key.public_key))
        try:
            verified = verifier.verify(message, max_age=dt.timedelta(seconds=MAX_AGE), expect_tag=TAG, expect_label=LABEL)
        except Exception as exc:
            raise AuthError('signature_invalid') from exc
        if len(verified) != 1:
            raise AuthError('signature_invalid')
        if scope not in key.scopes:
            raise PermissionError('scope denied')
        replay.consume(params['keyid'], params['nonce'], expires)
        return params['keyid'], key
    except (PermissionError, AuthError):
        raise
    except Exception as exc:
        raise AuthError('internal') from exc


def signed_headers(private_key, key_id, base_url, method, target, body=b'', content_type='application/octet-stream', *, created=None, expires=None, nonce=None, components=COMPONENTS):
    origin(base_url)
    if not KEY_ID.fullmatch(key_id):
        raise ValueError('invalid key ID')
    now = int(time.time()) if created is None else created
    headers = {'Content-Type': content_type, 'Content-Digest': digest(body), 'Content-Length': str(len(body))}
    message = SimpleNamespace(method=method, url=base_url + target, headers=headers)
    signer = HTTPMessageSigner(signature_algorithm=algorithms.ED25519, key_resolver=Resolver(key_id, private_key))
    signer.sign(message, key_id=key_id, created=dt.datetime.fromtimestamp(now, dt.timezone.utc), expires=dt.datetime.fromtimestamp(now + MAX_AGE if expires is None else expires, dt.timezone.utc), nonce=nonce or secrets.token_urlsafe(24), label=LABEL, tag=TAG, covered_component_ids=components)
    headers[SIGNATURE_INPUT_HEADER] = headers.pop('Signature-Input')
    headers[SIGNATURE_HEADER] = headers.pop('Signature')
    return headers
