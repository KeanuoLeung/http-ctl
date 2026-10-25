"""Run a short-lived client-signed health probe on loopback, never a private key."""
import argparse
import http.client
import json
from .auth import protected_read, strict_json, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file')
    parser.add_argument('--port', type=int, default=18082)
    args = parser.parse_args(argv)
    try:
        probe = strict_json(protected_read(args.file, 8192))
        if set(probe) != {'method', 'target', 'headers'} or probe['method'] != 'GET' or probe['target'] != '/health' or not isinstance(probe['headers'], dict):
            raise ValueError()
        headers = probe['headers']
        if set(headers) != {SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER, 'Content-Type', 'Content-Digest', 'Content-Length'} or headers['Content-Length'] != '0' or headers['Content-Type'] != 'application/octet-stream' or any(not isinstance(v, str) or any(ord(c) < 32 or ord(c) > 126 for c in v) for v in headers.values()):
            raise ValueError()
        connection = http.client.HTTPConnection('127.0.0.1', args.port, timeout=10)
        try:
            connection.request('GET', '/health', headers=headers)
            response = connection.getresponse()
            body = response.read(8193)
            if response.status != 200 or len(body) > 8192:
                raise ValueError()
            result = strict_json(body)
            if result.get('ok') is not True or result.get('version') != 2 or result.get('service') != 'http-ctl':
                raise ValueError()
        finally:
            connection.close()
        print('Verified signed http-ctl v2 loopback health.')
        return 0
    except Exception:
        print('Health probe failed; request was not retried. Use a fresh probe after diagnosis.')
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
