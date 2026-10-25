#!/usr/bin/env python3
"""http-ctl server: an HTTP control daemon for sandboxed AI agents.

The problem
-----------
Agent runtimes such as Muse or ChatGPT Dot often run behind an egress
HTTP proxy that MITMs TLS and blocks direct SSH. Go-based tunnel clients
(cloudflared, Tailscale, ...) can also fail there because the proxy
rejects their TLS handshake fingerprint. What does pass is ordinary
HTTPS from a normal TLS stack (curl / OpenSSL / Python requests).

This daemon turns that around: instead of the agent pushing SSH into a
machine, the machine exposes a small HTTP control service on loopback
only, a tunnel (Cloudflare Tunnel, Tailscale Funnel, ngrok, a plain
reverse proxy, ...) maps a public HTTPS hostname to it, and the agent
talks to that hostname with curl plus a bearer token. No SSH, no
Go-TLS handshake from the agent side, nothing for the egress proxy
to block.

Security model (read SECURITY.md before deploying)
-------------------------------------------------
- The daemon binds 127.0.0.1 ONLY. Never expose its port directly to
  a network. TLS is provided by the tunnel, not by this daemon.
- Every request must carry `Authorization: Bearer <token>` equal to
  the token in the token file. The token is equivalent to an SSH
  private key: whoever has it gets full shell on this machine.
- The sandbox egress operator can see the token in transit (it MITMs
  TLS by design). This protects against the open internet, not
  against the sandbox itself.

Endpoints (all require the Bearer token)
----------------------------------------
- GET  /health              -> {"ok": true, "service": ..., "uptime_s": ...}
- POST /exec                {"cmd": str, "timeout": int?}
                            -> {"exit": int, "stdout": str, "stderr": str,
                                "timed_out": bool, "truncated": bool}
- GET  /screenshot          -> PNG bytes (requires adb; else 501)
- GET  /download?path=/abs  -> file bytes (application/octet-stream)
- POST /upload?path=/abs    -> raw request body written to path

Configuration (environment)
---------------------------
- CTL_HOST        bind address, default 127.0.0.1 (do not change
                  unless you know what you are doing)
- CTL_PORT        bind port, default 18081
- CTL_TOKEN_FILE  token file, default ~/.config/http-ctl/token
                  (must exist, mode 600 recommended; the daemon
                  refuses to start without it)

Dependencies: Python 3.8+ standard library only.
"""

import hmac
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = os.environ.get("CTL_HOST", "127.0.0.1")
PORT = int(os.environ.get("CTL_PORT", "18081"))
TOKEN_FILE = os.path.expanduser(
    os.environ.get("CTL_TOKEN_FILE", "~/.config/http-ctl/token")
)
MAX_JSON_BODY = 1024 * 1024          # 1 MB for /exec requests
MAX_FILE_BODY = 50 * 1024 * 1024     # 50 MB for /upload
MAX_OUTPUT_CHARS = 100_000           # per stream for /exec output
EXEC_TIMEOUT_DEFAULT = 60
EXEC_TIMEOUT_MAX = 300
STARTED_AT = time.time()


def load_token():
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            token = f.read().strip()
    except OSError as exc:
        print(f"ctl-server: cannot read token file {TOKEN_FILE}: {exc}",
              file=sys.stderr)
        sys.exit(1)
    if not token:
        print(f"ctl-server: token file {TOKEN_FILE} is empty",
              file=sys.stderr)
        sys.exit(1)
    return token


TOKEN = load_token()
BASH = shutil.which("bash") or "/bin/bash"
ADB = shutil.which("adb")


def check_auth(handler):
    """True when the request carries the right Bearer token."""
    header = handler.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return False
    presented = header[len("Bearer "):].strip()
    return bool(presented) and hmac.compare_digest(presented, TOKEN)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------
    def log_message(self, *args):  # keep stdout clean; we log ourselves
        pass

    def _log(self, status):
        elapsed_ms = int((time.time() - self._t0) * 1000)
        print(f"{self.command} {self.path} -> {status} ({elapsed_ms}ms)",
              file=sys.stderr, flush=True)

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self._log(status)

    def _send_bytes(self, status, data, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self._log(status)

    def _read_body(self, limit):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > limit:
            return None
        return self.rfile.read(length) if length else b""

    def _require_auth(self):
        if not check_auth(self):
            self._send_json(401, {"error": "unauthorized"})
            return False
        return True

    # -- routing -----------------------------------------------------
    def do_GET(self):
        self._t0 = time.time()
        if not self._require_auth():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(200, {
                "ok": True,
                "service": "http-ctl",
                "uptime_s": int(time.time() - STARTED_AT),
            })
        elif parsed.path == "/screenshot":
            self._do_screenshot()
        elif parsed.path == "/download":
            self._do_download(parse_qs(parsed.query))
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        self._t0 = time.time()
        if not self._require_auth():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/exec":
            self._do_exec()
        elif parsed.path == "/upload":
            self._do_upload(parse_qs(parsed.query))
        else:
            self._send_json(404, {"error": "not found"})

    # -- endpoints ---------------------------------------------------
    def _do_exec(self):
        raw = self._read_body(MAX_JSON_BODY)
        if raw is None:
            self._send_json(413, {"error": "body too large"})
            return
        try:
            req = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            self._send_json(400, {"error": "invalid json"})
            return
        cmd = req.get("cmd")
        if not isinstance(cmd, str) or not cmd:
            self._send_json(400, {"error": "cmd must be a non-empty string"})
            return
        try:
            timeout = int(req.get("timeout", EXEC_TIMEOUT_DEFAULT))
        except (TypeError, ValueError):
            timeout = EXEC_TIMEOUT_DEFAULT
        timeout = max(1, min(timeout, EXEC_TIMEOUT_MAX))

        proc = subprocess.Popen(
            [BASH, "-c", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        timed_out = False
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            out, err = proc.communicate()
        stdout = out.decode("utf-8", "replace")
        stderr = err.decode("utf-8", "replace")
        truncated = False
        if len(stdout) > MAX_OUTPUT_CHARS:
            stdout = stdout[:MAX_OUTPUT_CHARS]
            truncated = True
        if len(stderr) > MAX_OUTPUT_CHARS:
            stderr = stderr[:MAX_OUTPUT_CHARS]
            truncated = True
        self._send_json(200, {
            "exit": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": timed_out,
            "truncated": truncated,
        })

    def _do_screenshot(self):
        if not ADB:
            self._send_json(501, {"error": "adb not available on this host"})
            return
        proc = subprocess.run(
            [ADB, "-s", "localhost:5555", "exec-out", "screencap", "-p"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
        png = proc.stdout
        if proc.returncode != 0 or not png.startswith(b"\x89PNG"):
            self._send_json(502, {
                "error": "screenshot failed",
                "detail": proc.stderr.decode("utf-8", "replace")[:500],
            })
            return
        self._send_bytes(200, png, "image/png")

    def _do_download(self, query):
        paths = query.get("path", [])
        if not paths or not paths[0].startswith("/"):
            self._send_json(400, {"error": "path must be absolute"})
            return
        path = paths[0]
        try:
            size = os.path.getsize(path)
            if size > MAX_FILE_BODY:
                self._send_json(413, {"error": "file too large"})
                return
            with open(path, "rb") as f:
                data = f.read()
        except OSError as exc:
            self._send_json(404, {"error": "cannot read file", "detail": str(exc)})
            return
        self._send_bytes(200, data, "application/octet-stream")

    def _do_upload(self, query):
        paths = query.get("path", [])
        if not paths or not paths[0].startswith("/"):
            self._send_json(400, {"error": "path must be absolute"})
            return
        data = self._read_body(MAX_FILE_BODY)
        if data is None:
            self._send_json(413, {"error": "body too large"})
            return
        path = paths[0]
        try:
            with open(path, "wb") as f:
                f.write(data)
        except OSError as exc:
            self._send_json(400, {"error": "cannot write file", "detail": str(exc)})
            return
        self._send_json(200, {"ok": True, "path": path, "bytes": len(data)})


def main():
    if HOST not in ("127.0.0.1", "::1", "localhost"):
        print("ctl-server: refusing to bind a non-loopback address "
              f"({HOST}); see SECURITY.md", file=sys.stderr)
        sys.exit(1)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    print(f"ctl-server: listening on {HOST}:{PORT} "
          f"(token file {TOKEN_FILE}, bash {BASH}, "
          f"adb {'yes' if ADB else 'no'})", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
