# http-ctl

HTTP control service for machines that sandboxed AI agents cannot SSH into.

## The problem

Agent runtimes such as Muse or ChatGPT Dot often run behind an egress
HTTP proxy that MITMs TLS and blocks direct SSH. Go-based tunnel clients
(cloudflared, Tailscale, ...) can fail there too, because the proxy
rejects their TLS handshake fingerprint. What does pass is ordinary
HTTPS from a normal TLS stack: curl, OpenSSL, Python requests.

So instead of the agent pushing SSH into a machine, the machine exposes
a small HTTP control service on loopback only, a tunnel maps a public
HTTPS hostname to it, and the agent talks to that hostname with curl
plus a bearer token.

```
agent VM --(HTTPS via egress proxy)--> tunnel edge --(tunnel)--> machine
        curl + Bearer token                       loopback daemon
                                                     /exec /health ...
```

No SSH from the agent side. No Go-TLS handshake from the agent side.
Nothing for the egress proxy to block.

## What you get

A single-file, stdlib-only Python daemon (`server/ctl-server.py`) with
five endpoints, all behind the bearer token:

| Endpoint | Method | What it does |
|---|---|---|
| `/health` | GET | Liveness: ok + uptime |
| `/exec` | POST | Run a shell command, return exit/stdout/stderr (timeout, output caps) |
| `/screenshot` | GET | PNG screenshot via adb (Android hosts; 501 elsewhere) |
| `/download?path=` | GET | Download a file from the machine |
| `/upload?path=` | POST | Upload a file to the machine (raw body) |

And a small bash client (`client/ctl`) that wraps curl:

```bash
export CTL_BASE_URL=https://ctl.example.com
ctl health
ctl exec "uptime; df -h" 60
ctl exec "adb -s localhost:5555 shell dumpsys battery"
ctl screenshot phone.png
ctl download /remote/log.txt
ctl upload ./script.sh /home/user/script.sh
```

## Quickstart

### On the machine to be controlled

1. Copy `server/ctl-server.py` somewhere, e.g. `/opt/http-ctl/`.
2. Generate a token and store it with mode 600:

   ```bash
   mkdir -p ~/.config/http-ctl
   openssl rand -hex 32 > ~/.config/http-ctl/token
   chmod 600 ~/.config/http-ctl/token
   ```

3. Run the daemon (it binds 127.0.0.1 only and refuses to start
   without the token file):

   ```bash
   python3 /opt/http-ctl/ctl-server.py
   ```

   For persistence use the systemd unit in `examples/systemd/` or the
   runit script in `examples/runit/` — both restart it on crash/boot.
4. Expose it through a tunnel that terminates TLS, e.g. Cloudflare
   Tunnel: add an ingress rule `ctl.example.com -> http://127.0.0.1:18081`
   and the matching DNS record. **Never expose the daemon port
   directly to the internet** — the token is the only auth, and the
   daemon speaks plain HTTP on loopback by design.

### On the agent side

1. Copy `client/ctl` somewhere on PATH and make it executable.
2. Copy the token into `~/.config/http-ctl/token` (mode 600).
3. `export CTL_BASE_URL=https://ctl.example.com` and run `ctl health`.

## Security

Read `SECURITY.md` before deploying. The short version:

- The token is equivalent to an SSH private key. Anyone with it gets
  full shell on the machine. Guard it like one; rotate by replacing
  the token file on both sides and restarting the daemon.
- The daemon binds loopback only and speaks plain HTTP; TLS comes
  from the tunnel. If you expose the port without a tunnel, the token
  travels in cleartext.
- The sandbox egress operator can see the token in transit (it MITMs
  TLS by design). This protects against the open internet, not
  against the sandbox itself.
- There is no rate limiting beyond the 256-bit token entropy; keep
  the token random and do not reuse it across machines.

## Layout

```
server/ctl-server.py        the daemon (stdlib only)
client/ctl                  bash + curl client
examples/systemd/           systemd unit for generic Linux servers
examples/runit/             runit run script (Termux / Void / etc.)
examples/termux-phone.md    worked deployment: an Android phone
                            controlled from a sandboxed agent VM
SECURITY.md                 threat model and operating rules
```

## First deployment

This project was built for a real case: a Pixel 4 (Termux + proot
Ubuntu) controlled from a Muse VM whose egress proxy blocks SSH and
Go-TLS. The phone deployment — runit service, boot hook, Cloudflare
Tunnel hostname, and the exact verification steps — is documented in
`examples/termux-phone.md`. It is the reference for "does this
actually work through a hostile egress".
