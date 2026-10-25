# SECURITY.md

## Threat model

http-ctl gives whoever holds the token **full shell access** to the
machine it runs on — the same as an SSH private key. Deploy it only
on machines you would give SSH access to, and guard the token the
same way.

### What it protects against

- **Random internet strangers.** The daemon binds 127.0.0.1 only and
  is reachable solely through a TLS-terminating tunnel. There is no
  open port to scan, and every request must carry the 256-bit token.
  Guessing the token over HTTPS is not a realistic attack.
- **Casual credential leakage.** The token lives in a mode-600 file
  on both sides and is never embedded in scripts, docs, or chat. The
  client reads it at runtime.

### What it does NOT protect against

- **The sandbox egress operator.** If the agent runs behind a MITM
  egress proxy (the exact environment this project is built for),
  that proxy sees the token in transit. This is accepted: the proxy
  already sees everything the agent does. Do not use http-ctl for a
  machine whose threat model includes its own sandbox provider.
- **Anyone with the token.** There are no roles, no scopes, no
  allowlist: `/exec` runs any command the daemon user can run.
  A restricted shell would be theater, because `/download` and
  `/upload` already give full file access.
- **The tunnel provider.** The tunnel sees the same traffic the
  daemon does. Pick a tunnel provider you trust (or self-host the
  reverse proxy on a machine you control).

## Operating rules

1. **Loopback only.** Never change `CTL_HOST` to a non-loopback
   address; the daemon refuses to start if you try. If you need
   LAN access, put a reverse proxy with TLS in front — do not
   expose the daemon.
2. **TLS from the tunnel, always.** The daemon speaks plain HTTP.
   The public hostname must be HTTPS, served by the tunnel or a
   reverse proxy you trust.
3. **One token per machine.** Do not reuse a token across machines;
   a leak then compromises one machine, not all of them.
4. **Rotate on suspicion.** Replace the token file on the machine
   and on every agent that uses it, then restart the daemon. There
   is no revocation list — replacement is revocation.
5. **Never log the token.** The daemon logs method, path, status,
   and duration only — never headers or bodies. Keep it that way
   when modifying it.
6. **Keep the daemon user least-privilege.** Run it as the user
   whose shell you want the agent to have — not as root — unless
   you specifically need root (e.g. Android `su` for screenshots,
   which the agent can invoke explicitly through `/exec`).
7. **Mind the output caps.** `/exec` truncates stdout/stderr at
   100k chars and `/upload`/`/download` cap at 50 MB. These are
   denial-of-service guards, not security boundaries.
