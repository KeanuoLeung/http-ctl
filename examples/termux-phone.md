# Worked deployment: Pixel 4 controlled from a sandboxed agent VM

This is the deployment http-ctl was built for, kept here as the
reference that the design actually works through a hostile egress.

## The situation

- Agent VM (Muse): egress is a MITM HTTP proxy. Direct SSH out is
  blocked, and Go-based tunnel clients (cloudflared, any version)
  fail the proxy's TLS handshake fingerprint check. curl/OpenSSL
  HTTPS passes.
- Phone (Pixel 4): Termux + proot Ubuntu, already running a
  Cloudflare Named Tunnel (`pixel4-ubuntu`) for a web page and SSH.
  The phone's own cloudflared has clean egress, so its tunnel works.
- Existing path (kept as backup): VM -> GCP Taipei VPS (IAP) ->
  cloudflared on Taipei -> phone SSH. Works, but fragile: IAP dies
  with VM replacement, multiplex masters go stale.

## What was deployed

- Daemon: `~/pixel-server/ctl-server.py` (a copy of
  `server/ctl-server.py`), run by Termux python3 under runit as
  service `ctl-server`, listening on 127.0.0.1:18081.
- Token: `~/.config/http-ctl/token` on the phone (mode 600) and the
  same value in the agent VM's `~/.config/http-ctl/token` (mode 600).
  The value is never written in docs, chat, or memory.
- Boot: `~/bin/pixel-start` gained a guarded line (same pattern as
  the existing `pixel-monitor` line) that brings `ctl-server` up at
  boot when the script exists.
- Tunnel: `~/.cloudflared/config.yml` gained, before the 404
  catch-all:
  ```yaml
  - hostname: ctl.0xsatori.biz
    service: http://127.0.0.1:18081
  ```
  plus the DNS record via `cloudflared tunnel route dns <tunnel-id>
  ctl.0xsatori.biz` (using the phone's `~/.cloudflared/cert.pem`).
- Client: `client/ctl` on the agent VM with
  `CTL_BASE_URL=https://ctl.0xsatori.biz`.

## Verification performed (from the agent VM, via curl)

- `ctl health` -> 200 with the token; 401 without it and with a
  wrong token.
- `ctl exec "echo CTL_OK; uptime"` -> exit 0, expected stdout.
- `ctl exec "adb -s localhost:5555 shell getprop ro.product.model"`
  -> `Pixel 4` (proves the adb control path works through the API).
- `ctl screenshot` -> valid PNG, non-empty.
- `ctl exec "sleep 5" 2` -> timed_out true (proves the timeout path).

## Notes specific to this phone

- **runsvdir can be dead.** On 2026-10-25 the phone's runsvdir was
  dead (stale pidfile, orphaned runsv processes with PPID 1), so
  `sv up` for a brand-new service dir failed with
  `unable to open supervise/ok`. Existing services kept running as
  orphans. Fix used: start runsv manually for the new service only
  (`LOGDIR=... setsid nohup runsv <service-dir> ... &`) — do not
  restart the whole service-daemon, which risks duplicating the
  orphaned services. At boot, pixel-start restarts runsvdir fresh,
  so the service comes up normally on reboot. Check first with
  `pidof runsvdir` when a new service refuses to start.

- The SSH shell on the phone is Termux, not proot: adb, su, and
  Termux binaries are on PATH there, and `proot-distro login
  ubuntu -- <cmd>` reaches the Ubuntu side when needed. The daemon
  inherits that same environment, so `/exec` can do everything the
  SSH shell could.
- `/screenshot` needs adbd in TCP mode (`localhost:5555`); the
  phone resets adbd to USB mode on reboot. If screenshots 502,
  re-enable TCP mode via `/exec` with root:
  `/system/bin/su -c 'setprop service.adb.tcp.port 5555; stop adbd; start adbd'`
  (Magisk authorization on the phone may prompt).
- Restarting cloudflared for a config change drops the SSH chain;
  the one-command rebuild script (`phone-chain-rebuild.sh` on the
  agent VM) restores it, and the tunnel watchdog restarts
  cloudflared on its own if the restart fails.
- Latency from the agent VM is ~1-2s per call (proxy + edge +
  tunnel). Slower than a healthy SSH multiplex, but stateless: a
  failed call never leaves a stale connection behind.
