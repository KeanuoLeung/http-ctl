#!/usr/bin/env bash
# Deploy http-ctl to the reference phone (Pixel 4, Termux + proot Ubuntu).
# Run from the agent VM. Requires the Taipei SSH chain (see phone-chain-rebuild.sh).
#
# What it does, in order:
#   1. pushes server/ctl-server.py to ~/pixel-server/ctl-server.py
#   2. pushes examples/runit/run to the runit service dir (ctl-server)
#   3. generates the token on the phone (mode 600) and copies it to
#      this VM's ~/.config/http-ctl/token (mode 600)
#   4. appends the boot hook to ~/bin/pixel-start (idempotent)
#   5. starts the service and checks its log for the listen line
#
# It does NOT touch the tunnel config or restart cloudflared — that is
# a separate step, because restarting cloudflared drops the SSH chain.
# It never prints the token; only its length is echoed.

set -euo pipefail
cd "$(dirname "$0")/.."

TERMUX_HOME=/data/data/com.termux/files/home
TERMUX_USR=/data/data/com.termux/files/usr
SERVICE_DIR="$TERMUX_USR/var/service/ctl-server"

# Run a command on the phone via the Taipei chain.
# Remote commands must not contain single quotes, $ or backticks:
# they are wrapped in single quotes for the inner ssh hop.
phone() {
    ssh -S ~/.ssh/cm-taipei -p 2222 mrkeanuo@localhost \
        "ssh -S ~/.ssh/cm/phone ssh.pixel.0xsatori.biz '$1'"
}

# 1. daemon
base64 -w0 server/ctl-server.py | phone "base64 -d > $TERMUX_HOME/pixel-server/ctl-server.py"
echo "daemon pushed"

# 2. runit service (+ log service, same template as the other services)
phone "mkdir -p $SERVICE_DIR/log"
base64 -w0 examples/runit/run | phone "base64 -d > $SERVICE_DIR/run"
base64 -w0 examples/runit/log-run | phone "base64 -d > $SERVICE_DIR/log/run"
phone "chmod +x $SERVICE_DIR/run $SERVICE_DIR/log/run"
echo "runit service installed"

# 3. token: generate on the phone, copy to this VM (length only echoed)
# Note: Termux here has no openssl binary, so use python3 secrets.
phone "mkdir -p $TERMUX_HOME/.config/http-ctl; python3 -c \"import secrets; print(secrets.token_hex(32))\" > $TERMUX_HOME/.config/http-ctl/token; chmod 600 $TERMUX_HOME/.config/http-ctl/token; wc -c $TERMUX_HOME/.config/http-ctl/token"
TOKEN="$(phone "cat $TERMUX_HOME/.config/http-ctl/token")"
mkdir -p ~/.config/http-ctl
printf '%s' "$TOKEN" > ~/.config/http-ctl/token
chmod 600 ~/.config/http-ctl/token
echo "token saved on both sides (${#TOKEN} chars)"
unset TOKEN

# 4. boot hook in ~/bin/pixel-start (idempotent)
# Note: pixel-start lives in ~/bin, not ~. Remove a stray ~/pixel-start
# if an earlier run created one.
phone "rm -f $TERMUX_HOME/pixel-start"
HOOK='if test -f "$HOME/pixel-server/ctl-server.py"; then sv -w 10 up "$SVDIR/ctl-server" || exit 1; fi'
HOOK_B64="$(printf '%s\n' "$HOOK" | base64 -w0)"
phone "grep -q ctl-server $TERMUX_HOME/bin/pixel-start || echo $HOOK_B64 | base64 -d >> $TERMUX_HOME/bin/pixel-start"
phone "tail -2 $TERMUX_HOME/bin/pixel-start"
echo "boot hook ok"

# 5. start + verify via the service log (no local HTTP test here: the
# full functional test runs from the VM once the tunnel rule is live)
# Note: on 2026-10-25 the phone's runsvdir was DEAD (stale pidfile,
# orphaned runsv processes), so `sv up` cannot start a new service
# live. Try it first (works when runsvdir is alive); if it fails,
# start runsv manually for this service only — do NOT restart the
# whole service-daemon, which risks duplicating the orphaned services.
# At boot, pixel-start restarts runsvdir fresh, so the service comes
# up normally on reboot either way.
if ! phone "SVDIR=$TERMUX_USR/var/service sv up $SERVICE_DIR" 2>/dev/null; then
    echo "sv up failed (runsvdir likely dead) — starting runsv manually"
    phone "LOGDIR=$TERMUX_USR/var/log setsid nohup runsv $SERVICE_DIR >/dev/null 2>&1 < /dev/null &"
    sleep 3
fi
sleep 2
phone "SVDIR=$TERMUX_USR/var/service sv status $SERVICE_DIR"
phone "tail -3 $TERMUX_USR/var/log/sv/ctl-server/current"
echo "deploy done — next: tunnel rule + DNS + cloudflared restart"
