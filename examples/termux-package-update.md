# Local package-only update after signed-v2 migration

This is a **local Termux procedure**, not a remote execution route. It does not use
`/exec`, file-upload endpoints, UI text entry, ADB shell injection, SSH, or a legacy
token. Obtain and review the source archive through an authorized transfer first,
verify its separately supplied SHA-256, then unpack it into a new private directory
inside Termux's home. Do not run an archive directly from shared Android storage.

The operator supplies the existing signed-v2 release, server configuration, and
runit service paths explicitly. The release's parent must contain the unchanged
`launch-production` created by the prior migration. Only the existing
`$PREFIX/var/service/ctl-server` service is supported, on production loopback port
18081; sidecar loopback port 18082 must be free. Inspect the existing run script
and record its SHA-256 before proceeding. No phone address or credentials belong
in this repository.

No dependency installation is performed. Requirements must be byte-identical.
Only `release/http_ctl/` is replaced. The helper retains the old signed-v2 package,
new staging files, and a sidecar log. It does not modify keys, grants, original
configuration, production replay history, launchers, runit scripts, service logs,
other services, tunnel configuration, or legacy credentials.

## Run locally

Keep Termux in the foreground. From the newly reviewed, unpacked source root:

```sh
umask 077
# Set these to the existing, reviewed installation paths, not a fresh migration.
RELEASE=/absolute/path/to/existing/release
CONFIG=/absolute/path/to/existing/server.json
SERVICE="$PREFIX/var/service/ctl-server"
# Review $SERVICE/run and assign its independently recorded SHA-256 here.
EXPECTED_RUN_SHA256=replace_with_reviewed_64_character_sha256
"$RELEASE/.venv/bin/python" examples/termux-package-update.py \
  --source "$PWD" --release "$RELEASE" --config "$CONFIG" \
  --service "$SERVICE" --expected-run-sha256 "$EXPECTED_RUN_SHA256" \
  --confirm-local-package-update
```

The helper validates the current signed-v2 listener and running supervisor,
copies and hashes the candidate package, imports it with the existing venv, and
starts a temporary loopback sidecar using a private configuration copy with
**every copied public key revoked** and an independent replay database. It never
accepts valid production-signed requests, preventing a second replay domain. The
production configuration and its key revocation states remain unchanged. It requires both health and hierarchy routes to
reject unsigned requests. No private key or new credential is needed. These
checks prove startup/route/authentication-gate readiness, **not successful signed
requests or working Android hierarchy capture**.

Only after staging passes does it stop `ctl-server`, rename the existing package
into a retained backup, move the candidate package into place, and start that
same service. A caught failure triggers **one** attempt to restore and start the
previous signed-v2 package, never legacy. Ordinary successful downtime should be
short; readiness and each supervisor operation have bounded waits. Interruptions
such as SIGKILL, phone reboot, OS process killing, disk failure, or failed supervisor
operations cannot be guaranteed recoverable automatically. Do not close Termux
during cutover, rerun blindly after an uncertain outcome, or invoke the old
migration rollback helper.

## Acceptance and recovery

After local success, use the already authorized trusted client and existing key to
make fresh signed public health and hierarchy requests. Test on a nonsensitive
screen. Existing `ui:control` authorizes hierarchy; no scope expansion is needed.
Also verify an unsigned hierarchy request is rejected. Do not put returned UI
content, signatures, or keys into public logs.

The helper prints the exact retained `previous-http_ctl` backup path. If signed
acceptance fails, stop and inspect locally. With explicit local recovery intent,
stop only `ctl-server`, retain the current package under a new distinct name,
rename that printed previous signed-v2 package back to `release/http_ctl`, and
start only `ctl-server`. Do not replace the venv, replay database, configuration,
run file, or any other service. If an update was interrupted, inspect whether
`release/http_ctl`, `previous-http_ctl`, and `failed-http_ctl` exist before moving
anything. Never use the disabled legacy token or restore the legacy launcher.
