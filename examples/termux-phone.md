# Termux: staged v2 installation and rollback

This is a generic operator runbook, not a record of a completed phone installation. A working legacy bearer-token deployment must remain available until the signed replacement has been tested. Keep independent, already authorized recovery access whenever available. When the legacy HTTP service is the only remote control path, use the prearmed, bounded rollback watchdog below. It reduces lockout risk but cannot guarantee recovery after a phone reboot, Android killing the watchdog, disk failure, or supervisor failure; retain the ability to open Termux locally.

The helper runs **locally on the phone in Termux**, from a separate reviewed v2 checkout. It does not use a personal SSH chain, modify Cloudflare/DNS/tunnel rules, reboot, change ADB settings, repair supervisors, edit boot scripts, touch other services, generate keys, delete logs, or overwrite the legacy server source. Running examples is not a substitute for obtaining approval for credential creation, persistent access, package installation, and cutover.

## 1. Record the baseline before changing anything

Confirm which account, interpreter, runit service, port, tunnel origin, and recovery path are actually in use. The defaults below assume a healthy existing runit service at `$PREFIX/var/service/ctl-server` listening on 127.0.0.1:18081. If that does not match your device, stop and review the plan.

```sh
python3 --version
uname -m
sv status "$PREFIX/var/service/ctl-server"
```

Do not copy a historical device address, username, PID, tunnel UUID, or ADB port from someone else's instructions. Do not expose the old token in terminal output. Preserve the old service run file, token, source, and logs. Avoid placing the new code in a shared or world-writable legacy directory; do not change permissions on a broad existing directory as a shortcut.

The helper refuses an absent/unhealthy supervisor or a pre-existing service check script that may depend on legacy authentication. Resolve those separately with approval. It never launches a second `runsv`, restarts `runsvdir`, or stops unrelated processes.

## 2. Approve and prepare the isolated installation

Use official Termux packages for Android-native dependencies. With package-installation approval:

```sh
pkg install python python-cryptography
```

The migration helper builds a private virtual environment with `--system-site-packages`, so it can use Termux's native `cryptography` package. It installs the repository's pinned protocol dependency and declared requirements into that environment, not into a global Python environment. Inspect `requirements.txt` first. Avoid unreviewed package mirrors or replacing certificate verification with an insecure option.

Place the reviewed checkout in an owned, non-group/world-writable directory. The default migration root is:

```sh
export CTL_MIGRATION_DIR="$HOME/.local/share/http-ctl-v2/migration"
export CTL_SERVICE_DIR="$PREFIX/var/service/ctl-server"
```

The helper requires a fresh migration directory and a private parent directory. It will not overwrite a previous migration or erase failed staging artifacts. For a later attempt, inspect the retained state and choose a new private migration directory.

Arrange the Ed25519 key with explicit owner approval on the trusted client. Keep the private key on that client. Install **only the public key** in a reviewed server configuration. For this migration, begin with `health:read`; add `screenshot:read` and `ui:control` only when the owner approved those capabilities. `files:read`, `files:write`, and especially `shell:exec` are not implied by a health-check or screen-control request.

Copy `examples/server.example.json` to a new private configuration file, replace its public-key placeholder and exact HTTPS origin, and set mode 600. Do not overwrite the old token file or save a private key on the phone. The migration copies this JSON to its private state directory and assigns a new persistent nonce database there.

## 3. Stage without touching production

From the reviewed repository root on the phone:

```sh
bash examples/termux-phone-deploy.sh stage \
  "$HOME/.config/http-ctl/server-v2.json" --confirm-stage
```

This backs up the exact original runit run file, records its digest and mode, copies the v2 package, creates an isolated virtual environment, installs dependencies, and writes staging/production launchers. It does not stop or edit the running service. The old service remains on port 18081.

In a separate local Termux terminal, start the stage in the foreground:

```sh
"$CTL_MIGRATION_DIR/launch-stage"
```

It listens only on 127.0.0.1:18082. Preserve terminal output needed for diagnosis; do not log signatures, keys, probe contents, or command/file output. If port 18082 is occupied, identify the process and choose a reviewed alternative plan rather than killing an unknown service. The helper deliberately fixes its staging port to 18082.

## 4. Prove the signed path locally

On the trusted client, with its v2 checkout and private key configured:

```sh
. .venv/bin/activate
export CTL_BASE_URL=https://ctl.example.com
export CTL_KEY_ID=my-client-readonly
export CTL_PRIVATE_KEY_FILE="$HOME/.config/http-ctl/client-ed25519.pem"
./client/ctl health-probe stage-health.json
```

This writes a mode-600, short-lived pre-signed GET `/health` request. It does not export the private key. The probe expires after 60 seconds and is usable only once; it is nevertheless a live request capability, so do not paste it into chat, logs, or a repository.

Transfer that probe through an already approved channel to a private file on the phone and immediately run:

```sh
bash examples/termux-phone-deploy.sh verify-stage /private/path/stage-health.json
```

The helper uses `python3 -m http_ctl.probe` against the fixed loopback staging port. The signature still covers the configured public HTTPS target, not an HTTP origin. This is a narrowly scoped on-device test, not permission to disable HTTPS on the public client.

If verification fails, production is unchanged. Check the clocks, origin, key ID, public key, scopes, config permissions, and installed dependencies. Generate a **fresh probe for every attempt**. Do not reuse a consumed probe, relax verification, or fall back to a bearer token.

The success receipt lasts 15 minutes for cutover and is tied to the staged source/configuration. A changed staged release needs a new reviewed stage, not an edited receipt. Local health does not yet establish public HTTPS reachability or Android functionality.

## 5. Preload a probe and explicitly cut over

First stop only the foreground staging server with Ctrl-C. Leave production, the tunnel, and existing recovery connections untouched.

Generate a **fresh** production probe on the trusted client and transfer it to the phone before cutover. It must still be within its 60-second validity window when the new service starts. Do not plan to upload a probe through the old `/exec` endpoint after switching: a narrow v2 key intentionally has no shell or file-writing authority.

Record the rollout ID from `bash examples/termux-phone-deploy.sh status` before switching. The ID is a public, random migration identifier, not a credential. The helper chooses the only active health key for temporary confirmation access; if several exist, specify `--confirmation-key-id KEY_ID` explicitly.

After approval of the switch, temporary `migration:confirm` capability, and one-shot legacy restoration on failure:

```sh
bash "$CTL_MIGRATION_DIR/deploy.sh" cutover \
  /private/path/production-health.json \
  --confirm-cutover --rollback-on-failure --confirmation-timeout 300
```

If invoking this through the old HTTP shell, launch the **whole cutover command** in a detached local session first, with standard input disconnected and output in a private migration log. For example, from the reviewed checkout on the phone:

```sh
setsid nohup bash "$CTL_MIGRATION_DIR/deploy.sh" cutover \
  /private/path/production-health.json \
  --confirm-cutover --rollback-on-failure --confirmation-timeout 300 \
  >"$CTL_MIGRATION_DIR/cutover.log" 2>&1 </dev/null &
```

The caller must have permission to run this local orchestration. Closing the HTTP connection is an **uncertain outcome**, not evidence of failure: do not blindly launch another cutover.

Before stopping the old service, the helper:

- Verifies the old run file still matches its backup.
- Creates bounded rollout state with a random ID, wall-clock deadline, same-boot monotonic deadline, and boot ID.
- Temporarily adds `migration:confirm` to the selected key and enables only this rollout's confirmation endpoint.
- Starts an independent, detached watchdog and waits for its readiness handshake. If it does not arm, the old service is not stopped.

It then stops only `ctl-server`, atomically replaces its run file, starts v2 on 18081, and immediately consumes the preloaded signed local health probe. Log configuration, legacy source/token, tunnel, DNS, and other services are unchanged.

A process-start or local-probe failure triggers one attempt to restore the original run file and start the legacy service. A passing local probe **does not cancel the watchdog**. By default, the operator has five minutes to validate the public path and explicitly confirm the rollout. The allowed window is 60–900 seconds.

The watchdog and signed confirmation handler share an exclusive lock and durable state. Confirmation atomically commits `confirmed`, or timeout atomically commits `rolling-back`; both cannot win. Missing or altered marker files do not override that state. A clock change cannot extend the monotonic acceptance deadline. Process-held operation locks are released automatically if the cutover process dies.

## 6. Verify the actual public endpoint and approved capabilities

From the trusted client, through the normal approved HTTPS path:

```sh
./client/ctl health
```

Then test only the capabilities actually granted, with non-sensitive content and safe actions:

```sh
./client/ctl screenshot phone.png
./client/ctl ui keyevent HOME
```

Do not run a UI action when it could submit a payment, approve a permission, send a message, or discard unsaved work. Screenshot and UI checks require an already authorized working ADB connection. The service does not enable root, pair ADB, change adbd to TCP mode, or accept Android permission dialogs. If the device connection is missing, diagnose and request the required separate authorization rather than silently changing its security settings.

If file scopes were separately granted, use a dedicated file root and a disposable relative-path round trip. Absolute paths and traversal should be rejected. A file-root test does not restrict `/exec`. Test shell commands only if `shell:exec` was explicitly granted; start with a harmless command, not an installation script.

Before calling the migration successful, check:

- Public signed health succeeds without exposing the private key.
- Missing/invalid signatures are rejected. A consumed probe is rejected on replay.
- The granted screenshot/UI/file/shell capabilities work as expected; ungranted capabilities are rejected.
- The existing supervisor restarts the v2 service successfully after an explicitly approved service restart, without a reboot or restarting other services.
- A fresh signed public health request succeeds after that restart.
- The original run file, legacy source/token, logs, and independent recovery access remain available.

Responses are unsigned. A malicious TLS terminator can alter them or race the original signed request, so use a trustworthy response path and corroborate consequential results independently.

## 7. Confirm only after external checks pass

Before the deadline, from the trusted client and only after the preceding checks pass:

```sh
./client/ctl migration-confirm ROLLOUT_ID
```

This sends a freshly signed POST `/migration/confirm` for exactly this rollout ID. It does not grant shell access, execute arbitrary code, or cancel any unrelated operation. The watchdog uses the committed state to retire the `migration:confirm` scope and rollout configuration atomically. No daemon restart is required for that removal, and the endpoint becomes unavailable when no rollout is active.

Verify the final local migration status where a permitted recovery channel is available. If confirmation's response is lost, do not infer success or failure from the disconnect. Check signed health, whether the endpoint remains enabled, and the retained rollout state/log through an already authorized channel. Never send a bearer request as an automatic v2-client fallback.

Without signed confirmation, the watchdog attempts one legacy-service restoration at the deadline. It reports any failure; restoration is not guaranteed if the OS kills it, the phone reboots, the filesystem fails, or the supervisor is unavailable. Boot ID checks make stale confirmations fail closed after a reboot, but a killed watchdog cannot restore a service by itself. Recover locally in Termux in that case; this script does not add or alter a boot service.

After successful confirmation the watchdog exits. It is not an ongoing health monitor, and later failures do not trigger an unrequested downgrade to legacy authentication.

## 8. Explicit rollback and retained evidence

If external verification or a required capability fails, withhold confirmation and let the preauthorized watchdog restore the old service, or use an independent permitted channel for explicit rollback. Do not retry with bearer authentication in the v2 client. To deliberately restore the old service when separately authorized:

```sh
bash examples/termux-phone-deploy.sh rollback --confirm-rollback
bash examples/termux-phone-deploy.sh status
```

Rollback checks the backup digest and refuses to overwrite an unexpected externally edited run file. It stops only this service, restores its original run file and mode, and requests the old service to start. It leaves the new release and replay database intact for diagnosis. The original token and legacy source were never replaced.

Restoring the old service restores its old security risks. Verify that service independently, explain the rollback, and plan a new explicit v2 attempt. There is no permanent dual-auth mode, automatic bearer retry, or infinite recovery loop.

Do not remove old files, tokens, backups, logs, replay state, or recovery access merely because health passed. Retiring legacy credentials and files is a separate reviewed cleanup after the new deployment has been accepted.
