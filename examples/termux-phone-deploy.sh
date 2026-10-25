#!/usr/bin/env bash
# Local-only, reviewed migration helper. Never runs SSH, touches a tunnel,
# generates keys, changes other services, reboots, or removes logs/backups.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
export CTL_DEPLOY_SOURCE="$REPO_ROOT"
PYTHON=python3
VENV_PYTHON="${CTL_MIGRATION_DIR:-$HOME/.local/share/http-ctl-v2/migration}/release/.venv/bin/python"
if [[ "${1:-}" != stage && -x "$VENV_PYTHON" ]]; then PYTHON="$VENV_PYTHON"; fi
exec "$PYTHON" - "$@" <<'PY'
import argparse
import hashlib
import fcntl
import json
import os
import secrets
from pathlib import Path
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time

os.umask(0o077)
HOME = Path.home()
PREFIX = Path(os.environ.get("PREFIX", "/data/data/com.termux/files/usr"))
SOURCE = Path(os.environ["CTL_DEPLOY_SOURCE"])
STATE = Path(os.environ.get("CTL_MIGRATION_DIR", str(HOME / ".local/share/http-ctl-v2/migration")))
SERVICE = Path(os.environ.get("CTL_SERVICE_DIR", str(PREFIX / "var/service/ctl-server")))


def fail(message):
    raise RuntimeError(message)


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def regular(path):
    if path.is_symlink() or not path.is_file():
        fail(f"Expected a regular non-symlink file: {path}")


def private_directory(path):
    if path.is_symlink() or not path.is_dir():
        fail(f"Expected a real private directory: {path}")
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        fail(f"Directory must be owned by this account and mode 700: {path}")


def phone_only():
    if not str(PREFIX).startswith("/data/data/com.termux/") or not (PREFIX / "bin/sh").is_file():
        fail("Run this helper locally in Termux, not on a workstation or inside proot.")
    if not Path("/system/bin").is_dir():
        fail("Android system directory was not found; this is a phone-only helper.")
    if os.geteuid() == 0:
        fail("Run as the normal Termux user, not root.")
    if not STATE.is_absolute() or not SERVICE.is_absolute():
        fail("CTL_MIGRATION_DIR and CTL_SERVICE_DIR must be absolute paths.")
    if SERVICE.is_symlink() or not SERVICE.is_dir():
        fail(f"Existing runit service directory not found or is a symlink: {SERVICE}")
    regular(SERVICE / "run")
    if not shutil.which("sv"):
        fail("The existing runit supervisor must be available; no supervisor repair is attempted.")


def service_status():
    result = run(["sv", "status", SERVICE], capture_output=True, text=True, timeout=15)
    return result.stdout.strip()


def atomic_bytes(path, content, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix=".http-ctl-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_record(data):
    atomic_bytes(STATE / "state.json", (json.dumps(data, indent=2) + "\n").encode())


def record():
    private_directory(STATE)
    regular(STATE / "state.json")
    data = json.loads((STATE / "state.json").read_text())
    if data["service"] != str(SERVICE):
        fail("CTL_SERVICE_DIR does not match the service recorded during staging.")
    return data


def fingerprint():
    paths = [STATE / "server.json", STATE / "launch-production", STATE / "launch-stage", STATE / "deploy.sh"]
    paths += sorted((STATE / "release/http_ctl").rglob("*.py"))
    paths += [STATE / "release/requirements.txt"]
    value = hashlib.sha256()
    for path in paths:
        regular(path)
        value.update(str(path.relative_to(STATE)).encode())
        value.update(path.read_bytes())
    return value.hexdigest()


def launcher(port):
    release = STATE / "release"
    q = shlex.quote
    return "\n".join([
        f"#!{PREFIX}/bin/sh", "set -eu", "umask 077", "exec 2>&1",
        "export HOME=" + q(str(HOME)),
        "export PATH=" + q(f"{PREFIX}/bin:/system/bin"),
        "export TMPDIR=" + q(str(PREFIX / "tmp")),
        "export CTL_HOST=127.0.0.1", f"export CTL_PORT={port}",
        "export CTL_CONFIG_FILE=" + q(str(STATE / "server.json")),
        "cd " + q(str(release)),
        "exec " + q(str(release / ".venv/bin/python")) + " -m http_ctl.server", "",
    ])


def stage(config_file):
    if STATE.exists() or STATE.is_symlink():
        fail("Migration directory already exists. Keep it for recovery; choose a new CTL_MIGRATION_DIR for a new migration.")
    if not service_status().startswith("run:"):
        fail("Existing production service must be running before a side-by-side migration.")
    if (SERVICE / "check").exists():
        fail("Existing service has a check script. Review its v2 compatibility separately before using this helper.")
    regular(config_file)
    raw = config_file.read_text()
    if "PRIVATE KEY" in raw:
        fail("Server configuration must not contain private key material.")
    config = json.loads(raw)
    if not isinstance(config, dict) or not config.get("external_origin") or not config.get("keys"):
        fail("Supply a reviewed v2 server JSON with external_origin and authorized public keys.")
    source_info = SOURCE.stat()
    if source_info.st_uid != os.getuid() or stat.S_IMODE(source_info.st_mode) & 0o022:
        fail("Use an owned, non-group/world-writable staged checkout, not a shared legacy source directory.")
    for part in (SOURCE / "http_ctl", SOURCE / "requirements.txt"):
        if not part.exists() or part.is_symlink():
            fail(f"Reviewed v2 source missing or symlinked: {part}")
    for path in (SOURCE / "http_ctl").rglob("*"):
        if path.is_symlink():
            fail(f"Staged package contains a symlink: {path}")
    try:
        import cryptography  # noqa: F401
    except ImportError:
        fail("Install official Termux packages first, with approval: pkg install python python-cryptography")
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", 18082))
        except OSError:
            fail("Port 18082 is occupied; do not stop an unknown process to free it.")
    STATE.parent.mkdir(parents=True, exist_ok=True)
    private_directory(STATE.parent)
    STATE.mkdir(mode=0o700)
    private_directory(STATE)
    shutil.copy2(SERVICE / "run", STATE / "legacy-run")
    os.chmod(STATE / "legacy-run", 0o600)
    data = {
        "service": str(SERVICE), "phase": "preparing", "created": int(time.time()),
        "original_sha256": digest(SERVICE / "run"),
        "original_mode": stat.S_IMODE((SERVICE / "run").stat().st_mode),
        "rollout_id": secrets.token_hex(16),
    }
    write_record(data)
    shutil.copy2(SOURCE / "examples/termux-phone-deploy.sh", STATE / "deploy.sh")
    os.chmod(STATE / "deploy.sh", 0o700)
    release = STATE / "release"
    release.mkdir(mode=0o700)
    shutil.copytree(SOURCE / "http_ctl", release / "http_ctl", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(SOURCE / "requirements.txt", release / "requirements.txt")
    # The isolated v2 instance gets new persistent replay state, not legacy files.
    config["replay_db"] = str(STATE / "replay.sqlite3")
    (STATE / "server.json").write_text(json.dumps(config, indent=2) + "\n")
    run([sys.executable, "-m", "venv", "--system-site-packages", release / ".venv"])
    run([release / ".venv/bin/python", "-m", "pip", "install", "--require-virtualenv", "-r", release / "requirements.txt"])
    for name, port in (("launch-stage", 18082), ("launch-production", 18081)):
        path = STATE / name
        path.write_text(launcher(port))
        path.chmod(0o700)
    run([release / ".venv/bin/python", "-c", "import http_ctl.server, http_ctl.probe"], cwd=release)
    data["phase"] = "staged"
    data["fingerprint"] = fingerprint()
    write_record(data)
    print("Staged without changing the running service, its logs, or its tunnel.")
    print(f"Backup and state: {STATE}")
    print(f"In a separate Termux terminal, run: {shlex.quote(str(STATE / 'launch-stage'))}")
    print("Then use verify-stage with a fresh, authorized client-generated health probe.")


def wait_listener(port, timeout=15):
    """runit `sv up` confirms a process, not readiness. Never retry a signature."""
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("Candidate listener did not become ready before the bounded deadline.")
        try:
            with socket.socket() as sock:
                sock.settimeout(min(0.25, remaining))
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    return
        except OSError:
            pass
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))


def probe(path, port):
    regular(path)
    run([STATE / "release/.venv/bin/python", "-m", "http_ctl.probe", path, "--port", str(port)],
        cwd=STATE / "release", timeout=20)


def verify_stage(path):
    data = record()
    if data["phase"] not in ("staged", "verified"):
        fail("This migration is not ready for staging verification.")
    if fingerprint() != data["fingerprint"]:
        fail("Staged code or configuration changed. Review and stage a new migration.")
    probe(path, 18082)
    data.update(phase="verified", verified_at=int(time.time()))
    write_record(data)
    print("Signed local staging health passed. This does not test the public HTTPS path or other capabilities.")
    print("Stop the foreground staging process with Ctrl-C before explicitly cutting over.")


def replace_run(source, mode):
    regular(source)
    atomic_bytes(SERVICE / "run", source.read_bytes(), mode)


def rollback(data):
    regular(SERVICE / "run")
    current = digest(SERVICE / "run")
    if current not in (data["original_sha256"], digest(STATE / "launch-production")):
        fail("Service run file changed outside this migration; refusing to overwrite it.")
    if digest(STATE / "legacy-run") != data["original_sha256"]:
        fail("Legacy run backup no longer matches its recorded digest.")
    run(["sv", "-w", "10", "down", SERVICE], timeout=20)
    replace_run(STATE / "legacy-run", data["original_mode"])
    data["phase"] = "restored-start-pending"
    try:
        write_record(data)
    except Exception as exc:
        print(f"WARNING: recovery journal update failed: {exc}; still restarting the verified legacy run.", file=sys.stderr)
    finally:
        run(["sv", "-w", "10", "up", SERVICE], timeout=20)
    data["phase"] = "rolled-back"
    write_record(data)
    print("WARNING: original legacy run file restored and start requested. Legacy bearer-token risks apply.")
    print(service_status())
    print("Verify the old service independently. No v2 client has retried with a bearer token.")


def atomic_config(config):
    atomic_bytes(STATE / "server.json", (json.dumps(config, indent=2) + "\n").encode())


def retire_confirmation(data):
    config = json.loads((STATE / "server.json").read_text())
    rollout = config.get("rollout")
    if rollout is not None and rollout.get("id") != data["rollout_id"]:
        fail("Rollout configuration changed outside this migration; refusing to overwrite it.")
    config.pop("rollout", None)
    key = config.get("keys", {}).get(data["confirmation_key_id"])
    if key is not None:
        key["scopes"] = [scope for scope in key.get("scopes", []) if scope != "migration:confirm"]
    atomic_config(config)


def rollout_api():
    sys.path.insert(0, str(STATE / "release"))
    from http_ctl import rollout
    return rollout


def operation_lock(wait=0):
    fd = os.open(STATE / ".operation-lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    end = time.monotonic() + wait
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            if time.monotonic() >= end:
                os.close(fd)
                fail("Another live operation holds the migration lock; inspect before retrying.")
            time.sleep(0.2)


def perform_rollback(data, force=False):
    api = rollout_api()
    with api.locked_state(str(STATE)):
        state = api.read_state(str(STATE))
        if state["status"] == "rolled-back":
            return True
        if state["status"] == "confirmed" and not force:
            return False
        state["status"] = "rolling-back"
        api.write_state(str(STATE), state)
    # The server can no longer accept confirmation after the atomic transition.
    rollback(data)
    retire_confirmation(data)
    with api.locked_state(str(STATE)):
        state = api.read_state(str(STATE))
        state["status"] = "rolled-back"
        api.write_state(str(STATE), state)
    return True


def watch_rollout():
    api = rollout_api()
    data = record()
    if data["phase"] != "rollout-arming":
        fail("No rollout is awaiting watchdog arming.")
    state = api.read_state(str(STATE))
    if state["id"] != data["rollout_id"] or state["status"] != "pending":
        fail("Rollout state does not match the migration being armed.")
    api.atomic_json(str(STATE / "watchdog-ready.json"),
        {"pid": os.getpid(), "id": data["rollout_id"], "deadline": data["rollout_deadline"]})
    print("Independent rollback watchdog armed.", flush=True)
    while True:
        data = record()
        if data["phase"] in ("rolled-back", "complete"):
            return
        try:
            with api.locked_state(str(STATE)):
                state = api.read_state(str(STATE))
                if state["id"] != data["rollout_id"] or state["deadline"] != data["rollout_deadline"]:
                    fail("Rollout state changed outside the approved migration.")
                confirmed = state["status"] == "confirmed"
                expired = (state["boot_id"] != api.boot_id() or time.time() >= state["deadline"]
                           or time.monotonic() >= state["deadline_monotonic"])
        except BlockingIOError:
            time.sleep(0.2)
            continue
        if confirmed:
            fd = operation_lock(wait=75)
            try:
                data = record()
                with api.locked_state(str(STATE)):
                    state = api.read_state(str(STATE))
                    if state["status"] != "confirmed":
                        continue
                    retire_confirmation(data)
                    data["phase"] = "complete"
                    write_record(data)
                print("Signed external acceptance committed; temporary confirmation access removed. Rollout complete.", flush=True)
                return
            except BlockingIOError:
                continue
            finally:
                os.close(fd)
        if expired and not confirmed:
            fd = operation_lock(wait=75)
            restored = False
            try:
                data = record()
                if data["phase"] not in ("rolled-back", "complete"):
                    print("External acceptance deadline elapsed; checking atomic state before legacy-service restoration.", flush=True)
                    restored = perform_rollback(data)
                else:
                    restored = True
            except BlockingIOError:
                continue
            finally:
                os.close(fd)
            if restored:
                return
            continue
        time.sleep(0.5)


def cutover(path, auto_rollback, confirmation_key_id, confirmation_timeout):
    if not auto_rollback:
        fail("HTTP-only cutover requires --rollback-on-failure and its temporary signed confirmation watchdog.")
    data = record()
    if data["phase"] != "verified" or time.time() - data["verified_at"] > 900:
        fail("A successful verify-stage within the last 15 minutes is required; use a fresh probe.")
    if fingerprint() != data["fingerprint"]:
        fail("Staged code or configuration changed since verification.")
    if digest(SERVICE / "run") != data["original_sha256"]:
        fail("Existing run file changed since the backup; refusing cutover.")
    regular(path)
    with socket.socket() as sock:
        if sock.connect_ex(("127.0.0.1", 18082)) == 0:
            fail("Stop only the foreground staging process before cutover; port 18082 is still active.")
    config = json.loads((STATE / "server.json").read_text())
    candidates = [key_id for key_id, key in config["keys"].items()
                  if not key.get("revoked", False) and "health:read" in key.get("scopes", [])]
    if confirmation_key_id is None and len(candidates) == 1:
        confirmation_key_id = candidates[0]
    if confirmation_key_id not in candidates:
        fail("Select an active health:read key with --confirmation-key-id; ambiguous key selection is not allowed.")
    if "rollout" in config or any("migration:confirm" in key.get("scopes", []) for key in config["keys"].values()):
        fail("Use a configuration without a pre-existing rollout or migration:confirm grant.")
    data.update(phase="rollout-arming", confirmation_key_id=confirmation_key_id,
                rollout_deadline=int(time.time()) + confirmation_timeout)
    config["keys"][confirmation_key_id]["scopes"].append("migration:confirm")
    config["rollout"] = {"id": data["rollout_id"], "deadline": data["rollout_deadline"],
                         "ack_file": str(STATE / "rollout-ack.json")}
    api = rollout_api()
    with api.locked_state(str(STATE)):
        api.write_state(str(STATE), {"id": data["rollout_id"], "deadline": data["rollout_deadline"],
            "deadline_monotonic": time.monotonic() + confirmation_timeout,
            "boot_id": api.boot_id(), "status": "pending"})
    atomic_config(config)
    write_record(data)
    environment = dict(os.environ, CTL_MIGRATION_DIR=str(STATE), CTL_SERVICE_DIR=str(SERVICE))
    with (STATE / "migration.log").open("ab") as log:
        watchdog = subprocess.Popen([str(PREFIX / "bin/bash"), str(STATE / "deploy.sh"), "watch-rollout"],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True, close_fds=True, env=environment)
    armed = False
    for _ in range(50):
        if watchdog.poll() is not None:
            break
        ready = STATE / "watchdog-ready.json"
        if ready.is_file() and not ready.is_symlink():
            marker = json.loads(ready.read_text())
            armed = marker == {"pid": watchdog.pid, "id": data["rollout_id"], "deadline": data["rollout_deadline"]}
            if armed:
                break
        time.sleep(0.1)
    if not armed:
        # Crucially: production has not been stopped.
        fail("Independent watchdog did not confirm readiness. Legacy service is unchanged; inspect retained state.")
    data["watchdog_pid"] = watchdog.pid
    data["phase"] = "cutover-started"
    write_record(data)
    try:
        run(["sv", "-w", "10", "down", SERVICE], timeout=20)
        replace_run(STATE / "launch-production", 0o700)
        data["phase"] = "cutover-start-pending"
        write_record(data)
        run(["sv", "-w", "10", "up", SERVICE], timeout=20)
        # Python and cryptography imports may outlast `sv up` startup reporting.
        # Probe the listener with TCP only, then consume the signed nonce ONCE.
        wait_listener(18081)
        # This one-use probe is supplied BEFORE cutting the old HTTP shell off.
        probe(path, 18081)
        data["phase"] = "rollout-awaiting-confirm"
        write_record(data)
        print(service_status())
    except Exception:
        print("Cutover or signed local production probe failed; attempting ONE explicitly authorized rollback.", file=sys.stderr)
        perform_rollback(data)
        raise
    print("Signed local production health passed; external acceptance is STILL REQUIRED.")
    print(f"Rollout ID: {data['rollout_id']}; deadline: {data['rollout_deadline']} (Unix time).")
    print("Test HTTPS health and approved capabilities, then send signed migration confirmation before the deadline.")
    print("Without confirmation the independent watchdog restores the legacy service once.")


def verify_production(path, auto_rollback):
    data = record()
    if data["phase"] not in ("rollout-awaiting-confirm", "complete"):
        fail("There is no cutover awaiting production verification.")
    if digest(SERVICE / "run") != digest(STATE / "launch-production"):
        fail("Production run file no longer matches the staged release.")
    try:
        probe(path, 18081)
    except Exception:
        if auto_rollback:
            print("Signed local production probe failed; attempting the one explicitly requested rollback.", file=sys.stderr)
            perform_rollback(data, force=True)
        raise
    print("Signed local production health passed. Now verify the actual HTTPS path and each authorized capability.")
    print("Retain the backup and independent recovery access; no logs or legacy files were removed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__ or "Local Termux v2 migration. Nothing is deployed remotely.")
    parser.add_argument("mode", choices=("stage", "verify-stage", "cutover", "verify-production", "rollback", "status", "watch-rollout"))
    parser.add_argument("file", nargs="?", type=Path, help="server JSON for stage; fresh signed probe for verification")
    parser.add_argument("--confirm-stage", action="store_true", help="approve isolated release creation and dependency installation")
    parser.add_argument("--confirm-cutover", action="store_true", help="explicitly stop legacy service and install the v2 run script")
    parser.add_argument("--confirm-rollback", action="store_true", help="explicitly restore legacy run script and its security risks")
    parser.add_argument("--rollback-on-failure", action="store_true", help="opt in to ONE legacy-service restore if cutover or production probe fails")
    parser.add_argument("--confirmation-key-id", help="active health key granted temporary migration:confirm during this rollout")
    parser.add_argument("--confirmation-timeout", type=int, default=300, help="external acceptance window in seconds, 60 through 900 (default 300)")
    args = parser.parse_args()
    phone_only()
    if args.mode in ("stage", "verify-stage", "cutover", "verify-production") and args.file is None:
        parser.error("this mode requires a file argument")
    if args.rollback_on_failure and args.mode not in ("cutover", "verify-production"):
        parser.error("--rollback-on-failure is only valid for cutover or verify-production")
    if args.mode == "stage":
        if not args.confirm_stage:
            parser.error("stage requires --confirm-stage after reviewing installation and public-key authorization")
        stage(args.file.resolve())
        return
    private_directory(STATE)
    if args.mode == "watch-rollout":
        watch_rollout()
        return
    if not 60 <= args.confirmation_timeout <= 900:
        parser.error("--confirmation-timeout must be 60 through 900 seconds")
    # Kernel locks release even if the old HTTP transport kills its request process.
    if args.mode == "status":
        print(json.dumps(record(), indent=2))
        print(service_status())
        return
    fd = operation_lock()
    try:
        if args.mode == "verify-stage":
            verify_stage(args.file.resolve())
        elif args.mode == "cutover":
            if not args.confirm_cutover:
                parser.error("cutover requires --confirm-cutover")
            cutover(args.file.resolve(), args.rollback_on_failure, args.confirmation_key_id, args.confirmation_timeout)
        elif args.mode == "verify-production":
            verify_production(args.file.resolve(), args.rollback_on_failure)
        elif args.mode == "rollback":
            if not args.confirm_rollback:
                parser.error("rollback requires --confirm-rollback")
            data = record()
            if data["phase"] not in ("rollout-arming", "cutover-started", "cutover-start-pending", "rollout-awaiting-confirm", "complete", "restored-start-pending"):
                fail("This migration has no active cutover to roll back.")
            perform_rollback(data, force=True)
    finally:
        os.close(fd)


try:
    main()
except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
    print(f"STOPPED: {exc}", file=sys.stderr)
    print("Inspect the service status and retained migration state before retrying; no automatic retry loop is used.", file=sys.stderr)
    sys.exit(1)
PY
