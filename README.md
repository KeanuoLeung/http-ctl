# http-ctl

An authenticated HTTP control service for a machine you own or are authorized to administer. The daemon listens on loopback; an existing HTTPS reverse proxy or tunnel can make it reachable by an authorized client.

**Version 2 replaces bearer tokens with Ed25519 HTTP Message Signatures. It is not wire-compatible with the old token client.** Do not replace a working deployment in place. Follow the [staged migration guide](examples/termux-phone.md), keep an independent recovery path, and make the final switch only after testing the signed client.

This project does not bypass a platform's sandbox, network controls, permissions, or approval requirements. Android permissions and ADB authorization still apply.

## Authentication and capabilities

Requests use [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html), with signature construction and parsing provided by the pinned `http-message-signatures==2.0.1` dependency. The application computes and verifies the SHA-256 [RFC 9530 Content-Digest](https://www.rfc-editor.org/rfc/rfc9530.html) and signs that header as part of its required profile. The server stores public keys only. Private signing keys remain on the trusted client.

Each key has its own scopes and can be revoked. No bearer-token fallback is accepted.

| Endpoint | Method | Required scope | Purpose |
| --- | --- | --- | --- |
| `/health` | GET | `health:read` | Authenticated liveness |
| `/screenshot` | GET | `screenshot:read` | PNG through an already authorized ADB connection |
| `/ui` | POST | `ui:control` | Typed `tap`, `swipe`, `keyevent`, and `text` actions |
| `/ui/hierarchy` | GET | `ui:control` | Read the active Android accessibility hierarchy as XML; no navigation |
| `/download?path=…` | GET | `files:read` | Read a relative path inside that key's file root |
| `/upload?path=…` | POST | `files:write` | Write a relative path inside that key's file root |
| `/exec` | POST | `shell:exec` | Arbitrary shell commands as the daemon user |
| `/jobs/submit` | POST | `shell:exec` | Admit a bounded asynchronous command with a caller-chosen ID |
| `/jobs/status` | POST | `shell:exec` | Read that key's retained job state and output sizes |
| `/jobs/logs` | POST | `shell:exec` | Read one output stream from a byte cursor |
| `/jobs/cancel` | POST | `shell:exec` | Request termination of that key's active job |
| `/migration/confirm` | POST | `migration:confirm` | Accept one bounded rollout; disabled outside migration |

`ui:control` can still perform consequential actions on an unlocked device. `shell:exec` intentionally gives broad shell access and is not constrained by the file root. Start with `health:read`, then grant only the capabilities you actually need. `migration:confirm` is a temporary migration-only capability, not a permanent administrative API.

## Fresh installation

These are operator instructions, not evidence that a particular phone has been deployed or tested. Read [SECURITY.md](SECURITY.md) first. For an existing installation, use [the migration procedure](examples/termux-phone.md) instead.

### Server

1. Review the code and dependencies. Use a dedicated, unprivileged account and a private configuration directory.
2. On ordinary Linux, create a virtual environment and install the pinned requirements:

   ```sh
   python3 -m venv .venv
   .venv/bin/python -m pip install -r requirements.txt
   ```

   On Termux, install Python and `python-cryptography` from the official Termux repository, then use `python3 -m venv --system-site-packages .venv`. See the [Termux guide](examples/termux-phone.md); do not rely on Linux manylinux wheels on Android.
3. Arrange an authorized Ed25519 signing key on the trusted client. Key creation and granting persistent access require the owner's explicit approval. Transfer **only the public key** to the server. Do not copy the private key to the phone, a tunnel provider, logs, or chat.
4. Copy [`examples/server.example.json`](examples/server.example.json) to `~/.config/http-ctl/server.json`, replace the placeholders, and restrict access:

   ```sh
   mkdir -p ~/.config/http-ctl
   chmod 700 ~/.config/http-ctl
   chmod 600 ~/.config/http-ctl/server.json
   ```

   Set `external_origin` to the exact public HTTPS origin, for example `https://ctl.example.com`, with no path or trailing slash. This is the signing origin, not the loopback transport address. Start with a `health:read` key. A key with file scopes also needs an existing absolute `file_root` dedicated to permitted files.
5. From the repository root, start the server:

   ```sh
   export CTL_CONFIG_FILE="$HOME/.config/http-ctl/server.json"
   export CTL_HOST=127.0.0.1
   export CTL_PORT=18081
   .venv/bin/python -m http_ctl.server
   ```

   The public endpoint must use HTTPS. Forward only the intended hostname and preserve the request path, query, signed headers, and body. Do not expose port 18081 directly. Changes to a tunnel, DNS, firewall, permissions, or service persistence need their own approval.

### Client

Install the same checkout and dependencies on the trusted client. `client/ctl` is a wrapper for the Python signed client; keep it with the package or invoke `python3 -m http_ctl.client` from the repository root.

```sh
. .venv/bin/activate
export CTL_BASE_URL=https://ctl.example.com
export CTL_KEY_ID=my-client-readonly
export CTL_PRIVATE_KEY_FILE="$HOME/.config/http-ctl/client-ed25519.pem"
chmod 600 "$CTL_PRIVATE_KEY_FILE"
./client/ctl health
# Only after granting the corresponding scope:
./client/ctl screenshot phone.png
./client/ctl ui tap 100 200
./client/ctl ui keyevent HOME
./client/ctl hierarchy hierarchy.xml
```

The private key must be an Ed25519 PEM file corresponding to the public key configured under `CTL_KEY_ID`. Do not put PEM contents or tokens in environment variables. Use `./client/ctl --help` for supported commands and their arguments.

An HTTP 200 health response proves that this request reached a responding endpoint; by itself, it does not prove screenshots, UI, files, or shell operations work. Test each granted capability safely before relying on it.

### Shell-friendly execution results

`ctl exec 'command'` keeps its JSON output, but now returns the **remote command's
exit status**, rather than reporting success for every HTTP 200 response. Existing
scripts that ignored the JSON `exit` field may now correctly stop on failures.
Use `ctl exec --raw 'command'` to write decoded command stdout and stderr to the
corresponding local streams. The legacy exec API is text-only, not a binary pipe.

Remote exits 0–255 are preserved; termination by signal N maps to 128+N. A timed
out execution returns 124, output-limit termination returns 125, and a transport,
HTTP, or invalid-response failure returns 255. Local configuration failures return
1. These values can overlap genuine command exit codes; JSON fields and static
client diagnostics distinguish the cause. Timeout takes priority over truncation.
HTTP errors identify the status without echoing potentially sensitive response
bodies. The client never retries an operation automatically.

The existing `/exec` operation remains bounded to 300 seconds and 100,000 bytes
per output stream; exceeding an output limit terminates its process group. Do not
use it for package upgrades, builds, interactive programs, or long-running jobs
whose output and duration are unknown.

### Asynchronous commands and disconnect recovery

```sh
./client/ctl jobs submit --id build-20261025-01 'make test' --timeout 3600
./client/ctl jobs status build-20261025-01
./client/ctl jobs logs build-20261025-01 --stream stdout --cursor 0
./client/ctl jobs logs build-20261025-01 --stream stderr --cursor 0 --raw
./client/ctl jobs cancel build-20261025-01
```

Status commands return a successful CLI status when the query succeeds; inspect
the JSON job `state` and `exit` to learn the command result. Cancellation is
asynchronous: query until terminal state to confirm it. Each logs command returns
one bounded page; continue from `next_cursor`. Raw mode writes the selected
stream's binary bytes to local stdout. There is no implicit retry or follow loop.

The jobs API separates a command's lifetime from an HTTP connection. Choose and
retain a unique ID **before submitting**. Submit returns HTTP 202 for a new job
and HTTP 200 for a matching existing job. If the connection drops, query that ID
with `/jobs/status`; do not invent another ID and rerun the command. Repeating
the same ID, command, and timeout under the same key returns the original job;
using the ID with different input returns 409. Every HTTP request still needs a
fresh signature and nonce. Transport replay prevention is not job deduplication.

All four endpoints take JSON bodies and require `shell:exec`. Status and cancel
accept `{"id":"my-job"}`. Submit adds `cmd` and optional `timeout` (1–3600 seconds,
default 3600). Logs take `id`, `stream` (`stdout` or `stderr`), optional `cursor`
(default 0) and `limit` (1–65536, default 65536). Log responses contain base64
bytes, the next byte cursor, state, and an EOF flag. EOF means the stream is
finished, not merely that no bytes are available at the moment. A key cannot
query or cancel another key's jobs. New requests honor key revocation.

This first implementation has explicit limits: two active jobs, 128 retained
job IDs, and 1 MiB combined stdout/stderr per job. Exceeding the output quota
terminates that job with state `output_limit`; it does not silently discard
unbounded output. Jobs have separate capacity from the short-operation pool.
They have no interactive stdin or PTY, and inherit only a small environment
allowlist. Commands execute as the daemon's OS user, not in a new sandbox.

Private metadata and logs are stored in `jobs/` beside the replay database.
Admission is persisted before starting a command. A daemon restart marks
previously active records `interrupted` and **never reexecutes them**. This is
disconnect recovery and retained results, not restart-resumable computation or
an exactly-once side-effect guarantee. After a hard crash, a detached descendant
may still exist and the outcome may be unknown; inspect it before taking action.
Do not automatically resubmit an interrupted command under a new ID.

IDs are deliberately not silently expired or recycled. At the retention limit,
new IDs are refused while existing records remain queryable. There is no remote
purge operation in this release. Plan an explicit offline retention policy before
using it as an unattended high-volume scheduler; deleting state also removes the
deduplication history. Do not delete the replay database to make room for jobs.

### Migration acceptance must include maintenance

Before changing authentication or replacing a service, record the capabilities
the owner actually needs and test them through the replacement client. A healthy
endpoint plus successful screenshots is **not** sufficient acceptance for a
machine that must remain remotely maintainable. Test an explicitly authorized,
harmless shell command and the independent recovery route before retiring the old
route. If a capability will intentionally be removed, obtain that decision before
cutover. Do not silently grant new scopes or reinstate an old authentication mode.

The current migration helper's signed health probe and confirmation watchdog do
not mechanically enforce this capability checklist. The operator must verify it;
do not treat a migration confirmation alone as evidence of shell/file access.

`shell:exec` is an application API permission, not an Android/Linux user or root
permission. Once authorized, commands run with the daemon's OS identity. This
does not make the daemon root or grant Android/ADB capabilities it does not have.

### Use standard Linux SSH clients (optional)

The separate [SSH-over-HTTPS guide](examples/ssh-over-https.md) describes the
optional fixed-loopback WebSocket bridge and Linux `ProxyCommand` helper. It uses
real OpenSSH on both sides of an opaque transport instead of emulating SSH with
the JSON API. After explicit setup, ordinary `ssh phone`, `scp` and `sftp` can use
it, subject to the destination sshd's policies and OS capabilities.

This requires `requirements-ssh.txt`, a separately granted `ssh:connect` scope,
an existing authorized sshd, independently verified host keys, and an approved
WebSocket route. None is enabled by the ordinary HTTP server or automatically
granted by an upgrade. An HTTPS hostname alone is not an SSH listener. Do not
disable SSH host-key checks or treat local transport tests as phone deployment.

### Read the active UI hierarchy

`hierarchy [output]` saves validated UTF-8 XML to an owner-only file (`hierarchy.xml` by default). It reads the existing accessibility tree with Android's `uiautomator dump --compressed`, without taps, swipes, app launches, or text input. The endpoint takes no query, body, shell command, device identifier, or path. It uses the existing `ui:control` scope and the fixed authorized ADB target `localhost:5555`; no new key or file/shell permission is needed.

The XML can contain private on-screen text, resource IDs, descriptions, bounds, and interaction attributes. Keep it private and treat text supplied by apps as untrusted data, not instructions. Accessibility APIs do not expose every custom-rendered/WebView element, and a busy, locked, or protected screen can return an error. This is not OCR or a guarantee of a complete layout.

The server and client remove `text` and `content-desc` values on nodes marked `password="true"`. This is defense in depth, not a guarantee that apps correctly mark every sensitive field; other visible values remain private.

Dump output is limited to 1 MiB, 10,000 XML elements, and 100 levels. DTD/entity declarations, processing instructions other than the XML declaration, namespace-qualified elements/attributes, and malformed XML are rejected. Only one hierarchy dump runs at a time. The operation uses a unique private directory under `/data/local/tmp`, a bounded Android timeout and file-size limit, and two cleanup paths (25 seconds for the main operation plus 5 seconds for cleanup, excluding bounded process termination overhead). An ADB outage may leave a private temporary directory requiring later local cleanup; it never falls back to shared `/sdcard/window_dump.xml`. Android system `sh`, `timeout`, `uiautomator`, and an already authorized ADB connection must be available. Local tests do not establish a particular device's compatibility.

A deployment with only health/screenshot/UI scopes cannot remotely install updates. Use an already authorized local Termux/administrative route; do not revive the disabled bearer token, grant shell/file access silently, or type shell commands through the UI to evade the scope boundary.

For an already migrated signed-v2 Termux installation with unchanged dependencies, the [local package-only update guide](examples/termux-package-update.md) preserves configuration and the existing venv, tests a disabled-key sidecar, and retains the previous signed-v2 package for recovery. It must be run locally, not through the service being replaced.

## Application signature transport

The client sends its signature in `X-Http-Ctl-Signature` and `X-Http-Ctl-Signature-Input`. Some infrastructure uses the ordinary `Signature` fields for its own identity; http-ctl does not assume those fields reach the application unchanged. The server maps only the two application-owned fields into the RFC 9421 library, without changing their values or the signed method, target URI, digest, content type, parameters, or replay checks. Ordinary `Signature`/`Signature-Input` fields never authenticate a request and are not a fallback.

This is an application-specific transport profile using RFC 9421 signature construction, not wire interoperability with generic RFC 9421 clients. Both application fields are required; duplicates and ambiguity are rejected. A network intermediary can still alter or remove them, causing safe rejection, but cannot make a modified request pass without the private key. Local audit logs contain only fixed failure categories, never header values, signatures, nonces, key identifiers, bodies, or exception details. Public authentication failures remain generic HTTP 401.

## Configuration

| Setting | Meaning |
| --- | --- |
| `CTL_CONFIG_FILE` | Server JSON file; default `~/.config/http-ctl/server.json` |
| `CTL_HOST` | Must be `127.0.0.1` |
| `CTL_PORT` | Local port; default `18081`, staged migration uses `18082` |
| `external_origin` | Exact public HTTPS origin used to verify the signed target URI |
| `keys` | Object mapping key IDs to `public_key_pem`, `scopes`, `revoked`, and optional `file_root` |
| `replay_db` | Persistent SQLite nonce database in a private local state directory |
| `CTL_BASE_URL` | Client HTTPS origin, matching `external_origin` |
| `CTL_KEY_ID` | Client's configured key ID |
| `CTL_PRIVATE_KEY_FILE` | Client-only Ed25519 private-key PEM path |

Omitting `replay_db` uses the server's private state default. Keep its directory private and its database persistent across restarts; do not delete it while signatures could still be valid. Key entries are reloaded for each newly authenticated request, so an atomic key update or revocation applies without a restart. An already authorized in-flight request may finish. Changing the origin, replay database, or ADB selection requires a restart; changing them live fails closed.

## Security boundaries

- Signatures bind the method, full configured target URI, content type, content digest, and signature parameters. The server enforces expiry and persistent nonce replay checks.
- An intercepting TLS proxy can still read requests and responses, suppress traffic, alter **unsigned responses**, or race the original signed request. It cannot forge a modified signed request or derive the private key merely by observing traffic.
- Request signatures are not end-to-end encryption, response authentication, or protection from a compromised client. HTTPS and a trustworthy response path are still needed.
- Relative file paths are confined to each key's configured root. This does not constrain `/exec`, ADB itself, or other software running as the same OS account.
- No tool or network path authorizes actions beyond the machine owner's permission or the assistant platform's policies.

## Repository layout

```text
http_ctl/                       v2 server, signed client, and probe helper
client/ctl                      signed-client launcher
examples/server.example.json   least-privilege configuration template
examples/runit/                 service templates
examples/systemd/               Linux service template
examples/termux-phone.md         staged phone migration and verification
examples/termux-phone-deploy.sh local-only stage/verify/cutover/rollback tool
SECURITY.md                      threat model and operational guidance
```

A device-specific installation is successful only after the signed public health check, required capability tests, service-restart check, and a review of the rollback path. Local tests alone do not establish phone compatibility.
