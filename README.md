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
| `/download?path=…` | GET | `files:read` | Read a relative path inside that key's file root |
| `/upload?path=…` | POST | `files:write` | Write a relative path inside that key's file root |
| `/exec` | POST | `shell:exec` | Arbitrary shell commands as the daemon user |
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
```

The private key must be an Ed25519 PEM file corresponding to the public key configured under `CTL_KEY_ID`. Do not put PEM contents or tokens in environment variables. Use `./client/ctl --help` for supported commands and their arguments.

An HTTP 200 health response proves that this request reached a responding endpoint; by itself, it does not prove screenshots, UI, files, or shell operations work. Test each granted capability safely before relying on it.

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
