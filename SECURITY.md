# Security model

http-ctl is a remote-control service, not a security sandbox. Deploy it only on machines you own or have permission to administer. Use a dedicated unprivileged OS account whenever possible. Never assume that a tunnel or a signature permits bypassing network restrictions, Android permissions, ADB authorization, or human approvals.

## Version 2 request authentication

The server accepts Ed25519 signatures using the pinned `http-message-signatures==2.0.1` library for RFC 9421 signature construction and parsing. The application separately computes and verifies the SHA-256 RFC 9530 Content-Digest and requires that header to be signed. The signing profile covers `@method`, `@target-uri`, `content-type`, and `content-digest`, including an empty-body digest for GET. Signature parameters include `created`, `expires`, `nonce`, `keyid`, `alg`, and the profile `tag`. The server checks the complete required profile, timestamps, key status, and a persistent nonce store before performing an authorized action.

The signed target URI is the configured `external_origin` plus the exact incoming request target. Configure one exact HTTPS origin, including its port if non-default. Do not trust an arbitrary forwarded-host header or change paths or query encoding in the reverse proxy. Both client and server clocks must be reasonably synchronized.

The server stores only public keys. Each key is assigned scopes; unknown, revoked, expired, malformed, replayed, tampered, and under-scoped requests are rejected. Old bearer tokens are not accepted, and a failed signature must never trigger an automatic retry using a legacy token.

## Application signature transport

The client sends its signature in `X-Http-Ctl-Signature` and `X-Http-Ctl-Signature-Input`. Some infrastructure uses the ordinary `Signature` fields for its own identity; http-ctl does not assume those fields reach the application unchanged. The server maps only the two application-owned fields into the RFC 9421 library, without changing their values or the signed method, target URI, digest, content type, parameters, or replay checks. Ordinary `Signature`/`Signature-Input` fields never authenticate a request and are not a fallback.

This is an application-specific transport profile using RFC 9421 signature construction, not wire interoperability with generic RFC 9421 clients. Both application fields are required; duplicates and ambiguity are rejected. A network intermediary can still alter or remove them, causing safe rejection, but cannot make a modified request pass without the private key. Local audit logs contain only fixed failure categories, never header values, signatures, nonces, key identifiers, bodies, or exception details. Public authentication failures remain generic HTTP 401.

## What this protects, and what it does not

A network observer that sees a correctly signed request does not learn the private key and cannot change the signed method, target, headers, or body without invalidating the signature. A captured request cannot be used repeatedly after its nonce has been accepted or its validity period has ended.

However, an intercepting proxy or tunnel operator can:

- Read request bodies, command output, uploaded files, screenshots, and other responses.
- Drop or delay traffic, and race the original still-valid signed request. The first accepted copy may execute; replay protection does not prove which route carried it.
- Modify or fabricate server responses, because this protocol signs requests, not responses.
- Observe timing and metadata, or deny service.

Consequently, this design is **not end-to-end secrecy** and does not establish an end-to-end authenticated response channel through a malicious TLS terminator. Use HTTPS and a trusted transport/response path. Do not treat an untrusted response as proof that a consequential operation succeeded. Compromise of the signing client, its private key, the server account, or its public-key configuration defeats the corresponding protection.

The loopback HTTP connection is not encrypted. Keep it local, run under an appropriate account, and do not expose it to a LAN or the internet. Local processes able to tamper with the daemon, configuration, or replay state are outside the network-signature protection.

## Least-privilege scopes

| Scope | Security consequence |
| --- | --- |
| `health:read` | Reads authenticated liveness. Good starting point. |
| `screenshot:read` | May expose private information visible on screen. |
| `ui:control` | Can interact with apps and trigger consequential actions. Typed inputs avoid a general command-string API but are not harmless. |
| `files:read` | Reads files inside the key's dedicated file root. |
| `files:write` | Writes files inside that root. Do not include service/configuration directories or code executed elsewhere. |
| `shell:exec` | Full shell authority of the daemon's OS account. Explicit opt-in only. |
| `migration:confirm` | Temporary acceptance of one bounded rollout after external tests. Disabled by default and removed on completion. |

File roots are not a sandbox for shell execution or other local programs. Never grant file access to the server configuration, signing keys, service definitions, startup files, or executable directories. An actor that can alter a file another program executes may gain that program's authority. Untrusted local processes sharing the daemon's account can also undermine file-level boundaries.

ADB and Android determine which screen and UI operations are available. The service does not enable root, change adbd mode, establish pairing, or approve device dialogs for you. Use an existing authorized connection; treat changes to ADB access as separate security-sensitive operations.

## Keys, configuration, and replay state

1. Obtain explicit owner approval before creating credentials or granting persistent access. Keep each private key only on its intended trusted client. Use a distinct key ID per client and a narrowly scoped public-key entry on the server.
2. Store the client private key and server configuration with owner-only permissions, with private parent directories. Do not paste keys into chat, commits, shell history, environment values, logs, or screenshots. The public key is not secret, but altering the configuration grants access.
3. Revoke a key by atomically replacing the configuration with its entry's `revoked` set to `true` or the entry removed. Key entries reload for each newly authenticated request. Confirm that the old key is rejected; an already authorized in-flight request may still finish. Keep `external_origin`, `replay_db`, and ADB selection unchanged during a live key update; changing those requires a restart and otherwise fails closed.
4. For rotation, authorize and test a new public-key entry first, then revoke the old entry. Keep the replacement private key on the client. Never restore a revoked key merely to work around an authentication failure.
5. Keep the nonce database persistent across restarts and in a private directory on a local filesystem. Do not delete, restore an older copy, or share it with untrusted processes while requests may remain valid. A stale database backup can allow a previously captured request to be accepted again within its validity window.
6. Retain normal HTTPS certificate verification. A connection error is not a reason to disable TLS validation or bypass a browser security warning.

## Operations and logs

Bind only `127.0.0.1`. Require HTTPS at the public origin and preserve the signed request unchanged. Limit exposure, concurrency, and request sizes; parser limits and output caps reduce resource abuse but are not a complete denial-of-service defense. A public reverse proxy may provide additional rate limiting without weakening signature verification.

Do not log authorization headers, `Signature`/`Signature-Input`, private keys, raw probes, request bodies, command output, or file contents. A live signed probe is a short-lived capability even though it does not disclose a private key. Protect existing logs and retain evidence during troubleshooting; do not wipe them to make an installation appear clean.

Keep an independent, already authorized recovery path whenever available. If legacy HTTP is the only remote path, prearm the documented bounded rollback watchdog before cutover and retain local Termux recovery. The watchdog is not a guarantee against OS termination, reboot, disk failure, or supervisor failure. Before migration, record the current service path and status and back up its run script. Stage v2 on port 18082 without touching the working service on 18081. Only an explicit cutover may replace it. An explicit rollback, or a one-shot rollback specifically approved with `--rollback-on-failure`, may restore the backed-up legacy service as a deliberate temporary operational choice; it is not an automatic authentication fallback, and it restores the legacy bearer-token risks. Signed rollout confirmation and timeout restoration are mutually exclusive through shared process-held locking and durable state. The public confirmation endpoint requires its temporary scope, exact rollout ID, same boot, and unexpired wall-clock/monotonic deadlines; it is not a general management endpoint.

## Reporting a vulnerability

Do not include private keys, tokens, unexpired signed requests, personal device addresses, or sensitive logs in a public issue. Check the repository's Security tab for an available private reporting channel. If none is configured, ask the maintainer for one without publicly disclosing exploit details or secrets.
