# Native SSH over the optional HTTPS transport

This is an **opt-in deployment guide, not evidence of a deployed phone**. The
normal HTTP daemon does not start this bridge. Do not alter a working recovery
route while testing it. Granting access, installing keys, starting services, or
changing a tunnel requires the owner's specific approval.

## Architecture

Linux OpenSSH uses `ProxyCommand` to exchange SSH bytes through the local
`ssh-proxy` helper. The helper authenticates a WSS upgrade using the existing
HTTP signing profile. The optional bridge forwards bytes to one fixed loopback
sshd. OpenSSH, not http-ctl, implements shell sessions, PTY, SFTP and forwarding.

Three identities are distinct:

1. The HTTP signing key allows opening the bridge (`ssh:connect`).
2. The SSH host key lets the Linux client verify the real sshd.
3. The SSH user key authenticates the login to that sshd.

Do not copy the HTTP private key onto the phone or implicitly reuse it for SSH.
Use an existing, authorized SSH login and independently verified host key.
The bridge does not configure sshd, create users, authorize keys, or enable root.

## Operator prerequisites

- An existing sshd that accepts the intended user's authorized login.
- An independently verified host fingerprint/known_hosts entry for that sshd.
- Official optional dependencies on both ends:
  `python -m pip install -r requirements-ssh.txt` in the project's venv.
- A separately approved public-key entry with `ssh:connect` in the server config.
  `shell:exec` alone deliberately does not grant bridge access.
- An approved exact HTTPS route `/ssh` to `http://127.0.0.1:18083` that forwards
  WebSocket upgrades and the signed headers unchanged. Keep existing API routes.
  The client-visible URL must remain HTTPS/WSS with certificate validation.

Do not expose the bridge listener or sshd directly to the internet. The bridge
CLI binds only `127.0.0.1` and dials only `127.0.0.1` with an operator-selected
port. It is not a client-selectable TCP proxy. The default backend port 8022 is a
convention, not proof that a particular phone listens there; verify it first.

## Sidecar invocation

From the reviewed checkout, using its optional-dependency venv:

```sh
.venv/bin/python -m http_ctl.ssh_bridge \
  --config /absolute/private/server.json \
  --listen-port 18083 --ssh-port 8022 --path /ssh
```

Keep the public origin in this config equal to the client HTTPS origin. The
signature binds `GET` and that origin plus the exact bridge path. A connection
must negotiate `http-ctl-ssh-v1`; the bridge rejects alternate paths and protocols.
The existing main HTTP daemon can continue on its own loopback port.

## Linux SSH configuration

Replace **all** example values. Absolute paths avoid depending on the shell's
working directory. The wrapper locates its own source package.

```sshconfig
Host phone
    HostName ctl.example.com
    User YOUR_TERMUX_USER
    ProxyCommand /absolute/http-ctl/.venv/bin/python /absolute/http-ctl/client/ssh-proxy --origin https://ctl.example.com --path /ssh --key-id YOUR_HTTP_KEY_ID --private-key /absolute/private/http-signing-key.pem
    HostKeyAlias http-ctl-phone
    UserKnownHostsFile ~/.ssh/known_hosts
    StrictHostKeyChecking yes
    IdentityFile ~/.ssh/phone_ssh_key
    IdentitiesOnly yes
    ServerAliveInterval 30
    ServerAliveCountMax 3
```

Before connecting, put the **independently verified** sshd host public key under
the `http-ctl-phone` alias in known_hosts. Do not use an unverified key scan as
trust establishment, set `StrictHostKeyChecking no`, or discard an unexpected
key-change warning. The helper emits only SSH bytes to stdout and diagnostics to
stderr. System proxy settings apply; `--proxy http://...` or `https://...` selects
an explicit CONNECT proxy. Proxy failure does not trigger a direct-route retry.

Once the approved deployment and host trust are validated:

```sh
ssh phone
ssh phone 'id; pwd'
scp ./example.txt phone:~/example.txt
sftp phone
ssh -N -L 8080:127.0.0.1:8080 phone
```

These are ordinary OpenSSH commands. Subsystems, PTY allocation, and forwarding
remain subject to the destination sshd configuration and OS permissions. Do not
promise they work on an untested device merely because a remote command worked.
An SSH connection to the public hostname without `ProxyCommand` is not an HTTP
request and cannot use this HTTPS endpoint.

## Bounded transport and recovery

- Inner SSH remains encrypted between OpenSSH and the verified sshd even when
  outer TLS terminates at a proxy. The proxy can observe traffic metadata and
  interrupt the connection; it cannot become the trusted SSH host without its key.
- The bridge permits at most 16 transport connections, uses 32 KiB payload chunks
  and bounded queues, disables compression, and checks established identities
  for revocation/scope removal/key replacement every five seconds.
- Binary transport frames have a versioned data/EOF envelope. Directional EOF
  lets the other direction drain for at most 30 seconds, not indefinitely.
- WebSocket heartbeat detects some dead connections; it does **not** make SSH
  streams transparently reconnectable. A connection loss ends the session's
  transport. Use an already configured multiplexer or the separate jobs API when
  a command must outlive a network connection.
- sshd sees the bridge's loopback address, not the original client's IP. Account
  for this when reviewing address-based rules and audit expectations.

## Acceptance checklist

Test the real HTTPS route, not only loopback health: exact SSH host verification,
login, nonzero remote exit propagation, binary stdin/stdout, large output, EOF
tail delivery, SCP/SFTP roundtrip, and any required forwarding. Separately verify
PTY/resize on the actual OS, scope denial and revocation, proxy failure, service
restart, and the independent recovery route. Preserve the old working path until
the owner accepts this evidence. Do not silently weaken a failure into success.

## Primary references

- [OpenSSH ProxyCommand and host-key options](https://man.openbsd.org/ssh_config)
- [SSH transport protocol](https://www.rfc-editor.org/rfc/rfc4253.html)
- [OpenSSH server policies and subsystems](https://man.openbsd.org/sshd_config)
- [WebSocket authentication](https://websockets.readthedocs.io/en/stable/topics/authentication.html)
- [Cloudflare WebSocket behavior](https://developers.cloudflare.com/network/websockets/)
