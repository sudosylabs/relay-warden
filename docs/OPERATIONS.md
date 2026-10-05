# relay-warden operations guide

Prepare-only artifacts. Nothing here touches a live host; every step below
requires the operator's explicit deployment authorization.

## Layout (operator-chosen paths)

- Binary: `/opt/relay-warden/relay-warden`
- Config: `/etc/relay-warden/warden.toml` (see `config.production.example.toml`)
- State dir: `/var/lib/relay-warden/` (`warden.db`, `admin.token` 0600)
- Service: `deploy/relay-warden.service` (example unit)

## Fresh install

1. Create the user and directories:
   `useradd -r -s /usr/sbin/nologin relay-warden`
   `install -d -o relay-warden -g relay-warden -m 0750 /var/lib/relay-warden`
2. Generate the admin secret (never ship a default):
   `head -c 32 /dev/urandom | base64 > /var/lib/relay-warden/admin.token`
   `chmod 600 /var/lib/relay-warden/admin.token`
   `chown relay-warden:relay-warden /var/lib/relay-warden/admin.token`
3. Write `/etc/relay-warden/warden.toml` (copy the production example;
   set `db_path`, `admin_token_file`, ordinary defaults, and the budget).
4. Install the binary and unit, `systemctl daemon-reload`,
   `systemctl enable --now relay-warden`.
5. Health: `GET /healthz` on the relay port; authenticated
   `GET /admin/status` on the admin socket (via SSH tunnel, see below).
6. Approve the first endpoint ID, then verify a relayed transfer before
   opening the proxy route.

## Reverse proxy

Forward only the relay paths to the loopback backend; keep everything else
for existing services. Preserve WebSocket upgrades and the
`Sec-WebSocket-Protocol` subprotocol (`iroh-relay-v1/v2`) plus the
`X-Iroh-Relay-Client-Auth-V1` header. Do not buffer relay WebSockets.
Examples: `deploy/caddy.example`, `deploy/nginx.example`.
UDP discovery stays off unless separately decided and implemented.

## Admin access

The admin listener binds loopback by default. Remote administration goes over
an SSH tunnel (`ssh -L 8081:127.0.0.1:8081 user@host`); direct remote admin
exposure (separate hostname + auth) is an undecided production choice.
Log in with the token from `admin.token`, which grants a short-lived
session cookie + CSRF token.

## Backup and restore

- Backup: stop the service (or accept a WAL-checkpointed copy) and copy
  `warden.db` (plus `-wal`/`-shm` if present) to versioned storage.
- Restore replaces the ledger: **re-verify endpoint approvals afterwards**,
  because a restore reverts later revocations. Restoring never creates
  spendable quota (spent bytes stay spent; exhaustion flags persist).
- A database stamped with a newer `user_version` is refused by older
  binaries (fail-closed); upgrade the binary, never hand-edit the DB.

## Upgrade

1. Snapshot `warden.db` (recoverable backup of the exact files replaced).
2. Stop the service, replace the binary, restart.
3. Check `/admin/status` (`db_ok`, period, exhaustion) and relay transfer.
4. Rollback: stop, restore the binary **and** the pre-upgrade DB snapshot
   together (never mix a new ledger with an old binary), restart, re-verify.
   Never fall back to an unrestricted relay binary: a failed custom server
   stays down, loud, rather than silently open.

## Monitoring and alerts

- Scrape the private `GET /admin/metrics` (Prometheus format, authenticated)
  with existing tooling; dashboard optional. Enforcement never depends on
  scraping.
- Set `alert_webhook_url` (config or `PATCH /admin/settings`) to receive
  `warning_75`, `warning_90`, `exhausted` POSTs. Each kind fires once per
  period; failures are recorded in `usage.alerts.last_delivery` and never
  affect enforcement. No sink = flags persist silently.
- Exhaustion response: confirm `exhausted: true` in `/admin/usage`, decide
  whether to re-budget (audited) or wait for the month boundary. Total-VPS
  egress (including other services) must be watched separately at the
  infrastructure layer.

## Resource notes

Default ceilings: 1024 global connections, 16 per endpoint, 64 concurrent
handshakes, 10s handshake timeout, 64KiB admin bodies. Tune in config.
Metrics use fixed label sets (no endpoint IDs/IPs). Logs carry no payloads,
tokens, or secrets; set verbosity with `RUST_LOG`.
