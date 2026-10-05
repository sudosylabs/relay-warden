# relay-warden operations guide

Runbook for installing, serving, and recovering a relay. Stopping,
replacing, or reconfiguring a live service is always disruptive — plan a
maintenance window; the rollback section below is part of that plan.

## Layout (operator-chosen paths)

- Binary: `/opt/relay-warden/relay-warden`
- Config: `/etc/relay-warden/warden.toml` (see `config.production.example.toml`)
- State dir: `/var/lib/relay-warden/` (`warden.db`, `admin.token` 0600)
- Service: `deploy/relay-warden.service` (example unit)

## Fresh install

Supported host: 64-bit Linux (x86-64 or ARM64) with glibc 2.39 or newer
(Ubuntu 24.04 or equivalent). The release binaries are dynamically linked
against the build runner's glibc — they do not run on musl-based or older
systems; check `ldd --version` before installing elsewhere.

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
Never route `/admin` or `/metrics` through the public edge: the admin
listener stays loopback-only (SSH tunnel for remote access) precisely so a
proxy misconfiguration cannot expose administration.
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
  because a restore reverts later revocations. A restore also reverts
  *usage*: spent bytes disappear and exhaustion flags clear, which recreates
  spendable allowance. Never restore a database over a live ledger — see
  Rollback for the reconciliation procedure.
- A database stamped with a newer `user_version` is refused by older
  binaries (fail-closed); upgrade the binary, never hand-edit the DB.

## Upgrade

1. Snapshot `warden.db` (recoverable backup of the exact files replaced).
2. Stop the service (`systemctl stop`: SIGTERM drains connections and
   confirms ledger persistence, bounded by `TimeoutStopSec=30`), replace the
   binary, restart.
3. Check `/admin/status` (`db_ok`, period, exhaustion) and relay transfer.

## Rollback (binary only — never restore an old database over a live ledger)

Restoring a pre-upgrade DB snapshot would delete usage recorded since the
snapshot and resurrect spent allowance, contradicting the durability
guarantee. Roll back the **binary only** and keep the current database:

1. `systemctl stop relay-warden`.
2. Reinstall the previous release binary (keep a copy of each deployed
   binary with its version).
3. Start and verify: `/admin/usage` must show the same `charged_bytes` and
   `exhausted` state as before the rollback.
4. If the old binary refuses to start with `database schema generation …
   is newer`, the schema moved forward: do **not** force the old database
   back. Either stay on the new binary (forward-fix) or reconcile
   explicitly — carry every period's `charged_bytes` and `exhausted`
   forward (taking the maximum of backup and live values), e.g.:
   `sqlite3 live.db "ATTACH 'backup.db' AS b; UPDATE quota_periods SET
   charged_bytes = max(charged_bytes, (SELECT charged_bytes FROM
   b.quota_periods WHERE period = quota_periods.period)), exhausted =
   exhausted OR (SELECT exhausted FROM b.quota_periods WHERE period =
   quota_periods.period);"`
   then re-verify `charged_bytes`/`exhausted` before opening traffic.
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
