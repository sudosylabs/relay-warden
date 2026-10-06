# Troubleshooting and maintenance

[Deploy](INSTALL.md) → [Use](USAGE.md) → Maintain

Use this page after installation. Commands run on the server unless marked
otherwise. Restarts disconnect clients and end admin sessions.

## A connection is not working

Start with the service and its logs:

```sh
sudo systemctl status relay-warden --no-pager
sudo journalctl -u relay-warden -n 50 --no-pager
curl --fail http://127.0.0.1:8080/healthz
```

Then check the public route **from your computer**:

```sh
curl --fail --include https://relay.example.com/ping
```

Replace the hostname. This route has an empty body; a valid HTTPS 200 is the
expected result. It does not prove a relayed transfer works.

| Symptom | Check next |
|---|---|
| Service refuses to start | Token file exists, service account can read it, default speeds and budget are configured |
| Backend works but HTTPS fails | DNS, TCP 80/443 in both firewalls, certificate, and proxy logs |
| `/ping` works but the app cannot relay | App's relay URL, WebSocket forwarding, token, access mode, and budget |
| HTTP 400 on `/relay` | Iroh client subprotocol; if using a trusted proxy, valid `X-Forwarded-For` |
| HTTP 429 | Shared IP/subnet attempt or connection limits; wait and avoid rapid retries |
| HTTP 503 | Global connection or handshake capacity |
| No access request appears | Correct relay URL, required token, non-exhausted budget; retry after a server restart |
| All requests show `127.0.0.1` | Configure the local proxy IP in `[network].trusted_proxies` |
| Saving a TOML speed/budget did nothing | Existing database settings win; use the dashboard |
| Admin login expired | Reopen the SSH tunnel and sign in; sessions end on restart or after one hour |

For Caddy errors:

```sh
sudo journalctl -u caddy -n 50 --no-pager
```

A bare HTTP request to `/relay` is not a valid Iroh handshake. Use an Iroh
client to test it. Also confirm your app is using a relayed path: direct
peer-to-peer success does not exercise this server.

## The relay feels slow

Check **Overview** for budget state, then **Devices** and **Settings** for
speed limits. Review IP/subnet/global limits in the TOML file.

Device limits do not override shared limits. Users on one campus or home
network may share an IP allowance. An unlimited approved device still shares
the global limit. Broad IPv4 subnet grouping can group unrelated users;
it is off by default.

If traffic is comfortably below every limit, inspect server CPU, storage
latency, and the proxy. Budget reservations wait for SQLite durability, so
storage is part of the packet path. See
[connection checks and latency](USAGE.md#connection-checks-and-latency).
There is no measured capacity or latency guarantee.

## The monthly budget ran out

On **Overview**, check the current UTC month, charged usage, and effective
cutoff. All relay connections close at cutoff; administration remains usable.

Choose between waiting for the next UTC month or raising the budget in
**Settings** after checking your provider's remaining allowance. Raising it
does not erase recorded usage. Restarting also does not reset the ledger.

Do not delete or restore the database to reopen a relay. That loses usage and
can restore previously revoked access. Monitor the provider's total traffic
separately: the ledger does not include other services or exact wire overhead.

## Monitor the service

Use **Overview** for current status and **Activity** for admin changes.
Recent device observations and connection counters reset on restart; saved
policies, settings, usage, and audit records persist.

For automated monitoring, the private `/admin/metrics` endpoint provides
Prometheus output and requires the admin credential. Follow the
[API authentication instructions](API.md). Do not expose it through the
public proxy.

Set a webhook in **Settings** if you want monthly budget notifications.
The events are `warning_75`, `warning_90`, and `exhausted`.
Delivery failures do not disable traffic enforcement.

## Back up

Schedule a maintenance window: this simple, consistent backup stops the relay.
It copies the entire state directory so SQLite's WAL files, if present, are
not forgotten. The backup also contains secrets; keep it private.

```sh
WARDEN_BACKUP="/var/backups/relay-warden/$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -m 700 "$WARDEN_BACKUP"
sudo systemctl stop relay-warden
sudo cp -a /var/lib/relay-warden "$WARDEN_BACKUP/state"
sudo cp -a /etc/relay-warden "$WARDEN_BACKUP/config"
sudo cp -a /opt/relay-warden/relay-warden "$WARDEN_BACKUP/relay-warden"
sudo systemctl start relay-warden
printf 'Backup: %s\n' "$WARDEN_BACKUP"
```

Check each copy succeeds before restarting. Store a protected copy off the
server too. A running database needs a proper SQLite online backup, not a
plain copy of `warden.db` alone.

## Upgrade

1. Download and verify the new archive using
   [installation step 1](INSTALL.md#1-download-a-release).
2. Read its release notes for configuration or schema changes.
3. Make a backup as above. Keep the current database and tokens.
4. From the **new archive directory**, replace only the executable:

```sh
sudo systemctl stop relay-warden
sudo install -m 755 ./relay-warden /opt/relay-warden/relay-warden
sudo systemctl start relay-warden
sudo systemctl status relay-warden --no-pager
curl --fail http://127.0.0.1:8080/healthz
```

If an install command fails, keep the service stopped until you resolve it.
Do not copy the example config over your existing config. Review service or
proxy changes separately rather than replacing them blindly.

Sign in again. Check the current month, usage, access mode, and settings, then
perform a relayed transfer. The systemd unit gives graceful shutdown up to
30 seconds to drain connections and persist the ledger.

## Roll back the executable

If an upgrade fails, restore the previous executable **without restoring its
old database**. Use the path printed by your backup command:

```sh
WARDEN_BACKUP='/var/backups/relay-warden/PASTE_YOUR_BACKUP_DIRECTORY'
sudo systemctl stop relay-warden
sudo install -m 755 "$WARDEN_BACKUP/relay-warden" /opt/relay-warden/relay-warden
sudo systemctl start relay-warden
sudo journalctl -u relay-warden -n 50 --no-pager
```

Check that charged usage has not decreased. If the old executable refuses a
newer database schema, reinstall a compatible executable and fix forward.
Do not hand-edit the schema version or restore stale usage to force it open.

## Recover from a lost database

Keep the relay stopped. A backup may omit traffic used since it was taken
and may restore access you later revoked. There is no automatic ledger merge
or supported database downgrade.

Before reopening, reconcile the backup with provider traffic records and your
allocation, reduce remaining allowance conservatively, and recheck access
policies. If you cannot establish remaining allowance, leave the service
stopped rather than treating old usage as current.

## Share the server with other apps

The supplied systemd unit caps the relay at 1 GB of memory, one CPU's worth
of CPU time, and 256 tasks. These are ceilings, not reserved resources or
measured requirements. Adjust them to your host.

Global speeds live in `[network]`. Set them with room for your other services,
and keep administration on loopback. Caddy/Nginx can route other hostnames
through the same HTTPS edge without moving the relay's private listeners.
