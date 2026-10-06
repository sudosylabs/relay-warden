# Using the dashboard

[Deploy](INSTALL.md) → Use → [Troubleshoot and maintain](OPERATIONS.md)

Open your private admin page through the SSH tunnel from the installation
guide. You use the **admin token** to sign in; your apps never need it.

## Find your way around

| Page | Use it to |
|---|---|
| Overview | Check access mode, live connections, and monthly usage |
| Observed devices / Access requests | Save a recent device or approve its request |
| Devices | Name devices, change speeds, or revoke access |
| Settings | Change default speeds, budget, and alerts |
| Activity | Review administrator changes |

Devices, requests, and activity are paginated. The URL remembers the selected
page; device searches are also kept on reload. Your session survives a reload,
but expires after one hour or a server restart.

## Choose an access policy

Access policy is set in the server configuration, not the dashboard:

```sh
sudoedit /etc/relay-warden/warden.toml
```

Choose one of these combinations in the top-level part of the file, **before**
the `[network]` section:

| Mode | `require_endpoint_approval` | `relay_token_file` |
|---|---|---|
| Public | `false` | Omit the line |
| Approval only | `true` | Omit the line |
| Token only | `false` | Path to your relay token |
| Token + approval | `true` | Path to your relay token |

Public means unknown endpoints can use the relay with default limits.
Revoked saved endpoints remain denied, even in public mode.

### Add a shared relay token

Generate a separate credential on the server:

```sh
sudo sh -c 'umask 077; head -c 32 /dev/urandom | base64 > /var/lib/relay-warden/relay.token'
sudo chown relay-warden:relay-warden /var/lib/relay-warden/relay.token
```

Only do this when creating a token, not on every restart. Add this top-level
line to the configuration:

```toml
relay_token_file = "/var/lib/relay-warden/relay.token"
```

Share the **relay token** privately with your app users and configure their
apps to send it. Do not share `admin.token`. A shared token proves possession
of the secret, not a person's identity.

Restart after changing access policy:

```sh
sudo systemctl restart relay-warden
```

This disconnects clients and ends admin sessions. Sign in again and check the
mode on **Overview**. Rotating the relay token also requires updating clients.

## Approve a device without typing its ID

With approval enabled:

1. Ask the user to connect their app to your relay. If a token is required,
   the app must already have it.
2. Open **Access requests**. Find the request and compare its endpoint ID
   with the ID the user sees in their app.
3. Choose **Review and approve**, enter a name, and select a speed policy.
4. Save the device, then ask the user to reconnect.

The request includes the source IP when available. IPs can be shared or
change; use the endpoint ID to verify the device.

Requests disappear after 24 hours of inactivity or a server restart.
**Dismiss** removes an entry, not access: another attempt can recreate it.
Saved approvals remain after restarts.

## Save a device that already has access

In public or token-only mode, the same page is called **Observed devices**.
These devices are already allowed to relay.

Choose **Save device**, give it a name, and keep **Allow this device** checked.
Saving makes its policy persistent; it is not an approval step in these modes.
You can also use **Devices → Add endpoint** if you already know a public ID.
Never enter a private key.

## Change a device's speed

On **Devices**, edit the device and choose:

- **Use default limits** — follows the values on Settings.
- **Custom limits** — sets this device's receive/send speeds.
- **Unlimited speed** — bypasses endpoint, IP, and subnet speed limits for
  an approved device. The global speed ceiling and monthly cutoff still apply.

Receive means upload **into the relay**; send means download **from the relay**.
Enter whole numbers in bytes per second, without commas:

| Value | Approximate speed |
|---|---|
| `100000` | 100 KB/s · 0.8 Mbit/s |
| `1000000` | 1 MB/s · 8 Mbit/s |
| `10000000` | 10 MB/s · 80 Mbit/s |

Save to apply the change to live connections. A custom device limit does not
override shared IP/subnet limits. For example, two devices behind one IP still
share that IP's allowance.

To block a saved device, choose **Revoke access** and confirm. Its live
connections close, and reconnects are denied. This works in every access mode.

## Set the monthly budget

Open **Settings**, change **Budget (bytes)** and **Safety headroom (bytes)**,
then choose **Save settings**. The production installation guide enables the
budget worker; these changes take effect without a restart.

For a 100 GB allocation with 1 GB reserved, enter:

| Field | Value |
|---|---|
| Budget | `100000000000` |
| Safety headroom | `1000000000` |
| Overhead allowance | `10` |

The effective cutoff is 99 GB of charged usage. Leave **Reservation chunk**
at its default unless you have measured a reason to change it.

The relay disconnects everyone at cutoff, including unlimited devices.
Usage resets for the next UTC calendar month, not 30 days after installation.
Raising the budget can reopen the relay; lowering it can stop traffic
immediately. Removing it disables the cutoff.

**Overview** shows charged usage, not a provider billing measurement.
Monitor total server traffic separately, especially when hosting other apps.
For alerts, enter your own webhook URL in Settings; notifications are sent
at 75%, 90%, and exhaustion, once per kind per month.

## What to edit where

| Change | Where | Restart? |
|---|---|---|
| Device policy, default speeds, active budget, webhook | Dashboard | No |
| Approval mode, relay token, listeners, network limits, trusted proxy IPs | TOML file | Yes |

On a fresh database, the file supplies the starting speeds and budget.
After that, saved dashboard values win. Editing those values in TOML does
not overwrite existing settings. Do not delete the database to change a
limit: that also deletes approvals and recorded usage.

If you started without a budget worker, saving a budget in the dashboard does
not start it. Configure a budget and restart; the Settings page tells you
when enforcement is inactive.

## Connection checks and latency

There are two different paths:

```text
Connect: HTTPS/WebSocket → prove endpoint identity → local access checks
Traffic: shared speed allowances → durable budget reservation → forward
```

On connection, Relay Warden checks source-IP capacity, verifies the endpoint
through Iroh's handshake, and checks the optional token and approval record.
These checks use local memory; there is no remote auth call or database
lookup for each approval decision. The signed-challenge handshake behind an
HTTPS proxy can involve a protocol exchange; it is not just a string lookup.

On the traffic path, bandwidth buckets are checked in memory. If allowance
is available, the shaper does not add a deliberate wait. If any applicable
bucket is empty, traffic waits: that is how the speed cap is enforced.
Limits are not checked by contacting the admin page.

Budget accounting reserves chunks through a serialized SQLite worker.
A connection can wait for that durable reservation, including before its
first outbound frame. Reservations are reused across frames, but not every
frame is guaranteed to avoid a new commit. Slow storage or many simultaneous
reservations can therefore increase latency even below bandwidth limits.

Direct peer-to-peer traffic bypasses the relay, so these per-frame waits
do not affect that path. The relay connection itself still has its handshake.

We do not publish an overhead or connection-time benchmark. To assess your
deployment, measure connection time and small-message round trips against
stock Iroh on the same host and proxy, with limits comfortably above test
traffic. Repeat with concurrent clients, token/approval enabled, and budget
enforcement on/off. Do not remove the production budget just to benchmark.

**Next:** [Troubleshooting and maintenance](OPERATIONS.md) for connection
failures, backups, upgrades, and budget exhaustion.
