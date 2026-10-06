# Relay Warden

A self-hosted [Iroh](https://iroh.computer) relay with traffic limits and a
private web dashboard. Run a public relay, or restrict access to your devices.

Set speeds per device, share limits across source IPs, and give the relay a
monthly traffic budget. When that budget runs out, relaying stops; the admin
page stays available. Other services can keep running on the same server.

![Devices use HTTPS; administration stays private through an SSH tunnel.](docs/images/deployment.svg)

## Get started

Download a Linux x86-64 or ARM64 archive from
[Releases](https://github.com/sudosylabs/relay-warden/releases/latest).
You do not need Rust to run it.

**[Deploy your relay →](docs/INSTALL.md)**

The guide takes you from a fresh Ubuntu server to an HTTPS relay and your
first connected device. It includes DNS, systemd, Caddy, private admin access,
and checks along the way. Already running a web server? Keep it and add the
relay as another hostname.

Once installed, follow **[Using the dashboard](docs/USAGE.md)** to manage
devices, access requests, speeds, and the monthly budget.

## Choose who can connect

| What you want | What to enable |
|---|---|
| A public relay with traffic limits | Nothing extra; this is the default |
| Only devices you approve | Endpoint approval |
| Anyone with a shared relay token | Relay token |
| A token first, then your approval | Both |

Approval requests appear after an eligible device tries to connect. Check its
endpoint ID with its owner, approve it in the dashboard, and have it reconnect.
In public mode, **Observed devices** lets you save and name devices that are
already using the relay. [Choose an access policy](docs/USAGE.md#choose-an-access-policy).

## Keep traffic under control

Limits apply to the endpoint, its source IP, its configured subnet, and the
relay as a whole. Creating new endpoint IDs does not reset a shared IP limit.
IPv6 subnet grouping is enabled by default; IPv4 grouping is optional.

You can give an approved device **Unlimited** speed. It bypasses device and
source-network speed caps, but still shares the global ceiling and monthly
budget. Rates are in bytes per second: `100_000` is about 100 KB/s.

The budget resets each UTC calendar month. It counts relayed traffic with an
overhead allowance, not your provider's exact bill or traffic from other
services. Leave room for those services when choosing a budget.

## Will it slow down my app?

Access checks happen locally when an endpoint connects; there is no remote
approval service. Traffic below the limits is not deliberately delayed by the
shaper. Traffic above them waits for allowance, and budget reservations can
wait for a database commit. Direct device-to-device traffic does not pass
through Relay Warden.

There is no measured latency guarantee. See
[connection checks and latency](docs/USAGE.md#connection-checks-and-latency)
for what happens on the connection and packet paths.

## More help

- [Deploy](docs/INSTALL.md) — install, HTTPS, admin login, and first connection.
- [Use the dashboard](docs/USAGE.md) — the everyday tasks.
- [Troubleshoot and maintain](docs/OPERATIONS.md) — logs, backups, upgrades, and cutoff.
- [Configuration reference](docs/CONFIGURATION.md) — settings and units.
- [Admin API](docs/API.md) — automate management.
- [Contribute](CONTRIBUTING.md) — build from source and run checks.
- [Architecture](docs/ARCHITECTURE.md) — implementation details.

Relay Warden is for Iroh applications, not a VPN or a general-purpose proxy.
Applications must be configured to use your relay; installing the server does
not redirect them automatically.

## Licence and community

Original code is [Apache-2.0](LICENSE-APACHE). Dependencies and adapted upstream
code retain their licences; see [third-party notices](THIRD_PARTY_NOTICES.md).

[Security policy](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md)
