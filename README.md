# Relay Warden

Relay Warden is a self-hosted Iroh relay with device approval, bandwidth
limits, and a shared monthly traffic budget. Manage endpoint access through
a private administration interface, exempt trusted devices from speed
limits, and keep relay usage within a configured allowance.

It works with compatible Iroh applications: apps that cannot reach each
other directly relay their encrypted traffic through this server until a
direct connection succeeds. It is not a general-purpose proxy or VPN, and
it cannot see or shape arbitrary network traffic.

> Status: pre-release. The code, tests, and deployment artifacts are
> implemented and locally verified (see `docs/ACCEPTANCE.md`), but no
> public release or hosted verification exists yet. Relay accounting tracks
> relayed bytes plus a configured overhead allowance — it is **not** exact
> cloud billing. Direct peer-to-peer traffic never touches this server and
> is outside the budget.

## Install

No published binaries exist yet; building from source is the only install
path today. Release archives (`relay-warden-v<version>-<target>.tar.gz`
plus `SHA256SUMS`) are planned — see `docs/RELEASING.md` for the pipeline.

Requires Rust 1.91.0 (pinned by `rust-toolchain.toml`):

```bash
cargo build --locked --release
./target/release/relay-warden --version
```

## First run

All paths below are yours to choose. This example uses a temporary
directory so nothing touches an existing setup:

```bash
mkdir -p /tmp/warden/state
head -c 32 /dev/urandom | base64 > /tmp/warden/state/admin.token
chmod 600 /tmp/warden/state/admin.token
cp deploy/config.production.example.toml /tmp/warden/warden.toml
# edit db_path and admin_token_file in warden.toml to point at /tmp/warden/state,
# and set ordinary speed limits plus the monthly budget (see docs/CONFIGURATION.md)
./target/release/relay-warden --config /tmp/warden/warden.toml
```

The relay listens on `127.0.0.1:8080` and the admin interface on
`127.0.0.1:8081`, both loopback-only. From another machine, reach the admin
interface through an SSH tunnel — never expose it directly:

```bash
ssh -L 8081:127.0.0.1:8081 you@your-server
# then open http://127.0.0.1:8081/admin/ locally
```

## Approve the first endpoint

Every Iroh app instance has an **endpoint ID**: the public key of that app
instance. It identifies the installation, not the hardware — reinstalling or
resetting keys creates a new ID. Public IDs are safe to submit for approval;
private keys are never needed and must never be shared.

An Iroh application prints or logs its endpoint ID on startup (see
[Connect an application](#connect-an-application)). Approve it in the admin
UI (`Add endpoint`, then tick approved and Save), or with the API:

```bash
TOKEN="$(cat /tmp/warden/state/admin.token)"
curl -X PUT http://127.0.0.1:8081/admin/endpoints/<ENDPOINT_ID> \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"label": "my laptop", "approved": true}'
```

The full API (revisions, revocation, settings, audit, usage, metrics) is
documented in `docs/API.md`; the UI covers the same actions.

## Connect an application

Point a compatible Iroh application at your relay URL instead of (or in
addition to) the default relays. With `iroh` this is a `RelayMap` holding
a `RelayConfig` for `https://relay.example.com`; see the tested example:

```bash
cargo run --example relayed_transfer -- --relay https://relay.example.com \
  --admin http://127.0.0.1:8081 --admin-token "$(cat admin.token)"
```

which generates two identities, approves them, and relays one message each
way, printing `relayed transfer OK`. Without approval the relay denies the
connection (`tests/relay.rs` pins this behaviour).

## Limits and budget

Each approved endpoint has a speed policy:

- `default`: the operator's `default_rx_bps` / `default_tx_bps`.
- `custom`: per-endpoint `custom_rx_bps` / `custom_tx_bps` overrides.
- `unlimited`: no speed cap (typically the operator's own devices).

`rx` caps upload *to* the relay, `tx` caps download *from* it; both are in
**bytes per second** (e.g. `100_000` ≈ 100 KB/s ≈ 0.8 Mbit/s). All
connections of one endpoint share its allowance.

Unlimited endpoints still draw from the shared monthly budget, and budget
exhaustion disconnects **everyone**, including unlimited endpoints. The
budget counts relayed bytes plus a configured overhead percentage, and
enforcement stops early at `budget − headroom`. The example 6 TB budget in
`deploy/config.production.example.toml` means 6,000,000,000,000 bytes
(decimal TB, not 6 TiB ≈ 6,597,069,766,656 bytes).

## HTTPS and running the service

Terminate TLS at a reverse proxy and forward only `/relay*` to the
loopback backend, preserving WebSocket upgrades, the subprotocol header,
and the client-auth header. Worked snippets live in
`deploy/caddy.example` and `deploy/nginx.example`. Keep `/admin` and
`/metrics` off the public routing. Run under systemd with
`deploy/relay-warden.service`; backup, upgrade, monitoring and recovery
are covered in `docs/OPERATIONS.md`.

## Build, contribute, licence

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
bash scripts/check-ui.sh
```

See `CONTRIBUTING.md` for the workflow and `docs/ARCHITECTURE.md` for how
the pieces fit. Original code is Apache-2.0 © Sudosy Labs contributors
(`LICENSE-APACHE`); linked and adapted third-party code keeps its own
notices — see `THIRD_PARTY_NOTICES.md` and `licenses/upstream/`.

Further reading: `docs/CONFIGURATION.md` (every setting, units, what
persists), `docs/API.md`, `docs/OPERATIONS.md`, `docs/RELEASING.md`.
