# Relay Warden

A self-hosted [Iroh](https://iroh.computer) relay that lets you decide who
can connect and how much traffic they can use.

Approve endpoints in a private web interface, give each one a speed limit,
and set a shared monthly budget. Your own endpoints can be exempt from
speed limits, but they still count towards the budget. When the budget is
exhausted, all relay connections close; administration remains available.

Relay Warden is for applications built with Iroh. It is not a VPN or a
general-purpose proxy. Direct peer-to-peer traffic does not pass through
the relay and is not counted. The traffic ledger includes an overhead
allowance, but it is **not a measurement of your cloud provider's bill**.

This project is pre-release. Linux x86-64 and ARM64 archives are configured
in the release workflow, but no published binaries or hosted validation are
available yet.

## Try it locally

Start with a source checkout of this repository and open a terminal in its
root directory. You need Rust (the repository pins 1.91.0), Python 3.11+
and the native C build tools required by the dependencies. Node 22 is only
needed for development checks.

Build the server and example client:

```sh
cargo build --locked --bin relay-warden --example relayed_transfer
```

Create a fresh trial directory. This example uses a 100 MB budget and
1 MB/s upload/download limits; it does not change an existing installation.

```sh
WARDEN_BIN="$PWD/target/debug/relay-warden"
WARDEN_DIR="$(mktemp -d)"
mkdir -m 700 "$WARDEN_DIR/state"
(umask 077; head -c 32 /dev/urandom | base64 > "$WARDEN_DIR/state/admin.token")
cp deploy/config.local.example.toml "$WARDEN_DIR/warden.toml"
printf 'Trial directory: %s\n' "$WARDEN_DIR"
(cd "$WARDEN_DIR" && "$WARDEN_BIN" --config warden.toml)
```

Leave that terminal running. Open
[http://127.0.0.1:8081/admin/](http://127.0.0.1:8081/admin/) and log in
with the token from the trial directory's `state/admin.token` file.
Treat the token like a password; anyone with it can administer the relay.

### Approve two endpoints and send a message

In a second terminal, from the repository root:

```sh
./target/debug/examples/relayed_transfer --relay http://127.0.0.1:8080
```

The example prints two endpoint IDs and waits. In the admin interface,
add each ID, enable its **approved** checkbox and save. Return to the
terminal and press Enter. You should see two received messages followed
by `relayed transfer OK`.

An endpoint ID is an application's public key, not a hardware identifier.
Applications must retain their private key to keep the same identity;
resetting it requires a new approval. Never submit a private key to the
relay administrator. This example intentionally creates disposable keys
each time it runs.

Stop the server with Ctrl-C when finished. Keep the trial directory if
you want to retain its policies and usage; otherwise it is just test state.

## Use it on a server

For a long-running installation, build with `cargo build --locked --release`
and follow the [installation guide](docs/INSTALL.md). It covers the service
account, state directory and systemd unit. Future release archives will
include the executable, the same guide, configuration examples, licence
texts and checksums.

Serve the public relay over HTTPS using the included
[Caddy](deploy/caddy.example) or [Nginx](deploy/nginx.example) example.
Keep the admin listener private. To administer a remote server:

```sh
ssh -N -L 8081:127.0.0.1:8081 you@your-server
```

Then open the same local admin URL. Stop your local trial first if it is
already using port 8081.

Your application must be configured to use your relay URL, for example
`https://relay.example.com`. This is an application-side setting:
Relay Warden cannot redirect existing apps automatically. The included
[transfer example](examples/relayed_transfer.rs) tests the relay protocol;
it is not a complete Iroh application or an SDK integration guide.

## Configure access and traffic

Each endpoint can use the default speed, a custom speed, or no speed cap.
Rates are **bytes per second**, not bits per second: `100_000` is about
100 KB/s or 0.8 Mbit/s. Upload and download limits are separate, and
multiple connections from the same endpoint share the same limits.

The monthly budget is shared across all approved endpoints, including
unlimited ones. It resets by UTC calendar month. The relay stops at
`budget − headroom`; for example, 6 TB means 6,000,000,000,000 bytes,
not 6 TiB. Other services on the same server need separate traffic
monitoring.

Configuration values seed a new database. Later admin changes persist:
editing the TOML file does not overwrite those saved settings.

- [Configuration](docs/CONFIGURATION.md): settings, units and persistence.
- [Operations](docs/OPERATIONS.md): HTTPS, monitoring, backups and upgrades.
- [Admin API](docs/API.md): authentication and scripted management.
- [Architecture](docs/ARCHITECTURE.md): relay integration and accounting.
- [Contributing](CONTRIBUTING.md): local checks and development.
- [Security policy](SECURITY.md): vulnerability reporting and supported versions.
- [Code of conduct](CODE_OF_CONDUCT.md): community expectations and reporting.
- [Releasing](docs/RELEASING.md): native builds, archives and draft releases.

## Licence

Original Relay Warden code is [Apache-2.0](LICENSE-APACHE).
Dependencies and adapted upstream code retain their own licences and
notices; see [third-party notices](THIRD_PARTY_NOTICES.md). Release archives
also include dependency licence texts and documented
[attribution exceptions](licenses/README.md).
