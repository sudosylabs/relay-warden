# Install on Linux

These instructions use systemd on Ubuntu 24.04. Keep the relay backend and
admin interface on loopback; expose only the relay through an HTTPS proxy.

## Obtain the executable

Before the first public release, build from a source checkout:

```sh
cargo build --locked --release
```

The executable is `target/release/relay-warden`. Examples are in `deploy/`.
Release archives will instead contain the executable and examples at the
archive root, with documentation under `docs/`. Download the archive for
your CPU and the accompanying `SHA256SUMS`; verify its entry before
extracting it. For example, after an x86-64 `v0.1.0` release exists:

```sh
grep '  relay-warden-v0.1.0-x86_64-unknown-linux-gnu.tar.gz$' SHA256SUMS | sha256sum -c -
tar -xzf relay-warden-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
cd relay-warden-v0.1.0-x86_64-unknown-linux-gnu
```

Checksums detect corruption, not who published the files. Get the archive
and checksum file from the same trusted release page.

## Install the service

From an extracted archive, run the commands below. From a source checkout,
first set `WARDEN_BINARY=target/release/relay-warden`,
`WARDEN_EXAMPLES=deploy`, and
`WARDEN_CONFIG=deploy/config.production.example.toml`.

```sh
WARDEN_BINARY="${WARDEN_BINARY:-./relay-warden}"
WARDEN_EXAMPLES="${WARDEN_EXAMPLES:-.}"
WARDEN_CONFIG="${WARDEN_CONFIG:-warden.example.toml}"
sudo useradd --system --user-group --shell /usr/sbin/nologin relay-warden
sudo install -d -m 755 /opt/relay-warden /etc/relay-warden
sudo install -d -o relay-warden -g relay-warden -m 750 /var/lib/relay-warden
sudo install -m 755 "$WARDEN_BINARY" /opt/relay-warden/relay-warden
```

Generate the secret only for a fresh installation. Do not overwrite an
existing token or configuration when upgrading:

```sh
sudo sh -c 'umask 077; head -c 32 /dev/urandom | base64 > /var/lib/relay-warden/admin.token'
sudo chown relay-warden:relay-warden /var/lib/relay-warden/admin.token
```

Install the example configuration and edit it:

```sh
sudo install -m 640 "$WARDEN_CONFIG" /etc/relay-warden/warden.toml
sudo chown root:relay-warden /etc/relay-warden/warden.toml
sudoedit /etc/relay-warden/warden.toml
```

Choose your default upload/download rates, monthly budget, headroom and
overhead allowance. The shipped values are examples, not your provider's
quota. See [configuration](CONFIGURATION.md). Then:

```sh
sudo install -m 644 "$WARDEN_EXAMPLES/relay-warden.service" /etc/systemd/system/relay-warden.service
sudo systemctl daemon-reload
sudo systemctl enable --now relay-warden
curl --fail http://127.0.0.1:8080/healthz
```

If startup fails, inspect `sudo journalctl -u relay-warden -n 50`.
Do not disable quota/approval protections to work around a startup error.

## Administer and expose the relay

From your own computer:

```sh
ssh -N -L 8081:127.0.0.1:8081 you@your-server
```

Open `http://127.0.0.1:8081/admin/`. Retrieve the token privately from the
server's `/var/lib/relay-warden/admin.token`, log in, and approve the public
endpoint IDs from your application. Never provide its private keys.

Configure DNS and HTTPS for the public relay, using the shipped
`caddy.example` or `nginx.example` as a starting point. In a source checkout
these are under `deploy/`. Preserve WebSocket upgrades and relay headers;
do not route the admin listener through the public proxy. Configure your
Iroh application to use the public relay URL, then test a relayed transfer.

See [operations](OPERATIONS.md) before backing up or replacing a live service.
