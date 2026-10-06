# Releasing

Releases contain native Linux x86-64 and ARM64 binaries. Tag pushes stage
a **draft**; a maintainer reviews it and publishes it manually. Manual
workflow runs only build and test. Neither workflow deploys a service.

## Prepare a version

1. Update `Cargo.toml` and `Cargo.lock` together. Use a version such as
   `0.1.0` or `0.1.0-rc.1`.
2. Regenerate the dependency inventory with `bash scripts/gen-notices.sh`.
   Review licence changes and any copied upstream code.
3. Run `bash scripts/check.sh` and test a package as described below.
4. Commit the change to `main`, push it, and wait for the `verify` check.
5. Once ready to create a release, tag that commit with `v<version>`
   and push that tag. A signed tag is preferable if you have a signing key.

Tag creation and pushing are maintainer actions, not part of local testing.

## What runs

The [release workflow](../.github/workflows/release.yml) has three stages:

1. **Validate:** pin the event commit, check that a tag matches the package
   version and belongs to `main` history, and lint the workflow files.
2. **Build:** on Ubuntu 24.04 x86-64 and ARM64, run the same checks as CI,
   build the server and test client, package them, inspect the archive, and
   run the extracted server with fresh state and real relayed traffic.
3. **Publish:** download the two named artifacts from this run, check their
   source/version/target metadata and checksums, collect a single
   `SHA256SUMS`, and upload the archives and manifest to a draft release.

Both builds must pass. Only the publisher has `contents: write`.
CI cancels obsolete runs for the same PR or ref. Releases use a separate
per-ref concurrency group and do not cancel an active publisher.

The ARM64 job uses the `ubuntu-24.04-arm` runner. Do not substitute the
production server as a build runner.

## Package contents and support

Each archive contains the executable, configuration and proxy examples,
the systemd unit, deployment/dashboard/operations/configuration/API guides,
the deployment diagram and security/community policies,
project and upstream licences, `DEPENDENCY_LICENSES.txt`, and `BUILD.json`.

Builds use Ubuntu 24.04 and dynamically linked GNU/Linux targets:
`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`. Ubuntu 24.04
is the intended tested baseline, not a promise of compatibility with every
distribution using glibc 2.39. The build metadata records the actual
platform, libc, target, toolchain and commit. Alpine/musl and older glibc
systems are not supported by these archives.
Local uncommitted changes are marked `dirty` in the metadata. Such archives
can be tested locally but are rejected by the release collector/publisher.

The licence bundle includes original licence/notice files from the locked
target graph, including nested vendored notices and build/test dependencies.
Extra entries are intentional. Review it when dependencies change; automated
collection is not a legal audit.

Versioned exceptions are in [dependency-overrides.json](../licenses/dependency-overrides.json).
Most recover texts from the exact upstream commit recorded in the crate.
The `enum-assoc` and `rustls-cert-utils` revisions omit licence texts entirely:
their bundles use the declared Apache/MIT branch and canonical licence text,
without inventing copyright owners. Review these attribution exceptions
before making a public release.

## Local package test

From the repository root, with Python 3.11+ installed:

```sh
cargo build --locked --release --bin relay-warden --example relayed_transfer
VERSION="$(python3 scripts/release.py metadata | sed -n 's/^version=//p')"
TARGET="$(rustc -vV | sed -n 's/host: //p')"
WARDEN_DIST="$(mktemp -d)"
bash scripts/package.sh "$VERSION" "$TARGET" target/release "$WARDEN_DIST"
bash scripts/smoke.sh "$WARDEN_DIST/relay-warden-v$VERSION-$TARGET.tar.gz" \
  target/release/examples/relayed_transfer
```

Packaging requires a matching native target. A macOS drill produces a
macOS-labelled archive, not a Linux release. Only the two Linux targets
are accepted by the release collector.

The smoke test checks help/version, server startup, denied unauthenticated
admin access, authenticated status/metrics and an approved bidirectional
transfer. All listeners are loopback. It does not prove public HTTPS or
browser interaction works.

## Draft review and retries

Review the source commit, both archives, checksum manifest and run results.
Add user-visible release notes and upgrade caveats, then publish through
GitHub's release UI. Checksums detect corruption; they are not signatures.

An interrupted upload leaves a draft. Rerunning can replace assets only in
an unpublished draft bearing the same source commit. Published releases
and different-source drafts are refused; tags are never moved. If a draft
has unexpected assets, resolve that conflict manually before publishing.

Repository environments and branch protection must be configured by a
maintainer. Require the CI `verify` check and inspect the workflow results
before publishing.
