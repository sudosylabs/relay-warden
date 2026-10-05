# Releasing

How a maintainer prepares, tags, verifies, and publishes a release. No
release is published, and no tag created, without explicit authorization;
the workflow below stages everything as a draft first.

## Versioning

SemVer, one package version in `Cargo.toml`. Tag form is `v<version>`
(e.g. `v0.1.0`); prerelease tags (`-rc.1`, …) publish as GitHub
prereleases. The release workflow refuses tags that do not match
`Cargo.toml`.

## Prepare

1. Bump `version` in `Cargo.toml` (and `Cargo.lock`), regenerate
   `THIRD_PARTY_NOTICES.md` (`scripts/gen-notices.sh`), review the diff.
2. Update release notes with user-visible changes and migration caveats.
3. Commit, push to the default branch, wait for CI green.
4. Tag the release commit: `git tag -s v0.1.0` (or annotated without `-s`
   if the maintainer has no signing key configured).

## What the release workflow does

On `v*` tags (plus a manual build-only dry run):

1. Validates the tag and checks it out exactly, recording its SHA.
2. Re-runs the full verification (fmt, clippy, tests, UI check) at that SHA.
3. Builds natively per target: `x86_64-unknown-linux-gnu` and
   `aarch64-unknown-linux-gnu`, with the locked toolchain and `--locked`
   dependencies.
4. Packages each target with `scripts/package.sh` (binary, config/systemd/
   proxy examples, `INSTALL.md`, licences, reviewed notices, `BUILD.txt`),
   checksums `SHA256SUMS`, and verifies archive contents after extraction.
5. Smoke-tests each extracted archive: `--help`/`--version`, boot from a
   fresh temp config, denied unauthenticated admin, authenticated
   health/status, and a real approved relayed transfer.
6. A single publisher job (the only `contents: write` holder) stages a
   **draft** release with exactly those assets. It goes public only after a
   maintainer checks the draft.

Reruns resume the same unpublished draft or fail with a conflict; published
releases and assets are never overwritten, and tags are never moved.
Interrupted runs leave no advertised partial release. See
`.github/workflows/release.yml`.

## Baselines

Release runners are current Ubuntu images (glibc 2.39+ on 24.04; the exact
baseline is recorded in each run's `BUILD.txt` environment notes). The
binaries are dynamically linked against the runner glibc and target the
same major distributions — they are not static/musl builds and are not
claimed to run on older or musl-based systems.

## Dry run locally

`scripts/package.sh` is pure staging logic and runs anywhere; give it a
locally built binary directory and any target label for a drill (archives
from a drill are labelled as such and must never be published):

```bash
cargo build --locked --release
VERSION=0.1.0 TARGET="$(rustc -vV | sed -n 's/host: //p')"
bash scripts/package.sh "$VERSION" "$TARGET" target/release /tmp/warden-dist
bash scripts/smoke.sh /tmp/warden-dist/relay-warden-v*.tar.gz \
  target/debug/examples/relayed_transfer
```
