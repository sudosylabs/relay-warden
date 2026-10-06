# Contributing

Contributions are welcome, including bug reports, documentation improvements,
tests and code changes. You do not need to run a public relay to contribute.

Please follow our [code of conduct](CODE_OF_CONDUCT.md). To report a
vulnerability, use the [security policy](SECURITY.md), not a public issue.

## Reporting bugs

Search existing issues first. If the problem has not been reported, open an
issue with:

- The Relay Warden version or commit, operating system and CPU architecture.
- Steps to reproduce the problem, what you expected and what happened.
- Relevant logs and a minimal configuration, with secrets and identifying
  information removed.

Do not include admin tokens, private keys, databases or other people's
endpoint details. A small local reproduction is preferable to access to a
live server.

## Proposing changes

For a substantial feature, dependency change or change to access control,
accounting or the database format, open an issue before implementing it.
Explain the problem and the proposed behavior so maintainers can discuss
scope and compatibility. Small fixes and documentation corrections can go
straight to a pull request.

## Development setup

Fork the repository and clone your fork, then create a branch from `main`.
From the repository root, install:

- Rust through rustup; `rust-toolchain.toml` selects Rust 1.91.0.
- Native C/C++ build tools and CMake for the dependencies.
- Python 3.11 or newer.
- Node.js 22 for the embedded admin JavaScript check.

Build the server and example client:

```sh
cargo build --locked --bin relay-warden --example relayed_transfer
```

For a local trial, start the server with fresh state:

```sh
WARDEN_BIN="$PWD/target/debug/relay-warden"
WARDEN_DIR="$(mktemp -d)"
mkdir -m 700 "$WARDEN_DIR/state"
(umask 077; head -c 32 /dev/urandom | base64 > "$WARDEN_DIR/state/admin.token")
cp deploy/config.local.example.toml "$WARDEN_DIR/warden.toml"
printf 'Trial directory: %s\n' "$WARDEN_DIR"
(cd "$WARDEN_DIR" && "$WARDEN_BIN" --config warden.toml)
```

Leave that terminal running. Open `http://127.0.0.1:8081/admin/` and sign in
with the trial directory's `state/admin.token`. In another terminal at the
repository root, run:

```sh
./target/debug/examples/relayed_transfer --relay http://127.0.0.1:8080
```

Expect `relayed transfer OK`. This trial uses public access, a 100 MB budget,
and 1 MB/s limits. Stop it with Ctrl-C. No production server or cloud
credentials are needed; [the dashboard guide](docs/USAGE.md) explains the UI.

## Tests and checks

```bash
bash scripts/check.sh
```

This runs formatting, Clippy, Rust tests, JavaScript syntax checking,
Python delivery tests, documentation/configuration checks and the dependency
inventory freshness check. To run a focused Rust suite, use, for example,
`cargo test --locked --test quota`.

Relay integration tests open loopback listeners and use synthetic budgets.
Dependency resolution may need network access; the relay tests do not need
a public relay. If your sandbox blocks local listeners, report that limitation
instead of treating the tests as passed.

When editing workflows, also run actionlint 1.7.7. CI installs it with
`go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.7`; it requires
a compatible Go installation. CI runs the same local checks and workflow lint.

## Pull requests

- Keep the change focused; avoid unrelated cleanup or generated artifacts.
- Describe the problem, the solution and any compatibility impact. Link the
  issue if there is one.
- Add regression tests for fixes and behavioral tests for new functionality.
- Update documentation and examples when behavior or configuration changes.
- List the checks you ran, their results and any checks you could not run.

Open the pull request against `main`. Use a draft if the work is not ready
for review. Maintainers may request revisions before merging; passing CI
does not replace review. There is no requirement to deploy your change or
publish a release as part of a contribution.

## Code conventions

Follow the surrounding Rust style, use rustfmt, and keep Clippy clean.
Prefer clear names and small changes over speculative abstractions. Preserve
fail-closed behavior for approval and quota enforcement; test both successful
and denied paths. See [architecture](docs/ARCHITECTURE.md) for module boundaries.

The UI assets live in `web/` and are served by `src/admin.rs`. Keep dynamic strings
in `textContent`, never `innerHTML`; keep every control wired to an
existing API route (add the route, handler, and a `tests/admin.rs` case
together). Run `scripts/check-ui.sh` and exercise the control in a browser.
The existing HTML marker test and HTTP API tests do not verify browser
interaction. Add behavioral assertions when extending UI test coverage;
a string appearing in the page is not proof that its control works.

Bump `SCHEMA_GENERATION` in `src/store.rs`, keep migrations additive and
idempotent, and extend `tests/store.rs` (including the newer-generation
refusal test). All SQLite work must stay inside the blocking-pool helper —
never add `.await` holding the connection, and never touch SQLite from
packet-processing paths.

## Dependencies and licensing

By submitting a contribution, you agree that it may be distributed under
the project's [Apache-2.0 licence](LICENSE-APACHE). Only contribute code you
have the right to share. Identify copied or adapted code and retain its
licence and attribution; do not relabel upstream code as original work.

Keep dependency changes deliberate and update `Cargo.lock`. Regenerate
`THIRD_PARTY_NOTICES.md` with `bash scripts/gen-notices.sh`, review the diff
and check the [attribution requirements](licenses/README.md).

Release preparation is a maintainer task described in
[Releasing](docs/RELEASING.md).
