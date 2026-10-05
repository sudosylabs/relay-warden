# Contributing

## Prerequisites

Rust 1.91.0 exactly (`rust-toolchain.toml` pins it; `rustup` picks it up
automatically) and Node 22 for the admin UI syntax check.

## Verify a change

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
bash scripts/check-ui.sh
```

`cargo test` runs unit tests plus one integration binary per `src/` module
(`tests/<module>.rs`, shared harness in `tests/common/`). The relay,
limiter, and quota suites move real traffic on loopback with small
synthetic budgets — nothing leaves the machine.

## Changing the admin UI

The UI is embedded in `src/admin.rs` (`ui_handler`). Keep dynamic strings
in `textContent`, never `innerHTML`; keep every control wired to an
existing API route (add the route, handler, and a `tests/admin.rs` case
together). Run `scripts/check-ui.sh` and extend
`admin_page_serves_working_management_ui` with markers for new controls.

## Changing the database

Bump `SCHEMA_GENERATION` in `src/store.rs`, keep migrations additive and
idempotent, and extend `tests/store.rs` (including the newer-generation
refusal test). All SQLite work must stay inside the blocking-pool helper —
never add `.await` holding the connection, and never touch SQLite from
packet-processing paths.

## Releases and licensing

Original contributions are Apache-2.0 (Sudosy Labs contributors). Keep
upstream `n0`/Tailscale notices intact, regenerate `THIRD_PARTY_NOTICES.md`
after dependency changes (`scripts/gen-notices.sh`), and follow
`docs/RELEASING.md` for tags and archives.
