# Testing and verification

This page is for contributors. To deploy a relay, use [the installation
guide](INSTALL.md); to manage one, use [the dashboard guide](USAGE.md).

## Run the checks

From the repository root:

```sh
bash scripts/check.sh
```

This checks formatting, Clippy, Rust behavior, UI syntax and navigation,
release tooling, documentation links, configuration examples, and licence
inventory. Relay tests use local listeners and synthetic budgets.

## What the tests cover

| Area | Tests |
|---|---|
| Protocol and relayed transfers | `tests/relay.rs` |
| Public, token, approval, and combined modes | `tests/admission.rs` |
| Saved policy, revisions, and admission limits | `tests/policy.rs`, `tests/access.rs` |
| Admin authentication, sessions, revocation, and pagination | `tests/admin.rs` |
| Endpoint speeds and live limit changes | `tests/limiter.rs` |
| IP/subnet/global safeguards and slow transfers | `tests/network.rs` |
| Durable budget, month rollover, refunds, and cutoff | `tests/quota.rs` |
| Configuration validation and state persistence | `tests/config.rs`, `tests/store.rs` |
| Reloadable routes, searches, and page numbers | `scripts/tests/navigation.test.mjs` |
| Archive integrity, draft publication rules, and licence collection | `scripts/tests/` |

In particular, slow-transfer tests verify exact payloads and continued
connectivity under endpoint, IP, subnet, and global shaping. Revocation is
also tested while a send is waiting on a long throttle delay. Socket-deadline
unit tests check that real transport stalls remain bounded.

Budget tests check that a frame cannot be sent without enough reserved
allowance, concurrent grants cannot exceed the cutoff, and restarting or
moving the clock backwards cannot resurrect spent usage.

## What a local pass does not prove

Local tests do not measure throughput, connection latency, production storage
performance, or maximum safe concurrency. They also do not prove your DNS,
certificate, cloud firewall, proxy, or chosen SDK versions work together.

After deployment, perform the public HTTPS and relayed-transfer checks in
[installation steps 5–7](INSTALL.md#5-give-it-https). Exercise the dashboard
in a browser; API tests and JavaScript syntax checks alone are not UI tests.

Native release jobs run the same checks and smoke-test the extracted package.
Use their actual results for platform support, rather than inferring Linux
behavior from a macOS build. See [Releasing](RELEASING.md) for that workflow.
