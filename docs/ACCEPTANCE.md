# Acceptance mapping (Gate E)

Every handoff requirement mapped to a test or a stated
deployment-dependent check. Deployment itself is a separate authorized phase.

## Gate A — unmodified dependency

| Requirement | Evidence |
|---|---|
| Pin toolchain + dependency, no upstream edits | `rust-toolchain.toml` (1.91.0), `Cargo.lock` (`iroh-relay` 1.3.0); only public APIs (`KeyCache`, `ExportKeyingMaterial`, `server::{AccessControl, ClientRequest, clients::Clients, client::Config, streams::RelayedStream}`, `protos::{handshake, streams::BytesStreamSink}`) |
| Two-client relayed transfer | `tests/relay.rs::relay_transfers_both_directions` |
| Unauthorized rejection | `tests/relay.rs::relay_denies_unapproved_identity` (`ServerDeniedAuth`) |
| Protocol negotiation (V2 preferred, V1 supported, others 400) | `src/relay.rs` unit tests; integration clients negotiate V2 |

## Gate B — policy and live administration

| Requirement | Evidence |
|---|---|
| Persistent policy across restart | `tests/policy.rs::policy_persists_across_reopen` |
| Unauthorized admin actions fail | `tests/admin.rs::admin_rejects_unauthenticated_calls` + `admin_session_csrf_origin_and_settings` |
| Revoke closes live, denies reconnect, peers unaffected | `tests/admin.rs::admin_revoke_closes_live_but_spares_peers` |
| Admission/revocation race closed | publish-then-disconnect + register-then-revalidate; `tests/policy.rs::policy_admission_cache_and_live_counts` |
| Lost-update protection, validation, escaped labels, audit without secrets | `tests/admin.rs::admin_upsert_validates_and_conflicts`, `tests/policy.rs::policy_validates_records_and_revisions` |

## Gate C — throughput enforcement

| Requirement | Evidence |
|---|---|
| Aggregate per-endpoint caps, both directions | `tests/limiter.rs::limiter_caps_sustained_rate`, `limiter_connections_share_allowance`, `limiter_directions_are_independent` |
| Owner unlimited, approval/quota intact | `tests/limiter.rs::limiter_unlimited_fast_but_still_governed` (incl. revoke disconnect) |
| Live transitions without reconnect/re burst mint | `tests/limiter.rs::limiter_live_update_reshapes_transfer`, unit `limiter_toggle_cannot_mint_burst` |
| Reconnect resistance, ordering, no double-charge | `tests/limiter.rs::limiter_reconnect_keeps_balances`, seq-order asserts, exact counter asserts, debt-bucket unit tests |
| Production default-limit gate | `require_default_limits` startup bail (deployment check: confirm values) |

## Gate D — durable monthly enforcement

| Requirement | Evidence |
|---|---|
| Exact budget boundary, concurrent grants | `tests/quota.rs::quota_concurrent_grants_cannot_exceed_cutoff` (200_000 exact) |
| Exhaustion closes all incl. owners, admin usable | `tests/quota.rs::quota_exhaustion_closes_all_including_owner` |
| Both traffic classes charged | `tests/quota.rs::quota_owner_and_ordinary_both_charged` |
| Crash/restart preserves ledger | `tests/quota.rs::quota_crash_preserves_ledger` (exact equality + continuation) |
| Forward-only months, backward-clock isolation | `tests/quota.rs::quota_month_rollover_and_backward_clock` |
| Budget-cut exhaustion, edit isolation, audited reopen | `tests/quota.rs::quota_budget_cut_exhausts_but_edits_do_not_reset` |
| No exact cloud-billing claim | `ARCHITECTURE.md` units section; `usage.uncertainty_note` |

## Gate E — operations and delivery

| Requirement | Evidence |
|---|---|
| Low-cardinality metrics, private, no leakage | `tests/admin.rs::admin_metrics_are_bounded` |
| Alert dedup once/period, persisted, failure-safe | `tests/quota.rs::quota_alerts_fire_once_per_period` |
| Connection ceilings, body limits, schema guard | `tests/policy.rs::policy_per_endpoint_cap_denies_with_balance`, `tests/relay.rs::relay_global_ceiling_drops_over_limit_without_service`, `tests/admin.rs::admin_rejects_oversize_bodies` + `tests/store.rs::store_stamps_generation_and_refuses_newer` |
| Scraper outage independence | Structural (no metrics dependency in grant path); all Gate D tests pass without scraping |
| ARM64 build | Attempted `cargo check --target aarch64-unknown-linux-gnu` (rust-std installed; `zig cc` + `cmake` installed locally): blocked in third-party `aws-lc-sys` 0.45.0 asm (`-Wa,--noexecstack` rejected by zig cc) — a cross-C-toolchain limitation of this Mac host, not our code (zero `cfg(target_*)`; all deps publish aarch64-Linux support). Mitigation: build natively on the ARM64 host/CI at deploy time (see `OPERATIONS.md` release pinning). Our code introduces no target-specific paths. |
| Release build | `rustup run 1.91.0 cargo build --release` on aarch64-apple-darwin: success in 5m49s. Smoke-tested the artifact with a temp config (6 TB budget): `/` → `relay-warden`, `/ping` → 200, `/admin/status` → 401 unauth / 200 authed with live quota ledger (period `2026-10`, cutoff = budget − 1 GB headroom). |
| Reverse-proxy compatibility | Negotiation/header preservation documented in `OPERATIONS.md` + `deploy/` snippets; live edge verification is a **deployment check** (loopback tests cannot prove a specific proxy) |
| Deploy/rollback artifacts, no execution | `deploy/`, `OPERATIONS.md`; nothing executed against any host |

## Proven upstream limitations (v1.3.0, verified in source)

1. `AccessControl` decides admission only, not per-packet bandwidth.
2. Stock `RelayService::set_client_rate_limit` is uniform → custom adapter.
3. `accept_conn_limit`/`accept_conn_burst` explicitly unimplemented → enforced at our edge instead (never reported as protection).
4. Connection `Config` rate-limit notify is internal → own counters; stock client-visible status not reproduced.
5. Axum path negotiates V1+V2 honestly; integration traffic uses V2 (client default). V1 client interop is a **deployment check** with the intended client versions.

## Review hardening (independent review, all addressed)

| Finding | Fix | Test |
|---|---|---|
| Frames spent unreserved bytes (12 KiB vs 1 KiB budget) | Full frame charge reserved before send; leases never overdraw | `tests/quota.rs::quota_large_frame_fully_reserved_before_send`, `quota_oversize_frame_cannot_spend_beyond_budget` |
| Old-month refunds reduced the new ledger | Generation-tagged refunds; stale generations dropped | `tests/quota.rs::quota_old_lease_refund_cannot_reduce_new_month` |
| Backward clock + restart reopened spent quota | Startup adopts the latest durable ledger | `tests/quota.rs::quota_restart_after_rollback_keeps_latest_ledger` |
| Concurrent edits bypassed revision protection | Single-statement CAS + cache refresh on conflict | `tests/policy.rs::policy_concurrent_edits_single_winner_per_revision` |
| Rejected settings patches partially persisted | Validate-all then one transaction | `tests/store.rs::store_rejected_patch_commits_nothing` |
| Admin page JS broken, no management controls | Rebuilt UI (node syntax-checked) with approve/revoke/edit/settings/usage/audit | `tests/admin.rs::admin_page_serves_working_management_ui` + node `--check` in CI step |
| Custom caps could not clear to unlimited | Tri-state fields (omit/null/set) | `tests/policy.rs::policy_custom_limits_clear_to_unlimited` |
| Rollback restored spent allowance | Binary-only rollback; reconciliation procedure | `docs/OPERATIONS.md` Rollback (+ `user_version` fail-closed guard) |
| Alternate ID spellings bypassed admission | Canonical hex at the domain boundary | `tests/policy.rs::policy_canonicalizes_alternate_id_spellings` |
| Settings orchestration scattered in handler | `service::App` coordinator | `tests/admin.rs` suite exercises every path through it |
| SQLite blocked runtime workers | All DB work on the blocking pool | Structural; full suite green under it |
| SIGTERM bypassed graceful shutdown | SIGTERM+SIGINT handling, ordered drain, acked ledger stop | Structural + `deploy/relay-warden.service` (`KillSignal`, `TimeoutStopSec`) |
| Incomplete shutdown order | Listeners close first, then drain, then acked persistence | Structural |
| Unsupervised listener failure | Both servers supervised; failure exits loudly for restart | Structural |
| Missing OS resource ceilings | Memory/CPU/tasks/journal ceilings in the unit | `deploy/relay-warden.service` |

## Unresolved production choices (operator must confirm pre-deploy)

- Production speed values (ordinary defaults, per-endpoint customs).
- Accounting period (UTC calendar months assumed) and headroom/overhead margins.
- Admin access method beyond SSH tunnel (hostname + auth if remote without SSH).
- Alert destination (webhook URL) and 75/90% threshold suitability.
- Whether protocol V1 clients must be supported in the field.
- Future aggregate shaper (would also constrain owners; currently none).
- VPS re-inspection at deploy time (addresses, listeners, firewall, free-tier terms, DNS).

## Verification status (docs-release track, 2026-10-05)

- Implemented: operator-first README + `CONFIGURATION`/`API`/`ARCHITECTURE`/
  `OPERATIONS`/`CONTRIBUTING`/`RELEASING` docs; Apache-2.0 licence +
  `LICENSE-APACHE`; `THIRD_PARTY_NOTICES.md` generated from `Cargo.lock`
  (382 crates, all permissive, reviewed) with vendored upstream texts;
  hardened CI (pins, concurrency, least privilege, timeouts, cache, locked
  builds); release workflow (validate/build/smoke/publish separation,
  dry-run default); `scripts/package.sh` + `scripts/smoke.sh` +
  `scripts/check-ui.sh` + `scripts/gen-notices.sh`; tested client example.
- Locally verified: `cargo fmt --check`, `cargo clippy --locked
  --all-targets -- -D warnings`, `cargo test --locked` (62 green),
  `scripts/check-ui.sh` + node syntax, YAML parses, doc-link check,
  packaging drill + checksum verification, smoke test incl. a real approved
  relayed transfer, README first-run flow against a temp state dir.
- Hosted-only (explicitly unverified): GitHub workflow runs, ARM64/x86-64
  release artifacts, draft publication, `ubuntu-24.04-arm` runner
  availability. No tag, release, remote, or deployment was created.
