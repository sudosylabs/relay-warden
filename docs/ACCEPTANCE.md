# Acceptance mapping (Gate E)

Every handoff requirement mapped to a test or a stated
deployment-dependent check. Deployment itself is a separate authorized phase.

## Gate A — unmodified dependency

| Requirement | Evidence |
|---|---|
| Pin toolchain + dependency, no upstream edits | `rust-toolchain.toml` (1.91.0), `Cargo.lock` (`iroh-relay` 1.3.0); only public APIs (`KeyCache`, `ExportKeyingMaterial`, `server::{AccessControl, ClientRequest, clients::Clients, client::Config, streams::RelayedStream}`, `protos::{handshake, streams::BytesStreamSink}`) |
| Two-client relayed transfer | `tests/gate_a_relay.rs::gate_a_two_clients_relay` |
| Unauthorized rejection | `tests/gate_a_relay.rs::gate_a_unknown_denied` (`ServerDeniedAuth`) |
| Protocol negotiation (V2 preferred, V1 supported, others 400) | `src/relay.rs` unit tests; integration clients negotiate V2 |

## Gate B — policy and live administration

| Requirement | Evidence |
|---|---|
| Persistent policy across restart | `gate_b_persists_across_restart` |
| Unauthorized admin actions fail | `gate_b_unauthorized_fails` (401s) + session/CSRF/Origin test |
| Revoke closes live, denies reconnect, peers unaffected | `gate_b_revoke_closes_live_and_denies_reconnect` |
| Admission/revocation race closed | publish-then-disconnect + register-then-revalidate; `gate_b_admission_cache_and_live_counts` |
| Lost-update protection, validation, escaped labels, audit without secrets | `gate_b_upsert_validation_and_lost_update`, `gate_b_session_csrf_and_settings_version` |

## Gate C — throughput enforcement

| Requirement | Evidence |
|---|---|
| Aggregate per-endpoint caps, both directions | `gate_c_caps_sustained_rate`, `gate_c_connections_share_allowance`, `gate_c_directions_are_independent` |
| Owner unlimited, approval/quota intact | `gate_c_unlimited_fast_but_still_governed` (incl. revoke disconnect) |
| Live transitions without reconnect/re burst mint | `gate_c_live_update_reshapes_transfer`, unit `limiter_toggle_cannot_mint_burst` |
| Reconnect resistance, ordering, no double-charge | `gate_c_reconnect_keeps_balances`, seq-order asserts, exact counter asserts, debt-bucket unit tests |
| Production default-limit gate | `require_default_limits` startup bail (deployment check: confirm values) |

## Gate D — durable monthly enforcement

| Requirement | Evidence |
|---|---|
| Exact budget boundary, concurrent grants | `quota_concurrent_grants_cannot_exceed_cutoff` (200_000 exact) |
| Exhaustion closes all incl. owners, admin usable | `quota_exhaustion_closes_all_including_owner` |
| Both traffic classes charged | `quota_owner_and_ordinary_both_charged` |
| Crash/restart preserves ledger | `quota_crash_preserves_ledger` (exact equality + continuation) |
| Forward-only months, backward-clock isolation | `quota_month_rollover_and_backward_clock` |
| Budget-cut exhaustion, edit isolation, audited reopen | `quota_budget_cut_exhausts_but_edits_do_not_reset` |
| No exact cloud-billing claim | `DESIGN.md` units section; `usage.uncertainty_note` |

## Gate E — operations and delivery

| Requirement | Evidence |
|---|---|
| Low-cardinality metrics, private, no leakage | `gate_e_metrics_private_bounded_and_counter_semantics` |
| Alert dedup once/period, persisted, failure-safe | `gate_e_alerts_fire_once_per_period_and_survive_restart` |
| Connection ceilings, body limits, schema guard | `gate_e_per_endpoint_cap_denies_with_balance`, `gate_e_global_ceiling_rejects_over_limit`, `gate_e_admin_body_limit_and_schema_guard` |
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

## Unresolved production choices (operator must confirm pre-deploy)

- Production speed values (ordinary defaults, per-endpoint customs).
- Accounting period (UTC calendar months assumed) and headroom/overhead margins.
- Admin access method beyond SSH tunnel (hostname + auth if remote without SSH).
- Alert destination (webhook URL) and 75/90% threshold suitability.
- Whether protocol V1 clients must be supported in the field.
- Future aggregate shaper (would also constrain owners; currently none).
- VPS re-inspection at deploy time (addresses, listeners, firewall, free-tier terms, DNS).
