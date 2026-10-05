# Configuration

All settings, their units, and where each value actually lives. Speeds are
**bytes per second** (`100_000` ≈ 100 KB/s ≈ 0.8 Mbit/s); budgets are
**bytes**, decimal (`6_000_000_000_000` = 6 TB, not 6 TiB).

## Precedence: file seeds, database wins

On startup, values from the TOML config file are written into the SQLite
database **only when the corresponding database setting is absent**
(`INSERT OR IGNORE`). Editing the file afterwards does **not** overwrite
values an administrator already set — change those with `PATCH
/admin/settings` (or the settings panel in the admin UI). To re-seed from
the file, clear the database key first or start from a fresh state
directory. `require_default_limits` / `require_quota_budget` are
startup-time guards read from the file only.

## Relay and admin listeners

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8080` | Relay `/relay` bind. Behind a proxy this stays loopback; direct exposure is an operator decision. |
| `admin_listen` | `127.0.0.1:8081` | Admin API/UI bind. Keep loopback; use an SSH tunnel (`ssh -L 8081:127.0.0.1:8081 you@host`). |
| `admin_token_file` | `admin.token` | File holding the high-entropy admin token (`chmod 600`). Missing/short file refuses startup; there is no default password. |
| `db_path` | `warden.db` | SQLite state: policies, settings, ledger, audit. Back it up; see `OPERATIONS.md`. |

## Throughput

| Key | Default | Meaning |
|---|---|---|
| `default_rx_bps` / `default_tx_bps` | unset | Ordinary-endpoint caps. Required at production startup unless `require_default_limits = false` (tests/dev). |
| `max_handshake_concurrency` | `64` | Cap on simultaneous unauthenticated handshakes. |
| `handshake_timeout_secs` | `10` | Per-handshake deadline. |
| `key_cache_capacity` | `1024` | Upstream relay key cache entries. |
| `max_connections` | `1024` | Global concurrent relay-connection ceiling; over-limit connections authenticate but are dropped without service. |
| `max_connections_per_endpoint` | `16` | Per-endpoint concurrent ceiling. TOML cannot express `null`; omission keeps the default of 16. Choose a positive finite ceiling. |

Per-endpoint records (`PUT /admin/endpoints/{id}`) carry `speed_policy`
(`default`/`custom`/`unlimited`), optional `custom_rx_bps`/`custom_tx_bps`,
`burst_bytes`, and a `revision` for lost-update protection. Omitting a
rate keeps it; explicit `null` clears it. `burst_bytes` defaults to a tenth
of the governing rate, clamped to 4 KiB–1 MiB.

## Monthly budget

| Key | Default | Meaning |
|---|---|---|
| `quota_budget_bytes` | unset | Nominal monthly allowance. Required at production startup unless `require_quota_budget = false`. Must exceed `quota_headroom_bytes`, or the effective cutoff is zero and the relay admits nothing (fail-closed; visible as `effective_cutoff_bytes: 0`). |
| `quota_headroom_bytes` | `1_000_000_000` | Safety margin: enforcement stops at `budget − headroom`. |
| `quota_overhead_pct` | `10` | Allowance added to every payload for framing/TLS (0–100). |
| `quota_chunk_bytes` | `32768` | Ledger commit granularity (1024–1048576). |
| `alert_webhook_url` | unset | `http(s)` URL receiving `warning_75`/`warning_90`/`exhausted` POSTs. Unset = disabled (flags still persist). |

Charged bytes (payload + overhead) are committed before sending; only
lease remainders proven unspent on clean close are handed back. See
`ARCHITECTURE.md` for the accounting model and `OPERATIONS.md` for
exhaustion response.

## What persists in SQLite

`endpoints` (policy + revision), `settings` (including `settings_version`),
`quota_periods` (one ledger row per UTC month: charged bytes, exhaustion,
warning flags), `audit` (append-only admin actions, no secrets).
Connection state, limiter balances beyond the ledger, and sessions are
in-memory only. Restoring an old database reverts usage and approvals —
never restore over a live ledger; see `OPERATIONS.md` rollback.
