# relay-warden

Private, self-hostable Iroh relay with endpoint approval, per-endpoint traffic policy, shared monthly budget, and private admin. Generic — not tied to any VPS, proxy, or domain.

Status: **Gate E** (operations and delivery). Implementation complete; deployment is a separate authorized phase.

## Quickstart (any host)

```bash
# 1. Create a high-entropy admin token (no default password):
head -c 32 /dev/urandom | base64 > admin.token && chmod 600 admin.token
# 2. Run (relay on :8080, admin on loopback :8081):
cargo run -- --config config.example.toml
```

Behind your own reverse proxy, forward `https://<your-host>/relay` to the loopback relay port. Admin stays on loopback; reach it via SSH tunnel.

## Admin

- `GET /admin/` — minimal UI shell (data loads via API).
- `POST /admin/login {"token": "..."}` — session cookie + CSRF token.
- `GET /admin/endpoints` — list with live connection counts.
- `PUT /admin/endpoints/{id}` — create/update (requires `revision` on update; 409 on conflict).
- `POST /admin/endpoints/{id}/revoke` — deny + disconnect live connections.
- `GET /admin/status`, `GET /admin/settings`, `PATCH /admin/settings` (versioned), `GET /admin/audit`, `GET /admin/usage`, `GET /admin/metrics` (Prometheus, authenticated, low-cardinality only).

Auth: `Authorization: Bearer <token>` for API clients, or session cookie + `X-CSRF-Token` header for browsers (Origin checked when present). Logins rate-limited; bodies capped at 64KiB. No secrets in logs/audit.

Auth: `Authorization: Bearer <token>` for API clients, or session cookie + `X-CSRF-Token` header for browsers (Origin checked when present). Logins rate-limited. No secrets in logs/audit.

## Design notes

- **Gate A:** Axum frontend on loopback, public `iroh-relay` APIs only. Subprotocol V2 preferred, V1 supported, others rejected. Signed-challenge fallback (no TLS exporter behind proxy/loopback).
- **Gate B:** SQLite policy store (`warden.db`) + in-memory admission cache (no SQLite on the handshake hot path). Revocation is publish-then-disconnect; registration is register-then-revalidate, closing the auth/register race. Speed-policy fields are validated and stored; enforcement lands in Gate C. Quota stub in `/admin/usage`; enforcement lands in Gate D.
- **Gate C:** shared per-endpoint debt buckets (`rx` upload / `tx` download, independent; `null` = unlimited owner exemption). Gating peeks, each frame deducts exactly once (polls/retries/flushes never charge). Policy edits reshape live transfers; reconnects reuse balances (no burst mint); unlimited→limited transitions start empty. Ordinary defaults required at production startup (`require_default_limits`); per-endpoint `custom` overrides or `unlimited`. Effective limits + byte/throttle counters in `GET /admin/endpoints` and `GET /admin/status`.
- **Gate D:** monthly budget on *charged* bytes (payload + `quota_overhead_pct`, default 10%) with cutoff at `budget - headroom`. Chunk leases (`quota_chunk_bytes`) granted by one serializing actor and committed to SQLite before spend; returns only for proven-unspent remainders, so crashes over-count (fail-closed). Exhaustion persists first, then denies + disconnects everyone incl. owners; new admissions denied on a shared flag. UTC-month ledgers, forward-only rollover, warnings at 75/90% persisted (delivery Gate E). Budget edits re-evaluate (audited `quota_reevaluated`); ordinary endpoint edits never touch the ledger. `require_quota_budget` gates production startup. In-flight bound ≈ connections × (chunk + max frame); charged bytes are relay accounting, not cloud billing.
- Backup: copy the db file while the server is stopped. Restoring an older copy reverts later revocations — re-verify approvals after any restore.

## Tests

```bash
rustup run 1.91.0 cargo test
```

Layout mirrors `src/`: each `tests/<module>.rs` covers one module's
responsibility (`tests/common/mod.rs` holds the shared harness), with unit
tests alongside the code they pin down:

- `relay` — transfer, denial, global ceiling. `policy` — records, revisions,
  admission, caps, revoke, quota flag. `store` — schema guard, settings,
  rows, ledger math, audit. `limiter` — caps, sharing, exemption, live
  updates, reconnect reuse, directions. `quota` — boundaries, exhaustion,
  charging, crash recovery, rollover, budget cuts, alerts. `admin` — auth,
  validation, revocation, sessions, status, metrics, body limits.
  `access`/`config` — allowlist decisions, startup validation.
