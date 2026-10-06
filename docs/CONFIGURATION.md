# Configuration

[Deploy](INSTALL.md) → [Use](USAGE.md) → Configuration reference

Looking for your first setup? Start with [Deploy your relay](INSTALL.md).
For everyday changes, use [the dashboard guide](USAGE.md). This page lists
settings when you need more control. Speeds are
**bytes per second** (`100_000` ≈ 100 KB/s ≈ 0.8 Mbit/s); budgets are
**bytes**, decimal (`6_000_000_000_000` = 6 TB, not 6 TiB).

## Precedence: file seeds, database wins

On startup, values from the TOML config file are written into the SQLite
database **only when the corresponding database setting is absent**
(`INSERT OR IGNORE`). Editing the file afterwards does **not** overwrite
values an administrator already set — change those with `PATCH
/admin/settings` (or the settings panel in the admin UI). To re-seed from
the file, clear the database key first or start from a fresh state
directory. Do not do this on a live relay to change limits: it also removes
recorded usage and access policies. `require_default_limits` / `require_quota_budget` are
startup-time guards read from the file only.

## Relay and admin listeners

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8080` | Relay `/relay` bind. Behind a proxy this stays loopback; direct exposure is an operator decision. |
| `admin_listen` | `127.0.0.1:8081` | Admin API/UI bind. Keep loopback; use an SSH tunnel (`ssh -L 8081:127.0.0.1:8081 you@host`). |
| `admin_token_file` | `admin.token` | File holding the high-entropy admin token (`chmod 600`). Missing/short file refuses startup; there is no default password. |
| `db_path` | `warden.db` | SQLite state: policies, settings, ledger, audit. Back it up; see `OPERATIONS.md`. |

## Access policy

Access options are read from the config file at startup, not seeded into
SQLite or editable through the settings API. Restart to change them.

| `require_endpoint_approval` | `relay_token_file` | Who can relay |
|---|---|---|
| `true` | omitted | Approved endpoint IDs |
| `true` | configured | Valid token and approved endpoint ID |
| `false` | configured | Any verified endpoint with the valid token |
| `false` (default) | omitted | Public access with layered limits |

Saved records with `approved = false` are denied in every mode, so
revocation also works in public and token-only deployments. Unsaved
devices in those modes receive ordinary default speed limits. All modes
respect an enabled monthly budget, including unlimited-speed devices.

Set `require_endpoint_approval = true` explicitly for an approval-only relay;
do not rely on an omitted option to keep a deployment private.
No token is required unless `relay_token_file` is configured.

To require a token, generate a high-entropy secret in a private file
(`chmod 600`) and set `relay_token_file = "relay.token"`. Missing files,
tokens shorter than 16 characters and reuse of the admin token refuse
startup. Share only the relay-access token with clients, never the admin
credential. Token rotation requires a restart and updating your clients.

Iroh clients use `RelayConfig::with_auth_token(token)`; low-level
`iroh_relay::client::ClientBuilder` clients use `.auth_token(token)`.
Native clients send `Authorization: Bearer …`. Browser/Wasm clients use
Iroh’s `token` URL query fallback: keep reverse-proxy access logs from
recording query strings, and always expose the public relay over HTTPS.

When approval is required, verified identities with a valid token (if
configured) appear in the pending queue after attempting to connect.
They cannot relay until approved and reconnected. Invalid-token or
quota-exhausted attempts do not create pending requests. Verify an ID
with its owner before approving; possession of a shared token is not
proof of the person’s identity.

Recent observations are in memory, capped at 1,000 identities, expire
after 24 hours without an eligible attempt and reset on restart. A full
observation cache skips new entries rather than growing unbounded. Saved
approvals, revocations and their audit history remain durable. Dismiss
only removes a request; the next attempt may recreate it.

In public and token-only modes the dashboard shows **Observed devices**,
not approval requests. Eligible unsaved identities already have access.

The dashboard and network safeguards use the socket peer IP by default.
Forwarded headers are ignored unless the peer is an explicitly trusted
proxy. An IP is context, not an access identity, and can be shared or change.

## Network safeguards

These startup-only options live in the `[network]` TOML table. They supplement
endpoint caps and the monthly budget; they do not replace either. Rates are
bytes per second in each direction, with a burst equal to the larger rate
clamped to 4,096–1,048,576 bytes. Defaults are starting values,
not a claim to reproduce Iroh's unpublished public-relay rates.

| Option | Default | Meaning |
|---|---|---|
| `ip_rx_bps` / `ip_tx_bps` | `1_000_000` | Shared across ordinary endpoints using a source IP. |
| `prefix_rx_bps` / `prefix_tx_bps` | `5_000_000` | Shared across addresses in a configured prefix. |
| `global_rx_bps` / `global_tx_bps` | `10_000_000` | Shared across every relayed connection, including exempt devices. |
| `ipv6_prefix` | `64` | IPv6 network grouping length. |
| `ipv6_prefix_enabled` | `true` | Set false to disable IPv6 grouping. |
| `ipv4_prefix` | unset | IPv4 grouping is off; set e.g. 24 deliberately. |
| `attempts_per_second` / `attempt_burst` | `5` / `20` | Per-IP relay HTTP connection attempts. |
| `prefix_attempts_per_second` / `prefix_attempt_burst` | `20` / `80` | Aggregate attempts for a configured prefix. |
| `global_attempts_per_second` / `global_attempt_burst` | `100` / `200` | Aggregate relay attempts before authentication. |
| `max_connections_per_ip` | `64` | Includes upgraded unauthenticated connections. |
| `max_connections_per_prefix` | `256` | Same ceiling for grouped addresses. |
| `max_entries` | `16384` | Combined IP/prefix entry bound; also the endpoint limiter registry bound. |
| `trusted_proxies` | `[]` | Exact socket-peer IPs of controlled reverse proxies. |

Bandwidth exhaustion applies backpressure. Source/attempt/capacity refusal
returns HTTP 429 before WebSocket upgrade; global concurrent or handshake
capacity refusal returns 503. Each retry is an attempt. Reconnects reuse
source buckets. Idle tracking entries are reclaimed only after at least ten
minutes and sufficient refill time; live entries and outstanding debt are
not evicted to make room. Full registries fail closed. Tracking resets on
process restart; durable monthly usage does not.

Only an **approved** saved endpoint with `speed_policy = "unlimited"` is
exempt from IP/prefix speed caps. Live policy updates apply to existing
connections. It still obeys global bandwidth, connection safeguards,
and the monthly budget. Leaving custom caps unset is not an exemption.

Shared-IP limits can affect campuses, households and carrier NAT users.
Adjust aggregate caps for your users. Broader subnet limits can penalize
unrelated people; they cannot identify a person changing networks.

For a controlled local reverse proxy, explicitly set
`trusted_proxies = ["127.0.0.1", "::1"]` in `[network]` and have the proxy
overwrite or correctly append `X-Forwarded-For`. Trusted peers must provide
one valid header; missing/malformed chains return 400. Chains are walked
right-to-left through explicitly trusted hops, stopping at the first
untrusted address. Untrusted peers' headers are ignored, IPv4-mapped IPv6
is normalized, and other forwarding headers are ignored. Never expose a
proxy listener that permits spoofed source headers.

These are application-layer relay safeguards, not volumetric DDoS protection:
TLS/TCP work happens upstream. Use host/proxy protections as well. Set global
speeds and a deployment-specific monthly budget with room for other services;
Relay Warden does not account for their traffic.

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
[architecture](ARCHITECTURE.md) for the accounting model and
[operations](OPERATIONS.md#the-monthly-budget-ran-out) for exhaustion response.

## What persists in SQLite

`endpoints` (policy + revision), `settings` (including `settings_version`),
`quota_periods` (one ledger row per UTC month: charged bytes, exhaustion,
warning flags), `audit` (append-only admin actions, no secrets).
Connection state, limiter balances beyond the ledger, and sessions are
in-memory only. Restoring an old database reverts usage and approvals —
never restore over a live ledger; see `OPERATIONS.md` rollback.
