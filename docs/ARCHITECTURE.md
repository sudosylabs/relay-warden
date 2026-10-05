# relay-warden architecture

How the upstream library integrates with policy, shaping, and accounting.
For operations see `OPERATIONS.md`; for settings reference see
`CONFIGURATION.md`.

## Upstream integration

One custom executable owns policy, accounting, administration, and the
relay integration around the public `iroh-relay` library API (no upstream
patches, no private APIs). The public HTTPS proxy stays shared
infrastructure; the relay itself binds loopback behind it.

```text
Approved Iroh clients
       |
       | HTTPS /relay
       v
Shared HTTPS edge ---- other hostnames ---> future services
       |
       v
Custom relay on loopback
  HTTP/WebSocket negotiation and bounded handshake
       |
  Upstream authentication and our admission policy
       |
  Endpoint-aware traffic adapter + shared quota gate
       |
  Upstream RelayedStream / Clients registry / routing
       |
  SQLite policy + accounting store
       ^
       |
Private admin API/UI + metrics + quota supervisor
```

Request path per connection: negotiate the WebSocket subprotocol (V2
preferred, V1 accepted, anything else rejected), wrap the socket in our
byte-stream adapter, run upstream `handshake::serverside`, authorize
against the current approval policy, attach the shared per-endpoint
limiter, register with the single shared `Clients` registry. Handshake
traffic flows unshaped; shaping and budget gating engage after
authorization. Behind a TLS-terminating edge there is no exporter keying
material, so authentication uses the signed-challenge fallback, exactly as
upstream's own embedding example does.

Module map: `relay` (protocol/adapter), `policy` (records, admission,
revocation), `limiter` (directional buckets), `quota` (monthly ledger),
`store` (SQLite on a worker thread), `admin` (private API/UI), `service`
(multi-step update coordinator), `config`, `observability` via
`/admin/status` + `/admin/metrics`.

## Design note

Units, directions, lifecycle, and failure behavior in one place so
operators do not have to infer them.

## Identity lifecycle

An **endpoint ID** is the public key of one app instance (client-proven via
the upstream relay handshake: signed challenge, or signed TLS-exporter key
material when the edge preserves it). It is not an IP, account, or device.

- Unknown IDs are denied by default. Approval is an explicit admin record.
- A key reset creates a *new* identity requiring fresh approval.
- Revocation publishes deny, then disconnects existing connections; a
  post-register revalidation closes the auth/register race for in-flight
  admissions. Reconnect stays denied. Live throttled transfers are cut the
  same way.
- Approval, speed policy, and budget draws are independent axes: unlimited
  speed still requires approval and still draws budget.

## Throughput directions

Both directions are capped independently per endpoint, shared across all of
that endpoint's connections (duplicates included):

- `rx_bps`: bytes/sec the relay **accepts from** the endpoint (its upload).
- `tx_bps`: bytes/sec the relay **delivers to** the endpoint (its download).
- `null` in either direction = unlimited there (owner exemption).
- `default` policy follows the operator's `default_rx/tx_bps`;
  `custom` carries per-endpoint overrides; `unlimited` carries none.
- Burst (`burst_bytes`, else `rate/10` clamped to 4KiB–1MiB) applies to each
  bucket independently. Reconfigurations clamp balances down, never mint;
  reconnects reuse the surviving limiter; unlimited→limited transitions
  start empty.

## Accounting units and cutoff precision

Three distinct numbers (never conflated in code or UI):

1. **Application bytes**: relay payload frames observed by the adapter
   (exact per-frame counters in `/admin/endpoints`).
2. **Charged bytes**: `payload + overhead allowance` (`quota_overhead_pct`,
   default 10%), committed to SQLite at chunk-grant time, before bytes enter
   the send pipeline. The enforced unit.
3. **Observed egress**: VPS/OCI counters including TLS, retries, proxy, and
   other services. Only visible outside this process.

Enforcement: `charged + grant <= budget - headroom`, serialized by one quota
actor. Everything granted is durable; only lease remainders proven unspent
(clean close) are handed back, tagged with their granting generation so a
stale refund can never reduce a newer month's ledger. Crash/restart
therefore over-counts, never under-counts. Framing rule: no outbound frame
is sent unless its complete charge (up to `MAX_PACKET_SIZE` + overhead) is
already reserved, so delivered bytes can never exceed durable charges; bytes
already in kernel/proxy buffers at exhaustion were all granted beforehand.
A packet-exact network cap would need kernel-level accounting and is
explicitly not claimed.

## Identity spelling

Endpoint IDs parse as hex or base32 but are stored, cached, and looked up
only in canonical hex (`Display`) form, canonicalized at the domain
boundary. An approved identity is therefore recognised however the operator
spelled it.

## Record updates

Endpoint edits are canonicalizing compare-and-swap: validation happens
against the cached revision, then one SQL statement writes only if the
revision still holds. Concurrent writers on one revision cannot both
succeed; losers refresh from the winning row and report a conflict.
Revocation always bumps the revision, so a stale edit can never overwrite
a concurrent revocation. Directional rate fields are tri-state (omitted =
keep, `null` = clear, value = set) so a custom cap can be removed again.
Settings patches validate every entry first, then commit in a single
transaction: a rejected patch changes nothing.

## Update coordination

Multi-step updates live in `service::App`, never scattered across handlers:
settings commit → audit → defaults refresh → limiter propagation → quota
re-evaluation; endpoint write → audit → limiter push → disconnect-on-unapprove.
Every control surface preserves the same order.

## Shutdown order

SIGTERM/SIGINT (or any listener failing on its own, which exits loudly so
systemd restarts) triggers: listeners stop accepting → clients drain
(returns proven-unspent remainders) → ledger actor confirms every queued
write persisted. Systemd's `TimeoutStopSec` bounds the sequence.

## Periods and exhaustion

UTC calendar months (`YYYY-MM`), forward-only rollover (a backward clock
never reopens a ledger or clears exhaustion). Exhaustion is persisted before
denial, disconnects every relay connection including owners, and denies new
admissions on a shared flag. Only the relay path stops; admin, proxy, and
future services keep running. Re-budgeting above usage reopens via an
audited settings change; ordinary endpoint edits never touch the ledger.

## Failure behavior

| Failure | Behavior |
|---|---|
| SQLite write fails on grant | Deny (fail-closed); nothing unrecorded is spent |
| SQLite corrupt/unreadable at startup | Process refuses to start |
| DB newer than binary (`user_version`) | Refuse to open |
| Crash between grant and send | Bytes stay charged (conservative) |
| Stale lease refund after month rollover | Dropped by generation tag; current ledger untouched |
| Restart with backward wall clock | Latest durable ledger adopted; spent quota cannot reopen |
| Alert webhook down/misconfigured | Recorded in `last_delivery`; enforcement unaffected |
| Metrics scraper down | Enforcement unaffected (separate paths, no dependency) |
| Clock jumps forward | Next grant/refresh rolls the ledger forward |
| Clock jumps backward | Ignored; current ledger and exhaustion stand |
| Integer overflow in accounting | Saturating/checked math denies rather than wraps |
