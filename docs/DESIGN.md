# relay-warden design note

Companion to the implementation handoff. Units, directions, lifecycle, and
failure behavior in one place so operators do not have to infer them.

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
(clean close) are handed back. Crash/restart therefore over-counts, never
under-counts. In-flight kernel/proxy bytes admitted before exhaustion cannot
be recalled; bound ≈ connections × (chunk + max frame). A packet-exact
network cap would need kernel-level accounting and is explicitly not claimed.

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
| Alert webhook down/misconfigured | Recorded in `last_delivery`; enforcement unaffected |
| Metrics scraper down | Enforcement unaffected (separate paths, no dependency) |
| Clock jumps forward | Next grant/refresh rolls the ledger forward |
| Clock jumps backward | Ignored; current ledger and exhaustion stand |
| Integer overflow in accounting | Saturating/checked math denies rather than wraps |
