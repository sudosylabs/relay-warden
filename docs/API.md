# Admin API

[Deploy](INSTALL.md) · [Dashboard guide](USAGE.md) · [Configuration](CONFIGURATION.md)

Base URL is the admin listener (loopback by default, e.g.
`http://127.0.0.1:8081`). The admin UI (`GET /admin/`) performs these same
calls; prefer it for interactive work and use this reference for scripting.

## Authentication

Two interchangeable mechanisms; data APIs require authentication. The
page shell, its CSS/JavaScript and `POST /admin/login` are public.
`GET /admin/session` specifically requires a valid session cookie.

**Bearer token** (scripts, API clients):

```bash
curl -H "Authorization: Bearer $(cat admin.token)" \
  http://127.0.0.1:8081/admin/status
```

**Session + CSRF** (browsers): `POST /admin/login {"token": "..."}` sets
an `HttpOnly; SameSite=Lax` cookie and returns `{"csrf": "..."}`. Mutating
requests must send it back as `X-CSRF-Token`; when an `Origin` header is
present its authority must match the full Host header (including port).
`GET /admin/session` returns `authenticated`, the session’s `csrf` token
and `expires_in_secs`, so a reload can restore the interface without
storing credentials in browser storage. All admin responses use
`Cache-Control: no-store`. Sessions expire after one
hour; `POST /admin/logout` ends them. Login attempts are rate-limited per
IP. Failed authentication returns `401`, failed CSRF/origin checks `403`.

## Endpoints

Set `TOKEN` from your admin token file and `ENDPOINT_ID` to the public ID
you want to manage. Never use a private key as an endpoint ID.

```bash
# List (approved and revoked) with live connection counts and limits
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8081/admin/endpoints

# Approve (create) — endpoint IDs are public keys, hex or base32;
# only the canonical form is stored
curl -X PUT "http://127.0.0.1:8081/admin/endpoints/$ENDPOINT_ID" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"label": "sensor 3", "approved": true}'

# Edit — updates require the current `revision` (409 on conflict);
# omitted rate fields are kept, explicit null clears them
curl -X PUT "http://127.0.0.1:8081/admin/endpoints/$ENDPOINT_ID" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"revision": 1, "speed_policy": "custom", "custom_rx_bps": 50000}'

# Revoke — denies immediately and disconnects live connections
curl -X POST "http://127.0.0.1:8081/admin/endpoints/$ENDPOINT_ID/revoke" \
  -H "Authorization: Bearer $TOKEN"
```

## Pending access requests

The list APIs accept `page` (positive integer) and `limit` (page size,
default 20, maximum 200). A paginated response includes `pagination`:
`page`, `page_size`, `total` and `total_pages`. Oversized page numbers
are clamped to the last page; empty lists use page 1. Devices also accept
`q`, searching names and endpoint IDs before pagination. For example:
`GET /admin/endpoints?page=2&limit=20&q=laptop`,
`GET /admin/pending?page=1&limit=20`, and
`GET /admin/audit?page=3&limit=20`.

Without `page`, existing list behaviour is preserved for API consumers;
the audit API retains its bounded latest-events `limit` behaviour.

`GET /admin/pending` returns `{"requests": [...], "mode": "requests"}` with verified
`endpoint_id`, trusted-source `observed_ip` (or null), `first_seen`,
`last_seen` and `attempts`. With approval disabled, `mode` is `"observed"`
and the list contains eligible unsaved identities that already have access.
If a relay token is required, only valid-token attempts appear.

Approve through the existing `PUT /admin/endpoints/{id}` API; use the
existing record’s revision if it has one. Approval removes the identity
from the pending list and lets it reconnect. `POST
/admin/pending/{id}/dismiss` removes an observation and audits the action.
It requires the same authentication and CSRF protection as other writes;
it does not permanently block the identity. Requests reset on restart,
expire after 24 hours and share a bounded cache of 1,000 observations.

Endpoint responses also include `observation` (nullable) and
`effective_limits`, which report configured speeds even before a device
connects. `status.access_policy` reports `token_required` and
`approval_required`; `pending_requests` and `denied_token_total` are
process-local diagnostics. Relay-access tokens never grant admin access.
`status.observed_devices` counts eligible unsaved observations in any mode.
`status.network_limits` reports startup network configuration, tracked source
count and network refusal count, or null when no network guard is attached.

## Settings, status, audit, usage, metrics

```bash
# Read settings with their version, then patch (409 on stale version)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8081/admin/settings
curl -X PATCH http://127.0.0.1:8081/admin/settings \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"version": 1, "settings": {"default_rx_bps": 100000}}'

curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8081/admin/status
curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8081/admin/audit?limit=50"
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8081/admin/usage
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8081/admin/metrics
```

`usage` reports the current UTC-month ledger: nominal budget, headroom,
effective cutoff, charged bytes, remaining bytes, exhaustion, warning flags
and an uncertainty note. `metrics` is Prometheus exposition with fixed,
low-cardinality labels (no endpoint IDs or IPs). Request bodies are capped
at 64 KiB (`413` beyond).
