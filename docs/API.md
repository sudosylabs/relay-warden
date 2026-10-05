# Admin API

Base URL is the admin listener (loopback by default, e.g.
`http://127.0.0.1:8081`). The admin UI (`GET /admin/`) performs these same
calls; prefer it for interactive work and use this reference for scripting.

## Authentication

Two interchangeable mechanisms; every endpoint except `GET /admin/` and
`POST /admin/login` requires one of them.

**Bearer token** (scripts, API clients):

```bash
curl -H "Authorization: Bearer $(cat admin.token)" \
  http://127.0.0.1:8081/admin/status
```

**Session + CSRF** (browsers): `POST /admin/login {"token": "..."}` sets
an `HttpOnly; SameSite=Lax` cookie and returns `{"csrf": "..."}`. Mutating
requests must send it back as `X-CSRF-Token`; when an `Origin` header is
present it must match the host or be loopback. Sessions expire after one
hour; `POST /admin/logout` ends them. Login attempts are rate-limited per
IP. Failed authentication returns `401`, failed CSRF/origin checks `403`.

## Endpoints

```bash
# List (approved and revoked) with live connection counts and limits
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8081/admin/endpoints

# Approve (create) — endpoint IDs are public keys, hex or base32;
# only the canonical form is stored
curl -X PUT http://127.0.0.1:8081/admin/endpoints/<ENDPOINT_ID> \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"label": "sensor 3", "approved": true}'

# Edit — updates require the current `revision` (409 on conflict);
# omitted rate fields are kept, explicit null clears them
curl -X PUT http://127.0.0.1:8081/admin/endpoints/<ENDPOINT_ID> \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"revision": 1, "speed_policy": "custom", "custom_rx_bps": 50000}'

# Revoke — denies immediately and disconnects live connections
curl -X POST http://127.0.0.1:8081/admin/endpoints/<ENDPOINT_ID>/revoke \
  -H "Authorization: Bearer $TOKEN"
```

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
