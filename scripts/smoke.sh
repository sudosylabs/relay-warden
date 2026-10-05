#!/usr/bin/env bash
# Smoke-test a packaged release archive against a throwaway local instance.
# Never deploys anywhere: everything binds loopback in a temp directory.
#
# Usage: scripts/smoke.sh <archive.tar.gz> [example-client-dir]
set -euo pipefail
ARCH="$1"
WORK="$(mktemp -d)"
trap 'kill ${SRV:-0} 2>/dev/null; rm -rf "$WORK"' EXIT
tar -C "$WORK" -xzf "$ARCH"
DIR="$(echo "$WORK"/relay-warden-v*)"
test -x "$DIR/relay-warden"

# Fresh state, production-shaped config. No real budget spent: tiny allowance.
head -c 32 /dev/urandom | base64 > "$WORK/admin.token"
chmod 600 "$WORK/admin.token"
PORT_R=$((18080 + RANDOM % 1000)); PORT_A=$((19080 + RANDOM % 1000))
sed -e "s#^listen = .*#listen = \"127.0.0.1:$PORT_R\"#" \
    -e "s#^admin_listen = .*#admin_listen = \"127.0.0.1:$PORT_A\"#" \
    -e "s#^db_path = .*#db_path = \"$WORK/warden.db\"#" \
    -e "s#^admin_token_file = .*#admin_token_file = \"$WORK/admin.token\"#" \
    -e "s#^quota_budget_bytes = .*#quota_budget_bytes = 100000000#" \
    -e "s#^quota_headroom_bytes = .*#quota_headroom_bytes = 1000000#" \
    "$DIR/warden.example.toml" > "$WORK/warden.toml"

"$DIR/relay-warden" --config "$WORK/warden.toml" & SRV=$!
TOKEN="$(cat "$WORK/admin.token")"
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$PORT_R/ping" >/dev/null && break; sleep 0.2; done
curl -sf "http://127.0.0.1:$PORT_R/ping" >/dev/null
echo "relay: OK"
test "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT_A/admin/status")" = "401"
AUTH="Authorization: Bearer $TOKEN"
test "$(curl -s -H "$AUTH" "http://127.0.0.1:$PORT_A/admin/status" | python3 -c 'import json,sys; print(json.load(sys.stdin)["db_ok"])')" = "True"
echo "admin auth: OK"
test "$(curl -s -H "$AUTH" "http://127.0.0.1:$PORT_A/admin/metrics" | grep -c '^warden_live_connections')" = "1"
echo "metrics: OK"

# Real relayed transfer after approval, via the compiled example client.
# Second positional arg: path to the `relayed_transfer` example binary.
test -n "${2:-}" || { echo "usage: $0 <archive> <example-binary>" >&2; exit 1; }
"$2" --relay "http://127.0.0.1:$PORT_R" --admin "http://127.0.0.1:$PORT_A" --admin-token "$TOKEN" | tail -n 1 | grep -q "relayed transfer OK"
echo "smoke: OK"
